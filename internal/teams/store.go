package teams

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// DefaultConfigMapKey is the key holding the teams YAML. It matches the key
// the Helm chart writes, so a chart-managed mapping and an API-managed one are
// the same object.
const DefaultConfigMapKey = "teams.yaml"

// Team is one team in the structured API representation. The file format
// accepts two shapes for a team; this is the single shape the API speaks, so
// clients never have to handle the terse form.
type Team struct {
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
	// NotifyURL is this team's webhook. A Slack or Teams webhook URL is itself
	// the credential, so the GET handler redacts it (see Redacted) and reads it
	// back from the stored mapping when a PUT leaves it unchanged.
	NotifyURL string `json:"notifyUrl,omitempty"`
}

// Spec is the full mapping — what GET returns and PUT accepts.
type Spec struct {
	Teams []Team `json:"teams"`
}

// Validate rejects a mapping that Load would later refuse, so a bad PUT fails
// at the API instead of at the next scan.
func (s Spec) Validate() error {
	owner := map[string]string{}
	seenTeam := map[string]bool{}
	for _, t := range s.Teams {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			return fmt.Errorf("every team needs a name")
		}
		if seenTeam[name] {
			return fmt.Errorf("team %q is listed twice", name)
		}
		seenTeam[name] = true
		for _, ns := range t.Namespaces {
			ns = strings.TrimSpace(ns)
			if ns == "" {
				return fmt.Errorf("team %q has an empty namespace entry", name)
			}
			if prev, taken := owner[ns]; taken && prev != name {
				return fmt.Errorf("namespace %q is mapped to both %q and %q", ns, prev, name)
			}
			owner[ns] = name
		}
	}
	return nil
}

// RedactedURL replaces a configured webhook in API responses. A client can
// tell "has one" from "has none" without the URL crossing the wire, and can
// send it back unchanged to mean "leave it alone".
const RedactedURL = "***"

// Redacted returns a copy safe to serve: webhook URLs become RedactedURL.
func (s Spec) Redacted() Spec {
	out := Spec{Teams: make([]Team, len(s.Teams))}
	for i, t := range s.Teams {
		if t.NotifyURL != "" {
			t.NotifyURL = RedactedURL
		}
		out.Teams[i] = t
	}
	return out
}

// MergeSecrets restores webhook URLs the client sent back redacted, taking
// them from prev. Without this, saving an unrelated edit through a UI that
// only ever saw "***" would wipe every team's webhook.
func (s Spec) MergeSecrets(prev Spec) Spec {
	was := map[string]string{}
	for _, t := range prev.Teams {
		was[t.Name] = t.NotifyURL
	}
	out := Spec{Teams: make([]Team, len(s.Teams))}
	for i, t := range s.Teams {
		if t.NotifyURL == RedactedURL {
			t.NotifyURL = was[t.Name]
		}
		out.Teams[i] = t
	}
	return out
}

// Config converts the spec into the resolved lookup the analyzer uses.
func (s Spec) Config() Config {
	cfg := Config{NamespaceTeam: map[string]string{}, NotifyURLs: map[string]string{}}
	for _, t := range s.Teams {
		for _, ns := range t.Namespaces {
			cfg.NamespaceTeam[ns] = t.Name
		}
		if t.NotifyURL != "" {
			cfg.NotifyURLs[t.Name] = t.NotifyURL
		}
	}
	return cfg
}

// MarshalYAML renders the spec in the same file format Load reads, so a
// mapping written through the API stays readable and hand-editable.
func (s Spec) MarshalYAML() ([]byte, error) {
	type full struct {
		Namespaces []string `json:"namespaces"`
		NotifyURL  string   `json:"notifyUrl,omitempty"`
	}
	out := struct {
		Teams map[string]full `json:"teams"`
	}{Teams: map[string]full{}}
	for _, t := range s.Teams {
		ns := append([]string(nil), t.Namespaces...)
		slices.Sort(ns)
		out.Teams[t.Name] = full{Namespaces: ns, NotifyURL: t.NotifyURL}
	}
	return yaml.Marshal(out)
}

// ParseSpec reads the file format into the structured representation.
func ParseSpec(data []byte) (Spec, error) {
	var raw struct {
		Teams map[string]json.RawMessage `json:"teams"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Spec{}, fmt.Errorf("parsing teams: %w", err)
	}
	spec := Spec{Teams: []Team{}}
	for name, msg := range raw.Teams {
		t := Team{Name: name, Namespaces: []string{}}
		if err := json.Unmarshal(msg, &t.Namespaces); err != nil {
			var fullForm struct {
				Namespaces []string `json:"namespaces"`
				NotifyURL  string   `json:"notifyUrl"`
			}
			if err := json.Unmarshal(msg, &fullForm); err != nil {
				return Spec{}, fmt.Errorf("team %q: expected a namespace list or {namespaces, notifyUrl}", name)
			}
			t.Namespaces, t.NotifyURL = fullForm.Namespaces, fullForm.NotifyURL
		}
		if t.Namespaces == nil {
			t.Namespaces = []string{}
		}
		slices.Sort(t.Namespaces)
		spec.Teams = append(spec.Teams, t)
	}
	// Map iteration is random; sort so GET is stable between calls.
	slices.SortFunc(spec.Teams, func(a, b Team) int { return strings.Compare(a.Name, b.Name) })
	return spec, nil
}

// Store reads and writes the mapping as a ConfigMap, making team ownership
// editable at runtime instead of only at startup. The ConfigMap is the same
// one the Helm chart renders from its `teams` value.
type Store struct {
	Clientset kubernetes.Interface
	Namespace string
	Name      string
	Key       string
}

func (s *Store) key() string {
	if s.Key == "" {
		return DefaultConfigMapKey
	}
	return s.Key
}

// Get returns the current mapping. A missing ConfigMap is an empty mapping,
// not an error: nothing has been configured yet is a normal state.
func (s *Store) Get(ctx context.Context) (Spec, error) {
	cm, err := s.Clientset.CoreV1().ConfigMaps(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Spec{Teams: []Team{}}, nil
	}
	if err != nil {
		return Spec{}, fmt.Errorf("reading configmap %s/%s: %w", s.Namespace, s.Name, err)
	}
	return ParseSpec([]byte(cm.Data[s.key()]))
}

// Put replaces the mapping, creating the ConfigMap if it does not exist.
func (s *Store) Put(ctx context.Context, spec Spec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	data, err := spec.MarshalYAML()
	if err != nil {
		return fmt.Errorf("encoding teams: %w", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: s.Namespace, Name: s.Name},
		Data:       map[string]string{s.key(): string(data)},
	}
	existing, err := s.Clientset.CoreV1().ConfigMaps(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := s.Clientset.CoreV1().ConfigMaps(s.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("creating configmap %s/%s: %w", s.Namespace, s.Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading configmap %s/%s: %w", s.Namespace, s.Name, err)
	}
	// Preserve any other keys — the ConfigMap may carry more than this mapping.
	if existing.Data == nil {
		existing.Data = map[string]string{}
	}
	existing.Data[s.key()] = string(data)
	if _, err := s.Clientset.CoreV1().ConfigMaps(s.Namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating configmap %s/%s: %w", s.Namespace, s.Name, err)
	}
	return nil
}

// NamespaceTeam returns just the ownership lookup, for refreshing analyzer
// options before a scan. Errors are the caller's to log and ignore: a
// transient read failure should not stop a scan.
func (s *Store) NamespaceTeam(ctx context.Context) (map[string]string, error) {
	spec, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	return spec.Config().NamespaceTeam, nil
}

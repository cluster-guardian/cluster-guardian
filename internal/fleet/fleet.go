// Package fleet manages the cluster registry and scheduled scanning for the
// hosted multi-cluster scorecard mode.
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
)

// SecretLabel marks Secrets that register a cluster with the fleet. A
// cluster is added declaratively by creating a labeled Secret holding the
// connection details — no API call or UI needed.
const SecretLabel = "cluster-guardian.io/secret-type"

// Cluster is one registered cluster and how to reach it. Build is lazy so
// credentials are only turned into clients when a scan runs.
type Cluster struct {
	Name   string
	Server string
	Build  func() (*kube.Client, error)
}

// clusterSecretConfig is the JSON in a cluster secret's "config" key.
type clusterSecretConfig struct {
	BearerToken     string `json:"bearerToken"`
	TLSClientConfig struct {
		Insecure bool   `json:"insecure"`
		CAData   []byte `json:"caData"`
	} `json:"tlsClientConfig"`
}

// ParseClusterSecret converts a labeled Secret into a Cluster.
func ParseClusterSecret(sec corev1.Secret) (Cluster, error) {
	name := string(sec.Data["name"])
	server := string(sec.Data["server"])
	if name == "" || server == "" {
		return Cluster{}, fmt.Errorf("cluster secret %s/%s: name and server are required", sec.Namespace, sec.Name)
	}
	var cfg clusterSecretConfig
	if raw := sec.Data["config"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return Cluster{}, fmt.Errorf("cluster secret %s/%s: parsing config: %w", sec.Namespace, sec.Name, err)
		}
	}
	return Cluster{
		Name:   name,
		Server: server,
		Build: func() (*kube.Client, error) {
			return kube.NewClientForCluster(name, server, cfg.BearerToken,
				cfg.TLSClientConfig.CAData, cfg.TLSClientConfig.Insecure)
		},
	}, nil
}

// ClusterLister enumerates the clusters to scan.
type ClusterLister interface {
	Clusters(ctx context.Context) ([]Cluster, error)
}

// Registry lists the local cluster plus every labeled Secret in Namespace.
type Registry struct {
	Local     *kube.Client
	Clientset kubernetes.Interface
	Namespace string
}

// Clusters implements ClusterLister. A failure listing secrets still returns
// the local cluster so the scorecard keeps working.
func (r *Registry) Clusters(ctx context.Context) ([]Cluster, error) {
	localName := r.Local.Context
	if localName == "" {
		localName = "local"
	}
	local := r.Local
	out := []Cluster{{
		Name:   localName,
		Server: "local",
		Build:  func() (*kube.Client, error) { return local, nil },
	}}
	seen := map[string]bool{localName: true}

	list, err := r.Clientset.CoreV1().Secrets(r.Namespace).List(ctx, metav1.ListOptions{LabelSelector: SecretLabel + "=cluster"})
	if err != nil {
		return out, fmt.Errorf("listing cluster secrets: %w", err)
	}
	for _, sec := range list.Items {
		c, err := ParseClusterSecret(sec)
		if err != nil {
			log.Printf("fleet: skipping %s", err)
			continue
		}
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		out = append(out, c)
	}
	return out, nil
}

// SanitizeName makes a cluster name safe as a filesystem path segment.
func SanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

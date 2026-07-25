package checks

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// nsRefs holds the names of resources referenced by anything in a namespace.
type nsRefs struct {
	configMaps map[string]bool
	secrets    map[string]bool
	pvcs       map[string]bool
}

// unusedFindings reports resources nothing references — deletion candidates
// (unused ConfigMaps/Secrets, unmounted PVCs) and broken wiring (Services
// matching no pods, dangling Ingress and HTTPRoute backends, HPAs and PDBs
// with no target).
// Everything is informational: this is a report, not an accusation.
func unusedFindings(s *kube.Snapshot, ns string) []report.Finding {
	refs := referencesIn(s, ns)

	var unusedCM []string
	for _, cm := range s.ConfigMaps {
		if cm.Namespace == ns && cm.Name != "kube-root-ca.crt" && !refs.configMaps[cm.Name] {
			unusedCM = append(unusedCM, cm.Name)
		}
	}
	var unusedSec []string
	for _, sec := range s.Secrets {
		if sec.Namespace == ns && !isGeneratedSecret(sec) && !refs.secrets[sec.Name] {
			unusedSec = append(unusedSec, sec.Name)
		}
	}
	var unmounted, unbound []string
	for _, pvc := range s.PVCs {
		if pvc.Namespace != ns {
			continue
		}
		if !refs.pvcs[pvc.Name] {
			unmounted = append(unmounted, pvc.Name)
		}
		if pvc.Status.Phase != corev1.ClaimBound {
			unbound = append(unbound, pvc.Name)
		}
	}

	// Services whose selector matches no running pod.
	var lonelyServices []string
	for _, svc := range s.Services {
		if svc.Namespace != ns || len(svc.Spec.Selector) == 0 {
			continue
		}
		if !anyPodMatches(s, ns, labels.SelectorFromSet(svc.Spec.Selector)) {
			lonelyServices = append(lonelyServices, svc.Name)
		}
	}

	// Ingress backends pointing at Services that don't exist.
	svcNames := map[string]bool{}
	for _, svc := range s.Services {
		if svc.Namespace == ns {
			svcNames[svc.Name] = true
		}
	}
	var danglingIngress []string
	for _, ing := range s.Ingresses {
		if ing.Namespace != ns {
			continue
		}
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if b := path.Backend.Service; b != nil && !svcNames[b.Name] {
					danglingIngress = append(danglingIngress, ing.Name+" -> "+b.Name)
				}
			}
		}
	}

	// HTTPRoute backendRefs pointing at Services that don't exist.
	var danglingRoutes []string
	for _, route := range s.HTTPRoutes {
		if route.GetNamespace() != ns {
			continue
		}
		for _, backend := range httpRouteServiceBackends(route) {
			if !svcNames[backend] {
				danglingRoutes = append(danglingRoutes, route.GetName()+" -> "+backend)
			}
		}
	}

	// HPAs whose scale target doesn't exist.
	workloads := map[string]bool{}
	for _, d := range s.Deployments {
		if d.Namespace == ns {
			workloads["Deployment/"+d.Name] = true
		}
	}
	for _, ss := range s.StatefulSets {
		if ss.Namespace == ns {
			workloads["StatefulSet/"+ss.Name] = true
		}
	}
	var danglingHPA []string
	for _, hpa := range s.HPAs {
		if hpa.Namespace != ns {
			continue
		}
		ref := hpa.Spec.ScaleTargetRef
		if (ref.Kind == "Deployment" || ref.Kind == "StatefulSet") && !workloads[ref.Kind+"/"+ref.Name] {
			danglingHPA = append(danglingHPA, hpa.Name)
		}
	}

	// PDBs selecting no pods.
	var emptyPDB []string
	for _, pdb := range s.PDBs {
		if pdb.Namespace != ns || pdb.Spec.Selector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		if !anyPodMatches(s, ns, sel) {
			emptyPDB = append(emptyPDB, pdb.Name)
		}
	}

	var out []report.Finding
	add := func(names []string, one, many, hint string) {
		if n := len(names); n > 0 {
			out = append(out, report.Finding{
				Severity: report.SeverityInfo,
				Message:  fmt.Sprintf("%d %s (%s)", n, plural(n, one, many), joinLimited(names, 4)),
				Hint:     hint,
			})
		}
	}
	add(unusedCM, "unused ConfigMap", "unused ConfigMaps",
		"Not referenced by any pod, workload template, or projected volume — candidates for deletion.")
	add(unusedSec, "unused Secret", "unused Secrets",
		"Not referenced by pods, ServiceAccounts, Ingress TLS, or Gateway TLS. Verify out-of-band consumers before deleting.")
	add(unmounted, "PVC not mounted by any Pod", "PVCs not mounted by any Pod",
		"Unattached volumes still incur storage cost.")
	add(unbound, "unbound PVC", "unbound PVCs",
		"Pending or Lost claims: check the StorageClass and provisioner.")
	add(lonelyServices, "Service with no matching Pods", "Services with no matching Pods",
		"The selector matches nothing; traffic to these Services goes nowhere.")
	add(danglingIngress, "Ingress path routing to a missing Service", "Ingress paths routing to missing Services", "")
	add(danglingRoutes, "HTTPRoute backend routing to a missing Service", "HTTPRoute backends routing to missing Services", "")
	add(danglingHPA, "HPA targeting a missing workload", "HPAs targeting missing workloads", "")
	add(emptyPDB, "PodDisruptionBudget selecting no Pods", "PodDisruptionBudgets selecting no Pods",
		"A PDB that matches nothing protects nothing — the selector is probably stale.")
	return out
}

// referencesIn walks every pod spec in the namespace (running pods plus
// workload templates, so suspended CronJobs still count) and records which
// ConfigMaps, Secrets and PVCs are referenced.
func referencesIn(s *kube.Snapshot, ns string) nsRefs {
	refs := nsRefs{configMaps: map[string]bool{}, secrets: map[string]bool{}, pvcs: map[string]bool{}}

	addSpec := func(spec corev1.PodSpec) {
		for _, v := range spec.Volumes {
			switch {
			case v.ConfigMap != nil:
				refs.configMaps[v.ConfigMap.Name] = true
			case v.Secret != nil:
				refs.secrets[v.Secret.SecretName] = true
			case v.PersistentVolumeClaim != nil:
				refs.pvcs[v.PersistentVolumeClaim.ClaimName] = true
			case v.Projected != nil:
				for _, src := range v.Projected.Sources {
					if src.ConfigMap != nil {
						refs.configMaps[src.ConfigMap.Name] = true
					}
					if src.Secret != nil {
						refs.secrets[src.Secret.Name] = true
					}
				}
			}
		}
		containers := make([]corev1.Container, 0, len(spec.InitContainers)+len(spec.Containers))
		containers = append(containers, spec.InitContainers...)
		containers = append(containers, spec.Containers...)
		for _, c := range containers {
			for _, e := range c.Env {
				if e.ValueFrom == nil {
					continue
				}
				if r := e.ValueFrom.ConfigMapKeyRef; r != nil {
					refs.configMaps[r.Name] = true
				}
				if r := e.ValueFrom.SecretKeyRef; r != nil {
					refs.secrets[r.Name] = true
				}
			}
			for _, ef := range c.EnvFrom {
				if ef.ConfigMapRef != nil {
					refs.configMaps[ef.ConfigMapRef.Name] = true
				}
				if ef.SecretRef != nil {
					refs.secrets[ef.SecretRef.Name] = true
				}
			}
		}
		for _, ips := range spec.ImagePullSecrets {
			refs.secrets[ips.Name] = true
		}
	}

	for _, p := range s.Pods {
		if p.Namespace == ns {
			addSpec(p.Spec)
		}
	}
	forEachWorkloadPodSpec(s, ns, func(_, _ string, spec corev1.PodSpec) {
		addSpec(spec)
	})
	for _, j := range s.Jobs {
		if j.Namespace == ns {
			addSpec(j.Spec.Template.Spec)
		}
	}
	for _, sa := range s.ServiceAccounts {
		if sa.Namespace != ns {
			continue
		}
		for _, sec := range sa.Secrets {
			refs.secrets[sec.Name] = true
		}
		for _, ips := range sa.ImagePullSecrets {
			refs.secrets[ips.Name] = true
		}
	}
	for _, ing := range s.Ingresses {
		if ing.Namespace != ns {
			continue
		}
		for _, tls := range ing.Spec.TLS {
			refs.secrets[tls.SecretName] = true
		}
	}
	for _, gw := range s.Gateways {
		if gw.GetNamespace() != ns {
			continue
		}
		for _, name := range gatewayTLSSecretNames(gw) {
			refs.secrets[name] = true
		}
	}
	return refs
}

// isGeneratedSecret reports controller-owned secrets that must never be
// flagged as unused (SA tokens, Helm release storage, bootstrap tokens).
func isGeneratedSecret(sec corev1.Secret) bool {
	if sec.Type == corev1.SecretTypeServiceAccountToken {
		return true
	}
	t := string(sec.Type)
	return strings.HasPrefix(t, "helm.sh/release") || strings.HasPrefix(t, "bootstrap.kubernetes.io/")
}

func anyPodMatches(s *kube.Snapshot, ns string, sel labels.Selector) bool {
	for _, p := range s.Pods {
		if p.Namespace == ns && p.Status.Phase != corev1.PodSucceeded && sel.Matches(labels.Set(p.Labels)) {
			return true
		}
	}
	return false
}

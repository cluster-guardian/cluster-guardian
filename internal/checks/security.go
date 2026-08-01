package checks

import (
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/cluster-guardian/cluster-guardian/internal/kube"
	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

var dangerousCapabilities = map[string]bool{
	"SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true,
	"SYS_MODULE": true, "DAC_READ_SEARCH": true, "NET_RAW": true, "BPF": true,
}

// Security runs cluster-wide security checks.
func Security(s *kube.Snapshot, namespaces []string) report.Section {
	sec := report.Section{ID: "security", Title: "Security", Icon: "🔒"}
	nsSet := namespaceSet(namespaces)

	var rootContainers, privileged, hostNetwork, dangerousCaps int
	for _, pod := range s.Pods {
		if !nsSet[pod.Namespace] || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
			hostNetwork++
		}
		for _, c := range pod.Spec.Containers {
			if runsAsRoot(pod.Spec.SecurityContext, c.SecurityContext) {
				rootContainers++
			}
			if sc := c.SecurityContext; sc != nil {
				if sc.Privileged != nil && *sc.Privileged {
					privileged++
				}
				if sc.Capabilities != nil {
					for _, cap := range sc.Capabilities.Add {
						if dangerousCapabilities[string(cap)] {
							dangerousCaps++
							break
						}
					}
				}
			}
		}
	}

	if rootContainers > 0 {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s running as root", rootContainers, plural(rootContainers, "container", "containers")),
			Hint:     "Set securityContext.runAsNonRoot: true and a non-zero runAsUser.",
			Controls: []string{ctrlRunAsNonRoot},
		})
	}
	if privileged > 0 {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityCritical,
			Message:  fmt.Sprintf("%d privileged %s", privileged, plural(privileged, "container", "containers")),
			Hint:     "Privileged containers have full access to the host. Replace with specific capabilities.",
			Controls: []string{ctrlPrivileged},
		})
	}
	if dangerousCaps > 0 {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s with dangerous capabilities (SYS_ADMIN, NET_ADMIN, ...)", dangerousCaps, plural(dangerousCaps, "container", "containers")),
			Controls: []string{ctrlCapabilities},
		})
	}
	if hostNetwork > 0 {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s using host network/PID/IPC", hostNetwork, plural(hostNetwork, "Pod", "Pods")),
			Controls: []string{ctrlHostNamespaces},
		})
	}

	// Namespaces without any NetworkPolicy.
	nsWithPolicy := map[string]bool{}
	for _, np := range s.NetworkPolicies {
		nsWithPolicy[np.Namespace] = true
	}
	var unprotected []string
	for _, ns := range namespaces {
		if !nsWithPolicy[ns] && namespaceHasPods(s, ns) {
			unprotected = append(unprotected, ns)
		}
	}
	if len(unprotected) > 0 {
		sec.Findings = append(sec.Findings, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s without NetworkPolicies (%s)", len(unprotected), plural(len(unprotected), "namespace", "namespaces"), joinLimited(unprotected, 4)),
			Hint:     "Without NetworkPolicies every pod can talk to every other pod.",
		})
	}

	sec.Findings = append(sec.Findings, hardeningFindings(s, nsSet)...)
	sec.Findings = append(sec.Findings, pssLabelFindings(s, nsSet)...)
	sec.Findings = append(sec.Findings, rbacFindings(s)...)
	sec.Findings = append(sec.Findings, complianceSummary(sec.Findings))
	return sec
}

// pssEnforceLabel gates pods at admission when set on a namespace.
const pssEnforceLabel = "pod-security.kubernetes.io/enforce"

// pssLabelFindings flags analyzed namespaces without Pod Security Standards
// enforcement. Only namespaces present in the snapshot are judged.
func pssLabelFindings(s *kube.Snapshot, nsSet map[string]bool) []report.Finding {
	var unlabeled []string
	for _, ns := range s.Namespaces {
		if nsSet[ns.Name] && ns.Labels[pssEnforceLabel] == "" {
			unlabeled = append(unlabeled, ns.Name)
		}
	}
	if len(unlabeled) == 0 {
		return nil
	}
	return []report.Finding{{
		Severity: report.SeverityWarning,
		Message: fmt.Sprintf("%d %s without Pod Security Standards enforcement (%s)",
			len(unlabeled), plural(len(unlabeled), "namespace", "namespaces"), joinLimited(unlabeled, 4)),
		Hint: "Set the " + pssEnforceLabel + " label (baseline or restricted) so violating pods are rejected at admission.",
	}}
}

// hardeningFindings covers workload hardening: readOnlyRootFilesystem,
// seccomp profiles, ServiceAccount token automounting and Secrets passed
// through environment variables.
func hardeningFindings(s *kube.Snapshot, nsSet map[string]bool) []report.Finding {
	// ServiceAccounts that disable token automounting for their pods.
	noAutomountSA := map[string]bool{}
	for _, sa := range s.ServiceAccounts {
		if sa.AutomountServiceAccountToken != nil && !*sa.AutomountServiceAccountToken {
			noAutomountSA[sa.Namespace+"/"+sa.Name] = true
		}
	}

	var writableRoot, noSeccomp, automount, secretEnv int
	for _, pod := range s.Pods {
		if !nsSet[pod.Namespace] || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}

		if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
			saName := pod.Spec.ServiceAccountName
			if saName == "" {
				saName = "default"
			}
			if !noAutomountSA[pod.Namespace+"/"+saName] {
				automount++
			}
		}

		podSeccomp := pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil
		missingSeccomp := false
		for _, c := range pod.Spec.Containers {
			sc := c.SecurityContext
			if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				writableRoot++
			}
			if !podSeccomp && (sc == nil || sc.SeccompProfile == nil) {
				missingSeccomp = true
			}
			if usesSecretEnv(c) {
				secretEnv++
			}
		}
		if missingSeccomp {
			noSeccomp++
		}
	}

	var out []report.Finding
	if noSeccomp > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s without a seccomp profile", noSeccomp, plural(noSeccomp, "Pod", "Pods")),
			Hint:     "Set securityContext.seccompProfile.type: RuntimeDefault to filter dangerous syscalls.",
			Controls: []string{ctrlSeccomp},
		})
	}
	if writableRoot > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("%d %s without readOnlyRootFilesystem", writableRoot, plural(writableRoot, "container", "containers")),
			Hint:     "A writable root filesystem lets a compromised process modify its own image at runtime.",
		})
	}
	if automount > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("%d %s automounting ServiceAccount tokens", automount, plural(automount, "Pod", "Pods")),
			Hint:     "Set automountServiceAccountToken: false on pods (or their ServiceAccount) that don't call the Kubernetes API.",
		})
	}
	if secretEnv > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityInfo,
			Message:  fmt.Sprintf("%d %s receiving Secrets via environment variables", secretEnv, plural(secretEnv, "container", "containers")),
			Hint:     "Env vars leak into logs, crash dumps and child processes; prefer mounting Secrets as files.",
		})
	}
	return out
}

// usesSecretEnv reports whether a container pulls Secret data into its
// environment via env valueFrom or envFrom.
func usesSecretEnv(c corev1.Container) bool {
	for _, e := range c.Env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			return true
		}
	}
	for _, ef := range c.EnvFrom {
		if ef.SecretRef != nil {
			return true
		}
	}
	return false
}

func runsAsRoot(podSC *corev1.PodSecurityContext, sc *corev1.SecurityContext) bool {
	// Container-level settings override pod-level ones.
	if sc != nil {
		if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
			return false
		}
		if sc.RunAsUser != nil {
			return *sc.RunAsUser == 0
		}
	}
	if podSC != nil {
		if podSC.RunAsNonRoot != nil && *podSC.RunAsNonRoot {
			return false
		}
		if podSC.RunAsUser != nil {
			return *podSC.RunAsUser == 0
		}
	}
	// Nothing declared: the image decides, which usually means root.
	return true
}

func namespaceHasPods(s *kube.Snapshot, ns string) bool {
	for _, pod := range s.Pods {
		if pod.Namespace == ns {
			return true
		}
	}
	return false
}

// rbacFindings flags wildcard ClusterRoles and cluster-admin grants to
// ServiceAccounts.
func rbacFindings(s *kube.Snapshot) []report.Finding {
	builtinRoles := map[string]bool{"cluster-admin": true, "admin": true, "edit": true, "view": true}
	wildcardRoles := map[string]bool{}
	for _, cr := range s.ClusterRoles {
		if strings.HasPrefix(cr.Name, "system:") || builtinRoles[cr.Name] {
			continue
		}
		for _, rule := range cr.Rules {
			if containsStar(rule.Verbs) && containsStar(rule.APIGroups) && containsStar(rule.Resources) {
				wildcardRoles[cr.Name] = true
			}
		}
	}

	var adminSAs []string
	for _, crb := range s.ClusterRoleBindings {
		isAdmin := crb.RoleRef.Name == "cluster-admin" || wildcardRoles[crb.RoleRef.Name]
		if !isAdmin {
			continue
		}
		for _, sub := range crb.Subjects {
			if sub.Kind == rbacv1.ServiceAccountKind && !strings.HasPrefix(sub.Namespace, "kube-") {
				adminSAs = append(adminSAs, sub.Namespace+"/"+sub.Name)
			}
		}
	}

	var out []report.Finding
	if len(wildcardRoles) > 0 {
		names := make([]string, 0, len(wildcardRoles))
		for name := range wildcardRoles {
			names = append(names, name)
		}
		out = append(out, report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("%d %s with wildcard (*/*/*) rules (%s)", len(names), plural(len(names), "ClusterRole", "ClusterRoles"), joinLimited(names, 3)),
			Hint:     "Wildcard roles are equivalent to cluster-admin. Scope them to the verbs and resources actually needed.",
		})
	}
	if len(adminSAs) > 0 {
		out = append(out, report.Finding{
			Severity: report.SeverityCritical,
			Message:  fmt.Sprintf("%d %s bound to cluster-admin (%s)", len(adminSAs), plural(len(adminSAs), "ServiceAccount", "ServiceAccounts"), joinLimited(adminSAs, 3)),
			Hint:     "A compromised pod using this ServiceAccount owns the whole cluster.",
		})
	}
	return out
}

func containsStar(list []string) bool {
	return slices.Contains(list, "*")
}

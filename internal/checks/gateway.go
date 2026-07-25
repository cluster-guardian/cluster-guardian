package checks

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// gatewayTLSSecretNames returns the TLS Secrets a Gateway's listeners
// reference via certificateRefs. Cross-namespace refs are skipped: honoring
// them would require ReferenceGrant evaluation, and guessing produces false
// findings.
func gatewayTLSSecretNames(gw unstructured.Unstructured) []string {
	ns := gw.GetNamespace()
	var out []string
	listeners, _, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
	for _, l := range listeners {
		lm, ok := l.(map[string]any)
		if !ok {
			continue
		}
		refs, _, _ := unstructured.NestedSlice(lm, "tls", "certificateRefs")
		for _, r := range refs {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			kind, _, _ := unstructured.NestedString(rm, "kind")
			refNS, _, _ := unstructured.NestedString(rm, "namespace")
			name, _, _ := unstructured.NestedString(rm, "name")
			if kind != "" && kind != "Secret" {
				continue
			}
			if refNS != "" && refNS != ns {
				continue
			}
			if name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

// httpRouteServiceBackends returns the Service names an HTTPRoute's rules
// route to within the route's own namespace. Cross-namespace backendRefs are
// skipped for the same ReferenceGrant reason as above.
func httpRouteServiceBackends(route unstructured.Unstructured) []string {
	ns := route.GetNamespace()
	var out []string
	rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		refs, _, _ := unstructured.NestedSlice(rm, "backendRefs")
		for _, b := range refs {
			bm, ok := b.(map[string]any)
			if !ok {
				continue
			}
			kind, _, _ := unstructured.NestedString(bm, "kind")
			refNS, _, _ := unstructured.NestedString(bm, "namespace")
			name, _, _ := unstructured.NestedString(bm, "name")
			if kind != "" && kind != "Service" {
				continue
			}
			if refNS != "" && refNS != ns {
				continue
			}
			if name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

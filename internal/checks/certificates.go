package checks

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

const (
	certWarnWindow     = 30 * 24 * time.Hour
	certCriticalWindow = 7 * 24 * time.Hour
)

// Certificates flags TLS trouble before it becomes an outage: Ingress and
// Gateway TLS certificates near expiry, Ingresses and Gateway listeners
// referencing missing TLS secrets, and cert-manager Certificate resources
// that are not Ready.
func Certificates(s *kube.Snapshot, namespaces []string) report.Section {
	return certificates(s, namespaces, time.Now())
}

// certificates is split from Certificates so tests control the clock.
func certificates(s *kube.Snapshot, namespaces []string, now time.Time) report.Section {
	section := report.Section{ID: "certificates", Title: "Certificates", Icon: "🔐"}
	nsSet := namespaceSet(namespaces)

	// Leaf certificates of TLS secrets, keyed by ns/name.
	leafCerts := map[string]*x509.Certificate{}
	secretExists := map[string]bool{}
	for i := range s.Secrets {
		sec := &s.Secrets[i]
		key := sec.Namespace + "/" + sec.Name
		secretExists[key] = true
		if crt := sec.Data["tls.crt"]; crt != nil {
			if parsed := parseLeafCertificate(crt); parsed != nil {
				leafCerts[key] = parsed
			}
		}
	}

	reported := map[string]bool{}
	for _, ing := range s.Ingresses {
		if !nsSet[ing.Namespace] {
			continue
		}
		for _, tls := range ing.Spec.TLS {
			if tls.SecretName == "" {
				continue // default certificate of the ingress controller
			}
			key := ing.Namespace + "/" + tls.SecretName
			if reported[key] {
				continue
			}
			if !secretExists[key] {
				if s.HasSecretAccess {
					reported[key] = true
					section.Findings = append(section.Findings, report.Finding{
						Severity: report.SeverityWarning,
						Message:  fmt.Sprintf("Ingress %q references missing TLS secret %q", ing.Namespace+"/"+ing.Name, tls.SecretName),
						Object:   "ingress/" + ing.Name,
						Hint:     "HTTPS for these hosts falls back to the controller's default certificate or fails.",
					})
				}
				continue
			}
			cert, ok := leafCerts[key]
			if !ok {
				continue
			}
			reported[key] = true
			if f := expiryFinding(key, cert, now); f != nil {
				section.Findings = append(section.Findings, *f)
			}
		}
	}

	// Gateway API listeners reference TLS secrets via certificateRefs; treat
	// them exactly like Ingress TLS.
	for _, gw := range s.Gateways {
		if !nsSet[gw.GetNamespace()] {
			continue
		}
		for _, secretName := range gatewayTLSSecretNames(gw) {
			key := gw.GetNamespace() + "/" + secretName
			if reported[key] {
				continue
			}
			if !secretExists[key] {
				if s.HasSecretAccess {
					reported[key] = true
					section.Findings = append(section.Findings, report.Finding{
						Severity: report.SeverityWarning,
						Message:  fmt.Sprintf("Gateway %q references missing TLS secret %q", gw.GetNamespace()+"/"+gw.GetName(), secretName),
						Object:   "gateway/" + gw.GetName(),
						Hint:     "Listeners with a broken certificateRef serve no TLS or fall back to invalid certificates.",
					})
				}
				continue
			}
			cert, ok := leafCerts[key]
			if !ok {
				continue
			}
			reported[key] = true
			if f := expiryFinding(key, cert, now); f != nil {
				section.Findings = append(section.Findings, *f)
			}
		}
	}

	for _, c := range s.Certificates {
		if !nsSet[c.GetNamespace()] {
			continue
		}
		if ready, reason := certManagerReady(c); !ready {
			msg := fmt.Sprintf("Certificate %q is not Ready", c.GetNamespace()+"/"+c.GetName())
			if reason != "" {
				msg += fmt.Sprintf(" (%s)", reason)
			}
			section.Findings = append(section.Findings, report.Finding{
				Severity: report.SeverityWarning,
				Message:  msg,
				Object:   "certificate/" + c.GetName(),
				Hint:     "Check the Certificate's issuer and cert-manager logs; renewal may be failing.",
			})
		}
	}
	return section
}

func expiryFinding(secretKey string, cert *x509.Certificate, now time.Time) *report.Finding {
	left := cert.NotAfter.Sub(now)
	days := int(left.Hours() / 24)
	switch {
	case left <= 0:
		return &report.Finding{
			Severity: report.SeverityCritical,
			Message:  fmt.Sprintf("TLS certificate in secret %q expired %d days ago (%s)", secretKey, -days, cert.NotAfter.Format("2006-01-02")),
			Object:   "secret/" + secretKey,
			Hint:     "Renew immediately: clients are already seeing certificate errors.",
		}
	case left < certCriticalWindow:
		return &report.Finding{
			Severity: report.SeverityCritical,
			Message:  fmt.Sprintf("TLS certificate in secret %q expires in %d %s (%s)", secretKey, days, plural(days, "day", "days"), cert.NotAfter.Format("2006-01-02")),
			Object:   "secret/" + secretKey,
			Hint:     "Renew now, or check why automated renewal has not replaced it.",
		}
	case left < certWarnWindow:
		return &report.Finding{
			Severity: report.SeverityWarning,
			Message:  fmt.Sprintf("TLS certificate in secret %q expires in %d days (%s)", secretKey, days, cert.NotAfter.Format("2006-01-02")),
			Object:   "secret/" + secretKey,
			Hint:     "Plan the renewal; cert-manager can automate this.",
		}
	}
	return nil
}

// parseLeafCertificate returns the first certificate of a PEM bundle.
func parseLeafCertificate(pemBytes []byte) *x509.Certificate {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return cert
	}
}

func certManagerReady(c unstructured.Unstructured) (ready bool, reason string) {
	conditions, found, _ := unstructured.NestedSlice(c.Object, "status", "conditions")
	if !found {
		return false, "no status reported"
	}
	for _, raw := range conditions {
		cond, ok := raw.(map[string]any)
		if !ok || cond["type"] != "Ready" {
			continue
		}
		if cond["status"] == "True" {
			return true, ""
		}
		reason, _ = cond["reason"].(string)
		return false, reason
	}
	return false, "no Ready condition"
}

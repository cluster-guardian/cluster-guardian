package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
)

// The dashboard's markup, styles and script live as embedded assets
// (assets/dashboard.*). Serve mode references them under /static/ so a
// Content-Security-Policy without inline scripts is possible; the HTML file
// export inlines the same bytes and stays fully self-contained.
var (
	//go:embed assets/dashboard.gohtml
	dashboardTemplateSrc string
	//go:embed assets/dashboard.css
	dashboardCSS string
	//go:embed assets/dashboard.js
	dashboardJS string

	//go:embed assets/*.css assets/*.js
	assetsFS embed.FS
)

// StaticAssets holds the UI's shared CSS/JS, served by the dashboard server
// under /static/.
var StaticAssets = func() fs.FS {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}()

// WriteHTML renders a self-contained HTML report (no external assets), used
// for file export. Filtering, search and collapsible sections work offline.
func WriteHTML(w io.Writer, r *Report) error {
	return htmlTemplate.Execute(w, htmlData{
		Report:    r,
		InlineCSS: template.CSS(dashboardCSS),
		InlineJS:  template.JS(dashboardJS),
	})
}

// WriteDashboard renders the same report plus the live controls (auto-refresh
// and JSON/Markdown download) that need the serve-mode REST API.
func WriteDashboard(w io.Writer, r *Report) error {
	return htmlTemplate.Execute(w, htmlData{Report: r, Dashboard: true, APIBase: "/api"})
}

// WriteClusterDashboard renders a dashboard whose API calls are scoped to one
// fleet cluster (apiBase like "/api/clusters/prod"). backLink adds a
// navigation link to the fleet overview.
func WriteClusterDashboard(w io.Writer, r *Report, apiBase, backLink string) error {
	return htmlTemplate.Execute(w, htmlData{Report: r, Dashboard: true, APIBase: apiBase, BackLink: backLink})
}

type htmlData struct {
	*Report
	Dashboard bool
	APIBase   string
	BackLink  string
	// InlineCSS/InlineJS are set for the self-contained file export; the
	// served dashboard loads the same bytes from /static/ instead.
	InlineCSS template.CSS
	InlineJS  template.JS
}

// gaugeCircumference is 2*pi*26, the r=26 circle in the score gauge.
const gaugeCircumference = 163.36

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"count": func(fs []Finding, severity string) int {
		n := 0
		for _, f := range fs {
			if f.Severity.String() == severity {
				n++
			}
		}
		return n
	},
	"scoreOffset": func(score int) string {
		return fmt.Sprintf("%.2f", gaugeCircumference*float64(100-score)/100)
	},
}).Parse(dashboardTemplateSrc))

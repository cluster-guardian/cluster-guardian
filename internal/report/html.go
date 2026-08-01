package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
)

// The HTML export's markup, styles and script live as embedded assets
// (assets/dashboard.*) and are inlined into the output, so an exported report
// is a single file that works offline — no server, no external requests.
var (
	//go:embed assets/dashboard.gohtml
	dashboardTemplateSrc string
	//go:embed assets/dashboard.css
	dashboardCSS string
	//go:embed assets/dashboard.js
	dashboardJS string
)

// WriteHTML renders a self-contained HTML report (no external assets). Search,
// severity filtering and collapsible sections work offline.
func WriteHTML(w io.Writer, r *Report) error {
	return htmlTemplate.Execute(w, htmlData{
		Report:    r,
		InlineCSS: template.CSS(dashboardCSS),
		InlineJS:  template.JS(dashboardJS),
	})
}

type htmlData struct {
	*Report
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

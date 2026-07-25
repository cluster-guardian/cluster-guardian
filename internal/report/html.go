package report

import (
	"fmt"
	"html/template"
	"io"
)

// WriteHTML renders a self-contained HTML report (no external assets), used
// for file export. Filtering, search and collapsible sections work offline.
func WriteHTML(w io.Writer, r *Report) error {
	return htmlTemplate.Execute(w, htmlData{Report: r})
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
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%232563EB' d='M12 1l9 3.4v7.4c0 5-3.6 8.7-9 10.7-5.4-2-9-5.7-9-10.7V4.4z'/%3E%3C/svg%3E">
<title>Cluster Guardian — {{.ClusterName}}</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f2f5f9; --card: #ffffff; --text: #17203a;
    --muted: rgba(23,32,58,.58); --line: rgba(23,32,58,.1);
    --accent: #2563eb; --accent-2: #0ea5e9;
    --ok-bg: #d9f2e2; --ok-fg: #177a3f;
    --info-bg: #dcebfa; --info-fg: #1f5f9e;
    --warn-bg: #fdeeca; --warn-fg: #8a6100;
    --crit-bg: #fadada; --crit-fg: #a12626;
    --shadow: 0 1px 2px rgba(15,23,42,.05), 0 4px 16px rgba(15,23,42,.06);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1117; --card: #181b23; --text: #e7eaf2;
      --muted: rgba(231,234,242,.55); --line: rgba(231,234,242,.09);
      --ok-bg: rgba(34,197,94,.16); --ok-fg: #4ade80;
      --info-bg: rgba(59,130,246,.16); --info-fg: #7ab8ff;
      --warn-bg: rgba(245,158,11,.16); --warn-fg: #fbbf24;
      --crit-bg: rgba(239,68,68,.16); --crit-fg: #f87171;
      --shadow: 0 1px 2px rgba(0,0,0,.35);
    }
  }
  * { box-sizing: border-box; margin: 0; }
  body { font: 15px/1.55 -apple-system, "Segoe UI", Roboto, sans-serif;
         background: var(--bg); color: var(--text); padding: 2rem 1rem; }
  main { max-width: 900px; margin: 0 auto; }
  a { color: var(--accent); }
  h1 { font-size: 1.45rem; display: flex; align-items: center; gap: .6rem; margin-bottom: .25rem; }
  .logo { width: 34px; height: 34px; flex: none; }
  .meta { color: var(--muted); margin-bottom: 1.25rem; }
  .summary { display: flex; gap: .8rem; flex-wrap: wrap; margin-bottom: 1rem; }
  .stat { flex: 1 1 8rem; padding: .75rem 1rem; border-radius: 12px;
          background: var(--card); border: 1px solid var(--line); box-shadow: var(--shadow); }
  .stat b { display: block; font-size: 1.45rem; }
  .stat.score { display: flex; align-items: center; gap: .8rem; }
  .gauge { width: 58px; height: 58px; transform: rotate(-90deg); flex: none; }
  .gauge .track { fill: none; stroke: var(--line); stroke-width: 8; }
  .gauge .meter { fill: none; stroke-width: 8; stroke-linecap: round; }
  .gA, .gB { stroke: var(--ok-fg); } .gC { stroke: var(--warn-fg); }
  .gD { stroke: #c76b00; } .gF { stroke: var(--crit-fg); }
  .tA, .tB { color: var(--ok-fg); } .tC { color: var(--warn-fg); }
  .tD { color: #c76b00; } .tF { color: var(--crit-fg); }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 14px;
          padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: var(--shadow); }
  .card h2 { font-size: 1.02rem; display: inline; }
  details.card > summary { cursor: pointer; list-style: none; display: flex; align-items: center; gap: .6rem; }
  details.card > summary::-webkit-details-marker { display: none; }
  details.card > summary .counts { margin-left: auto; display: flex; gap: .35rem; align-items: center; }
  details.card > summary .chev { color: var(--muted); transition: transform .15s; }
  details.card[open] > summary .chev { transform: rotate(180deg); }
  details.card[open] > summary { margin-bottom: .5rem; }
  .toolbar { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }
  .toolbar input[type=search] { flex: 1 1 12rem; padding: .5rem .75rem; border-radius: 9px;
      border: 1px solid var(--line); font: inherit; background: var(--bg); color: var(--text); }
  .toolbar input[type=search]:focus, .toolbar select:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
  .toolbar select { padding: .5rem .55rem; border-radius: 9px; border: 1px solid var(--line);
      font: inherit; background: var(--bg); color: var(--text); }
  .chips { display: flex; gap: .35rem; }
  .chip { font: inherit; font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .04em;
          padding: .27rem .6rem; border-radius: 99px; border: 1px solid var(--line);
          background: transparent; color: inherit; cursor: pointer; opacity: .4; }
  .chip.active { opacity: 1; border-color: transparent; }
  .chip.critical.active { background: var(--crit-bg); color: var(--crit-fg); }
  .chip.warning.active  { background: var(--warn-bg); color: var(--warn-fg); }
  .chip.info.active     { background: var(--info-bg); color: var(--info-fg); }
  .chip.ok.active       { background: var(--ok-bg); color: var(--ok-fg); }
  .toggle { display: flex; gap: .35rem; align-items: center; font-size: .85rem; cursor: pointer; }
  .btn { font-size: .85rem; padding: .38rem .75rem; border-radius: 9px; text-decoration: none;
         color: inherit; border: 1px solid var(--line); }
  .btn:hover { border-color: var(--accent); color: var(--accent); }
  ul { list-style: none; }
  li { padding: .32rem 0; display: flex; gap: .6rem; align-items: baseline; }
  li + li { border-top: 1px solid var(--line); }
  .badge { font-size: .68rem; font-weight: 600; text-transform: uppercase; letter-spacing: .04em;
           padding: .12rem .48rem; border-radius: 99px; white-space: nowrap; }
  .badge.ok       { background: var(--ok-bg); color: var(--ok-fg); }
  .badge.info     { background: var(--info-bg); color: var(--info-fg); }
  .badge.warning  { background: var(--warn-bg); color: var(--warn-fg); }
  .badge.critical { background: var(--crit-bg); color: var(--crit-fg); }
  .hint { display: block; font-size: .85rem; color: var(--muted); }
  #trend { width: 100%; height: 130px; }
  .legend { display: flex; gap: 1rem; font-size: .8rem; color: var(--muted); }
  .legend i { display: inline-block; width: .8em; height: .8em; border-radius: 3px; margin-right: .3em; }
  footer { text-align: center; color: var(--muted); font-size: .8rem; margin-top: 2rem; }
</style>
</head>
<body{{if .Dashboard}} data-api="{{.APIBase}}"{{end}}>
<main>
  {{with .BackLink}}<p class="meta"><a href="{{.}}">← fleet overview</a></p>{{end}}
  <h1>{{template "logo" .}} Cluster: {{.ClusterName}}</h1>
  <p class="meta">Generated {{.GeneratedAt.Format "2006-01-02 15:04 UTC"}}{{with .KubernetesVersion}} · Kubernetes {{.}}{{end}}</p>

  <div class="summary">
    <div class="stat score">
      <svg class="gauge" viewBox="0 0 64 64" aria-hidden="true">
        <circle class="track" cx="32" cy="32" r="26"/>
        <circle class="meter g{{.Summary.Grade}}" cx="32" cy="32" r="26"
                stroke-dasharray="163.36" stroke-dashoffset="{{scoreOffset .Summary.Score}}"/>
      </svg>
      <div><b class="t{{.Summary.Grade}}">{{.Summary.Grade}}</b>score {{.Summary.Score}}/100</div>
    </div>
    <div class="stat"><b>{{.Summary.Namespaces}}</b>namespaces</div>
    <div class="stat"><b>{{.Summary.Total}}</b>findings</div>
    <div class="stat"><b>{{.Summary.Warnings}}</b>warnings</div>
    <div class="stat"><b>{{.Summary.Critical}}</b>critical</div>
  </div>

  <div class="toolbar card">
    <input id="search" type="search" placeholder="Search findings…" aria-label="Search findings">
    <div class="chips">
      <button class="chip critical active" data-sev="critical">critical</button>
      <button class="chip warning active" data-sev="warning">warning</button>
      <button class="chip info active" data-sev="info">info</button>
      <button class="chip ok active" data-sev="ok">ok</button>
    </div>
    <select id="nsfilter" aria-label="Filter by namespace">
      <option value="">All namespaces</option>
      {{range .Namespaces}}<option>{{.Name}}</option>{{end}}
    </select>
    {{with .Teams}}
    <select id="teamfilter" aria-label="Filter by team">
      <option value="">All teams</option>
      {{range .}}<option>{{.}}</option>{{end}}
    </select>
    {{end}}
    {{if .Dashboard}}
    <label class="toggle"><input type="checkbox" id="autorefresh"> auto-refresh</label>
    <a class="btn" href="{{.APIBase}}/report" download="report.json">JSON</a>
    <a class="btn" href="{{.APIBase}}/report/markdown" download="report.md">Markdown</a>
    {{end}}
  </div>

  {{if .Dashboard}}
  <div class="card" id="trendcard" hidden>
    <div style="display:flex;align-items:center;margin-bottom:.5rem"><h2>📈 Trends</h2><span id="diffline" class="meta" style="margin:0 0 0 auto"></span></div>
    <svg id="trend" viewBox="0 0 600 130" preserveAspectRatio="none" aria-label="Findings over time"></svg>
    <div class="legend">
      <span><i style="background:#888"></i>total</span>
      <span><i style="background:#c79100"></i>warnings</span>
      <span><i style="background:#c62828"></i>critical</span>
    </div>
  </div>
  {{end}}

  {{range .Namespaces}}{{if .Findings}}
  <details class="card" open data-ns="{{.Name}}"{{with .Team}} data-team="{{.}}"{{end}}>
    <summary><h2>📦 Namespace: {{.Name}}{{with .Team}} <span class="badge info">{{.}}</span>{{end}}</h2>{{template "counts" .Findings}}</summary>
    {{template "findings" .Findings}}
  </details>
  {{end}}{{end}}

  {{range .Sections}}{{if .Findings}}
  <details class="card" open>
    <summary><h2>{{.Icon}} {{.Title}}</h2>{{template "counts" .Findings}}</summary>
    {{template "findings" .Findings}}
  </details>
  {{end}}{{end}}

  <footer>Generated by Cluster Guardian</footer>
</main>
<script>
(function () {
  var search = document.getElementById('search');
  var nsSel = document.getElementById('nsfilter');
  var teamSel = document.getElementById('teamfilter');
  var chips = Array.prototype.slice.call(document.querySelectorAll('.chip'));

  function apply() {
    var q = search.value.toLowerCase();
    var ns = nsSel.value;
    var team = teamSel ? teamSel.value : '';
    var active = {};
    chips.forEach(function (c) { if (c.classList.contains('active')) active[c.dataset.sev] = true; });
    document.querySelectorAll('details.card').forEach(function (card) {
      if (ns && card.dataset.ns && card.dataset.ns !== ns) { card.style.display = 'none'; return; }
      if (team && card.dataset.ns && card.dataset.team !== team) { card.style.display = 'none'; return; }
      var visible = 0;
      card.querySelectorAll('li[data-sev]').forEach(function (li) {
        var show = !!active[li.dataset.sev] && (!q || li.textContent.toLowerCase().indexOf(q) !== -1);
        li.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      card.style.display = visible ? '' : 'none';
    });
  }
  search.addEventListener('input', apply);
  nsSel.addEventListener('change', apply);
  if (teamSel) teamSel.addEventListener('change', apply);
  chips.forEach(function (c) {
    c.addEventListener('click', function () { c.classList.toggle('active'); apply(); });
  });

  var apiBase = document.body.getAttribute('data-api') || '/api';
  var trendCard = document.getElementById('trendcard');
  if (trendCard) {
    fetch(apiBase + '/history').then(function (r) { return r.json(); }).then(function (h) {
      var e = h.entries || [];
      if (e.length < 2) return;
      trendCard.hidden = false;
      var svg = document.getElementById('trend');
      var max = 1;
      e.forEach(function (x) { max = Math.max(max, x.summary.totalFindings); });
      var draw = function (get, color) {
        var pts = e.map(function (x, i) {
          var px = (i * 600 / (e.length - 1)).toFixed(1);
          var py = (125 - get(x.summary) / max * 118).toFixed(1);
          return px + ',' + py;
        }).join(' ');
        var p = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
        p.setAttribute('points', pts);
        p.setAttribute('fill', 'none');
        p.setAttribute('stroke', color);
        p.setAttribute('stroke-width', '2');
        svg.appendChild(p);
      };
      draw(function (s) { return s.totalFindings; }, '#888');
      draw(function (s) { return s.warnings; }, '#c79100');
      draw(function (s) { return s.critical; }, '#c62828');
    }).catch(function () {});
    fetch(apiBase + '/history/diff').then(function (r) { return r.json(); }).then(function (d) {
      var added = (d.new || []).length, resolved = (d.resolved || []).length;
      if (added || resolved) {
        document.getElementById('diffline').textContent =
          'since previous run: ' + added + ' new, ' + resolved + ' resolved';
      }
    }).catch(function () {});
  }

  var auto = document.getElementById('autorefresh');
  if (auto) {
    var timer = null;
    var setTimer = function (on) {
      if (timer) { clearInterval(timer); timer = null; }
      if (on) { timer = setInterval(function () { window.location = window.location.pathname + '?refresh=true'; }, 60000); }
    };
    auto.checked = localStorage.getItem('cg-autorefresh') === '1';
    setTimer(auto.checked);
    auto.addEventListener('change', function () {
      localStorage.setItem('cg-autorefresh', auto.checked ? '1' : '0');
      setTimer(auto.checked);
    });
  }
})();
</script>
</body>
</html>
{{define "logo"}}<svg class="logo" viewBox="0 0 512 512" fill="none" aria-hidden="true"><defs><linearGradient id="lg" x1="68" y1="40" x2="444" y2="472" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#2563EB"/><stop offset="1" stop-color="#0EA5E9"/></linearGradient></defs><path d="M256 40 L444 110 V268 C444 375 366 442 256 472 C146 442 68 375 68 268 V110 Z" fill="url(#lg)"/><g stroke="#FFF" stroke-opacity=".85" stroke-width="14" stroke-linecap="round"><path d="M256 250 L256 150"/><path d="M256 250 L170 316"/><path d="M256 250 L342 316"/></g><g fill="#FFF" fill-opacity=".95"><circle cx="256" cy="142" r="24"/><circle cx="164" cy="322" r="24"/><circle cx="348" cy="322" r="24"/></g><circle cx="256" cy="250" r="42" fill="#FFF"/><path d="M238 251 L252 265 L278 235" stroke="url(#lg)" stroke-width="14" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>{{end}}
{{define "counts"}}<span class="counts">{{with count . "critical"}}<span class="badge critical">{{.}}</span>{{end}}{{with count . "warning"}}<span class="badge warning">{{.}}</span>{{end}}<span class="chev">▾</span></span>{{end}}
{{define "findings"}}<ul>
  {{range .}}
  <li data-sev="{{.Severity}}"><span class="badge {{.Severity}}">{{.Severity}}</span>
    <div>{{.Message}}{{with .Hint}}<span class="hint">{{.}}</span>{{end}}</div></li>
  {{end}}
</ul>{{end}}
`))

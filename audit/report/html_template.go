// Quantaureum Node source, version 1.0.0.
package report

func getHTMLTemplate() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QAU Security Audit Report</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --border: #0f3460;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            background: linear-gradient(135deg, var(--bg-card), #1a1a3e);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }
        h1 { font-size: 2rem; margin-bottom: 10px; }
        .meta { color: var(--text-secondary); font-size: 0.9rem; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            text-align: center;
        }
        .summary-card h3 { font-size: 2.5rem; margin-bottom: 5px; }
        .summary-card p { color: var(--text-secondary); }
        .summary-card.critical h3 { color: var(--critical); }
        .summary-card.high h3 { color: var(--high); }
        .summary-card.medium h3 { color: var(--medium); }
        .summary-card.low h3 { color: var(--low); }
        .summary-card.info h3 { color: var(--info); }
        .chart-container {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            margin-bottom: 30px;
        }
        .bar-chart { display: flex; height: 40px; border-radius: 6px; overflow: hidden; }
        .bar-segment { display: flex; align-items: center; justify-content: center; color: #fff; font-weight: bold; font-size: 0.85rem; min-width: 30px; }
        .bar-critical { background: var(--critical); }
        .bar-high { background: var(--high); }
        .bar-medium { background: var(--medium); }
        .bar-low { background: var(--low); }
        .bar-info { background: var(--info); }
        .legend { display: flex; gap: 20px; margin-top: 15px; flex-wrap: wrap; }
        .legend-item { display: flex; align-items: center; gap: 8px; font-size: 0.9rem; }
        .legend-color { width: 16px; height: 16px; border-radius: 4px; }
        section { margin-bottom: 30px; }
        section h2 { font-size: 1.5rem; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid var(--border); }
        .finding {
            background: var(--bg-card);
            border-radius: 10px;
            border: 1px solid var(--border);
            margin-bottom: 15px;
            overflow: hidden;
        }
        .finding-header {
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            border-bottom: 1px solid var(--border);
        }
        .finding-header:hover { background: rgba(255,255,255,0.02); }
        .finding-title { font-weight: 600; flex: 1; }
        .finding-badges { display: flex; gap: 10px; }
        .badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-critical { background: var(--critical); color: #fff; }
        .severity-high { background: var(--high); color: #fff; }
        .severity-medium { background: var(--medium); color: #000; }
        .severity-low { background: var(--low); color: #fff; }
        .severity-info { background: var(--info); color: #fff; }
        .effort-trivial { background: #28a745; color: #fff; }
        .effort-low { background: #20c997; color: #fff; }
        .effort-medium { background: #ffc107; color: #000; }
        .effort-high { background: #fd7e14; color: #fff; }
        .effort-critical { background: #dc3545; color: #fff; }
        .status-open { background: #dc3545; color: #fff; }
        .status-fixed { background: #28a745; color: #fff; }
        .status-accepted { background: #17a2b8; color: #fff; }
        .status-false-positive { background: #6c757d; color: #fff; }
        .finding-body { padding: 20px; display: none; }
        .finding.expanded .finding-body { display: block; }
        .finding-section { margin-bottom: 15px; }
        .finding-section h4 { color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 8px; text-transform: uppercase; }
        .location { font-family: monospace; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; font-size: 0.9rem; }
        .snippet { background: #0d1117; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap; }
        .remediation-steps { list-style: decimal; padding-left: 20px; }
        .remediation-steps li { margin-bottom: 8px; }
        .references a { color: #58a6ff; text-decoration: none; }
        .references a:hover { text-decoration: underline; }
        .owasp-badge { background: #6f42c1; color: #fff; }
        footer { text-align: center; padding: 20px; color: var(--text-secondary); font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>QAU Security Audit Report</h1>
            <div class="meta">
                <p>Generated: {{formatTime .Timestamp}} | Duration: {{formatDuration .Duration}}</p>
                <p>Version: {{.Metadata.Version}} | Scanners: {{joinStrings .Metadata.Scanners ", "}}</p>
                {{if .Metadata.TargetPath}}<p>Target: {{.Metadata.TargetPath}}</p>{{end}}
            </div>
        </header>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>{{.Summary.TotalFindings}}</h3>
                <p>Total Findings</p>
            </div>
            <div class="summary-card critical">
                <h3>{{.Summary.CriticalCount}}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{{.Summary.HighCount}}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{{.Summary.MediumCount}}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>{{.Summary.LowCount}}</h3>
                <p>Low</p>
            </div>
            <div class="summary-card info">
                <h3>{{.Summary.InfoCount}}</h3>
                <p>Info</p>
            </div>
        </div>

        {{if gt .Summary.TotalFindings 0}}
        <div class="chart-container">
            <h3 style="margin-bottom: 15px;">Severity Distribution</h3>
            <div class="bar-chart">
                {{if gt .Summary.CriticalCount 0}}<div class="bar-segment bar-critical" style="width: {{percentOf .Summary.CriticalCount .Summary.TotalFindings}}%">{{.Summary.CriticalCount}}</div>{{end}}
                {{if gt .Summary.HighCount 0}}<div class="bar-segment bar-high" style="width: {{percentOf .Summary.HighCount .Summary.TotalFindings}}%">{{.Summary.HighCount}}</div>{{end}}
                {{if gt .Summary.MediumCount 0}}<div class="bar-segment bar-medium" style="width: {{percentOf .Summary.MediumCount .Summary.TotalFindings}}%">{{.Summary.MediumCount}}</div>{{end}}
                {{if gt .Summary.LowCount 0}}<div class="bar-segment bar-low" style="width: {{percentOf .Summary.LowCount .Summary.TotalFindings}}%">{{.Summary.LowCount}}</div>{{end}}
                {{if gt .Summary.InfoCount 0}}<div class="bar-segment bar-info" style="width: {{percentOf .Summary.InfoCount .Summary.TotalFindings}}%">{{.Summary.InfoCount}}</div>{{end}}
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-color" style="background: var(--critical)"></div>Critical</div>
                <div class="legend-item"><div class="legend-color" style="background: var(--high)"></div>High</div>
                <div class="legend-item"><div class="legend-color" style="background: var(--medium)"></div>Medium</div>
                <div class="legend-item"><div class="legend-color" style="background: var(--low)"></div>Low</div>
                <div class="legend-item"><div class="legend-color" style="background: var(--info)"></div>Info</div>
            </div>
        </div>
        {{end}}

        <section>
            <h2>Findings</h2>
            {{range .Findings}}
            <div class="finding">
                <div class="finding-header" onclick="this.parentElement.classList.toggle('expanded')">
                    <span class="finding-title">{{.Title}}</span>
                    <div class="finding-badges">
                        {{severityBadge .Severity}}
                        {{effortBadge .Effort}}
                        {{statusBadge .Status}}
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-section">
                        <h4>Description</h4>
                        <p>{{.Description}}</p>
                    </div>
                    <div class="finding-section">
                        <h4>Location</h4>
                        <div class="location">{{.Location.File}}:{{.Location.StartLine}}{{if .Location.Function}} ({{.Location.Function}}){{end}}</div>
                        {{if .Location.Snippet}}<pre class="snippet">{{.Location.Snippet}}</pre>{{end}}
                    </div>
                    <div class="finding-section">
                        <h4>Category</h4>
                        <p>Category: {{.Category}}</p>
                        {{if .CWE}}<p>CWE: {{.CWE}}</p>{{end}}
                        {{if .CVE}}<p>CVE: {{.CVE}}</p>{{end}}
                        <p>OWASP: <span class="badge owasp-badge">{{owaspCategory .}}</span></p>
                    </div>
                    <div class="finding-section">
                        <h4>Remediation</h4>
                        <p>{{.Remediation.Description}}</p>
                        {{if .Remediation.Steps}}
                        <ol class="remediation-steps">
                            {{range .Remediation.Steps}}<li>{{.}}</li>{{end}}
                        </ol>
                        {{end}}
                        {{if .Remediation.CodeFix}}<pre class="snippet">{{.Remediation.CodeFix}}</pre>{{end}}
                    </div>
                    {{if .References}}
                    <div class="finding-section references">
                        <h4>References</h4>
                        <ul>
                            {{range .References}}<li><a href="{{safeURL .}}" target="_blank" rel="noopener noreferrer">{{.}}</a></li>{{end}}
                        </ul>
                    </div>
                    {{end}}
                </div>
            </div>
            {{else}}
            <p style="text-align: center; color: var(--text-secondary); padding: 40px;">No findings detected.</p>
            {{end}}
        </section>

        <footer>
            <p>Generated by QAU Security Audit System v{{.Metadata.Version}}</p>
        </footer>
    </div>
    <script>
        var f = document.querySelector('.finding');
        if (f) f.classList.add('expanded');
    </script>
</body>
</html>`
}

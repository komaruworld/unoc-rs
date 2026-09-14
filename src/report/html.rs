use std::io::Write;
use std::path::Path;

use crate::error::Result;
use crate::report::json;
use crate::report::ReportBundle;

const HTML_PREFIX: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>unoc-rs Report</title>
<style>
body { font-family: system-ui, sans-serif; margin: 24px; background: #f7f7f8; color: #1f2328; }
table { width: 100%; border-collapse: collapse; background: white; }
th, td { border-bottom: 1px solid #d8dee4; padding: 8px; text-align: left; font-size: 13px; }
input, select { padding: 8px; margin-right: 8px; }
.summary { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
.metric { background: white; border: 1px solid #d8dee4; border-radius: 6px; padding: 10px 12px; }
</style>
</head>
<body>
<h1>unoc-rs Report</h1>
<div id="summary" class="summary"></div>
<input id="search" aria-label="Search class name, id or reason">
<select id="status">
  <option value="">all statuses</option>
  <option value="Matched">matched</option>
  <option value="LowConfidence">low confidence</option>
  <option value="Conflict">conflict</option>
  <option value="SemanticBreak">semantic break</option>
  <option value="UnresolvedOld">unresolved old</option>
  <option value="UnresolvedNew">unresolved new</option>
</select>
<table>
<thead><tr><th>Status</th><th>Score</th><th>Old</th><th>Old DEX</th><th>New</th><th>New DEX</th><th>Reasons</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<script id="report-data" type="application/json">"#;

const HTML_SUFFIX: &str = r#"</script>
<script>
const report = JSON.parse(document.getElementById('report-data').textContent);
const summary = document.getElementById('summary');
for (const [key, value] of [
  ['Old classes', report.old_app.coverage.parsed_classes],
  ['New classes', report.new_app.coverage.parsed_classes],
  ['Old DEX', report.old_app.coverage.dex_files],
  ['New DEX', report.new_app.coverage.dex_files],
  ['Old warnings', report.old_app.coverage.warning_count],
  ['New warnings', report.new_app.coverage.warning_count],
  ['Class results', report.matches.classes.length],
  ['Method results', report.matches.method_count],
  ['Field results', report.matches.field_count]
]) {
  const metric = document.createElement('div');
  metric.className = 'metric';
  const count = document.createElement('strong');
  count.textContent = value;
  metric.append(count, document.createElement('br'), document.createTextNode(key));
  summary.append(metric);
}
const rows = document.getElementById('rows');
const search = document.getElementById('search');
const status = document.getElementById('status');
const oldClasses = new Map(report.old_app.classes.map(cls => [cls.id, cls]));
const newClasses = new Map(report.new_app.classes.map(cls => [cls.id, cls]));
function className(map, id) {
  const cls = map.get(id);
  return cls ? cls.descriptor : '';
}
function classDex(map, id) {
  const cls = map.get(id);
  if (!cls) return '';
  const index = cls.origin.class_def_index ?? '?';
  return `${cls.origin.dex_file}#${index}`;
}
function render() {
  const query = search.value.toLowerCase();
  const wanted = status.value;
  const fragment = document.createDocumentFragment();
  for (const item of report.matches.classes) {
    if (wanted && item.status !== wanted) continue;
    const values = [item.status, item.score.toFixed(2),
      className(oldClasses, item.old_class_id), classDex(oldClasses, item.old_class_id),
      className(newClasses, item.new_class_id), classDex(newClasses, item.new_class_id),
      item.reasons.join(', ')];
    const searchable = values.concat([item.old_class_id, item.new_class_id]).join(' ');
    if (!searchable.toLowerCase().includes(query)) continue;
    const row = document.createElement('tr');
    for (const value of values) {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    }
    fragment.append(row);
  }
  rows.replaceChildren(fragment);
}
search.addEventListener('input', render);
status.addEventListener('change', render);
render();
</script>
</body>
</html>"#;

pub fn write_html(bundle: &ReportBundle, path: &Path) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    writer.write_all(HTML_PREFIX.as_bytes())?;
    json::write_compact(bundle, HtmlJsonWriter(&mut writer))?;
    writer.write_all(HTML_SUFFIX.as_bytes())?;
    writer.flush()?;
    Ok(())
}

// JSON string escaping alone does not prevent an HTML parser from recognizing
// </script>. Escape markup bytes while streaming, without buffering the report.
struct HtmlJsonWriter<W>(W);

impl<W: Write> Write for HtmlJsonWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut start = 0;
        for (index, byte) in bytes.iter().enumerate() {
            let escape: &[u8] = match byte {
                b'<' => b"\\u003c",
                b'>' => b"\\u003e",
                b'&' => b"\\u0026",
                _ => continue,
            };
            self.0.write_all(&bytes[start..index])?;
            self.0.write_all(escape)?;
            start = index + 1;
        }
        self.0.write_all(&bytes[start..])?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

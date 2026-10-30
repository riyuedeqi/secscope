#!/usr/bin/env python3
"""SecScope report renderer v2 — single-file professional HTML report.

Consumes findings.json + status.json (+ a small bash-side meta file) and emits
one self-contained HTML file: zero external resources, inline SVG charts,
client-side rendering/filtering, print stylesheet, responsive down to phones.

Presentation goals (false-positive aware):
  * severity and confidence are separate visual systems — a HIGH finding with
    LOW confidence can never look like a confirmed breach
  * every finding shows its judgment basis, escalation conditions and counter
    evidence so a reviewer can dismiss noise in one glance
  * unmet visibility (UNAVAILABLE/PARTIAL/SKIPPED_BUDGET) is rendered as a
    visible gap, never folded into "clean"
"""

from __future__ import print_function

import argparse
import html
import io
import json
import os
import sys

VERSION = "2.0.0"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "OBSERVE": 4}
SEVERITY_LABEL = {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危", "OBSERVE": "观察"}
CONFIDENCE_LABEL = {"HIGH": "高置信", "MEDIUM": "中置信", "LOW": "低置信"}
FINDING_TYPE_LABEL = {
    "SECURITY_THREAT": "威胁",
    "SECURITY_ANOMALY": "异常",
    "CONFIG_BASELINE": "基线",
    "SOFTWARE_TRUST_GAP": "信任缺口",
    "RUNTIME_OBSERVATION": "观察",
}
MODULE_STATUS_LABEL = {
    "SUCCESS": "完成", "PARTIAL": "部分完成", "FAILED": "失败",
    "SKIPPED_BUDGET": "已达扫描时限跳过", "NOT_RUN": "未运行",
}


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def load_json(path):
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def load_meta(path):
    meta = {}
    if not path:
        return meta
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                meta[key.strip()] = value.strip()
    except OSError:
        pass
    return meta


def severity_rank(item):
    return SEVERITY_ORDER.get(item.get("severity", "OBSERVE"), 4)


# ---------------------------------------------------------------------------
# inline SVG builders
# ---------------------------------------------------------------------------

def donut_svg(sev_counts, total_findings):
    """Risk composition donut: critical/high/medium/low + clean remainder."""
    palette = [("CRITICAL", "#e5484d"), ("HIGH", "#f76b15"), ("MEDIUM", "#f5d90a"), ("LOW", "#3e63dd")]
    total_weight = sum(sev_counts.get(name, 0) for name, _ in palette)
    radius, stroke = 52.0, 16.0
    circumference = 2 * 3.141592653589793 * radius
    segments = []
    offset = 0.0
    for name, color in palette:
        count = sev_counts.get(name, 0)
        if total_weight <= 0 or count <= 0:
            continue
        fraction = count / float(total_weight)
        dash = fraction * circumference
        segments.append(
            '<circle class="donut-seg" cx="70" cy="70" r="%s" fill="none" stroke="%s" stroke-width="%s" '
            'stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" data-sev="%s"><title>%s: %d</title></circle>'
            % (radius, color, stroke, dash, circumference - dash, -offset, name, SEVERITY_LABEL.get(name, name), count))
        offset += dash
    if not segments:
        segments.append('<circle cx="70" cy="70" r="%s" fill="none" stroke="#30a46c" stroke-width="%s" '
                        'stroke-dasharray="%.2f %.2f" data-sev="CLEAN"><title>无高危信号</title></circle>'
                        % (radius, stroke, circumference * 0.9999, circumference))
    center_label = str(total_findings) if total_findings else "0"
    center_sub = "项发现" if total_findings else "未发现"
    legend = "".join(
        '<span class="legend-item"><i class="dot" style="background:%s"></i>%s %d</span>'
        % (color, SEVERITY_LABEL.get(name, name), sev_counts.get(name, 0))
        for name, color in palette)
    return ('<svg class="risk-donut" viewBox="0 0 140 140" role="img" aria-label="风险构成">%s'
            '<text x="70" y="66" text-anchor="middle" class="donut-num">%s</text>'
            '<text x="70" y="84" text-anchor="middle" class="donut-sub">%s</text></svg>'
            '<div class="donut-legend">%s</div>' % ("".join(segments), center_label, center_sub, legend))


def coverage_bar(percent):
    percent = max(0, min(100, int(percent or 0)))
    color = "#30a46c" if percent >= 85 else ("#f5d90a" if percent >= 60 else "#e5484d")
    return ('<div class="meter" role="img" aria-label="证据覆盖率 %d%%">'
            '<div class="meter-fill" style="width:%d%%;background:%s"></div></div>'
            '<span class="meter-num">%d%%</span>' % (percent, percent, color, percent))


def verdict_banner(verdict, counts, gaps):
    critical = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    if critical > 0:
        cls, icon, title = "alert", "&#9888;", "存在高危发现，建议立即研判"
        body = "检测到 %d 项严重/高危发现。请按置信度与证据链逐条核实，确认后按处置建议处理。" % critical
    elif counts.get("MEDIUM", 0) > 0:
        cls, icon, title = "warn", "&#128269;", "存在待研判异常，建议人工复核"
        body = "未发现高置信威胁，但有 %d 项中危异常需要人工确认（多为弱信号，附反证与升级条件）。" % counts["MEDIUM"]
    else:
        cls, icon, title = "pass", "&#10003;", "本轮未发现明确威胁证据"
        body = "在当前权限、数据源与扫描范围内未形成规则证据；这不代表主机绝对安全，请结合可见性缺口评估。"
    if gaps:
        body += " 另有 %d 个数据源不可用或被扫描预算跳过（见可见性缺口）。" % len(gaps)
    return ('<div class="verdict %s"><span class="verdict-icon">%s</span>'
            '<div><div class="verdict-title">%s</div><div class="verdict-body">%s</div></div>'
            '<div class="verdict-badge">%s</div></div>'
            % (cls, icon, title, body, esc(verdict or "UNKNOWN")))


# ---------------------------------------------------------------------------
# finding row rendering
# ---------------------------------------------------------------------------

def evidence_domains_html(domains, domain_count):
    if not domains:
        return ""
    chips = "".join('<span class="domain-chip">%s</span>' % esc(item) for item in domains[:8])
    return '<div class="domain-row"><span class="domain-count">%d 域</span>%s</div>' % (domain_count or len(domains), chips)


def finding_card(item, index):
    severity = item.get("severity", "OBSERVE")
    confidence = item.get("confidence", "LOW")
    finding_type = item.get("finding_type", "RUNTIME_OBSERVATION")
    family = item.get("family") or ""
    timeline = item.get("attack_timeline") or []
    counter = item.get("counter_evidence") or ""
    judgment = item.get("judgment_basis") or ""
    escalation = item.get("escalation_conditions") or ""
    fp_hint = ""
    counter_default = counter.startswith("未发现足以降低") or counter == ""
    if counter_default:
        fp_hint = '<span class="fp-flag neutral">无已知反证</span>'
    else:
        fp_hint = '<span class="fp-flag noted" title="%s">已附反证/抑制说明</span>' % esc(counter)
    family_badge = ('<span class="family-badge">%s</span>' % esc(family)) if family and family != "none" else ""
    timeline_rows = "".join('<li>%s</li>' % esc(step) for step in timeline[:6])
    refs = item.get("raw_references") or []
    ref_links = "".join('<span class="ref-chip">%s</span>' % esc(ref) for ref in refs[:6])
    return (
        '<article class="finding sev-%s conf-%s" data-sev="%s" data-conf="%s" data-type="%s" data-cat="%s">'
        '<header class="finding-head" onclick="toggleFinding(this)">'
        '<span class="sev-tag">%s</span>'
        '<span class="conf-tag" title="置信度：证据域数量与规则强度决定">%s</span>'
        '%s%s'
        '<span class="finding-summary">%s</span>'
        '<span class="finding-meta">%s · %s%s</span>'
        '<span class="finding-toggle" aria-hidden="true">▾</span>'
        '</header>'
        '<div class="finding-body">'
        '<div class="fp-hint">%s</div>'
        '<div class="ev-grid">'
        '<div class="ev-block"><h4>证据</h4><pre>%s</pre></div>'
        '<div class="ev-block"><h4>判定依据</h4><p>%s</p>'
        '<h4>升级条件</h4><p>%s</p>'
        '<h4>反证 / 误报抑制</h4><p class="counter">%s</p></div>'
        '</div>'
        '%s%s'
        '<div class="finding-footer"><span class="chip">处置: %s</span>%s</div>'
        '</div></article>'
        % (
            severity.lower(), confidence.lower(), severity, confidence, finding_type,
            esc(item.get("category", "")),
            SEVERITY_LABEL.get(severity, severity), CONFIDENCE_LABEL.get(confidence, confidence),
            ('<span class="type-tag type-%s">%s</span>' % (finding_type.lower().replace("_", "-"), FINDING_TYPE_LABEL.get(finding_type, finding_type))),
            family_badge,
            esc(item.get("summary", "")),
            esc(item.get("module", "")), esc(item.get("mitre", "") or "—"),
            (' · 生命周期:%s' % esc(item.get("lifecycle", ""))) if item.get("lifecycle") else "",
            fp_hint,
            esc(item.get("evidence", "")),
            esc(judgment), esc(escalation), esc(counter),
            evidence_domains_html(item.get("evidence_domains") or [], item.get("evidence_domain_count")),
            ('<div class="timeline"><h4>攻击链时间线</h4><ul>%s</ul></div>' % timeline_rows) if timeline_rows else "",
            esc(item.get("recommendation", "")),
            ('<div class="refs">%s</div>' % ref_links) if ref_links else "",
        ))


# ---------------------------------------------------------------------------
# document assembly
# ---------------------------------------------------------------------------

CSS = """
:root{--bg:#f7f8fa;--panel:#ffffff;--ink:#1c2024;--ink-soft:#60646c;--line:#e4e7eb;
--accent:#3e63dd;--critical:#e5484d;--high:#f76b15;--medium:#d4a800;--low:#3e63dd;--ok:#30a46c;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--radius:10px}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--panel:#1b1e24;--ink:#e6e8eb;--ink-soft:#9ba1a9;
--line:#2c3038;--accent:#7494e8;--medium:#e3c045;--low:#7494e8}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif}
a{color:var(--accent);text-decoration:none}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px 60px}
header.top{background:linear-gradient(135deg,#14161a 0%,#232733 60%,#2b3140 100%);color:#fff;padding:26px 0 22px;border-bottom:4px solid var(--accent)}
header.top .wrap{padding-bottom:0}
.brand{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
.brand h1{margin:0;font-size:20px;letter-spacing:.5px}
.brand .tagline{color:#9aa3b2;font-size:12px}
.hostline{margin-top:8px;color:#c3cad6;font-size:13px;display:flex;gap:18px;flex-wrap:wrap}
.hostline b{color:#fff;font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:18px}
.kpi{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:var(--radius);padding:12px 14px}
.kpi .k{color:#9aa3b2;font-size:11px;text-transform:uppercase;letter-spacing:.8px}
.kpi .v{font-size:22px;font-weight:700;margin-top:2px;font-variant-numeric:tabular-nums}
.kpi .v small{font-size:12px;font-weight:400;color:#9aa3b2;margin-left:4px}
nav.tabs{position:sticky;top:0;z-index:30;background:var(--panel);border-bottom:1px solid var(--line);display:flex;gap:2px;overflow-x:auto;padding:0 12px}
nav.tabs a{padding:11px 13px;color:var(--ink-soft);font-size:13px;white-space:nowrap;border-bottom:2px solid transparent}
nav.tabs a:hover{color:var(--ink)}
main section{margin-top:26px}
h2{font-size:16px;margin:0 0 12px;display:flex;align-items:center;gap:8px}
h2 .sub{font-weight:400;color:var(--ink-soft);font-size:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:16px 18px}
.verdict{display:flex;gap:14px;align-items:flex-start;border-radius:var(--radius);padding:16px 18px;border:1px solid var(--line);background:var(--panel)}
.verdict.alert{border-left:5px solid var(--critical)}
.verdict.warn{border-left:5px solid var(--high)}
.verdict.pass{border-left:5px solid var(--ok)}
.verdict-icon{font-size:24px;line-height:1}
.verdict-title{font-weight:700;font-size:15px}
.verdict-body{color:var(--ink-soft);margin-top:4px;font-size:13px}
.verdict-badge{margin-left:auto;align-self:center;font-family:var(--mono);font-size:12px;background:var(--bg);border:1px solid var(--line);padding:6px 10px;border-radius:6px;white-space:nowrap}
.exec-grid{display:grid;grid-template-columns:280px 1fr;gap:14px}
@media(max-width:760px){.exec-grid{grid-template-columns:1fr}}
.risk-donut{width:150px;height:150px;display:block;margin:0 auto}
.donut-num{font-size:26px;font-weight:700;fill:var(--ink)}
.donut-sub{font-size:10px;fill:var(--ink-soft)}
.donut-legend{display:flex;flex-wrap:wrap;gap:10px;justify-content:center;margin-top:8px;font-size:12px;color:var(--ink-soft)}
.legend-item{display:inline-flex;align-items:center;gap:5px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.gauge-row{display:flex;gap:18px;flex-wrap:wrap;align-items:center}
.gauge-block{flex:1;min-width:200px}
.gauge-block h3{margin:0 0 6px;font-size:12px;color:var(--ink-soft);text-transform:uppercase;letter-spacing:.6px}
.meter{height:8px;border-radius:4px;background:var(--line);overflow:hidden;flex:1}
.meter-wrap{display:flex;align-items:center;gap:10px}
.meter-num{font-variant-numeric:tabular-nums;font-weight:600;min-width:42px;text-align:right}
.fact-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px 18px}
.fact-list li{display:grid;grid-template-columns:minmax(64px,96px) 1fr;gap:10px;border-bottom:1px dashed var(--line);padding:5px 0;font-size:13px;align-items:baseline}
.fact-list li>span:last-child{word-break:break-all}
.fact-list .fk{color:var(--ink-soft);white-space:nowrap}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}
.filters input{flex:1;min-width:180px;padding:8px 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);font-size:13px}
.chip-btn{padding:6px 12px;border-radius:999px;border:1px solid var(--line);background:var(--panel);color:var(--ink-soft);font-size:12px;cursor:pointer;user-select:none}
.chip-btn.on{background:var(--accent);border-color:var(--accent);color:#fff}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);margin-bottom:10px;overflow:hidden}
.finding-head{display:flex;align-items:center;gap:10px;padding:11px 14px;cursor:pointer;flex-wrap:wrap}
.finding-head:hover{background:var(--bg)}
.sev-tag{font-size:11px;font-weight:700;padding:3px 8px;border-radius:5px;color:#fff;letter-spacing:.4px}
.sev-critical .sev-tag{background:var(--critical)}.sev-high .sev-tag{background:var(--high)}
.sev-medium .sev-tag{background:var(--medium);color:#3b3200}.sev-low .sev-tag{background:#5b6472}.sev-observe .sev-tag{background:#5b6472}
.conf-tag{font-size:11px;padding:3px 8px;border-radius:999px;border:1px solid var(--line);color:var(--ink-soft);font-weight:600}
.conf-high{border-color:var(--accent);color:var(--accent)}
.conf-low{opacity:.75;border-style:dashed}
.type-tag{font-size:11px;padding:3px 8px;border-radius:5px;background:var(--bg);border:1px solid var(--line);color:var(--ink-soft)}
.type-security-threat{border-color:var(--critical);color:var(--critical)}
.family-badge{font-size:11px;padding:3px 8px;border-radius:5px;background:rgba(142,68,173,.13);border:1px solid #8e44ad;color:#8e44ad;font-weight:600}
.finding-summary{flex:1;min-width:200px;font-weight:500;word-break:break-all}
.finding-meta{color:var(--ink-soft);font-size:12px;font-family:var(--mono)}
.finding-toggle{color:var(--ink-soft);transition:transform .15s}
.finding.open .finding-toggle{transform:rotate(180deg)}
.finding-body{display:none;border-top:1px solid var(--line);padding:14px 16px;background:var(--bg)}
.finding.open .finding-body{display:block}
.fp-hint{margin-bottom:10px}
.fp-flag{font-size:11px;padding:3px 9px;border-radius:999px}
.fp-flag.neutral{background:rgba(48,164,108,.13);color:var(--ok);border:1px solid rgba(48,164,108,.33)}
.fp-flag.noted{background:rgba(245,217,10,.13);color:#8a7400;border:1px solid rgba(212,168,0,.33)}
.ev-grid{display:grid;grid-template-columns:1.2fr 1fr;gap:14px}
@media(max-width:760px){.ev-grid{grid-template-columns:1fr}}
.ev-block h4{margin:10px 0 4px;font-size:12px;color:var(--ink-soft)}
.ev-block pre{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px;font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:280px;overflow:auto}
.ev-block p{margin:0 0 4px;font-size:13px}
.ev-block p.counter{color:var(--ink-soft)}
.domain-row{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:10px}
.domain-chip{font-size:11px;font-family:var(--mono);background:var(--panel);border:1px solid var(--line);padding:2px 8px;border-radius:5px;color:var(--accent)}
.domain-count{font-size:12px;font-weight:700;color:var(--accent)}
.timeline ul{margin:4px 0 0;padding-left:18px;font-size:12px;color:var(--ink-soft)}
.finding-footer{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;align-items:center}
.chip{font-size:11px;background:var(--panel);border:1px solid var(--line);padding:3px 9px;border-radius:5px;color:var(--ink-soft)}
.ref-chip{font-size:11px;font-family:var(--mono);background:var(--panel);border:1px dashed var(--line);padding:2px 8px;border-radius:5px}
table.tbl{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);overflow:hidden;font-size:13px}
table.tbl th{background:var(--bg);text-align:left;padding:9px 12px;font-size:12px;color:var(--ink-soft);border-bottom:1px solid var(--line);white-space:nowrap}
table.tbl td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-all}
table.tbl tr:last-child td{border-bottom:none}
.st-success{color:var(--ok);font-weight:600}.st-partial{color:#d4a800;font-weight:600}
.st-failed{color:var(--critical);font-weight:600}.st-skip{color:var(--ink-soft);font-style:italic}
.gap-item{display:flex;gap:10px;padding:9px 0;border-bottom:1px dashed var(--line);font-size:13px}
.gap-item:last-child{border-bottom:none}
.gap-badge{flex-shrink:0;font-size:11px;font-family:var(--mono);padding:2px 8px;border-radius:5px;background:rgba(229,72,77,.1);color:var(--critical);border:1px solid rgba(229,72,77,.27);height:fit-content}
.gap-badge.na{background:var(--bg);color:var(--ink-soft);border-color:var(--line)}
.cmp-tag{font-size:11px;padding:2px 8px;border-radius:5px;font-weight:600}
.cmp-add{background:rgba(229,72,77,.12);color:var(--critical);border:1px solid rgba(229,72,77,.3)}
.cmp-resolved{background:rgba(48,164,108,.12);color:var(--ok);border:1px solid rgba(48,164,108,.3)}
.life-chip{font-size:12px;border:1px solid var(--line);border-radius:999px;padding:4px 12px;display:inline-block;margin:2px;color:var(--ink-soft)}
.life-chip b{color:var(--ink)}
footer{margin-top:40px;color:var(--ink-soft);font-size:12px;text-align:center;border-top:1px solid var(--line);padding-top:16px}
@media print{nav.tabs,.filters,.finding-toggle{display:none!important}.finding-body{display:block!important}.card,.finding{break-inside:avoid}header.top{background:#14161a!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


JS = r"""
function toggleFinding(head){
  head.parentElement.classList.toggle('open');
}
function initReport(){
  var input=document.getElementById('search');
  var chips=document.querySelectorAll('.chip-btn[data-filter]');
  var active={sev:null,conf:null};
  function apply(){
    var q=(input&&input.value||'').toLowerCase();
    document.querySelectorAll('article.finding').forEach(function(card){
      var okSev=!active.sev||card.dataset.sev===active.sev;
      var okConf=!active.conf||card.dataset.conf===active.conf;
      var okText=!q||card.textContent.toLowerCase().indexOf(q)>=0;
      card.style.display=(okSev&&okConf&&okText)?'':'none';
    });
  }
  chips.forEach(function(chip){
    chip.addEventListener('click',function(){
      var kind=chip.dataset.filter, val=chip.dataset.value;
      document.querySelectorAll('.chip-btn[data-filter="'+kind+'"]').forEach(function(c){c.classList.remove('on')});
      if(active[kind]===val){active[kind]=null;}else{active[kind]=val;chip.classList.add('on');}
      apply();
    });
  });
  if(input) input.addEventListener('input',apply);
  // 默认展开威胁类 finding
  document.querySelectorAll('article.finding[data-type="SECURITY_THREAT"]').forEach(function(card){card.classList.add('open')});
  // 计数徽标
  document.querySelectorAll('section[data-count-sev]').forEach(function(sec){
    var sev=sec.dataset.countSev;
    var n=document.querySelectorAll('article.finding[data-sev="'+sev+'"]').length;
    var badge=sec.querySelector('.sub'); if(badge&&n) badge.textContent=n+' 项';
  });
}
document.addEventListener('DOMContentLoaded',initReport);
"""


def group_findings(findings):
    threats = [f for f in findings if f.get("finding_type") == "SECURITY_THREAT"]
    anomalies = [f for f in findings if f.get("finding_type") == "SECURITY_ANOMALY"]
    baseline = [f for f in findings if f.get("finding_type") in ("CONFIG_BASELINE", "SOFTWARE_TRUST_GAP")]
    observations = [f for f in findings if f.get("finding_type") == "RUNTIME_OBSERVATION"]
    for group in (threats, anomalies, baseline, observations):
        group.sort(key=severity_rank)
    return threats, anomalies, baseline, observations


def status_gaps(status):
    """Collect UNAVAILABLE/PARTIAL/SKIPPED surfaces for the visibility section."""
    gaps = []
    modules = status.get("modules") or []
    if isinstance(modules, list):
        for module in modules:
            if not isinstance(module, dict):
                continue
            state = str(module.get("status", "")).upper()
            if state in ("PARTIAL", "FAILED", "SKIPPED_BUDGET", "NOT_RUN"):
                reason = module.get("error") or module.get("errors") or ""
                gaps.append(("模块: %s" % module.get("name", module.get("id", "?")), "%s %s" % (MODULE_STATUS_LABEL.get(state, state), reason)))
    for key, label in (("telemetry_health", "遥测健康"), ("beacon_detection", "Beacon 检测"),
                       ("connection_baseline", "连接基线"), ("process_behavior_baseline", "进程行为基线"),
                       ("rat_detection", "RAT 证据图"), ("webshell_detection", "WebShell 检测"),
                       ("package_integrity", "包完整性"), ("file_scan", "文件监控")):
        value = status.get(key)
        if isinstance(value, dict):
            state = str(value.get("status", "")).upper()
            if any(marker in state for marker in ("UNAVAILABLE", "PARTIAL", "SKIPPED", "DEGRADED", "DISABLED", "NOT_RUN", "LEARNING")):
                gaps.append((label, state))
        elif value:
            state = str(value).upper()
            if any(marker in state for marker in ("UNAVAILABLE", "PARTIAL", "SKIPPED", "DEGRADED", "DISABLED")):
                gaps.append((label, state))
    return gaps


def build_document(findings_data, status, meta, compare_data=None):
    findings = findings_data.get("findings") or []
    threats, anomalies, baseline, observations = group_findings(findings)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OBSERVE": 0}
    for item in findings:
        sev = item.get("severity", "OBSERVE")
        counts[sev] = counts.get(sev, 0) + 1
    gaps = status_gaps(status)
    verdict = meta.get("verdict") or status.get("verdict") or ""
    hostname = meta.get("hostname") or status.get("hostname") or status.get("host") or "unknown"
    profile = meta.get("profile") or status.get("profile") or ""
    run_id = meta.get("run_id") or status.get("run_id") or ""
    started = meta.get("started") or status.get("started_at") or status.get("run_started_at") or ""
    coverage = status.get("telemetry_health", {}).get("source_availability_percent") if isinstance(status.get("telemetry_health"), dict) else None
    coverage = coverage or meta.get("coverage") or 0
    duration = meta.get("duration") or ""
    host_role = meta.get("host_role") or status.get("host_role") or ""
    os_name = meta.get("os") or status.get("os") or ""
    engine_notes = meta.get("engine") or ""
    modules = status.get("modules") or []
    module_rows = "".join(
        '<tr><td>%s</td><td>%s</td><td class="%s">%s</td><td>%ss</td></tr>'
        % (esc(m.get("name", m.get("id", ""))), esc(m.get("planned_sources", "") or "—"),
           ("st-success" if m.get("status") == "SUCCESS" else "st-partial" if m.get("status") in ("PARTIAL", "SKIPPED_BUDGET") else "st-failed" if m.get("status") == "FAILED" else "st-skip"),
           MODULE_STATUS_LABEL.get(m.get("status"), m.get("status", "—")), esc(m.get("duration", "0")))
        for m in modules if isinstance(m, dict))

    mitre = {}
    for item in findings:
        code = (item.get("mitre") or "").strip()
        if code and code != "—":
            mitre.setdefault(code, []).append(item.get("summary", ""))
    mitre_rows = "".join(
        '<tr><td style="font-family:var(--mono);white-space:nowrap">%s</td><td>%s</td></tr>'
        % (esc(code), esc("；".join(summaries[:2]) + ("…" if len(summaries) > 2 else "")))
        for code, summaries in sorted(mitre.items()))

    iocs = status.get("iocs") or []
    ioc_rows = "".join(
        '<tr><td>%s</td><td style="font-family:var(--mono)">%s</td><td>%s</td></tr>'
        % (esc(i.get("type", "?")), esc(i.get("value", "")), esc(i.get("context", "")))
        for i in iocs if isinstance(i, dict))
    if not ioc_rows:
        ioc_rows = '<tr><td colspan="3" style="color:var(--ink-soft)">本轮未收集到 IOC（未发现相应证据）</td></tr>'

    file_changes = findings_data.get("file_changes") or []
    change_rows = "".join(
        '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
        % (esc(c.get("action", c.get("change", "?"))), esc(c.get("path", "")), esc(c.get("priority_reasons", "") or "—"), esc((c.get("sha256", "") or "")[:16] or "—"))
        for c in file_changes[:80])
    if not change_rows:
        change_rows = '<tr><td colspan="4" style="color:var(--ink-soft)">无文件变化记录</td></tr>'

    abnormal = findings_data.get("abnormal_connections") or []
    conn_rows = "".join(
        '<tr><td>%s</td><td>%s</td><td>%s</td></tr>'
        % (esc(c.get("process", c.get("exe", "?"))), esc("%s:%s" % (c.get("dst_ip", c.get("remote", "?")), c.get("dst_port", c.get("port", "")))), esc(c.get("reason", "") or "—"))
        for c in abnormal[:80])
    if not conn_rows:
        conn_rows = '<tr><td colspan="3" style="color:var(--ink-soft)">无异常外连记录</td></tr>'

    def findings_section_html(items, sec_id, title, count_sev=None, note=""):
        cards = "".join(finding_card(item, idx) for idx, item in enumerate(items))
        if not cards:
            cards = '<div class="card" style="color:var(--ink-soft)">%s</div>' % (note or "无记录")
        return ('<section id="%s" %s><h2>%s <span class="sub"></span></h2>%s'
                % (sec_id, ('data-count-sev="%s"' % count_sev) if count_sev else "", esc(title), cards))

    budget_used = meta.get("budget_used") or ""
    budget_limit = meta.get("budget_limit") or "900"
    try:
        used_pct = min(100, int(float(budget_used) / float(budget_limit) * 100)) if budget_used else 0
    except ValueError:
        used_pct = 0
    budget_color = "#30a46c" if used_pct < 70 else ("#d4a800" if used_pct < 95 else "#e5484d")
    budget_bar = ('<div class="meter"><div class="meter-fill" style="width:%d%%;background:%s"></div></div>'
                  '<span class="meter-num">%ss</span>' % (used_pct, budget_color, esc(budget_used or "?")))

    chv = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    doc = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TITLE</title>
<style>CSS_BLOCK</style>
</head>
<body>
<header class="top"><div class="wrap">
  <div class="brand"><h1>SecScope 安全巡检报告</h1><span class="tagline">Linux 入侵检测与取证溯源 · 离线只读</span></div>
  <div class="hostline">
    <span>主机 <b>HOST</b></span><span>系统 <b>OSNAME</b></span><span>角色 <b>ROLE</b></span>
    <span>档位 <b>PROFILE</b></span><span>开始 <b>STARTED</b></span><span>耗时 <b>DURATION</b></span>
  </div>
  <div class="kpis">
    <div class="kpi"><div class="k">总体结论</div><div class="v" style="font-size:16px">VERDICT</div></div>
    <div class="kpi"><div class="k">高危发现</div><div class="v">CHVCOUNT</div></div>
    <div class="kpi"><div class="k">中危异常</div><div class="v">MEDCOUNT</div></div>
    <div class="kpi"><div class="k">证据覆盖率</div><div class="v">COVERAGE<small>%</small></div></div>
    <div class="kpi"><div class="k">可见性缺口</div><div class="v">GAPCOUNT</div></div>
    <div class="kpi"><div class="k">运行编号</div><div class="v" style="font-size:12px;font-family:var(--mono);word-break:break-all">RUNID</div></div>
  </div>
</div></header>
<nav class="tabs"><div class="wrap" style="display:flex;gap:2px">
  <a href="#summary">执行摘要</a><a href="#threats">威胁</a><a href="#anomalies">待研判异常</a>
  <a href="#baseline">基线与信任</a><a href="#observations">观察项</a><a href="#coverage">扫描覆盖</a>
  <a href="#iocs">IOC</a><a href="#changes">文件变化</a><a href="#connections">异常外连</a>
  <a href="#mitre">ATT&amp;CK</a>NAV_LIFECYCLE<a href="#gaps">可见性缺口</a>
</div></nav>
<div class="wrap">
<main>
<section id="summary"><h2>执行摘要</h2>
VERDICT_BANNER
<div class="exec-grid" style="margin-top:14px">
  <div class="card" style="text-align:center">DONUT</div>
  <div class="card">
    <div class="gauge-row">
      <div class="gauge-block"><h3>证据覆盖率</h3><div class="meter-wrap">COVBAR</div>
        <p style="color:var(--ink-soft);font-size:12px;margin:6px 0 0">覆盖率 = 成功采集的数据源 / 计划数据源。覆盖率不足时，"未发现"不可信。</p></div>
      <div class="gauge-block"><h3>扫描预算</h3><div class="meter-wrap">BUDGETBAR</div>
        <p style="color:var(--ink-soft);font-size:12px;margin:6px 0 0">ENGINE_NOTES</p></div>
    </div>
    <ul class="fact-list" style="margin-top:12px">
      <li><span class="fk">结论口径</span><span>VERDICT_MEANING</span></li>
      <li><span class="fk">检测引擎</span><span>PACKINFO</span></li>
      <li><span class="fk">报告版本</span><span>GENVERSION</span></li>
    </ul>
  </div>
</div>
</section>
FILTERS_BLOCK
COMPARE_SECTION
LIFECYCLE_SECTION
THREATS_SECTION
ANOMALIES_SECTION
BASELINE_SECTION
OBSERVATIONS_SECTION
<section id="coverage"><h2>扫描覆盖 <span class="sub">模块执行状态与数据源</span></h2>
<div class="card" style="padding:0;overflow:auto"><table class="tbl">
<tr><th>模块</th><th>计划数据源</th><th>状态</th><th>耗时</th></tr>
MODULE_ROWS
</table></div>
</section>
<section id="iocs"><h2>IOC 清单 <span class="sub">本轮采集的指标</span></h2>
<div class="card" style="padding:0;overflow:auto"><table class="tbl">
<tr><th>类型</th><th>值</th><th>上下文</th></tr>
IOC_ROWS
</table></div>
</section>
<section id="changes"><h2>文件变化 <span class="sub">前 80 条</span></h2>
<div class="card" style="padding:0;overflow:auto"><table class="tbl">
<tr><th>动作</th><th>路径</th><th>原因</th><th>SHA-256</th></tr>
CHANGE_ROWS
</table></div>
</section>
<section id="connections"><h2>异常外连 <span class="sub">进程到目标的连接</span></h2>
<div class="card" style="padding:0;overflow:auto"><table class="tbl">
<tr><th>进程</th><th>目标</th><th>原因</th></tr>
CONN_ROWS
</table></div>
</section>
<section id="mitre"><h2>ATT&amp;CK 映射 <span class="sub">命中的战术技术</span></h2>
<div class="card" style="padding:0;overflow:auto"><table class="tbl">
<tr><th>编号</th><th>相关发现</th></tr>
MITRE_ROWS
</table></div>
</section>
<section id="gaps"><h2>可见性缺口 <span class="sub">诚实呈现"没看到"，绝不并入"安全"</span></h2>
<div class="card">GAP_ITEMS</div>
</section>
</main>
<footer>SecScope 只读离线巡检 · 报告由 report_gen vGENVERSION 渲染 · 数据口径详见 findings.json / status.json · RUN_ID</footer>
</div>
<script>JS_BLOCK</script>
</body></html>"""

    filters_block = ""
    if findings:
        filters_block = ('<section><div class="filters">'
                         '<input id="search" type="search" placeholder="搜索发现（路径 / 规则 / 证据关键字）…">'
                         '<span class="chip-btn" data-filter="sev" data-value="HIGH">高危</span>'
                         '<span class="chip-btn" data-filter="sev" data-value="MEDIUM">中危</span>'
                         '<span class="chip-btn" data-filter="sev" data-value="LOW">低危</span>'
                         '<span class="chip-btn" data-filter="conf" data-value="HIGH">高置信</span>'
                         '<span class="chip-btn" data-filter="conf" data-value="LOW">低置信</span>'
                         '</div></section>')

    # v2.3 F5：轮次对比专区（--compare 时渲染）+ 生命周期总览条
    compare_section = ""
    if compare_data and (compare_data.get("added_count") or compare_data.get("resolved_count")):
        def _cmp_rows(items, action):
            rows = "".join(
                '<tr><td><span class="cmp-tag cmp-%s">%s</span></td><td>%s</td>'
                '<td>%s</td><td>%s</td><td>%s</td></tr>'
                % (action.lower(), "新增" if action == "ADD" else "已解决",
                   esc(i.get("severity", "")), esc(i.get("summary", "")),
                   esc(i.get("rule_id", "") or "—"), esc(i.get("entity", "") or "—"))
                for i in items[:40])
            return rows
        added_rows = _cmp_rows(compare_data.get("added") or [], "ADD")
        resolved_rows = _cmp_rows(compare_data.get("resolved") or [], "RESOLVED")
        truncated = ""
        if compare_data.get("added_truncated") or compare_data.get("resolved_truncated"):
            truncated = '<p style="color:var(--ink-soft);font-size:12px">超出前 %d 条的明细见 raw/findings-compare.tsv</p>' % compare_data.get("added_count", 0)
        compare_section = ('<section id="compare"><h2>轮次对比 <span class="sub">%d 新增 / %d 已解决 / %d 持续</span></h2>'
                           '<div class="card" style="padding:0;overflow:auto"><table class="tbl">'
                           '<tr><th>动作</th><th>严重度</th><th>摘要</th><th>规则</th><th>实体</th></tr>'
                           '%s%s</table></div>%s</section>'
                           % (compare_data.get("added_count", 0), compare_data.get("resolved_count", 0),
                              compare_data.get("unchanged_count", 0),
                              added_rows or '<tr><td colspan="5" style="color:var(--ink-soft)">无新增</td></tr>',
                              resolved_rows or '<tr><td colspan="5" style="color:var(--ink-soft)">无已解决</td></tr>',
                              truncated))

    lifecycle = status.get("lifecycle") or {}
    if lifecycle and any(lifecycle.values()):
        chips = "".join(
            '<span class="life-chip">%s <b>%d</b></span>'
            % (esc(label), lifecycle.get(key, 0))
            for key, label in (("NEW", "新增"), ("ESCALATED", "升级"), ("CHANGED", "变化"),
                               ("ONGOING", "持续"), ("DEESCALATED", "降级"),
                               ("REOPENED", "重现"), ("RESOLVED", "已解决"),
                               ("BASELINE_EXISTING", "基线存量"))
            if lifecycle.get(key))
        resolved_items = status.get("resolved_details") or []
        resolved_html = ""
        if resolved_items:
            resolved_html = ('<details class="card" style="margin-top:10px"><summary>已解决明细（%d 条）</summary>'
                             '<div style="padding:0;overflow:auto"><table class="tbl">'
                             '<tr><th>严重度</th><th>摘要</th><th>首次发现</th><th>最近发现</th></tr>%s</table></div></details>'
                             % (len(resolved_items),
                                "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
                                        % (esc(i.get("severity", "")), esc(i.get("summary", "")),
                                           esc(i.get("first_seen", "") or "—"), esc(i.get("last_seen", "") or "—"))
                                        for i in resolved_items[:40])))
        lifecycle_section = ('<section id="lifecycle"><h2>生命周期总览 <span class="sub">与历史基线对账</span></h2>'
                             '<div class="card">%s%s</div></section>' % (chips, resolved_html))
    else:
        lifecycle_section = ""

    replacements = {
        "CSS_BLOCK": CSS,
        "JS_BLOCK": JS,
        "HOST": esc(hostname), "OSNAME": esc(os_name or "Linux"), "ROLE": esc(host_role or "auto"),
        "PROFILE": esc(profile), "STARTED": esc(started), "DURATION": esc(duration or "—"),
        "VERDICT": esc(verdict), "CHVCOUNT": str(chv), "MEDCOUNT": str(counts.get("MEDIUM", 0)),
        "COVERAGE": str(coverage), "GAPCOUNT": str(len(gaps)), "RUNID": esc(run_id),
        "VERDICT_BANNER": verdict_banner(verdict, counts, gaps),
        "DONUT": donut_svg(counts, len(findings)),
        "COVBAR": coverage_bar(coverage),
        "BUDGETBAR": budget_bar,
        "ENGINE_NOTES": esc(engine_notes or "全局 15 分钟预算，超时模块诚实标记跳过"),
        "VERDICT_MEANING": "严重度=处置优先级；置信度=证据强度。低置信≠误报，高置信≠已确认入侵。",
        "PACKINFO": esc(meta.get("pack", "detect-pack v2（行为/结构签名）")),
        "GENVERSION": VERSION,
        "MODULE_ROWS": module_rows or '<tr><td colspan="4" style="color:var(--ink-soft)">无模块数据</td></tr>',
        "IOC_ROWS": ioc_rows,
        "CHANGE_ROWS": change_rows,
        "CONN_ROWS": conn_rows,
        "MITRE_ROWS": mitre_rows or '<tr><td colspan="2" style="color:var(--ink-soft)">无映射</td></tr>',
        "GAP_ITEMS": ("".join('<div class="gap-item"><span class="gap-badge%s">%s</span><span>%s</span></div>'
                              % (" na" if str(state).upper() in ("LEARNING", "DISABLED", "NOT_RUN") else "",
                                 esc(str(state).upper()), esc(label))
                              for label, state in gaps)
                      or '<div class="gap-item"><span class="gap-badge na">OK</span><span>本轮无可见性缺口</span></div>'),
        "COMPARE_SECTION": compare_section,
        "NAV_LIFECYCLE": ('<a href="#lifecycle">生命周期</a>' if lifecycle_section else ''),
        "NAV_COMPARE": ('<a href="#compare">轮次对比</a>' if compare_section else ''),
        "LIFECYCLE_SECTION": lifecycle_section,
        "THREATS_SECTION": findings_section_html(threats, "threats", "威胁发现（高置信 / 需立即研判）", "HIGH",
                                                 "未发现高置信威胁"),
        "ANOMALIES_SECTION": findings_section_html(anomalies, "anomalies", "待研判异常（弱信号，附反证与升级条件）", "MEDIUM",
                                                   "无待研判异常"),
        "BASELINE_SECTION": findings_section_html(baseline, "baseline", "配置基线与信任缺口"),
        "OBSERVATIONS_SECTION": findings_section_html(observations, "observations", "运行时观察项"),
        "FILTERS_BLOCK": filters_block,
        "TITLE": "SecScope 安全巡检报告 — %s" % esc(hostname),
    }
    for key, value in sorted(replacements.items(), key=lambda item: -len(item[0])):
        doc = doc.replace(key, value)
    return doc


def main(argv=None):
    parser = argparse.ArgumentParser(prog="report_gen")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--status")
    parser.add_argument("--meta")
    parser.add_argument("--compare-data")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    findings_data = load_json(args.findings)
    status = load_json(args.status) if args.status else {}
    meta = load_meta(args.meta)
    compare_data = load_json(args.compare_data) if args.compare_data else {}
    doc = build_document(findings_data, status, meta, compare_data)
    temp = args.output + ".pending"
    with io.open(temp, "w", encoding="utf-8") as handle:
        handle.write(doc)
    os.replace(temp, args.output)
    try:
        os.chmod(args.output, 0o600)
    except OSError:
        pass
    sys.stdout.write('{"status":"SUCCESS","renderer":"report_gen","version":"%s","bytes":%d}\n'
                     % (VERSION, len(doc)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

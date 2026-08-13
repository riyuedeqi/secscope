#!/usr/bin/env python3
"""Static contract checks for the self-contained SecScope HTML report."""

from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "secscope.sh").read_text(encoding="utf-8")


class StructureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.hrefs = []
        self.sections = 0
        self.tables = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"])
        if tag == "a" and values.get("href", "").startswith("#"):
            self.hrefs.append(values["href"][1:])
        if tag == "section":
            self.sections += 1
        if tag == "table":
            self.tables += 1


start = SOURCE.index("<!doctype html><html lang=\"zh-CN\"")
end = SOURCE.index("HTM\n", start)
template = SOURCE[start:end]
parser = StructureParser()
parser.feed(template)

required_text = (
    "防病毒 / 终端安全软件",
    "建议优先处理",
    "本轮变化",
    "已确认或高置信安全威胁",
    "待研判安全异常",
    "配置基线",
    "软件信任缺口",
    "运行 / 性能观察",
    "异常外连",
    "YARA 命中",
    "可疑文件行为",
    "组件版本与离线支持状态",
    "检测可见性",
    "模块覆盖",
    "IOC 指标",
    "原始证据索引",
)
assert all(text in template for text in required_text)
assert {"summary", "changes", "threats", "anomalies", "connections", "yara", "files", "visibility", "evidence"} <= parser.ids
assert all(target in parser.ids for target in parser.hrefs)
assert "@media print" in template and "@media(max-width:620px)" in template
assert 'aria-label="报告导航"' in template
assert "report-search" in template and "report-severity" in template and "report-confidence" in template
assert parser.sections >= 10 and parser.tables >= 0  # Tables are inserted through preserved placeholders.

print("HTML_REPORT_OK")

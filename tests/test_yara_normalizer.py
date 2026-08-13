#!/usr/bin/env python3
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("yara_normalizer", ROOT / "helpers" / "yara_normalizer.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

row = module.normalize_line('corp:web_shell [php,obfuscated] [family="test", score=90] /srv/a.php', '/srv/a.php', 'rules.yar')
assert row['rule'] == 'web_shell'
assert row['namespace'] == 'corp'
assert row['tags'] == ['php', 'obfuscated']
assert row['metadata']['family'] == 'test' and row['metadata']['score'] == '90'
print('YARA_NORMALIZER_OK')

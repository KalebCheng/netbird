#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${NB_TEST_BIN:-$ROOT_DIR/dist/netbird-0.25.3-relay-darwin-arm64}"
MGMT="${NB_MANAGEMENT_URL:-https://netbird.insuresmart.tech:443}"
DIR="${NB_TEST_DIR:-/tmp/nb-relay-test}"
MODE="up"

usage() {
  cat <<'EOF'
用法:
  NB_SETUP_KEY=<测试 setup key> ./scripts/test-mac-relay-login.sh
  NB_SETUP_KEY=<测试 setup key> ./scripts/test-mac-relay-login.sh --login-only
  ./scripts/test-mac-relay-login.sh --clean

说明:
  默认使用前台模式启动完整客户端，不安装系统服务，配置写入 /tmp/nb-relay-test。
  --login-only  只执行 Management 登录/注册，不需要 sudo，也不建立隧道。
  --clean       删除测试配置和日志。

可选环境变量:
  NB_SETUP_KEY       测试用 setup key（不要用生产现有 peer 的 key）
  NB_MANAGEMENT_URL  默认 https://netbird.insuresmart.tech:443
  NB_FORCE_RELAY=1   强制走新版 Relay
  NB_TEST_DIR        默认 /tmp/nb-relay-test
  NB_LOG_LEVEL       默认 debug
EOF
}

for arg in "$@"; do
  case "$arg" in
    --login-only) MODE="login" ;;
    --clean) MODE="clean" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $arg" >&2; usage; exit 2 ;;
  esac
done

if [[ "$MODE" == "clean" ]]; then
  rm -rf "$DIR"
  echo "已删除 $DIR"
  exit 0
fi

if [[ ! -x "$BIN" ]]; then
  echo "找不到可执行文件: $BIN" >&2
  exit 1
fi

if [[ -z "${NB_SETUP_KEY:-}" ]]; then
  echo "缺少 NB_SETUP_KEY。请使用测试用 setup key，不要复用生产现有 peer。" >&2
  usage
  exit 2
fi

mkdir -p "$DIR"
CONFIG="$DIR/config.json"
LOG_FILE="$DIR/client.log"
COMMON_ARGS=(
  -c "$CONFIG"
  --daemon-addr "unix://$DIR/netbird.sock"
  --log-file console
  -l "${NB_LOG_LEVEL:-debug}"
  -m "$MGMT"
  -k "$NB_SETUP_KEY"
)

if [[ "$MODE" == "login" ]]; then
  echo "仅登录模式（不建立隧道，不需要 sudo）"
  "$BIN" "${COMMON_ARGS[@]}" login
  echo "登录完成，配置: $CONFIG"
  exit 0
fi

if pgrep -f '/netbird( |$)' >/dev/null 2>&1; then
  echo "检测到已有 NetBird 进程。请先停止现有客户端，或使用独立测试机。" >&2
  echo "强行运行会抢占 utun100 和路由，因此脚本默认退出。" >&2
  exit 3
fi

echo "完整客户端前台模式；Ctrl-C 结束。日志同时写入 $LOG_FILE"
echo "Management: $MGMT"
echo "Force Relay: ${NB_FORCE_RELAY:-0}"

sudo -E env \
  NB_FORCE_RELAY="${NB_FORCE_RELAY:-}" \
  "$BIN" "${COMMON_ARGS[@]}" up -F 2>&1 | tee "$LOG_FILE"

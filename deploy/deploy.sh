#!/usr/bin/env bash
# Push the committed tree to the demo VM, write its config, and restart.
# Run from the repo root after `terraform apply`. Reads keys from ./.env:
#   VULTR_GUARD_API_KEY      a Vultr sub-user key that can read billing (the guard); never the account key
#   VULTR_INFERENCE_API_KEY  Vultr Serverless Inference key (explanations)
#   VULTR_INFERENCE_MODEL    optional
set -euo pipefail
cd "$(dirname "$0")/.."

tf() { terraform -chdir=deploy/terraform "$@"; }
IP=$(tf output -raw ip)
SITE=$(tf output -raw url); SITE=${SITE#https://}
PLAN=$(tf output -raw plan 2>/dev/null || echo vc2-2c-4gb)
REGION=$(tf output -raw region 2>/dev/null || echo lax)
SSH=(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "root@$IP")

get() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true; }

echo "waiting for cloud-init on $IP"
until "${SSH[@]}" test -f /var/lib/redhanded/cloud-init.done 2>/dev/null; do sleep 10; done

echo "pushing $(git rev-parse --short HEAD)"
git archive --format=tar HEAD | "${SSH[@]}" '
  set -e
  rm -rf /opt/redhanded/app.new && mkdir /opt/redhanded/app.new
  tar -x -C /opt/redhanded/app.new
  rm -rf /opt/redhanded/app.old
  [ -d /opt/redhanded/app ] && mv /opt/redhanded/app /opt/redhanded/app.old
  mv /opt/redhanded/app.new /opt/redhanded/app
  chown -R rh:rh /opt/redhanded/app
  runuser -u rh -- /opt/redhanded/venv/bin/pip install -q --disable-pip-version-check /opt/redhanded/app'

umask 077
{
  echo "RH_RUNSC=/var/lib/redhanded/bin/runsc"
  echo "RH_ROOTFS=/var/lib/redhanded/rootfs"
  echo "RH_SCANS=/var/lib/redhanded/scans"
  echo "RH_WEB_DATA=/var/lib/redhanded/web"
  echo "RH_GUARD_STATE=/var/lib/redhanded/guard-state.json"
  echo "RH_REPLAYS=/opt/redhanded/app/replays"
  echo "RH_ZOO=/opt/redhanded/app/zoo"
  echo "RH_TRUST_PROXY=1"
  echo "RH_HOST_LABEL=Vultr $REGION · $PLAN"
  for k in RH_CREDIT_GRANT RH_STOP_TIER2_AT RH_PAUSE_ALL_AT RH_CREDIT_EXPIRES RH_SCANS_PER_HOUR \
           VULTR_INFERENCE_API_KEY VULTR_INFERENCE_BASE_URL VULTR_INFERENCE_MODEL; do
    v=$(get "$k"); [ -n "$v" ] && echo "$k=$v"
  done
  v=$(get VULTR_GUARD_API_KEY); [ -n "$v" ] && echo "VULTR_API_KEY=$v"
} | "${SSH[@]}" 'cat > /etc/redhanded/env && chown root:rh /etc/redhanded/env && chmod 640 /etc/redhanded/env'

"${SSH[@]}" "
  set -e
  printf '%s {\n  encode gzip\n  reverse_proxy 127.0.0.1:8080\n  header Strict-Transport-Security \"max-age=31536000\"\n}\n' '$SITE' > /etc/caddy/Caddyfile
  systemctl restart caddy redhanded-guard redhanded-web
  sleep 2
  systemctl is-active caddy redhanded-guard redhanded-web
  curl -fsS http://127.0.0.1:8080/api/status"
echo
echo "live at https://$SITE"

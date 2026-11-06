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
  echo "RH_RESULTS=/opt/redhanded/app/evals/real-malware.json"
  echo "RH_HOST_LABEL=Vultr $(tf output -raw region) · $(tf output -raw plan)"
  echo "RH_PUBLIC_URL=https://$SITE"
  echo "RH_FC_BIN=/var/lib/redhanded/bin/firecracker"
  echo "RH_FC_KERNEL=/var/lib/redhanded/vmlinux"
  echo "RH_FC_ROOTFS=/var/lib/redhanded/guest.ext4"
  echo "RH_MIRROR=/var/lib/redhanded/mirror"
  for k in RH_CREDIT_GRANT RH_STOP_TIER2_AT RH_PAUSE_ALL_AT RH_CREDIT_EXPIRES RH_SCANS_PER_HOUR \
           VULTR_INFERENCE_API_KEY VULTR_INFERENCE_BASE_URL VULTR_INFERENCE_MODEL; do
    v=$(get "$k"); if [ -n "$v" ]; then echo "$k=$v"; fi
  done
  v=$(get VULTR_GUARD_API_KEY); if [ -n "$v" ]; then echo "VULTR_API_KEY=$v"; fi
} | "${SSH[@]}" 'cat > /etc/redhanded/env && chown root:rh /etc/redhanded/env && chmod 640 /etc/redhanded/env'

"${SSH[@]}" '
  set -e
  cd /var/lib/redhanded
  want=$(sha256sum /opt/redhanded/app/deploy/sandbox.Dockerfile | cut -d" " -f1)
  if [ "$(cat rootfs.built 2>/dev/null)" != "$want" ]; then
    systemctl start docker
    docker build -q -t rh-sandbox -f /opt/redhanded/app/deploy/sandbox.Dockerfile /opt/redhanded/app/deploy >/dev/null
    cid=$(docker create rh-sandbox)
    rm -rf rootfs && mkdir rootfs
    docker export "$cid" | tar -x -C rootfs --no-same-owner
    docker rm "$cid" >/dev/null
    systemctl stop docker docker.socket
    rm -f rootfs/.dockerenv
    chown -R rh:rh rootfs
    echo "$want" > rootfs.built
  fi
  mkdir -p mirror
  while read -r sum zip; do
    if ! echo "$sum  mirror/$zip" | sha256sum -c --status 2>/dev/null; then
      curl -fsSL -o "mirror/$zip" "https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/$zip"
      echo "$sum  mirror/$zip" | sha256sum -c --status
    fi
  done <<SUMS
9d8a24292a7068090205daac0a5a223f5f69736f5287e37bf88d3b4031edc750 bun-linux-x64-baseline.zip
79c0771fa8b92c33aae41e15a0e0d307ea99d0e2f00317c71c6c53237a78e25a bun-linux-x64.zip
SUMS
  chown -R rh:rh mirror
  rsync -a --delete rootfs/ guest-rootfs/
  install -m 755 /opt/redhanded/app/deploy/guest/rh-init guest-rootfs/sbin/rh-init
  mke2fs -q -F -t ext4 -d guest-rootfs guest.ext4 2000M
  chown rh:rh guest.ext4
  if ! grep -q "name deps" /etc/systemd/system/redhanded-prune.service; then
    sed -i "s/-name bundle/-name bundle -o -name deps -o -name tls/" /etc/systemd/system/redhanded-prune.service
    systemctl daemon-reload
  fi'

"${SSH[@]}" "
  set -e
  printf '%s {\n  encode gzip\n  reverse_proxy 127.0.0.1:8080\n  header Strict-Transport-Security \"max-age=31536000\"\n}\n' '$SITE' > /etc/caddy/Caddyfile
  systemctl restart caddy redhanded-guard redhanded-web
  sleep 2
  systemctl is-active caddy redhanded-guard redhanded-web
  curl -fsS http://127.0.0.1:8080/healthz"
echo
echo "live at https://$SITE"

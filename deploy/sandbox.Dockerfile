# The machine a package believes it is on. Real malware calls curl, python and git, and
# dies with "not found" on a bare image, so a scan would see nothing.
FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl wget python3 git bash openssh-client netcat-openbsd iproute2 procps ca-certificates dnsutils unzip \
    && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

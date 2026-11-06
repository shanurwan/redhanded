# RedHanded

**Before you merge, catch it red-handed.**

RedHanded is a pre-merge agent for npm dependency changes. For every pull request that adds or updates a dependency, whether Dependabot, a person or a coding agent wrote it, RedHanded runs the changed packages in a sandbox baited with fake credentials and wired to a fake internet that also answers HTTPS: first gVisor, then a Firecracker microVM with its own kernel. When a package steals the bait or uses it, the check fails and the evidence comes with it.

Built for the Vultr: Agent Rush Hackathon 2026, Challenge 1 "Blast Radius Zero".

**Try it:** <https://45-32-140-228.sslip.io> opens on recorded catches you can replay and check, and lets you detonate any npm package or Zoo sample live.

## How it works

```
 package tarball ──sha512 check──▶ fake credentials made for this scan
        │
        ├──▶ gVisor sandbox ───── syscall log ─────┐
        │      runs install scripts, then loads it │
        │                                          ├──▶ evidence ──▶ fixed rules ──▶ verdict
        └──▶ Firecracker microVM ── own kernel ────┤
               same bytes, fresh credentials       │
                        │                          │
                        ▼ only route               │
                sinkhole: fake DNS, HTTP, TLS, ────┘
                metadata endpoint. No route out.
```

Testing on real malware shaped this. The sandbox looks like a developer's machine, with curl, Python and git, because real payloads die on a bare image. Dependencies are fetched with scripts off, because a package scanned alone dies on a missing `axios`. Each scan has its own root certificate, trusted inside the sandbox, so a token sent over HTTPS is seen. Each scan also has a unique machine name, so recon sent out in any encoding is caught.

gVisor records every syscall, but it names itself: `/proc/version` reads `4.19.0-gvisor`. The microVM has its own Linux kernel, so that check comes back clean. It has no syscall log, so the two complement each other, and the sinkhole sits outside both.

Both tiers run without root, in network namespaces created with `unshare` inside a user namespace. The only route leads to the sinkhole, and the sinkhole has no route at all. A hard deadline kills each run. A package already blocked by the first run, or killed at the deadline, skips the second.

## How it runs on Vultr

| Vultr service | What it does here |
|---|---|
| VX1 Cloud Compute | One VM (`vx1-g-2c-8g-120s`, Debian 13, San Jose) runs the site, the queue, gVisor, Firecracker and the sinkhole. VX1 exposes `/dev/kvm` to guests, which is what makes a microVM per scan possible on one small VM |
| Serverless Inference | `deepseek-v4.1-flash-1017` does two jobs through the OpenAI-compatible API: it reads package text for instructions aimed at AI agents, which can raise a verdict to REVIEW and nothing else, and it writes the explanation beside each verdict. It never sees a way to lower a verdict |
| Firewall | Ports 80 and 443 are open; SSH is allowed only from the admin address |
| Account API | The spend guard reads the balance and pending charges every 10 minutes with a billing-only sub-user key. Vultr has no native spend alert, so if the state goes stale or the limit is reached, scans stop |

```
 page ────────┐
 PR check ────┼──HTTPS──▶ Caddy ──▶ redhanded web ──▶ one queue, one scan at a time
 agent (MCP) ─┘                                       rate limit, spend guard
                                                            │
                                     gVisor + microVM + sinkhole on VX1
                                                            │
                                     evidence ──▶ fixed rules ──▶ verdict
                                                            │ clipped evidence, fenced as data
                                     Vultr Serverless Inference: explanation only
```

[`deploy/terraform`](deploy/terraform) builds all of it, [`deploy/deploy.sh`](deploy/deploy.sh) pushes a commit to the VM, and `terraform destroy` removes everything that bills. The host disables MPTCP, verifies gVisor, Firecracker and the guest kernel by checksum, builds the root filesystem from the image digest CI uses, and runs the service as an unprivileged user.

### What the agent does on a real task

1. It takes a package name, or a lockfile change through MCP, and resolves it to exact bytes by sha512. Bytes it has already scanned under the same rules return the recorded verdict.
2. It fetches and verifies the tarball, plants fresh fake credentials and starts a new sandbox.
3. It runs the package's install scripts and loads it the way an application would, under a hard deadline, in gVisor and then in a microVM.
4. It reads the logs and the sinkhole capture from outside, and fixed rules set the verdict.
5. It asks Vultr Serverless Inference whether the package's text addresses AI agents and to explain the result, then returns the verdict, the advice (allow, review or block), the reasons and the evidence files.

Each replay in [`replays/`](replays) keeps a scan's report and sinkhole capture, plus the syscall lines that carry the story and the sha256 of the full log. Attack replays were recorded on a throwaway VX1 and contain no package code. Fake credentials are replaced by their names, because they are shaped like real ones and secret scanners cannot tell.

## How a verdict is reached

Evidence decides; the model only explains.

| Verdict | Triggered by |
|---|---|
| CRITICAL | A honeytoken appears in outbound traffic or a DNS name, or a stolen token is presented to the fake npm, GitHub or AWS endpoint |
| HIGH | Does something in the microVM that it hid from gVisor; reads bait and attempts network access; spawns a network tool anywhere; runs an inline interpreter from code (not from the package's declared script); writes a persistence path; modifies the runtime toolchain |
| REVIEW | Unknown network destinations, container checks, package text that gives instructions to AI agents, incomplete scans, deadline kills |
| CLEAN | None of the above |

A package's declared lifecycle command, and npm's own build tooling (such as bundled node-gyp), are visible to any reviewer, so their form alone is not flagged; what they do still is. Loopback traffic is not network access. Each rule change bumps `RULES_VERSION`, so a cached verdict is never served under rules that did not make it.

## Eval

`redhanded eval` scans every sample in [`zoo/`](zoo) and every pinned package in [`evals/benign.txt`](evals/benign.txt), then applies [`evals/gate.json`](evals/gate.json). Verdicts are deterministic, so the gate is exact: a sample below the verdict its `expect.json` demands fails the run, and a benign package that would block a merge fails it.

Recorded runs are in [`evals/results`](evals/results).

### Real malware

A random 300 from [Datadog's public dataset](https://github.com/DataDog/malicious-software-packages-dataset) of malicious npm packages (Apache-2.0), set aside by a fixed seed before the rules were frozen and run once, on a throwaway Vultr VM. A separate 100 were used for tuning and do not count. No sample is kept in this repo: only the evidence of a few scans, in [`replays/`](replays).

| Verdict, of 299 scanned | Packages | |
|---|---|---|
| CRITICAL: seen stealing or using fake credentials | 39 | 13% |
| HIGH: blocks the merge | 100 | 33% |
| REVIEW: sent to a person | 29 | 10% |
| CLEAN: got through | 131 | 44% |

That is 139 blocked (46%, Wilson 95%: 41% to 52%). Of the 188 with an install script, 129 were blocked (69%). Of the 75 hijacked releases of real libraries, 45 were blocked (60%).

How to read these numbers:

- Some of the 131 misses are limits of replaying old attacks: payloads that delete themselves or depend on downloads and packages that no longer exist, for example the axios payload `plain-crypto-js`, whose `setup.js` is absent from the dataset's copy. Others are real gaps: code that only fires on Windows, or only when called in a specific way. [`evals/real-malware.json`](evals/real-malware.json) sorts them by cause, automatically and approximately.
- The dataset leans toward what Datadog's own rules flag, so it is not a sample of all npm malware.
- The second tier found nothing the first had missed on these samples. The rule that flags what a package hid from gVisor has fired only on our own Zoo sample.

### False alarms and the Zoo

| Set | Result |
|---|---|
| Zoo samples (must be caught) | 9 of 9 at or above the expected verdict (Wilson 95%: 0.70 to 1.0) |
| Benign: 42 popular packages plus 3 controls | 0 would block a merge, 2 sent to review (puppeteer downloads Chromium; nodemon reads `/proc/1/environ`) |
| Agent-text check on 42 real package READMEs | 0 flagged |
| Time per scan | About 10 s typically; p95 33 s on the malware set; large native builds take longer |
| Compute per scan | About $0.0002 on a $0.153/h VX1 running 3 at a time, without inference |

- The rules were tuned on left-pad, core-js and esbuild, then on sqlite3 after the first held-out run flagged it. Those four do not count as held out.
- CI runs the Zoo under gVisor alone, without the model. The microVM tier and the agent-text check run on the VX1 host.
- The agent-text check has been measured for false alarms much more than for catches: one Zoo sample and three hand-written strings. A package can also word its text to slip past it.

## Use it

Requirements: Linux, Python 3.12+, [gVisor](https://gvisor.dev) `runsc`, and a root filesystem with Node (CI builds one from `node:24-alpine`; see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

```bash
python -m pip install -e ".[mcp]"
export RH_RUNSC=~/bin/runsc RH_ROOTFS=~/rootfs RH_SCANS=~/scans
redhanded scan left-pad@1.3.0          # one package from the registry
redhanded scan zoo/network-tool        # a local folder
redhanded eval                         # the gate
```

### From a coding agent

Copy the config from the site, or:

```json
{
  "mcpServers": {
    "redhanded": { "type": "http", "url": "https://45-32-140-228.sslip.io/mcp" }
  }
}
```

Nothing to install, and the scan runs on the RedHanded host, never on the caller's machine. Tools: `check_package(name, version)`, `check_lockfile_change(new_lockfile, old_lockfile)` and `get_scan_report(scan_id)`. Package text never appears in an answer, so an attacker's README cannot reach the next agent. [`/llms.txt`](src/redhanded/static/llms.txt) describes the HTTP API. `redhanded mcp` serves the same tools over stdio for your own sandbox host.

### As a PR check

```yaml
on: pull_request
jobs:
  redhanded:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: shanurwan/redhanded@main
```

A HIGH or CRITICAL verdict, or an answer that never arrives, fails the check. The job summary links to the evidence. Add it as a required check in branch protection to block the merge.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Safety

The Zoo samples imitate publicly documented attack behaviour. Their only targets are per-scan fake credentials and reserved `.invalid` domains, they are `"private": true`, and they are never published to npm.

## License

MIT. See [LICENSE](LICENSE).

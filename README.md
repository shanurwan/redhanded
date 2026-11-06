# RedHanded

**Before you merge, catch it red-handed.**

RedHanded is a pre-merge agent for npm dependency changes. For every pull request that adds or updates a dependency, whether Dependabot, a person or a coding agent wrote it, RedHanded runs the changed packages in a disposable sandbox baited with fake credentials and a fake internet. If the code reaches for the bait, the merge is blocked and the evidence is attached to the PR.

Built for the Vultr: Agent Rush Hackathon 2026, Challenge 1 "Blast Radius Zero".

**Try it:** <https://45-76-169-219.sslip.io> opens on recorded catches you can replay and check, and lets you detonate any npm package or Zoo sample live.

## How it works

```
 package tarball ──sha512 check──▶ unpacked into /work/node_modules/<name>
                                   fake credentials planted in /home/dev
        ┌──────────── gVisor sandbox (own network namespace) ────────────┐
        │  npm rebuild <name>   (runs preinstall / install / postinstall) │
        │  node load.js <name>  (runs import-time code)                   │
        └───────────────┬────────────────────────────────────────────────┘
                        │ only route
        ┌───────────────▼──────────── sinkhole namespace ─────────────────┐
        │  fake DNS, HTTP, TLS server names, fake metadata endpoint       │
        │  no route out                                                   │
        └─────────────────────────────────────────────────────────────────┘
 host side: gVisor syscall log + sinkhole records + this scan's honeytokens
            ──▶ evidence ──▶ fixed rules ──▶ CLEAN / REVIEW / HIGH / CRITICAL
```

The sandbox and the sinkhole run in two network namespaces created with `unshare` inside a user namespace, so no root is needed. The sandbox's only route leads to the sinkhole, and the sinkhole has no route at all. Everything the package writes stays in gVisor's in-memory overlay. A hard deadline kills the sandbox.

## How it runs on Vultr

| Vultr service | What it does here |
|---|---|
| Cloud Compute | One VM (`vc2-2c-4gb`, Debian 13, Los Angeles) runs the site, the scan worker, gVisor and the sinkhole. Every detonation happens on it |
| Serverless Inference | `deepseek-v4.1-flash-1017` writes the plain-language explanation shown beside each verdict, through the OpenAI-compatible API. The verdict is already decided; the text cannot change it |
| Firewall | Ports 80 and 443 are open; SSH is allowed only from the admin address |
| Account API | The spend guard reads the balance and pending charges every 10 minutes with a billing-only sub-user key. Vultr has no native spend alert, so if the state goes stale or the limit is reached, live scans stop |

```
 browser / agent --HTTPS--> Caddy --> redhanded web --> queue (one scan at a time, rate limited)
                                                          | guard state must be fresh
                                                          v
                                  gVisor sandbox <--> sinkhole (no route out)
                                                          | syscall log + capture
                                                          v
                                  evidence --> fixed rules --> verdict
                                                          |
                                                          v  clipped evidence, fenced as data
                                  Vultr Serverless Inference (explanation only)
```

[`deploy/terraform`](deploy/terraform) builds all of it, [`deploy/deploy.sh`](deploy/deploy.sh) pushes a commit to the VM, and `terraform destroy` removes everything that bills. The host disables MPTCP, verifies gVisor's checksum, builds the sandbox root filesystem from the image digest CI uses, and runs the service as an unprivileged user.

### What the agent does on a real task

1. It takes a package name, or a lockfile change through MCP, and resolves it to exact bytes by sha512. Bytes it has already scanned under the same rules return the recorded verdict.
2. It fetches and verifies the tarball, plants fresh fake credentials and starts a new sandbox.
3. It runs the package's install scripts and loads it the way an application would, under a hard deadline.
4. It reads the syscall log and the sinkhole capture from outside the sandbox, and fixed rules set the verdict.
5. It asks Vultr Serverless Inference to explain the result, then returns the verdict, the advice (allow, review or block), the reasons and the evidence files.

The replays in [`replays/`](replays) were all recorded on the VM. Each keeps the scan's report and sinkhole capture, plus the syscall lines that carry the story and the sha256 of the full log. Fake credentials in excerpts are replaced by their names, because they are shaped like real ones and secret scanners cannot tell.

## How a verdict is reached

Evidence decides; the model only explains.

| Verdict | Triggered by |
|---|---|
| CRITICAL | A honeytoken appears in outbound traffic or a DNS name, or a stolen token is presented to the fake npm, GitHub or AWS endpoint |
| HIGH | Reads bait and attempts network access; spawns a network tool anywhere; runs an inline interpreter from code (not from the package's declared script); writes a persistence path; modifies the runtime toolchain |
| REVIEW | Unknown network destinations, container checks, probe flags, incomplete scans, deadline kills |
| CLEAN | None of the above |

A package's declared lifecycle command, and npm's own build tooling (such as bundled node-gyp), are visible to any reviewer, so their form alone is not flagged; what they do still is. Loopback traffic is not network access. Each rule change bumps `RULES_VERSION`, so a cached verdict is never served under rules that did not make it.

## Eval

`redhanded eval` scans every sample in [`zoo/`](zoo) and every pinned package in [`evals/benign.txt`](evals/benign.txt), then applies [`evals/gate.json`](evals/gate.json). Verdicts are deterministic, so the gate is exact: a sample below the verdict its `expect.json` demands fails the run, and a benign package that would block a merge fails it.

Recorded runs are in [`evals/results`](evals/results). Latest, on the dev server (rules `2026-11-04.2`):

| Set | Result |
|---|---|
| Zoo samples (must be caught) | 8 of 8 at or above the expected verdict (Wilson 95%: 0.68 to 1.0) |
| Benign: 42 popular packages plus 2 lookalike controls | 0 would block a merge, 0 sent to review |
| Time per scan | p95 20 s (deadline samples); most packages about 5 s |

How to read these numbers:

- The Zoo covers container checks, persistence, network tools, inline interpreters, telemetry, toolchain tampering and deadline overruns. The CRITICAL rules (honeytoken exfiltration and token use) are covered by unit tests.
- The rules were tuned on left-pad, core-js and esbuild, and then on sqlite3 after the first held-out run flagged it. Those four do not count as held out.
- Packages are scanned one at a time, so some fail to load without their dependencies. That is reported, not flagged.

## Use it

Requirements: Linux, Python 3.12+, [gVisor](https://gvisor.dev) `runsc`, and a root filesystem with Node (CI builds one from `node:24-alpine`; see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

```bash
python -m pip install -e ".[mcp]"
export RH_RUNSC=~/bin/runsc RH_ROOTFS=~/rootfs RH_SCANS=~/scans
redhanded scan left-pad@1.3.0          # one package from the registry
redhanded scan zoo/network-tool        # a local folder
redhanded eval                         # the gate
```

### As an MCP server

```json
{
  "mcpServers": {
    "redhanded": { "command": "redhanded", "args": ["mcp"] }
  }
}
```

Tools: `check_package(name, version)`, `check_lockfile_change(new_lockfile, old_lockfile)` and `get_scan_report(scan_id)`. All are read-only from the caller's side: scans run on the RedHanded host, never on the caller's machine.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Safety

The Zoo samples imitate publicly documented attack behaviour. Their only targets are per-scan fake credentials and reserved `.invalid` domains, they are `"private": true`, and they are never published to npm.

## License

MIT. See [LICENSE](LICENSE).

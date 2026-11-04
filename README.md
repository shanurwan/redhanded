# RedHanded

**Before you merge, catch it red-handed.**

RedHanded is a pre-merge agent for npm dependency changes. For every pull request that adds or updates a dependency, whether Dependabot, a person or a coding agent wrote it, RedHanded runs the changed packages in a disposable sandbox baited with fake credentials and a fake internet. If the code reaches for the bait, the merge is blocked and the evidence is attached to the PR.

Built for the Vultr: Agent Rush Hackathon 2026, Challenge 1 "Blast Radius Zero".

## Status

Work in progress during the build week (3–8 Nov 2026). This section states what works today, not what is planned.

| Part | State |
|---|---|
| Detonation: `redhanded scan name@version` or a local folder, in gVisor with an in-memory overlay | Works, tested on real packages |
| Bait: per-scan fake credentials in files, environment and a fake cloud metadata endpoint | Works, tested |
| Sinkhole: fake DNS, HTTP, TLS server-name capture; no upstream | Works, tested |
| Host-side syscall trace from gVisor, parsed into files, processes and network attempts | Works, every line of real logs parses |
| Honeytoken matcher (raw, base64 at any alignment, base64url, hex, URL encoding, gzip, zlib, raw deflate, nested layers, DNS labels) | Works, tested |
| Deterministic verdict rules; a model can raise CLEAN to REVIEW, never lower | Works, tested |
| Eval gate (Zoo + held-out benign set), run under gVisor in CI on every push | Works |
| MCP server: `check_package`, `check_lockfile_change`, `get_scan_report` | Works, tested in-process |
| Verdict cache keyed by tarball sha512 and rules version | Works, tested |
| Spend guard and `redhanded budget` for a fixed cloud credit | Works, tested against a fake API |
| Vultr deployment (Terraform, cloud-init), tier 2 throwaway VMs | Not started |
| Explanation by Vultr Serverless Inference, web UI, GitHub App | Not started |

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

What these numbers do not show yet:

- The Zoo so far covers container checks, persistence, network tools, inline interpreters, telemetry, toolchain tampering and deadline overruns. Credential-exfiltration samples are not in the Zoo yet, so the CRITICAL rules are covered by unit tests only.
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

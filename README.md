# RedHanded

**Make new code prove itself before your agent trusts it.**

Agents now install packages and skills nobody reviews. RedHanded sits between the agent and that code. It runs the code on a disposable machine baited with fake credentials and a fake internet that also answers HTTPS, first in gVisor and then in a Firecracker microVM with its own kernel. It answers three questions from what the code did:

- **What changed?** The new version runs next to the one before it. New domains, install scripts, credential reads and commands are the evidence.
- **What does it make the agent do?** A real agent uses a new skill on an ordinary task, near fake credentials. A skill can do harm through instructions alone, which a package scan never sees.
- **What do we go back to?** After a block, an agent tests older versions and opens the fix as a PR. It chooses what to check. Only the fixed rules can clear a version.

Built for the Vultr: Agent Rush Hackathon 2026, Challenge 1 "Blast Radius Zero".

**Try it:** <https://45-32-140-228.sslip.io> opens on recorded catches you can replay and check, and lets you run any npm package, compare two versions, or give a skill to the agent.

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
| VX1 Cloud Compute | One VM (`vx1-g-2c-8g-120s`, Debian 13, San Jose) runs the site, the queue, gVisor, Firecracker and the sinkhole. `/dev/kvm` is there from first boot, so each scan gets a microVM with its own kernel, without root. Median gVisor run 4.5 s, median microVM run 6.4 s |
| Serverless Inference | `deepseek-v4.1-flash-1017` drives the decoy agent and the repair agent with tool calling, reads package text for instructions aimed at AI agents, and writes the explanation beside each verdict. It never sets a verdict. The decoy agent reaches it through a gateway outside the sandbox that adds the real key and caps the calls, so the machine under attack holds only a fake key |
| Vector Store | Attack memory: the behaviour of 71 recorded real attacks, never their code. Search finds candidates, and a measured overlap check keeps only real matches, so an explanation can say which attack a package behaves like. It has no effect on the verdict |
| Account API | The spend guard reads the balance and pending charges every 10 minutes with a billing-only sub-user key. Vultr has no native spend alert, so if the reading goes stale or the limit is reached, scans stop |
| Firewall and Terraform | Ports 80 and 443 are open, SSH only from the admin address. One command builds it in any of the plan's 12 regions, and `terraform destroy` removes everything that bills |

Measured on a throwaway `vx1-g-4c-16g-240s` ($0.153/h) over the held-out run: 855 scans an hour, three at a time, or about $0.0002 of compute per scan, without inference.

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

### What the agents do on a real task

**Checking a package.** It resolves the name or lockfile change to exact bytes by sha512, plants fresh fake credentials, and runs install scripts and exports under a hard deadline, in gVisor and then a microVM. Fixed rules read the logs and the sinkhole capture from outside.

**Comparing versions.** It runs the version before as well and diffs the two records. The comparison can raise a verdict and never lower it. A new install script goes to review, or fails the check in strict mode.

**Checking a skill.** A real agent, driven by Vultr Serverless Inference, gets the skill and an ordinary task on a machine with a small project, its memory files, fake credentials and stub AI tools. Its work runs inside the sandbox, and its model calls go through the gateway. Rules built for an agent working normally read what happened: a credential sent somewhere it does not belong, a paste site, changed agent memory, another skill installed.

**Repairing.** The model picks the next tool: list older versions, run one, compare it, pin it. A pin is refused unless the rules returned CLEAN in this run, and a fixed walk finishes the job if the model fails. The Action then rewrites only the lockfile, with scripts off, opens the PR and posts the verdict on it.

Each replay in [`replays/`](replays) keeps a scan's report and sinkhole capture, plus the syscall lines that carry the story and the sha256 of the full log. Attack replays were recorded on a throwaway VX1 and contain no package code. Fake credentials are replaced by their names, because they are shaped like real ones and secret scanners cannot tell.

## How a verdict is reached

Evidence decides; the model only explains.

| Verdict | Triggered by |
|---|---|
| CRITICAL | A honeytoken appears in outbound traffic or a DNS name, or a stolen token is presented to the fake npm, GitHub or AWS endpoint |
| HIGH | Runs the machine's AI coding tool with its permission checks off; reads bait and attempts network access; sends this scan's unique machine name out; contacts a data-collection service; spawns a network tool anywhere; writes a persistence path; modifies the runtime toolchain; does something in the microVM that it hid from gVisor |
| REVIEW | Unknown network destinations, container checks, inline code run from code, package text that gives instructions to AI agents, incomplete scans, deadline kills |
| CLEAN | None of the above |

A package's declared lifecycle command, and npm's own build tooling (such as bundled node-gyp), are visible to any reviewer, so their form alone is not flagged; what they do still is. Loopback traffic is not network access. Each rule change bumps `RULES_VERSION`, so a cached verdict is never served under rules that did not make it.

## Eval

`redhanded eval` scans every sample in [`zoo/`](zoo) and every pinned package in [`evals/benign.txt`](evals/benign.txt), then applies [`evals/gate.json`](evals/gate.json). Verdicts are deterministic, so the gate is exact: a sample below the verdict its `expect.json` demands fails the run, and a benign package that would block a merge fails it.

Recorded runs are in [`evals/results`](evals/results).

### Real malware

Two random sets of 300 from [Datadog's public dataset](https://github.com/DataDog/malicious-software-packages-dataset) of malicious npm packages (Apache-2.0), with no overlap, set aside by a fixed seed and each run once, on a throwaway Vultr VM. A separate 100 were used for tuning and do not count. No sample is kept in this repo: only the evidence of a few scans, in [`replays/`](replays).

| Verdict | First run | Second run | Both |
|---|---|---|---|
| CRITICAL: seen stealing or using fake credentials | 39 | 49 | 88 |
| HIGH: blocks the merge | 100 | 85 | 185 |
| REVIEW: sent to a person | 29 | 34 | 63 |
| CLEAN: got through | 131 | 132 | 263 |

That is 273 blocked of 599 (46%). Of the 380 with an install script, 255 were blocked (67%). Of the 150 hijacked releases of real libraries, 89 were blocked (59%).

How to read these numbers:

- Some misses are limits of replaying old attacks: payloads that delete themselves or depend on downloads and packages that no longer exist, for example the axios payload `plain-crypto-js`, whose `setup.js` is absent from the dataset's copy. Others are real gaps: code that only fires on Windows, or only when called in a specific way. [`evals/real-malware.json`](evals/real-malware.json) sorts them by cause, automatically and approximately.
- The dataset leans toward what Datadog's own rules flag, so it is not a sample of all npm malware.
- Rules changed slightly between and after the runs: inline code alone and reading only `.npmrc` went to review, and git's sample hooks stopped counting. No blocked held-out result relied on these.
- The second tier found nothing the first had missed on these samples. The rule that flags what a package hid from gVisor has fired only on our own Zoo sample.

### What changed since the last version

For every hijacked release in those two runs with an earlier release still on npm, the version before it ran too (142 pairs).

| | One version alone | With the comparison |
|---|---|---|
| Flagged for a person or blocked | 86 (61%) | 108 (76%) |
| Blocked by default | 85 | 85 |
| Blocked in strict mode | | 107 (75%) |

On 75 ordinary consecutive releases from live npm, the comparison moved 0 verdicts and 0 added an install script. Strict mode's rule was written after seeing the hijack side, so its 107 is not a held-out figure. Legitimate packages do sometimes add install scripts, which is why it stays off by default.

### Real agent skills

Labels are [SkillSieve's](https://github.com/xiaohou521/skillsieve) human-reviewed index (MIT), with files from a public MIT fork of the ClawHub archive. 15 malicious and 15 benign were used for tuning. Results below are from the rest, with the agent run up to twice per skill.

| Set | Skills | Blocked | Review | Clean |
|---|---|---|---|---|
| Malicious, main campaign (one account) | 36 | 33 | 0 | 3 |
| Malicious, four other accounts | 4 | 0 | 0 | 4 |
| Benign, never used before | 117 | 9 | 41 | 67 |

How to read these numbers:

- The data is narrow. 50 of the 55 labelled malicious skills come from one account, so the campaign result does not predict other attackers. All four skills from other accounts got through, because the agent did nothing the rules recognise in its allowed steps.
- The paste-site rule came from reading a tuning sample of that same campaign, so its result there is optimistic.
- This is a second pass. The first held-out pass blocked 8 of 98 benign skills and sent 51 to a person, and blocked 34 of 36 in the main campaign. The false-alarm rules were then changed and measured on benign skills never used before. Review fell from 52% to about 35%, and false blocks stayed near 8%. Most of those are skills that write to the agent's memory on purpose, which is hard to tell apart from tampering, so a block on a skill is a reason to read it, not proof of malice. The malicious set is the same one, run again after the changes.
- A clean result means nothing bad happened in these runs. Agents vary from run to run, and a different agent may do something else.
- [MalSkillBench](https://github.com/lxyeternal/MalSkillBench) verified skills by running them through an agent in Docker before we did. We did not use its data, because its licence covers academic research only.

### False alarms on live npm

681 new npm releases, scanned as they were published. Under the current rules 6 were blocked (0.9%), and 6 of the 112 with an install script. Checked by hand, these are aggressive installers rather than confirmed malware: telemetry carrying the machine name, shell profile edits, downloads with curl, using a GitHub token without asking. Relaxing the rule for curl alone would remove 2 of the 6 and lose 29 of the 139 held-out catches, so it stays. No malware has been found this way so far.

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

Nothing to install, and the scan runs on the RedHanded host, never on the caller's machine. Tools: `check_package(name, version)`, `check_lockfile_change(new_lockfile, old_lockfile)`, `compare_versions(name, version)`, `find_safe_version(name, blocked_version)`, `check_skill(files)` and `get_scan_report(scan_id)`. Package text never appears in an answer, so an attacker's README cannot reach the next agent. [`/llms.txt`](src/redhanded/static/llms.txt) describes the HTTP API. `redhanded mcp` serves the same tools over stdio for your own sandbox host.

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
        with:
          repair: "true"    # after a block, open the fix as a PR (needs contents and pull-requests: write)
          strict: "false"   # "true" also fails on a release that adds an install script
```

A HIGH or CRITICAL verdict, or an answer that never arrives, fails the check. The job summary links to the evidence. Add it as a required check in branch protection to block the merge.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Safety

The Zoo samples imitate publicly documented attack behaviour. Their only targets are per-scan fake credentials and reserved `.invalid` domains, they are `"private": true`, and they are never published to npm.

## Built during the event

See [`BUILT_DURING_HACKATHON.md`](BUILT_DURING_HACKATHON.md).

## License

MIT. See [LICENSE](LICENSE).

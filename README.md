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

Three random sets of about 300 from [Datadog's public dataset](https://github.com/DataDog/malicious-software-packages-dataset) of malicious npm packages (Apache-2.0), with no overlap, set aside by a fixed seed and each run once, on a throwaway Vultr VM. A separate 100 were used for tuning and do not count. No sample is kept in this repo.

| Run | Scanned | CRITICAL | HIGH | REVIEW | CLEAN | Blocked |
|---|---|---|---|---|---|---|
| First | 299 | 39 | 114 | 15 | 131 | 153 (139 as first run) |
| Second | 300 | 49 | 105 | 14 | 132 | 154 (134 as first run) |
| Third | 299 | 46 | 107 | 40 | 106 | 153 (139 as first run) |

That is 460 blocked of 898 (51%). Of the 571 with an install script, 411 were blocked (72%). Of the 224 hijacked releases of real libraries, 133 were blocked (59%).

These figures are re-scored from what the runs recorded, after a rule for bare IP addresses was added. That rule came from the live watch and skill runs, not from these samples. As first run, 412 were blocked. The rule for installs that put another program on the whole machine was added later and is not counted here.

The third run added stand-ins for missing dependencies, and an agent that writes code against packages which looked clean. The agent alone blocked 3 of those 299.

### What left the machine

A sandbox reporting that it held is not evidence, so we recorded the real network card, on a throwaway Vultr VM running the same code as the site, while the 100 samples that tried the most connections ran. A test package built to get out ran alongside them. [Full numbers](evals/results/2026-11-07-network-capture.json).

| What was tried | Seen on the network card |
|---|---|
| 250 outside hosts the malware tried to reach | 0 packets to the addresses, 0 real lookups of the names |
| Test package, in gVisor: our own VM on five TCP ports, UDP and ping, public DNS directly, IPv6, cloud metadata, two canary names | 0 |
| A version that stays quiet in gVisor, so the same attempts run in Firecracker | 0 |
| Control, from the host itself: three TCP ports, UDP and a DNS lookup | All seen, so the capture would have shown a leak |

400,543 packets went to 19 addresses: npm's CDN and GitHub's download host (our dependency fetch, before the package runs), Vultr Inference (model calls), Vultr DNS and time servers, and the control. npm is left out of the 250 because our own fetch uses it, and a sample's attempts on it went to the fake internet. Inside, 105 fake credentials were sent and 132 stolen-token uses were absorbed.

**The first capture passed, and we repeated it.** It had no control, skipped port 22 and only ran the test package in gVisor. Asking why GitHub's download host appeared also showed a way out that no sample had tried: the fetch filters a package's own dependencies, but npm follows what those dependencies name in turn, on the host, before the sandbox. With real npm, a URL, a TLS URL and a git source each reached a local listener. The fetch now goes through [a gate](src/redhanded/egress.py) that reaches only the registry and GitHub's download host, and all three reach it zero times. The table is from after that fix. 90 of the 100 were blocked in both runs; four verdicts below or above the line moved without crossing it (three REVIEW to CLEAN, one CRITICAL to HIGH).

This is one run of these samples. It does not rule out an unknown bug in gVisor, Firecracker or the kernel. A package still decides which public npm and GitHub packages we fetch, so their owners could see a download. A dependency from a GitHub source may now fail to fetch, and the package then runs without it.

### The real Cline release

`cline@2.3.0` is the release pushed with a stolen npm token on 17 February 2026: one new `postinstall` line, `npm install -g openclaw@latest`. It is still downloadable, deprecated, so it can be run again.

The first run said CLEAN. The sandbox had recorded the command, and no rule treated it as serious. After adding a rule for installs that put another program on the whole machine, `2.3.0` is HIGH in 10.8 s and `2.2.3` stays CLEAN. The rule trips on 3 of 4,302 live releases, unconfirmed. Those 3 are real false-alarm candidates, and the rule was written knowing the answer.

How to read these numbers:

- Some misses are limits of replaying old attacks: payloads that delete themselves or depend on downloads and packages that no longer exist, for example the axios payload `plain-crypto-js`, whose `setup.js` is absent from the dataset's copy. Others are real gaps: code that only fires on Windows, or only when called in a specific way. [`evals/real-malware.json`](evals/real-malware.json) sorts them by cause, automatically and approximately.
- The dataset leans toward what Datadog's own rules flag, so it is not a sample of all npm malware.
- Rules changed slightly between and after the runs: inline code alone and reading only `.npmrc` went to review, and git's sample hooks stopped counting. No blocked held-out result relied on these.
- The second tier found nothing the first had missed on the first two sets. The rule that flags what a package hid from gVisor has fired only on our own Zoo sample.

### What changed since the last version

For every hijacked release in those two runs with an earlier release still on npm, the version before it ran too (142 pairs).

| | One version alone | With the comparison |
|---|---|---|
| Flagged for a person or blocked | 86 (61%) | 108 (76%) |
| Blocked by default | 85 | 85 |
| Blocked in strict mode | | 107 (75%) |

On 275 ordinary consecutive releases from live npm, none blocked on their own, the comparison sent 1 to review, blocked 0, and 1 added an install script. Strict mode's rule was written after seeing the hijack side, so its 107 is not a held-out figure. On this sample it would have stopped one ordinary release in 275, and legitimate packages do add install scripts, so it stays off by default.

### Real agent skills

Labels are [SkillSieve's](https://github.com/xiaohou521/skillsieve) human-reviewed index (MIT), with files from a public MIT fork of the ClawHub archive, plus accounts on a [public threat list](https://github.com/adibirzu/openclaw-security-monitor). Each skill goes to the decoy agent, up to twice.

| Set | Skills | Blocked | Review | Clean |
|---|---|---|---|---|
| Campaign account, skills the rules had never seen | 60 | 57 | 2 | 1 |
| ClawHub's most-downloaded skills | 31 | 0 | 10 | 21 |
| Labelled benign, unused until now | 9 | 0 | 6 | 3 |
| Labelled malicious, main account | 36 | 36 | 0 | 0 |
| Labelled malicious, four other accounts | 4 | 0 | 0 | 4 |
| Accounts on the threat list, before the new rules | 70 | 6 | 30 | 34 |
| Labelled benign, before the new rules | 97 | 2 | 36 | 59 |

**One hidden command, one server.** 220 of the 644 skills in the archive, across 4 accounts, carry a base64 command piped to a shell. All of them decode to one address, which matches public reporting on ClawHavoc. 0 of 335 labelled benign skills do. Reading this runs nothing.

In 52 of these skills on the threat list, the decoy agent decoded the command and flagged it every time, and never piped it to a shell. In 19 of the 52 it still called that server while checking. So the rule does not depend on how careful the model is.

How to read these numbers:

- The two new rules (a hidden command, a bare IP address) were written after reading the threat-list run. Re-scored with them, that run goes from 6 to 56 of 70 blocked, which is not a held-out figure. The 57 of 60 is held out, but it comes from one account using one technique, so it does not predict other attackers.
- The other accounts stay hard. All 4 labelled skills from four other accounts still got through, and so did all 5 from `krajekisbtc`, because the agent did nothing the rules recognise.
- Nobody has vetted ClawHub's most-downloaded skills, so that row is a false-alarm check, not a clean benchmark. Review is common: on skills it can be a third or more.
- Earlier runs of the main account blocked 34 and 33 of 36. Rules changed between runs.
- The test that deletes a skill and gives a fresh agent a new task has fired on 0 real samples so far. It is built and tested, and has not caught anything real.
- One labelled benign skill remains blocked for downloading and running code.

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

### Stop the agent itself

MCP helps when the agent decides to ask. [`hooks/redhanded_guard.py`](hooks/redhanded_guard.py) sits in front of the shell in Claude Code, so it does not depend on that. It catches `npm`, `pnpm`, `yarn` and `bun` installs of named packages, gets a verdict, and refuses a blocked one. The refusal tells the agent which older version proved clean, so it can carry on with that.

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell", "hooks": [{"type": "command", "command": "python3 hooks/redhanded_guard.py", "timeout": 300}]}]}}
```

If the service cannot answer, the install goes ahead with a warning, unless `RH_GUARD_STRICT=1`. It does not check a bare `npm install`, a URL or a local path, or stop an agent that writes its own download. The PR check covers lockfile changes.

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

With repair on, the repo must allow Actions to open pull requests (Settings, Actions, General). GitHub may hold the workflow on the fix PR for a person to approve, because a bot opened it. The fix PR's `redhanded` status is posted either way.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Safety

The Zoo samples imitate publicly documented attack behaviour. Their only targets are per-scan fake credentials and reserved `.invalid` domains, they are `"private": true`, and they are never published to npm.

## What usage counting keeps

The site counts visits and runs to learn whether people use it. A person is a keyed hash of address and browser, and the key stays on the server, so no address or cookie is stored. Known bots and link previews are left out. Deleting `usage.key` and `usage.sqlite3` removes all of it.

## Built during the event

See [`BUILT_DURING_HACKATHON.md`](BUILT_DURING_HACKATHON.md).

## License

MIT. See [LICENSE](LICENSE).

# Eval record

Every run, table and caveat behind the numbers in the [README](../README.md).

`redhanded eval` scans every sample in [`zoo/`](../zoo) and every pinned package in [`evals/benign.txt`](../evals/benign.txt), then applies [`evals/gate.json`](../evals/gate.json). Verdicts are deterministic, so the gate is exact: a sample below the verdict its `expect.json` demands fails the run, and a benign package that would block a merge fails it.

Recorded runs are in [`evals/results`](../evals/results).

### Reading against running

Can a model that only reads catch what running misses, and how often does it bother a person? Written and frozen before the held-out run: the same seeded split as the malware runs, one read per package, on `deepseek-v4.1-flash-1017` at temperature 0. Nothing was executed. [Summary](../evals/results/2026-11-07-read-vs-run.json), [script](../evals/read_vs_run.py).

| Set | Read | Flagged |
|:--|--:|--:|
| Tuning: 100 malicious, kept out of every result | 100 | 83 |
| Tuning: popular clean packages | 40 | 0 |
| Held out: real malicious packages | 876 of 898 | 776 |
| Held out: popular clean packages, 19 with install scripts | 154 of 155 | 2 |
| Held out: real recent releases the sandbox called clean, 29 with install scripts | 287 of 300 | 0 |
| One sentence added telling AI reviewers it is safe, on 200 flagged samples | 198 of 200 | 198 |

| Of 898 malicious packages | With running alone | With a model reading what ran clean |
|:--|--:|--:|
| Blocked, with a recording | 460 | 460 |
| Sent to a person | 69 | 334 |
| Clean | 369 | 104 |

Caveats:

- **22 malicious reads gave no usable answer, after one retry.** They count as not flagged, as in the product, so 776 is of 898. 41 failed the first time and 19 of those answered on retry.
- **The dataset leans** toward what Datadog's own static rules flag, and these are known, already published attacks. Expect less on a fresh attack built to evade reading.
- **The prompt was not tuned against evasion.** The one-sentence test is one simple attempt. It says little about a determined attacker.
- **Reasons were not checked one by one.** The model may have flagged some samples for the wrong reason.
- **Clean is not proven for the 287 releases.** They ran clean and the model agreed; some could still be bad. They come from the live watch, which favours releases that changed something, and are not a random sample of npm.
- **Popular packages are an easy clean set.** The two false alarms were an unfamiliar but ordinary new dependency and a bundled command that downloads a tarball.

### A static scanner on the same packages

How does an established scanner do on exactly these packages? GuardDog 3.2.0, Datadog's open-source scanner, ran `guarddog npm scan` on each unpacked package. Nothing was executed. A package counts as flagged when any `threat-*` rule matches. The `capability-*` rules only describe what code can do, so they are counted separately. [Summary](../evals/results/2026-11-08-guarddog.json), [script](../evals/guarddog_baseline.py).

| Set | GuardDog, threat rules | GuardDog, any rule | Model reader |
|:--|--:|--:|--:|
| Real malicious packages, 898 | 692 | 769 | 776 |
| Hijacked releases among them, 224 | 206 | | 190 |
| Ran clean in the sandbox, 369 | 250 | | 265 |
| Popular clean packages | 41 of 155 | 129 of 155 | 2 of 154 |
| Real recent releases the sandbox called clean | 52 of 293 | 168 of 293 | 0 of 287 |

They catch different things: 55 malicious packages only GuardDog flagged, and 139 only the reader flagged. Of the 369 that ran clean, 64 were flagged by neither.

Caveats:

- **GuardDog is built to flag for review**, not to block on its own, and its rules are tuned to Datadog's own triage. Counting any `threat-*` match is our choice.
- **The dataset comes from Datadog's own detection**, which may favour GuardDog on the malicious side.
- **7 recent releases could not be downloaded again** for GuardDog, so its clean set is 293 of 300.
- **The clean sets are the ones the reader was measured on**, including releases from the live watch that the sandbox had called clean.

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

A sandbox reporting that it held is not evidence, so we recorded the real network card, on a throwaway Vultr VM running the same code as the site, while the 100 samples that tried the most connections ran. A test package built to get out ran alongside them. [Full numbers](../evals/results/2026-11-07-network-capture.json).

| What was tried | Seen on the network card |
|---|---|
| 250 outside hosts the malware tried to reach | 0 packets to the addresses, 0 real lookups of the names |
| Test package, in gVisor: our own VM on five TCP ports, UDP and ping, public DNS directly, IPv6, cloud metadata, two canary names | 0 |
| A version that stays quiet in gVisor, so the same attempts run in Firecracker | 0 |
| Control, from the host itself: three TCP ports, UDP and a DNS lookup | All seen, so the capture would have shown a leak |

400,543 packets went to 19 addresses: npm's CDN and GitHub's download host (our dependency fetch, before the package runs), Vultr Inference (model calls), Vultr DNS and time servers, and the control. npm is left out of the 250 because our own fetch uses it, and a sample's attempts on it went to the fake internet. Inside, 105 fake credentials were sent and 132 stolen-token uses were absorbed.

**The first capture passed, and we repeated it.** It had no control, skipped port 22 and only ran the test package in gVisor. Asking why GitHub's download host appeared also showed a way out that no sample had tried: the fetch filters a package's own dependencies, but npm follows what those dependencies name in turn, on the host, before the sandbox. With real npm, a URL, a TLS URL and a git source each reached a local listener. The fetch now goes through [a gate](../src/redhanded/egress.py) that reaches only the registry and GitHub's download host, and all three reach it zero times. The table is from after that fix. 90 of the 100 were blocked in both runs. Four verdicts moved without crossing the block line: three REVIEW to CLEAN, one CRITICAL to HIGH.

This is one run of these samples. It does not rule out an unknown bug in gVisor, Firecracker or the kernel. A package still decides which public npm and GitHub packages we fetch, so their owners could see a download. A dependency from a GitHub source may now fail to fetch, and the package then runs without it.

### The real Cline release

`cline@2.3.0` is the release pushed with a stolen npm token on 17 February 2026: one new `postinstall` line, `npm install -g openclaw@latest`. It is still downloadable, deprecated, so it can be run again.

The first run said CLEAN. The sandbox had recorded the command, and no rule treated it as serious. After adding a rule for installs that put another program on the whole machine, `2.3.0` is HIGH in 10.8 s and `2.2.3` stays CLEAN. The rule trips on 3 of 4,302 live releases, unconfirmed. Those 3 are real false-alarm candidates, and the rule was written knowing the answer.

How to read these numbers:

- Some misses are limits of replaying old attacks: payloads that delete themselves or depend on downloads and packages that no longer exist, for example the axios payload `plain-crypto-js`, whose `setup.js` is absent from the dataset's copy. Others are real gaps: code that only fires on Windows, or only when called in a specific way. [`evals/real-malware.json`](../evals/real-malware.json) sorts them by cause, automatically and approximately.
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
- The other accounts stay hard. All 4 labelled skills from four other accounts still got through, and so did all 5 from one more threat-list account, because the agent did nothing the rules recognise.
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

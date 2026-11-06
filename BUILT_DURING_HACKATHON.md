# What was built during the event

Agent Rush kicked off on 3 November 2026. The first commit here is from 4 November, and everything in this repo was written after kickoff. `git log` has the full record.

| Day | Built |
|---|---|
| 4 Nov | Honeytokens and the matcher, verdict rules, spend guard, gVisor runner, sinkhole, eval gate, Zoo, MCP server, verdict cache, CI gate |
| 6 Nov, morning | Demo on Vultr by Terraform, Serverless Inference, Firecracker microVM tier on VX1, hosted MCP, PR check, agent-text check |
| 6 Nov, afternoon | First run on real malware, and what it forced: a realistic sandbox image, fetched dependencies, exercising exports, machine-name bait, reading HTTPS. Held-out run. Attack memory on Vector Store. Live scanning of new npm releases |
| 6 Nov, night | Version comparison, repair agent and fix PRs, decoy agent for skills with the model gateway, stub AI tool bait, second held-out run, real skill evaluation |

Third-party parts: gVisor, Firecracker and its guest kernel, Node.js and Debian images, the Geist fonts (OFL), and SkillSieve's labels (MIT), a public MIT fork of the ClawHub archive for evaluation only, [Datadog's malicious package dataset](https://github.com/DataDog/malicious-software-packages-dataset) for testing (Apache-2.0). No sample from it is in this repo.

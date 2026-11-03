# RedHanded

**Before you merge, catch it red-handed.**

RedHanded is a pre-merge agent for npm dependency changes. For every pull request that adds or updates a dependency, whether Dependabot, a person or a coding agent wrote it, RedHanded runs the changed packages in a disposable Vultr sandbox baited with fake credentials and a fake internet. If the code reaches for the bait, the merge is blocked and the evidence is attached to the PR.

Built for the Vultr: Agent Rush Hackathon 2026, Challenge 1 "Blast Radius Zero".

## Status

Work in progress during the build week (3–8 Nov 2026). This section states what works today, not what is planned.

| Part | State |
|---|---|
| Per-scan honeytokens and bait files | Done, tested |
| Honeytoken matcher (raw, base64 at any alignment, base64url, hex, URL encoding, gzip, zlib, raw deflate, nested layers, DNS labels) | Done, tested |
| Deterministic verdict rules; model can raise to REVIEW, never lower | Done, tested |
| Lockfile diff (package-lock v2/v3) | Done, tested |
| Sandbox runner (gVisor), sinkhole, host-side trace | Next |
| Vultr infrastructure (Terraform, cloud-init), spend guard | Next |
| Agent loop on Vultr Serverless Inference, web UI, GitHub App | Planned |

## How a verdict is reached

Evidence decides; the model only explains.

| Verdict | Triggered by |
|---|---|
| CRITICAL | A honeytoken appears in outbound traffic, or a stolen token is used against the fake npm or GitHub API |
| HIGH | Reads bait and attempts network access; spawns a network tool or inline interpreter from an install script; writes a persistence path |
| REVIEW | Unknown network destinations, container checks, probe flags, incomplete scans, deadline kills |
| CLEAN | None of the above |

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Safety

The benchmark samples in this repository imitate publicly documented attack behaviour. Their only targets are per-scan fake credentials and reserved `.invalid` domains, and they are never published to npm.

## License

MIT. See [LICENSE](LICENSE).

# Security policy

RedHanded runs untrusted code on purpose, so a report here matters.

**Please report privately** through a [GitHub security advisory](https://github.com/shanurwan/redhanded/security/advisories/new), not a public issue.

Most useful to hear about:

- A way out of the gVisor or microVM sandbox, or past the sinkhole or the dependency fetch gate
- A package or skill that gets a real key, or reaches the host, the gateway or the model outside its fenced role
- A way to make a malicious package come back CLEAN by something other than behaving well, such as tampering with the evidence
- A path where the PR check passes when it should fail

Real malware samples are welcome on the hosted instance, as a package name or an upload. Please do not run a denial of service against it, or use it to attack others. It is a demo on one VM, and its sandbox holds only fake credentials.

Missing a piece of malware is a detection gap and not a vulnerability. Those are welcome as ordinary issues, with the package name and version.

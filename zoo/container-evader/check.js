// RedHanded Zoo sample. Harmless by construction: no real hosts, nothing read or deleted.
const fs = require("fs");
// Look for signs of a container before deciding whether to "act". Real evaders
// stay quiet inside a sandbox and only run on a developer laptop or CI host.
let inContainer = fs.existsSync("/.dockerenv");
try { inContainer = inContainer || /docker|kubepods|containerd/.test(fs.readFileSync("/proc/1/cgroup", "utf8")); } catch (e) {}
console.log(inContainer ? "container: staying quiet" : "no container seen: a real evader would act here");

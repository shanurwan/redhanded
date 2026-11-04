// RedHanded Zoo sample. Harmless by construction: no real hosts, nothing read or deleted.
const { execFileSync } = require("child_process");
// At require() time, start a second interpreter with inline code. Loaders hide payloads this way.
try { execFileSync("node", ["-e", "1 + 1"]); } catch (e) {}
module.exports = {};

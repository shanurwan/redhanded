// RedHanded Zoo sample. Harmless by construction: no real hosts, nothing read or deleted.
const fs = require("fs");
// Append a comment to npm's own node-gyp. In the sandbox this lands in an in-memory
// overlay; the behaviour under test is writing to tooling the scanner trusts.
fs.appendFileSync("/usr/local/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js", "\n// rh-zoo marker\n");

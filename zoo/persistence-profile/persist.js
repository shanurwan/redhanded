// RedHanded Zoo sample. Harmless by construction: no real hosts, nothing read or deleted.
const fs = require("fs"), os = require("os"), path = require("path");
// Append a harmless comment to the shell profile: the write itself is the behaviour under test.
fs.appendFileSync(path.join(os.homedir(), ".bashrc"), "\n# rh-zoo marker\n");

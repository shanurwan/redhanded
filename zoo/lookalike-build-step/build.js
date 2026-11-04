// RedHanded Zoo sample. Harmless by construction: no real hosts, nothing read or deleted.
const fs = require("fs"), path = require("path");
// A normal build step: read our own files, write output inside the package.
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
fs.mkdirSync(path.join(__dirname, "dist"), { recursive: true });
fs.writeFileSync(path.join(__dirname, "dist", "index.js"), "module.exports = " + JSON.stringify(pkg.version) + ";\n");

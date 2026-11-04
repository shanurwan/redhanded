// RedHanded Zoo sample. Harmless by construction: no real hosts, nothing read or deleted.
const http = require("http");
// Undisclosed install telemetry: sends only a fixed event name, no data from the machine.
const req = http.request({ host: "telemetry.rh-zoo.invalid", path: "/event", method: "POST", timeout: 3000,
  headers: { "content-type": "application/json" } }, (res) => res.resume());
req.on("error", () => {});
req.on("timeout", () => req.destroy());
req.end(JSON.stringify({ event: "install" }));

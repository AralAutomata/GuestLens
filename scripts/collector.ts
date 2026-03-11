import { startCollectorServer } from "@/lib/security/collector-server";
import { getCollectorSocketPath } from "@/lib/security/state";

const server = startCollectorServer();
const socketPath = getCollectorSocketPath();

console.log(`GuestLens collector listening on ${socketPath}`);

function shutdown() {
  server.close(() => {
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

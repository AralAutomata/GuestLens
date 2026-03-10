import { startCollectorServer } from "@/lib/security/collector-server";
import { getCollectorSocketPath } from "@/lib/security/state";

const server = startCollectorServer();
const socketPath = getCollectorSocketPath();

console.log(`InsideJobVM collector listening on ${socketPath}`);

function shutdown() {
  server.close(() => {
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

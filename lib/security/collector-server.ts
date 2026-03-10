import { chmodSync, existsSync, unlinkSync } from "node:fs";
import net from "node:net";

import { collectSnapshot } from "@/lib/security/collector";
import { getCollectorSocketPath } from "@/lib/security/state";

interface CollectorRequest {
  id: string;
  action: "scan" | "ping";
}

interface CollectorResponse {
  id: string;
  ok: boolean;
  error?: string;
  snapshot?: ReturnType<typeof collectSnapshot>;
}

export function startCollectorServer(): net.Server {
  const socketPath = getCollectorSocketPath();
  if (existsSync(socketPath)) {
    unlinkSync(socketPath);
  }

  const server = net.createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (!buffer.includes("\n")) {
        return;
      }

      const line = buffer.trim();
      buffer = "";

      try {
        const request = JSON.parse(line) as CollectorRequest;
        const response: CollectorResponse =
          request.action === "ping"
            ? { id: request.id, ok: true }
            : { id: request.id, ok: true, snapshot: collectSnapshot() };
        socket.write(`${JSON.stringify(response)}\n`);
      } catch (error) {
        socket.write(
          `${JSON.stringify({
            id: "unknown",
            ok: false,
            error: error instanceof Error ? error.message : "collector request failed"
          } satisfies CollectorResponse)}\n`
        );
      } finally {
        socket.end();
      }
    });
  });

  server.listen(socketPath, () => {
    chmodSync(socketPath, 0o600);
  });

  return server;
}


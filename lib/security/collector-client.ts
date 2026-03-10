import net from "node:net";

import { getCollectorSocketPath } from "@/lib/security/state";
import type { ScanSnapshot } from "@/lib/types";

interface CollectorResponse {
  id: string;
  ok: boolean;
  error?: string;
  snapshot?: ScanSnapshot;
}

export async function requestGuestScan(): Promise<ScanSnapshot> {
  const socketPath = getCollectorSocketPath();

  return await new Promise<ScanSnapshot>((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let buffer = "";

    socket.on("connect", () => {
      socket.write(`${JSON.stringify({ id: crypto.randomUUID(), action: "scan" })}\n`);
    });

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (!buffer.includes("\n")) {
        return;
      }
      socket.end();
      try {
        const response = JSON.parse(buffer.trim()) as CollectorResponse;
        if (!response.ok || !response.snapshot) {
          reject(new Error(response.error ?? "collector returned no snapshot"));
          return;
        }
        resolve(response.snapshot);
      } catch (error) {
        reject(error);
      }
    });

    socket.on("error", (error) => {
      reject(
        new Error(
          `Collector socket unavailable at ${socketPath}. Start the collector with 'bun run collector' or use 'bun run dev'. ${error.message}`
        )
      );
    });
  });
}


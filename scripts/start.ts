import { spawn } from "node:child_process";

const host = process.env.HOST ?? "127.0.0.1";
const port = process.env.PORT ?? "3000";

function start(name: string, args: string[]) {
  const child = spawn("bun", args, {
    stdio: "inherit",
    env: process.env
  });

  child.on("exit", (code) => {
    if (code && code !== 0) {
      console.error(`${name} exited with code ${code}`);
      process.exit(code);
    }
  });

  return child;
}

const collector = start("collector", ["run", "collector"]);
const web = start("web", ["x", "next", "start", "--hostname", host, "--port", port]);

function shutdown() {
  collector.kill("SIGTERM");
  web.kill("SIGTERM");
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

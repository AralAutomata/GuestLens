import { chmodSync, existsSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const APP_DIR = "hostguard-linux";

function ensurePrivateDir(dirPath: string): string {
  if (!existsSync(dirPath)) {
    mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  }
  chmodSync(dirPath, 0o700);
  return dirPath;
}

function resolveStateDirPath(): string {
  const configured = process.env.HOSTGUARD_STATE_DIR;
  if (configured) {
    return configured;
  }

  const xdg = process.env.XDG_STATE_HOME;
  const base = xdg ? xdg : path.join(os.homedir(), ".local", "state");
  return path.join(base, APP_DIR);
}

export function getStateDir(): string {
  return ensurePrivateDir(resolveStateDirPath());
}

export function getRuntimeDir(): string {
  const configured = process.env.HOSTGUARD_RUNTIME_DIR;
  if (configured) {
    return ensurePrivateDir(configured);
  }

  const xdgRuntime = process.env.XDG_RUNTIME_DIR;
  if (xdgRuntime) {
    return ensurePrivateDir(path.join(xdgRuntime, APP_DIR));
  }

  return ensurePrivateDir(path.join("/tmp", `${APP_DIR}-${process.getuid?.() ?? 0}`));
}

export function getDatabasePath(): string {
  return path.join(getStateDir(), "hostguard-linux.db");
}

export function getCollectorSocketPath(): string {
  return path.join(getRuntimeDir(), "collector.sock");
}

export function getImportedAdvisoryPath(create = true): string {
  return path.join(create ? getStateDir() : resolveStateDirPath(), "advisories.bundle.json");
}

export function getBundledAdvisoryPath(): string {
  return path.join(process.cwd(), "data", "advisories", "sample-bundle.json");
}

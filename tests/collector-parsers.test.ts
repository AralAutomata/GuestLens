import { describe, expect, test } from "bun:test";

import { isLoopbackHost, detectDistroFamily, looksLikeLibvirtNatGateway } from "../lib/security/collector";
import type { RouteRecord } from "../lib/types";

describe("isLoopbackHost", () => {
  test("127.0.0.1 is loopback", () => {
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
  });

  test("127.0.0.2 is loopback", () => {
    expect(isLoopbackHost("127.0.0.2")).toBe(true);
  });

  test("::1 is loopback", () => {
    expect(isLoopbackHost("::1")).toBe(true);
  });

  test("[::1] is loopback", () => {
    expect(isLoopbackHost("[::1]")).toBe(true);
  });

  test("localhost is loopback", () => {
    expect(isLoopbackHost("localhost")).toBe(true);
  });

  test("0:0:0:0:0:0:0:1 is loopback", () => {
    expect(isLoopbackHost("0:0:0:0:0:0:0:1")).toBe(true);
  });

  test("LOCALHOST is loopback (case-insensitive)", () => {
    expect(isLoopbackHost("LOCALHOST")).toBe(true);
  });

  test("::1%eth0 is loopback (scoped)", () => {
    expect(isLoopbackHost("::1%eth0")).toBe(true);
  });

  test("192.168.1.1 is not loopback", () => {
    expect(isLoopbackHost("192.168.1.1")).toBe(false);
  });

  test("0.0.0.0 is not loopback", () => {
    expect(isLoopbackHost("0.0.0.0")).toBe(false);
  });

  test("10.0.2.2 is not loopback", () => {
    expect(isLoopbackHost("10.0.2.2")).toBe(false);
  });

  // Bug 4: empty string should return false, not true
  test("empty string is not loopback", () => {
    expect(isLoopbackHost("")).toBe(false);
  });
});

describe("detectDistroFamily", () => {
  test("Ubuntu 24.04 LTS → ubuntu", () => {
    expect(detectDistroFamily("Ubuntu 24.04 LTS")).toBe("ubuntu");
  });

  test("Debian GNU/Linux 12 → debian", () => {
    expect(detectDistroFamily("Debian GNU/Linux 12")).toBe("debian");
  });

  test("Rocky Linux 9.3 → rhel", () => {
    expect(detectDistroFamily("Rocky Linux 9.3")).toBe("rhel");
  });

  test("Fedora Linux 41 → rhel", () => {
    expect(detectDistroFamily("Fedora Linux 41")).toBe("rhel");
  });

  test("AlmaLinux 9.3 → rhel", () => {
    expect(detectDistroFamily("AlmaLinux 9.3")).toBe("rhel");
  });

  test("Red Hat Enterprise Linux 9 → rhel", () => {
    expect(detectDistroFamily("Red Hat Enterprise Linux 9")).toBe("rhel");
  });

  // Bug 2: CentOS is missing from RHEL family detection
  test("CentOS Stream 9 → rhel", () => {
    expect(detectDistroFamily("CentOS Stream 9")).toBe("rhel");
  });

  test("CentOS Linux 7 → rhel", () => {
    expect(detectDistroFamily("CentOS Linux 7")).toBe("rhel");
  });

  test("Arch Linux → arch", () => {
    expect(detectDistroFamily("Arch Linux")).toBe("arch");
  });

  test("NixOS → unknown", () => {
    expect(detectDistroFamily("NixOS 24.05")).toBe("unknown");
  });

  test("empty string → unknown", () => {
    expect(detectDistroFamily("")).toBe("unknown");
  });
});

function route(overrides: Partial<RouteRecord> & { raw: string; destination: string }): RouteRecord {
  return {
    via: undefined,
    device: "eth0",
    scope: "default" as RouteRecord["scope"],
    observedAt: "2026-03-10T12:00:00.000Z",
    collectedFrom: "ip route show",
    ...overrides
  };
}

describe("looksLikeLibvirtNatGateway", () => {
  test("canonical 192.168.122.1 is recognized", () => {
    const defaultRoute = route({ raw: "default via 192.168.122.1 dev virbr0", destination: "default", via: "192.168.122.1", device: "virbr0" });
    expect(looksLikeLibvirtNatGateway([], defaultRoute)).toBe(true);
  });

  test("virbr device with non-default gateway is recognized", () => {
    const defaultRoute = route({ raw: "default via 10.0.0.1 dev virbr1", destination: "default", via: "10.0.0.1", device: "virbr1" });
    expect(looksLikeLibvirtNatGateway([], defaultRoute)).toBe(true);
  });

  test("br0 bridge device is recognized", () => {
    const defaultRoute = route({ raw: "default via 192.168.100.1 dev br0", destination: "default", via: "192.168.100.1", device: "br0" });
    expect(looksLikeLibvirtNatGateway([], defaultRoute)).toBe(true);
  });

  test("bridge0 device is recognized", () => {
    const defaultRoute = route({ raw: "default via 192.168.100.1 dev bridge0", destination: "default", via: "192.168.100.1", device: "bridge0" });
    expect(looksLikeLibvirtNatGateway([], defaultRoute)).toBe(true);
  });

  test("eth0 with subnet route and gateway ending in .1 is recognized", () => {
    const defaultRoute = route({ raw: "default via 10.0.0.1 dev eth0", destination: "default", via: "10.0.0.1", device: "eth0" });
    const subnetRoute = route({ raw: "10.0.0.0/24 dev eth0", destination: "10.0.0.0/24", device: "eth0", scope: "local-subnet" });
    expect(looksLikeLibvirtNatGateway([subnetRoute], defaultRoute)).toBe(true);
  });

  test("regular eth0 without subnet route is not recognized", () => {
    const defaultRoute = route({ raw: "default via 10.0.0.1 dev eth0", destination: "default", via: "10.0.0.1", device: "eth0" });
    expect(looksLikeLibvirtNatGateway([], defaultRoute)).toBe(false);
  });

  test("no default route returns false", () => {
    expect(looksLikeLibvirtNatGateway([])).toBe(false);
  });

  test("default route without via returns false", () => {
    const defaultRoute = route({ raw: "default dev eth0", destination: "default", device: "eth0" });
    expect(looksLikeLibvirtNatGateway([], defaultRoute)).toBe(false);
  });
});

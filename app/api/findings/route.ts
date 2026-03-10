import { NextResponse } from "next/server";

import { getLatestStoredScan } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const latest = getLatestStoredScan();
  return NextResponse.json({
    scanId: latest?.scanId ?? null,
    profile: latest?.profile ?? null,
    findings: latest?.findings ?? [],
    groups: latest?.groups ?? [],
    delta: latest?.delta ?? null
  });
}

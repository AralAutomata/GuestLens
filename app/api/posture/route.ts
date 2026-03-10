import { NextResponse } from "next/server";

import { getLatestStoredScan } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const latest = getLatestStoredScan();
  return NextResponse.json({
    posture: latest?.posture ?? null,
    scanId: latest?.scanId ?? null,
    collectedAt: latest?.snapshot.collectedAt ?? null,
    profile: latest?.profile ?? null,
    delta: latest?.delta ?? null
  });
}

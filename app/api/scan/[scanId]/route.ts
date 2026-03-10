import { NextResponse } from "next/server";

import { getStoredScan } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_request: Request, context: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await context.params;
  const scan = getStoredScan(scanId);
  if (!scan) {
    return NextResponse.json({ error: "scan not found" }, { status: 404 });
  }

  return NextResponse.json(scan);
}

import { NextResponse } from "next/server";

import { runFullScan } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST() {
  try {
    const scan = await runFullScan();
    return NextResponse.json(scan);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "scan failed" },
      { status: 503 }
    );
  }
}


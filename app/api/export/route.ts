import { NextResponse } from "next/server";

import { exportSanitizedScan } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get("scanId");
  const format = searchParams.get("format") ?? "json";
  if (format !== "json") {
    return NextResponse.json({ error: "only json export is supported" }, { status: 400 });
  }

  const exported = exportSanitizedScan(scanId);
  if (!exported) {
    return NextResponse.json({ error: "scan not found" }, { status: 404 });
  }

  return NextResponse.json(exported, {
    headers: {
      "Content-Disposition": `attachment; filename="insidejobvm-${exported.scanId.slice(0, 8)}.json"`
    }
  });
}

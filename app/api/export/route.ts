import { NextResponse } from "next/server";

import { exportHtmlReport, exportSanitizedScan } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get("scanId");
  const format = searchParams.get("format") ?? "json";
  const includeSuppressed = searchParams.get("includeSuppressed") !== "false";
  if (format === "html") {
    const exported = exportHtmlReport(scanId, includeSuppressed);
    if (!exported) {
      return NextResponse.json({ error: "scan not found" }, { status: 404 });
    }

    return new NextResponse(exported, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": `attachment; filename="hostguard-linux-${scanId?.slice(0, 8) ?? "latest"}.html"`
      }
    });
  }

  if (format !== "json") {
    return NextResponse.json({ error: "only json and html export are supported" }, { status: 400 });
  }

  const exported = exportSanitizedScan(scanId, includeSuppressed);
  if (!exported) {
    return NextResponse.json({ error: "scan not found" }, { status: 404 });
  }

  return NextResponse.json(exported, {
    headers: {
      "Content-Disposition": `attachment; filename="hostguard-linux-${exported.scanId.slice(0, 8)}.json"`
    }
  });
}

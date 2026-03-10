import { NextResponse } from "next/server";

import { getStoredDiff } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const from = searchParams.get("from");
  const to = searchParams.get("to");
  const diff = getStoredDiff(from, to);

  if (!diff) {
    return NextResponse.json({ error: "diff not available" }, { status: 404 });
  }

  return NextResponse.json({ diff });
}

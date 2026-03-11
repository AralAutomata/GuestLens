import { NextResponse } from "next/server";

import { createSuppression, getSuppressionState, removeSuppression } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({
    suppressions: getSuppressionState()
  });
}

export async function POST(request: Request) {
  const body = (await request.json()) as {
    scope?: "rule" | "fingerprint";
    matchValue?: string;
    reason?: string;
    author?: string;
    expiresAt?: string | null;
  };

  if (!body.scope || !body.matchValue) {
    return NextResponse.json({ error: "scope and matchValue are required" }, { status: 400 });
  }

  const suppression = createSuppression({
    scope: body.scope,
    matchValue: body.matchValue,
    reason: body.reason,
    author: body.author,
    expiresAt: body.expiresAt ?? null
  });

  return NextResponse.json({ suppression }, { status: 201 });
}

export async function DELETE(request: Request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get("id");
  if (!id) {
    return NextResponse.json({ error: "suppression id is required" }, { status: 400 });
  }

  removeSuppression(id);
  return NextResponse.json({ ok: true });
}

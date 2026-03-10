import { NextRequest, NextResponse } from "next/server";

import { runRemediationByActionId } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ actionId: string }> }
) {
  try {
    const { actionId } = await context.params;
    const body = (await request.json().catch(() => ({ execute: false }))) as { execute?: boolean };
    const result = await runRemediationByActionId(actionId, Boolean(body.execute));
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "remediation failed" },
      { status: 400 }
    );
  }
}


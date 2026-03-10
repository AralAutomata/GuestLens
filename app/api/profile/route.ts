import { NextResponse } from "next/server";

import { isPolicyProfile } from "@/lib/security/profiles";
import { updateActiveProfile } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const body = (await request.json().catch(() => null)) as { profile?: string } | null;
  if (!body?.profile || !isPolicyProfile(body.profile)) {
    return NextResponse.json({ error: "invalid profile" }, { status: 400 });
  }

  return NextResponse.json(updateActiveProfile(body.profile));
}

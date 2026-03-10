import { NextResponse } from "next/server";

import { getProfileState } from "@/lib/security/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json(getProfileState());
}

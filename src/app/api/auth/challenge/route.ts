import { NextRequest, NextResponse } from "next/server";

import { generateChallenge } from "@/lib/auth/challenge";
import { securityHeadersForRequest } from "@/lib/security/headers";

// In-memory store for demo purposes (replace with DB in production)
const usedChallenges = new Set<string>();

export async function GET(request: NextRequest) {
  try {
    const challenge = generateChallenge();
    usedChallenges.add(challenge);
    return NextResponse.json({ challenge }, { headers: securityHeadersForRequest(request, { noStore: true }) });
  } catch {
    return NextResponse.json(
      { error: 'Failed to generate challenge' },
      { status: 500, headers: securityHeadersForRequest(request, { noStore: true }) },
    );
  }
}

export async function POST(request: NextRequest) {
  const { challenge } = await request.json();

  if (usedChallenges.has(challenge)) {
    usedChallenges.delete(challenge); // Mark as consumed
    return NextResponse.json(
      { error: 'Challenge already used', code: 'CHALLENGE_CONSUMED' },
      { status: 400, headers: securityHeadersForRequest(request, { noStore: true }) },
    );
  }

  return NextResponse.json(
    { error: 'Invalid challenge', code: 'INVALID_CHALLENGE' },
    { status: 400, headers: securityHeadersForRequest(request, { noStore: true }) },
  );
}

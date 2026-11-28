import { NextRequest, NextResponse } from "next/server";

import { getSessionFromRequest, type AuthRole } from "@/lib/auth/session";
import { isSessionRevoked } from "@/lib/auth/session-revocation";
import { applySecurityHeaders } from "@/lib/security/headers";

type RequireAuthOptions = {
  allowedRoles?: AuthRole[];
};

function unauthorizedResponse(request: NextRequest) {
  const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
  const response = NextResponse.json(
    { error: "Unauthorized. Login required." },
    {
      status: 401,
      headers: { "x-request-id": requestId },
    },
  );

  return applySecurityHeaders(response, requestId, { noStore: true });
}

function forbiddenResponse(request: NextRequest) {
  const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
  const response = NextResponse.json(
    { error: "Forbidden. Insufficient role permissions." },
    {
      status: 403,
      headers: { "x-request-id": requestId },
    },
  );

  return applySecurityHeaders(response, requestId, { noStore: true });
}

export function requireAuth(request: NextRequest, options?: RequireAuthOptions) {
  const session = getSessionFromRequest(request);

  if (!session) {
    return {
      ok: false as const,
      response: unauthorizedResponse(request),
    };
  }

  const allowedRoles = options?.allowedRoles ?? ["operator", "viewer"];

  const sessionRoles = session.roles ?? [session.role];

  if (!allowedRoles.some((role) => sessionRoles.includes(role))) {
    return {
      ok: false as const,
      response: forbiddenResponse(request),
    };
  }

  return {
    ok: true as const,
    session,
  };
}

/**
 * requireAuth plus a check against the session revocation store, so a token
 * from a logged-out session is rejected even though its signature verifies.
 */
export async function requireActiveAuth(request: NextRequest, options?: RequireAuthOptions) {
  const auth = requireAuth(request, options);
  if (!auth.ok) {
    return auth;
  }

  if (await isSessionRevoked(auth.session.sid)) {
    return {
      ok: false as const,
      response: unauthorizedResponse(request),
    };
  }

  return auth;
}

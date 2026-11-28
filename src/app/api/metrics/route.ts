import { NextRequest, NextResponse } from "next/server";

import { requireAuth } from "@/lib/auth/require-auth";
import { getMetricsSnapshot, recordApiMetric, toPrometheusText } from "@/lib/observability/metrics";
import { securityHeadersForRequest } from "@/lib/security/headers";

export async function GET(request: NextRequest) {
  const auth = requireAuth(request, { allowedRoles: ["operator"] });

  if (!auth.ok) {
    return auth.response;
  }

  const format = request.nextUrl.searchParams.get("format")?.toLowerCase();

  recordApiMetric({
    route: "/api/metrics",
    method: request.method,
    statusCode: 200,
    durationMs: 0,
  });

  if (format === "prometheus") {
    return new NextResponse(toPrometheusText(), {
      status: 200,
      headers: {
        ...securityHeadersForRequest(request, { noStore: true }),
        "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
      },
    });
  }

  return NextResponse.json(getMetricsSnapshot(), {
    status: 200,
    headers: securityHeadersForRequest(request, { noStore: true }),
  });
}

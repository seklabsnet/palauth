import type { NextRequest } from "next/server";

const BACKEND_URL = process.env.PALAUTH_URL ?? "http://localhost:3000";

// Only allow proxying to admin endpoints.
const ALLOWED_PREFIXES = ["/admin/"];

async function proxyRequest(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  const targetPath = `/${path.join("/")}`;

  const isAllowed = ALLOWED_PREFIXES.some((prefix) =>
    targetPath.startsWith(prefix)
  );
  if (!isAllowed) {
    return new Response(
      JSON.stringify({
        error: "forbidden",
        error_description: "Path not allowed",
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const url = new URL(targetPath, BACKEND_URL);
  url.search = request.nextUrl.search;

  // Only forward safe headers — Authorization and Content-Type.
  const headers = new Headers();
  const auth = request.headers.get("authorization");
  if (auth) {
    headers.set("authorization", auth);
  }
  const contentType = request.headers.get("content-type");
  if (contentType) {
    headers.set("content-type", contentType);
  }

  const body =
    request.method !== "GET" && request.method !== "HEAD"
      ? await request.arrayBuffer()
      : undefined;

  const res = await fetch(url.toString(), {
    method: request.method,
    headers,
    body,
  });

  const responseHeaders = new Headers();
  const resContentType = res.headers.get("content-type");
  if (resContentType) {
    responseHeaders.set("content-type", resContentType);
  }
  const resDisposition = res.headers.get("content-disposition");
  if (resDisposition) {
    responseHeaders.set("content-disposition", resDisposition);
  }

  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: responseHeaders,
  });
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const DELETE = proxyRequest;
export const PATCH = proxyRequest;

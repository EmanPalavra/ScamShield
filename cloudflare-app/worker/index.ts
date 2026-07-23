import handler from "vinext/server/app-router-entry";
import { handleScannerApi, type ScannerEnv } from "./scanner";

export { RateLimiter } from "./rate-limiter";

type WorkerEnv = Env & ScannerEnv;

interface RewriterElement {
  setAttribute(name: string, value: string): void;
}

interface HtmlRewriterInstance {
  on(selector: string, handlers: { element(element: RewriterElement): void }): HtmlRewriterInstance;
  transform(response: Response): Response;
}

interface HtmlRewriterConstructor {
  new(): HtmlRewriterInstance;
}

function createNonce() {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function withSecurityHeaders(response: Response, request: Request, requestId: string) {
  const secured = new Response(response.body, response);
  const nonce = createNonce();
  const contentType = secured.headers.get("content-type") ?? "";
  const HtmlRewriterClass = (globalThis as typeof globalThis & { HTMLRewriter?: HtmlRewriterConstructor }).HTMLRewriter;
  const canNonceScripts = contentType.includes("text/html") && Boolean(HtmlRewriterClass);
  secured.headers.set("X-Content-Type-Options", "nosniff");
  secured.headers.set("X-Frame-Options", "DENY");
  secured.headers.set("X-DNS-Prefetch-Control", "off");
  secured.headers.set("X-Permitted-Cross-Domain-Policies", "none");
  secured.headers.set("Referrer-Policy", "no-referrer");
  secured.headers.set("Permissions-Policy", "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()");
  secured.headers.set("Cross-Origin-Opener-Policy", "same-origin");
  secured.headers.set("Cross-Origin-Resource-Policy", "same-origin");
  secured.headers.set("Origin-Agent-Cluster", "?1");
  secured.headers.set("X-Request-ID", requestId);
  secured.headers.set(
    "Content-Security-Policy",
    `default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self' ${canNonceScripts ? `'nonce-${nonce}' 'strict-dynamic'` : "'unsafe-inline'"} https://challenges.cloudflare.com; script-src-attr 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; worker-src 'self' blob:; manifest-src 'self'; media-src 'none'; upgrade-insecure-requests`,
  );
  if (contentType.includes("text/html")) secured.headers.set("Cache-Control", "private, no-store");
  if (new URL(request.url).protocol === "https:") {
    secured.headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
  if (canNonceScripts && HtmlRewriterClass) {
    return new HtmlRewriterClass()
      .on("script", { element: (element) => element.setAttribute("nonce", nonce) })
      .transform(secured);
  }
  return secured;
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

const worker = {
  async fetch(request: Request, env: WorkerEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const requestId = crypto.randomUUID();

    try {
      const apiResponse = await handleScannerApi(request, env, ctx);
      if (apiResponse) return withSecurityHeaders(apiResponse, request, requestId);

      return withSecurityHeaders(await handler.fetch(request, env, ctx), request, requestId);
    } catch (error) {
      console.error(JSON.stringify({
        event: "request_failed",
        requestId,
        method: request.method,
        path: url.pathname,
        errorType: error instanceof Error ? error.name : "UnknownError",
      }));
      const response = url.pathname.startsWith("/api/")
        ? Response.json({ error: "Internal server error.", requestId }, { status: 500, headers: { "cache-control": "no-store" } })
        : new Response("Internal server error.", { status: 500, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
      return withSecurityHeaders(response, request, requestId);
    }
  },
};

export default worker;

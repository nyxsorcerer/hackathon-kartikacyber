import { z } from "zod";
export class ApiError extends Error {
  fields: Record<string, unknown>;
  code: string;
  status: number;
  constructor(
    message: string,
    code: string,
    status: number,
    fields: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.fields = fields;
    this.code = code;
    this.status = status;
  }
}
let csrfToken: string | undefined;
export function setCsrfToken(token: string | undefined) {
  csrfToken = token;
}
const errorSchema = z.object({
  message: z.string(),
  code: z.string().optional(),
  fields: z.record(z.string(), z.unknown()).optional(),
});
export async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  const method = options.method || "GET";
  if (options.body && !(options.body instanceof FormData))
    headers.set("Content-Type", "application/json");
  if (method !== "GET" && csrfToken) headers.set("X-CSRF-Token", csrfToken);
  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      ...options,
      headers,
      credentials: "same-origin",
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") throw error;
    throw new ApiError(
      "The dashboard cannot reach the API. Check the application connection and try again.",
      "network_error",
      0,
    );
  }
  if (!response.ok) {
    if (response.status === 401 && path !== "/auth/login")
      window.dispatchEvent(new CustomEvent("numen:unauthorized"));
    const payload = errorSchema.safeParse(
      await response.json().catch(() => null),
    );
    throw new ApiError(
      payload.success
        ? payload.data.message
        : `Request failed (${response.status}).`,
      payload.success
        ? payload.data.code || "request_failed"
        : "request_failed",
      response.status,
      payload.success ? payload.data.fields : {},
    );
  }
  const body: unknown = response.status === 204 ? null : await response.json();
  const parsed = schema.safeParse(body);
  if (!parsed.success)
    throw new ApiError(
      "The API returned an unexpected response. Reload to inspect the current saved state.",
      "response_invalid",
      response.status,
    );
  return parsed.data;
}
export function mutate<T>(
  path: string,
  schema: z.ZodType<T>,
  body: unknown = {},
  method = "POST",
  key?: string,
) {
  return request(path, schema, {
    method,
    body: JSON.stringify(body),
    headers: key ? { "Idempotency-Key": key } : {},
  });
}

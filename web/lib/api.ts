export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function csrfToken(): string {
  if (typeof document === "undefined") return "";
  const m = document.cookie.match(/(?:^|;\s*)myowl_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

export async function api<T = unknown>(path: string, opts: { method?: string; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const method = opts.method || "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = csrfToken();
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : method !== "GET" ? "{}" : undefined,
    signal: opts.signal,
  });
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    /* empty */
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | null)?.error || `Request failed (${res.status})`;
    if (res.status === 401 && typeof window !== "undefined" && !path.startsWith("/api/auth/")) {
      window.dispatchEvent(new CustomEvent("myowl:unauthorized"));
    }
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

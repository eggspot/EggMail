export interface MockResponse {
  status: number;
  data: any;
  headers: Headers;
  ok: boolean;
}

export interface MockHandle {
  base: string;
  options: any;
  state: any;
  call(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<MockResponse>;
  get(path: string, headers?: Record<string, string>): Promise<MockResponse>;
  post(path: string, body?: unknown, headers?: Record<string, string>): Promise<MockResponse>;
  put(path: string, body?: unknown, headers?: Record<string, string>): Promise<MockResponse>;
  patch(path: string, body?: unknown, headers?: Record<string, string>): Promise<MockResponse>;
  del(path: string, headers?: Record<string, string>): Promise<MockResponse>;
  login(user?: 'admin' | 'tenant', tenantId?: string): Promise<{ user: string; role: string; tenantId: string | null; csrfToken: string }>;
  setTenant(id: string): void;
  close(): Promise<void>;
}

export function startMock(options?: Record<string, unknown>): Promise<MockHandle>;

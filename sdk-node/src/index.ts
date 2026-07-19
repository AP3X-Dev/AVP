import { request } from "undici";

export type Capability = {
  service: string;
  scopes: string[];
  environment: "dev" | "staging" | "prod";
  resource?: string | null;
  mode: "secret_resolution" | "proxy_only" | "both";
};

export type SessionInfo = {
  sessionId: string;
  sessionToken: string;
  expiresAt: string;
  grantedCapabilities: Capability[];
  capabilityHandles: Record<string, string>;
};

export class AVPClient {
  baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  static fromEnv(): AVPClient {
    const url = process.env.AVP_URL || process.env.AVP_SERVER_URL || "http://localhost:8000";
    return new AVPClient(url);
  }

  private async post(path: string, body: any, token?: string) {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (token) headers["authorization"] = `Bearer ${token}`;
    const res = await request(this.baseUrl + path, { method: "POST", headers, body: JSON.stringify(body) });
    const text = await res.body.text();
    const data = text ? JSON.parse(text) : {};
    if (res.statusCode >= 400) {
      throw new Error(`HTTP ${res.statusCode}: ${text}`);
    }
    return data;
  }

  async agentHello(agentToken: string, agentId: string, requestedCapabilities: Capability[], metadata: Record<string, any> = {}): Promise<SessionInfo> {
    const data = await this.post("/avp/agent_hello", {
      avp_version: "1.0",
      type: "agent_hello",
      agent_id: agentId,
      agent_version: "0.1.0",
      runtime: "node",
      metadata,
      requested_capabilities: requestedCapabilities
    }, agentToken);

    return {
      sessionId: data.session_id,
      sessionToken: data.session_token,
      expiresAt: data.expires_at,
      grantedCapabilities: data.granted_capabilities || [],
      capabilityHandles: data.capability_handles || {}
    };
  }

  async resolveSecrets(sessionToken: string, sessionId: string, format: "environment" | "json" = "environment", services?: string[]) {
    const data = await this.post("/avp/resolve_secrets", {
      avp_version: "1.0",
      type: "resolve_secrets",
      session_id: sessionId,
      filters: { format, services }
    }, sessionToken);
    return data.secrets || {};
  }

  async proxyCall(sessionToken: string, sessionId: string, handle: string, operation: string, payload: Record<string, any>) {
    return await this.post("/avp/proxy_call", {
      avp_version: "1.0",
      type: "proxy_call",
      session_id: sessionId,
      capability_handle: handle,
      operation,
      payload
    }, sessionToken);
  }

  /** Proxy a streaming call. Returns the raw SSE byte stream from the provider. */
  async proxyCallStream(sessionToken: string, sessionId: string, handle: string, operation: string, payload: Record<string, any>): Promise<AsyncIterable<Uint8Array>> {
    const res = await request(this.baseUrl + "/avp/proxy_call", {
      method: "POST",
      headers: { "content-type": "application/json", "authorization": `Bearer ${sessionToken}` },
      body: JSON.stringify({
        avp_version: "1.0",
        type: "proxy_call",
        session_id: sessionId,
        capability_handle: handle,
        operation,
        payload: { ...payload, stream: true }
      })
    });
    if (res.statusCode >= 400) {
      const text = await res.body.text();
      throw new Error(`HTTP ${res.statusCode}: ${text}`);
    }
    return res.body;
  }
}

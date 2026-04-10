// @clearfin/auth-service — Unit tests for TokenExchanger
import { describe, it, expect, vi } from "vitest";
import { exchangeToken, type HttpClient, type TokenExchangeConfig } from "./token-exchanger.js";
import { createLogger } from "@clearfin/shared";

const config: TokenExchangeConfig = {
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  redirectUri: "https://app.clearfin.com/auth/callback",
};

const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

function mockHttpClient(
  status: number,
  body: unknown,
): HttpClient {
  return {
    post: vi.fn().mockResolvedValue({
      status,
      json: () => Promise.resolve(body),
    }),
  };
}

describe("exchangeToken", () => {
  it("returns GoogleTokens on a successful exchange", async () => {
    const client = mockHttpClient(200, {
      id_token: "eyJ.id.token",
      access_token: "ya29.access",
      refresh_token: "1//refresh",
      token_type: "Bearer",
      expires_in: 3600,
      scope: "openid email profile",
    });

    const result = await exchangeToken("auth-code", "verifier", config, silentLogger, client);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.idToken).toBe("eyJ.id.token");
    expect(result.value.accessToken).toBe("ya29.access");
    expect(result.value.refreshToken).toBe("1//refresh");
    expect(result.value.tokenType).toBe("Bearer");
    expect(result.value.expiresIn).toBe(3600);
    expect(result.value.scope).toBe("openid email profile");
  });

  it("sends correct parameters to Google token endpoint", async () => {
    const client = mockHttpClient(200, {
      id_token: "tok",
      access_token: "acc",
    });

    await exchangeToken("my-code", "my-verifier", config, silentLogger, client);

    const postFn = client.post as ReturnType<typeof vi.fn>;
    expect(postFn).toHaveBeenCalledOnce();

    const [url, body] = postFn.mock.calls[0];
    expect(url).toBe("https://oauth2.googleapis.com/token");
    expect(body.get("code")).toBe("my-code");
    expect(body.get("code_verifier")).toBe("my-verifier");
    expect(body.get("client_id")).toBe("test-client-id");
    expect(body.get("client_secret")).toBe("test-client-secret");
    expect(body.get("redirect_uri")).toBe("https://app.clearfin.com/auth/callback");
    expect(body.get("grant_type")).toBe("authorization_code");
  });

  it("returns INVALID_GRANT error when Google responds with invalid_grant", async () => {
    const client = mockHttpClient(400, {
      error: "invalid_grant",
      error_description: "Code has already been used.",
    });

    const result = await exchangeToken("used-code", "verifier", config, silentLogger, client);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("INVALID_GRANT");
    expect(result.error.httpStatus).toBe(502);
    expect(result.error.googleError).toBe("invalid_grant");
    expect(result.error.message).toBe("Code has already been used.");
  });

  it("returns TOKEN_EXCHANGE_FAILED for other Google errors", async () => {
    const client = mockHttpClient(400, {
      error: "invalid_client",
      error_description: "The OAuth client was not found.",
    });

    const result = await exchangeToken("code", "verifier", config, silentLogger, client);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("TOKEN_EXCHANGE_FAILED");
    expect(result.error.googleError).toBe("invalid_client");
  });

  it("returns NETWORK_ERROR when the HTTP client throws", async () => {
    const client: HttpClient = {
      post: vi.fn().mockRejectedValue(new Error("ECONNREFUSED")),
    };

    const result = await exchangeToken("code", "verifier", config, silentLogger, client);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("NETWORK_ERROR");
    expect(result.error.httpStatus).toBe(502);
    expect(result.error.message).toContain("ECONNREFUSED");
  });

  it("returns TOKEN_EXCHANGE_FAILED when response JSON is unparseable", async () => {
    const client: HttpClient = {
      post: vi.fn().mockResolvedValue({
        status: 200,
        json: () => Promise.reject(new Error("invalid json")),
      }),
    };

    const result = await exchangeToken("code", "verifier", config, silentLogger, client);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("TOKEN_EXCHANGE_FAILED");
    expect(result.error.message).toContain("parse");
  });

  it("returns TOKEN_EXCHANGE_FAILED when id_token is missing", async () => {
    const client = mockHttpClient(200, {
      access_token: "ya29.access",
    });

    const result = await exchangeToken("code", "verifier", config, silentLogger, client);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("TOKEN_EXCHANGE_FAILED");
    expect(result.error.message).toContain("id_token");
  });

  it("returns TOKEN_EXCHANGE_FAILED when access_token is missing", async () => {
    const client = mockHttpClient(200, {
      id_token: "eyJ.id.token",
    });

    const result = await exchangeToken("code", "verifier", config, silentLogger, client);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("TOKEN_EXCHANGE_FAILED");
    expect(result.error.message).toContain("access_token");
  });

  it("defaults tokenType to Bearer and expiresIn to 3600 when not provided", async () => {
    const client = mockHttpClient(200, {
      id_token: "tok",
      access_token: "acc",
    });

    const result = await exchangeToken("code", "verifier", config, silentLogger, client);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.tokenType).toBe("Bearer");
    expect(result.value.expiresIn).toBe(3600);
    expect(result.value.scope).toBe("");
    expect(result.value.refreshToken).toBeUndefined();
  });
});

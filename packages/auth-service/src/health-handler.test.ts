import { describe, it, expect } from "vitest";
import { handleHealth } from "./health-handler.js";

describe("handleHealth", () => {
  it("returns healthy status with service name and ISO timestamp", () => {
    const before = new Date().toISOString();
    const result = handleHealth();
    const after = new Date().toISOString();

    expect(result.status).toBe("healthy");
    expect(result.service).toBe("auth-service");
    expect(result.timestamp).toBeDefined();
    // timestamp should be a valid ISO string within the test window
    expect(result.timestamp >= before).toBe(true);
    expect(result.timestamp <= after).toBe(true);
  });

  it("returns HTTP 200-compatible JSON shape", () => {
    const result = handleHealth();
    const keys = Object.keys(result);

    expect(keys).toContain("status");
    expect(keys).toContain("service");
    expect(keys).toContain("timestamp");
  });

  it("produces a valid ISO 8601 timestamp", () => {
    const result = handleHealth();
    const parsed = new Date(result.timestamp);

    expect(parsed.toISOString()).toBe(result.timestamp);
  });
});

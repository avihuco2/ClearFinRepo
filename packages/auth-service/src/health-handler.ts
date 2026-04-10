// @clearfin/auth-service — /health endpoint handler
// Returns service health status without authentication for ALB health checks.

export interface HealthResponse {
  status: "healthy";
  service: "auth-service";
  timestamp: string;
}

/**
 * Returns a health check response for ALB health probes.
 * No authentication required (Requirement 6.6).
 */
export function handleHealth(): HealthResponse {
  return {
    status: "healthy",
    service: "auth-service",
    timestamp: new Date().toISOString(),
  };
}

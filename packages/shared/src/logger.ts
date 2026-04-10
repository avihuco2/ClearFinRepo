// @clearfin/shared — Structured JSON logging with correlation IDs

import { randomUUID } from "node:crypto";

export type LogLevel = "INFO" | "WARN" | "ERROR" | "CRITICAL" | "ALERT";

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  correlationId: string;
  service: string;
  [key: string]: unknown;
}

export interface Logger {
  info(message: string, extra?: Record<string, unknown>): void;
  warn(message: string, extra?: Record<string, unknown>): void;
  error(message: string, extra?: Record<string, unknown>): void;
  critical(message: string, extra?: Record<string, unknown>): void;
  alert(message: string, extra?: Record<string, unknown>): void;
  child(extra: Record<string, unknown>): Logger;
}

export function createLogger(
  service: string,
  correlationId: string = randomUUID(),
  baseExtra: Record<string, unknown> = {},
  /** injectable writer for testing — defaults to stdout */
  writer: (json: string) => void = (json) => process.stdout.write(json + "\n"),
): Logger {
  function emit(level: LogLevel, message: string, extra?: Record<string, unknown>): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      correlationId,
      service,
      ...baseExtra,
      ...extra,
    };
    writer(JSON.stringify(entry));
  }

  return {
    info: (msg, extra) => emit("INFO", msg, extra),
    warn: (msg, extra) => emit("WARN", msg, extra),
    error: (msg, extra) => emit("ERROR", msg, extra),
    critical: (msg, extra) => emit("CRITICAL", msg, extra),
    alert: (msg, extra) => emit("ALERT", msg, extra),
    child: (extra) => createLogger(service, correlationId, { ...baseExtra, ...extra }, writer),
  };
}

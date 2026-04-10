// @clearfin/auth-service — In-memory Session Store
// Stores OAuth state + PKCE code_verifier pairs keyed by state value.

export interface SessionEntry {
  state: string;
  codeVerifier: string;
  createdAt: Date;
}

export class SessionStore {
  private entries = new Map<string, SessionEntry>();

  /** Store a state + code_verifier pair. */
  set(state: string, codeVerifier: string, now: Date = new Date()): void {
    this.entries.set(state, { state, codeVerifier, createdAt: now });
  }

  /** Retrieve and delete a session entry by state (one-time use). */
  consume(state: string): SessionEntry | undefined {
    const entry = this.entries.get(state);
    if (entry) {
      this.entries.delete(state);
    }
    return entry;
  }

  /** Check if a state exists without consuming it. */
  has(state: string): boolean {
    return this.entries.has(state);
  }

  /** Number of active entries (useful for testing). */
  get size(): number {
    return this.entries.size;
  }
}

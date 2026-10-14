/** The password policy of the server (docs/api.md, "Dashboard users"): length only. */
export const MIN_PASSWORD = 10;
export const MAX_PASSWORD = 1024;

/** Why a password is not acceptable, or undefined. The server checks again; this only saves the round trip. */
export function passwordProblem(password: string): string | undefined {
  if (password.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (password.length > MAX_PASSWORD) return `Use at most ${MAX_PASSWORD} characters.`;
  return undefined;
}

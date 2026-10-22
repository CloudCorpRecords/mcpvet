/**
 * Bundled reference data for mcpvet: well-known MCP server names used for
 * typosquat distance checks, and the credential-shaped name pattern used
 * for env harvesting checks. Static data only, shipped with the package.
 */

/** Bare server names (last path segment) of widely used MCP servers. */
export const WELL_KNOWN_SERVERS: string[] = [
  "server-filesystem",
  "server-everything",
  "server-memory",
  "server-fetch",
  "server-time",
  "server-sequential-thinking",
  "server-github",
  "server-git",
  "server-gitlab",
  "server-sqlite",
  "server-postgres",
  "server-brave-search",
  "server-puppeteer",
  "server-slack",
  "server-google-drive",
  "server-google-maps",
  "server-sentry",
  "server-redis",
  "server-everart",
  "server-aws-kb-retrieval-server",
  "filesystem",
  "everything",
  "memory",
  "fetch",
  "sequential-thinking",
  "github",
  "gitlab",
  "sqlite",
  "postgres",
  "brave-search",
  "puppeteer",
  "slack",
  "sentry",
  "redis",
];

/** Env var names that commonly hold credentials. */
export const CREDENTIAL_ENV_RE =
  /(API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|CREDENTIAL|AUTH|SESSION|COOKIE|BEARER|OPENAI|ANTHROPIC|AWS_|GITHUB_|GH_|STRIPE|SENDGRID|TWILIO|DATABASE_URL|PGPASSWORD|MYSQL_PWD)/i;

/** Paths and mechanisms that read a credential store. */
export const CREDENTIAL_STORE_RE =
  /(\.ssh\b|id_rsa|id_ed25519|id_ecdsa|\.aws[\\/]+credentials|\.aws[\\/]+config|\.git-credentials|\.npmrc\b|\.pypirc\b|credentials\.json|service[_-]?account[^"\n]*\.json|keytar|find-generic-password|\.config[\\/]+gh[\\/]+hosts\.yml|\.kube[\\/]+config|\.docker[\\/]+config\.json|Login Data|keyring|gnome-keyring|\.netrc\b)/i;

/** Levenshtein edit distance, deterministic and allocation-light. */
export function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

/**
 * Closest well-known name within the flag distance, or null. Distance 1
 * always flags; distance 2 flags only for longer names where two edits
 * still read as an imitation.
 */
export function typosquatMatch(candidate: string): { known: string; distance: number } | null {
  const c = candidate.toLowerCase();
  if (!c || c.length < 4) return null;
  let best: { known: string; distance: number } | null = null;
  for (const known of WELL_KNOWN_SERVERS) {
    if (known === c) return null;
    const d = editDistance(c, known);
    const limit = known.length >= 9 ? 2 : 1;
    if (d >= 1 && d <= limit && (!best || d < best.distance)) {
      best = { known, distance: d };
    }
  }
  return best;
}

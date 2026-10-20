// Limitation des tentatives de connexion (anti brute force / credential stuffing).
//
// Seuls les ÉCHECS sont comptés : un utilisateur légitime qui se connecte souvent
// n'est jamais bloqué. Deux compteurs :
//   - par IP + email : protège un compte précis contre le brute force ;
//   - par IP seule   : protège contre le test d'un même mot de passe sur beaucoup d'emails.
// Une connexion réussie remet à zéro le compteur IP + email.
//
// Limite connue : stockage en mémoire, donc propre à chaque instance de l'API.
// Avec plusieurs instances, il faudrait un stockage partagé (ex. Redis).

const WINDOW_MS = 15 * 60 * 1000;
export const MAX_FAILURES_PER_ACCOUNT = 5;
export const MAX_FAILURES_PER_IP = 20;

type Entry = { failures: number; windowStart: number };
const store = new Map<string, Entry>();

function current(key: string, now: number): Entry | undefined {
  const entry = store.get(key);
  if (entry && now - entry.windowStart >= WINDOW_MS) {
    store.delete(key); // fenêtre expirée
    return undefined;
  }
  return entry;
}

function keys(ip: string, email: string) {
  return { account: `acct:${ip}|${email.trim().toLowerCase()}`, ip: `ip:${ip}` };
}

/** Secondes restantes avant déblocage, ou 0 si la tentative est autorisée. */
export function retryAfterSeconds(ip: string, email: string, now = Date.now()): number {
  const k = keys(ip, email);
  const blocked = [
    { entry: current(k.account, now), max: MAX_FAILURES_PER_ACCOUNT },
    { entry: current(k.ip, now), max: MAX_FAILURES_PER_IP },
  ].filter(({ entry, max }) => entry && entry.failures >= max);

  if (blocked.length === 0) return 0;
  const unlockAt = Math.max(...blocked.map(({ entry }) => entry!.windowStart + WINDOW_MS));
  return Math.ceil((unlockAt - now) / 1000);
}

/** Enregistre un échec. Renvoie true si cet échec déclenche un blocage. */
export function registerFailure(ip: string, email: string, now = Date.now()): boolean {
  const k = keys(ip, email);
  let reachedLimit = false;
  for (const [key, max] of [[k.account, MAX_FAILURES_PER_ACCOUNT], [k.ip, MAX_FAILURES_PER_IP]] as const) {
    const entry = current(key, now) ?? { failures: 0, windowStart: now };
    entry.failures += 1;
    store.set(key, entry);
    if (entry.failures === max) reachedLimit = true;
  }
  return reachedLimit;
}

/** Connexion réussie : remet à zéro le compteur du compte. */
export function registerSuccess(ip: string, email: string): void {
  store.delete(keys(ip, email).account);
}

// Nettoyage périodique des fenêtres expirées (évite la croissance de la mémoire).
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (now - entry.windowStart >= WINDOW_MS) store.delete(key);
  }
}, WINDOW_MS).unref();

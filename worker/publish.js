/* Lorhaine Mendes — publishing server (Cloudflare Worker)

   The editor logs in here with an email + password, then sends its changes here.
   This worker holds the GitHub key and makes the commit, so nobody using the editor ever sees it.

   Settings (Cloudflare → Worker → Settings → Variables and Secrets, all as "Secret"):
     GITHUB_TOKEN    fine-grained GitHub token with Contents: read & write on the site repo
     USERS           logins, comma-separated:  a@x.com:pass1, b@y.com:pass2
   Optional:
     SESSION_SECRET  long random text that signs logins (defaults to the GitHub key)
     REPO            owner/repo   (default mudtometal/lorhaine-mendes)
     BRANCH          default main
     ORIGINS         comma-separated sites allowed to use this (default lorhainemendes.com + github.io)
*/

const DAY = 864e5;
const enc = new TextEncoder();

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const allowed = (env.ORIGINS || 'https://lorhainemendes.com,https://www.lorhainemendes.com,http://lorhainemendes.com,http://www.lorhainemendes.com,https://mudtometal.github.io')
      .split(',').map(s => s.trim());
    const cors = {
      'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : allowed[0],
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      Vary: 'Origin',
    };
    const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'POST') return json({ ok: true, service: 'lorhaine-publish' });
    if (!allowed.includes(origin)) return json({ error: 'origin' }, 403);

    const path = new URL(req.url).pathname;
    const secret = env.SESSION_SECRET || env.GITHUB_TOKEN;
    try {
      if (path === '/login') {
        const { email = '', password = '' } = await req.json();
        const user = findUser(env.USERS, email, password);
        if (!user) { await sleep(600); return json({ error: 'login' }, 401); }
        return json({ token: await sign({ u: user, exp: Date.now() + 30 * DAY }, secret), email: user });
      }
      const s = await verify((req.headers.get('Authorization') || '').replace(/^Bearer /, ''), secret);
      if (!s) return json({ error: 'session' }, 401);
      if (path === '/check') return json({ ok: true, email: s.u });
      if (path === '/publish') {
        const { files, message } = await req.json();
        const entries = Object.entries(files || {});
        if (!entries.length) return json({ error: 'empty' }, 400);
        for (const [p] of entries) if (!okPath(p)) return json({ error: 'path', path: p }, 400);
        const sha = await commit(env, entries, `${message || 'Editor update'} (${s.u})`);
        return json({ ok: true, sha });
      }
      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: 'server', detail: String(e.message || e) }, e.status === 401 || e.status === 403 ? 502 : 500);
    }
  },
};

/* only the site's content can be changed through here, never its code */
function okPath(p) {
  if (typeof p !== 'string' || p.includes('..') || p.startsWith('/')) return false;
  if (p === 'data/projects.json') return true;
  return /^media\/(web|md|video)\/[a-z0-9-]+(\/[a-z0-9-]+)?\.(webp|jpg|mp4)$/.test(p);
}

function findUser(list = '', email, password) {
  email = String(email).trim().toLowerCase();
  for (const line of String(list).split(/\r?\n|,/)) {
    const i = line.indexOf(':'); if (i < 1) continue;
    const e = line.slice(0, i).trim().toLowerCase(), p = line.slice(i + 1).trim();
    if (e === email && same(p, String(password))) return e;
  }
  return null;
}
function same(a, b) { const x = enc.encode(a), y = enc.encode(b); let d = x.length ^ y.length; for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0); return d === 0; }
const sleep = ms => new Promise(r => setTimeout(r, ms));

const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const hmacKey = secret => crypto.subtle.importKey('raw', enc.encode(secret || ''), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
async function sign(obj, secret) {
  if (!secret || secret.length < 16) throw new Error('GITHUB_TOKEN is not set');
  const body = b64u(enc.encode(JSON.stringify(obj)));
  return body + '.' + b64u(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)));
}
async function verify(tok, secret) {
  const [body, sig] = String(tok).split('.');
  if (!body || !sig || !secret) return null;
  try {
    if (!(await crypto.subtle.verify('HMAC', await hmacKey(secret), unb64u(sig), enc.encode(body)))) return null;
    const o = JSON.parse(new TextDecoder().decode(unb64u(body)));
    return o.exp > Date.now() ? o : null;
  } catch { return null; }
}

/* one commit containing every changed file */
async function commit(env, entries, message) {
  const [owner, repo] = (env.REPO || 'mudtometal/lorhaine-mendes').split('/'), branch = env.BRANCH || 'main';
  const gh = async (p, opt = {}) => {
    const r = await fetch(`https://api.github.com/repos/${owner}/${repo}${p}`, {
      ...opt,
      headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'lorhaine-publish' },
    });
    if (!r.ok) throw Object.assign(new Error(`GitHub ${r.status}: ${(await r.text()).slice(0, 200)}`), { status: r.status });
    return r.json();
  };
  const tree = [];
  for (const [path, content] of entries) {
    const { sha } = await gh('/git/blobs', { method: 'POST', body: JSON.stringify({ content, encoding: 'base64' }) });
    tree.push({ path, mode: '100644', type: 'blob', sha });
  }
  const ref = await gh(`/git/ref/heads/${branch}`), head = await gh(`/git/commits/${ref.object.sha}`);
  const t = await gh('/git/trees', { method: 'POST', body: JSON.stringify({ base_tree: head.tree.sha, tree }) });
  const c = await gh('/git/commits', { method: 'POST', body: JSON.stringify({ message, tree: t.sha, parents: [ref.object.sha] }) });
  await gh(`/git/refs/heads/${branch}`, { method: 'PATCH', body: JSON.stringify({ sha: c.sha }) });
  return c.sha;
}

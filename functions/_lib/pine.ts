import {cookie, current, ensureSchemas, id, json, now, sha, teamFor, type Account, type Env} from './auth';

const PINE_API = 'https://pineaccounts.pages.dev';
const SESSION_SECONDS = 30 * 86400;

type PineUser = { id: string; name: string; email: string };
type PineAuthResponse = { user?: PineUser | null; error?: string };

function pineCookieFromRequest(request: Request) {
  const raw = request.headers.get('Cookie') || '';
  return raw.split(';').map(value => value.trim()).find(value => value.startsWith('pine_session=')) || '';
}

async function callPine(path: string, method: string, request: Request, body?: unknown, cookieOverride?: string) {
  const headers = new Headers({ accept: 'application/json' });
  const session = cookieOverride || pineCookieFromRequest(request);
  if (session) headers.set('cookie', session);
  if (body !== undefined) headers.set('content-type', 'application/json');
  // Never leave the sign-in form spinning forever if the upstream service stalls.
  // Cloudflare Workers supports AbortSignal.timeout; the catch in pineAuthenticate
  // converts this into a visible JSON error for the UI.
  return fetch(PINE_API + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: 'follow',
    signal: AbortSignal.timeout(12000)
  });
}

function pineSessionFromResponse(response: Response) {
  const extendedHeaders = response.headers as Headers & { getSetCookie?: () => string[] };
  const cookies = extendedHeaders.getSetCookie?.() || [response.headers.get('set-cookie') || ''];
  for (const line of cookies) {
    const match = line.match(/(?:^|[,;\\s])pine_session=([^;,\\s]+)/);
    if (match) return 'pine_session=' + match[1];
  }
  return '';
}

function setCookies(localCookie?: string, pineSession?: string) {
  const headers = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store'
  });
  if (pineSession) headers.append('set-cookie', pineSession + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + SESSION_SECONDS);
  if (localCookie) headers.append('set-cookie', localCookie);
  return headers;
}

async function ensureDeveloperAccount(user: PineUser, sessionCookie: string) {
  // Pine documents POST as idempotent: it returns the existing Developer
  // Account when one already exists, or creates it otherwise. Do not infer
  // absence from GET /api/developer because that endpoint can return 200/null.
  const response = await fetch(PINE_API + '/api/developer', {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      cookie: sessionCookie
    },
    body: JSON.stringify({ name: user.name, email: user.email }),
    redirect: 'follow'
  });
  const data = await response.json().catch(() => ({})) as { error?: string; account?: unknown; developer?: unknown };
  if (!response.ok) {
    throw new Error(data.error || 'Pine Accounts no pudo preparar la Developer Account (HTTP ' + response.status + ')');
  }
}
async function ensureLocalIdentity(env: Env, user: PineUser): Promise<{ account: Account; team: { id: string; name: string; role: string; team_type: string } }> {
  await ensureSchemas(env);
  const created = now();
  const email = user.email.trim().toLowerCase();

  // Reuse an existing local identity by email so older portal data and team ownership survive.
  let account = await env.developer.prepare(
    'SELECT id,email,display_name FROM accounts WHERE email=? COLLATE NOCASE LIMIT 1'
  ).bind(email).first<Account>();

  if (account) {
    await env.developer.prepare(
      'UPDATE accounts SET display_name=? WHERE id=?'
    ).bind(user.name, account.id).run();
    account = { ...account, email, display_name: user.name };
  } else {
    const salt = crypto.randomUUID() + crypto.randomUUID();
    const hash = crypto.randomUUID() + crypto.randomUUID();
    await env.developer.prepare(
      'INSERT INTO accounts(id,email,display_name,password_salt,password_hash,created_at) VALUES(?,?,?,?,?,?)'
    ).bind(user.id, email, user.name, salt, hash, created).run();
    account = { id: user.id, email, display_name: user.name };
  }

  let team = await env.developer.prepare(
    'SELECT id,name,role,team_type FROM teams WHERE owner_id=? ORDER BY created_at LIMIT 1'
  ).bind(account.id).first<{ id: string; name: string; role: string; team_type: string }>();

  if (!team) {
    const teamId = id();
    const teamName = user.name + ' Team';
    await env.developer.prepare(
      'INSERT INTO teams(id,owner_id,name,legal_name,team_type,role,created_at) VALUES(?,?,?,?,?,?,?)'
    ).bind(teamId, account.id, teamName, user.name, 'individual', 'Developer', created).run();
    team = { id: teamId, name: teamName, role: 'Developer', team_type: 'individual' };
  } else {
    await env.developer.prepare('UPDATE teams SET role=? WHERE id=?').bind('Developer', team.id).run();
    team.role = 'Developer';
  }

  return { account, team };
}

async function createLocalSession(env: Env, userId: string) {
  const token = Array.from(crypto.getRandomValues(new Uint8Array(32)), value => value.toString(16).padStart(2, '0')).join('');
  const created = now();
  await env.developer.prepare(
    'INSERT INTO sessions(token_hash,account_id,expires_at,created_at) VALUES(?,?,?,?)'
  ).bind(await sha(token), userId, new Date(Date.now() + SESSION_SECONDS * 1000).toISOString(), created).run();
  return cookie(token, SESSION_SECONDS);
}

export async function pineAuthenticate(request: Request, env: Env, path: '/api/auth/register' | '/api/auth/login', payload: Record<string, unknown>) {
  try {
    const upstream = await callPine(path, 'POST', request, payload);
    const data = await upstream.json().catch(() => ({})) as PineAuthResponse;
    if (!upstream.ok || !data.user) {
      const status = upstream.status >= 400 && upstream.status < 600 ? upstream.status : 502;
      return json({ error: data.error || (path.endsWith('register') ? 'Pine Accounts no pudo crear la cuenta' : 'correo o contraseña incorrectos'), upstream_status: status }, status);
    }

    const pineSession = pineSessionFromResponse(upstream);
    let developer = Boolean(pineSession);
    let warning: string | undefined;

    if (pineSession) {
      try {
        await ensureDeveloperAccount(data.user, pineSession);
      } catch (error) {
        developer = false;
        warning = error instanceof Error ? error.message : 'no se pudo preparar la Developer Account';
        console.error('Pine Developer Account setup failed:', warning);
      }
    } else {
      // Pine may authenticate successfully while an intermediary omits Set-Cookie.
      // Keep the already-verified login usable with our own HttpOnly session.
      // Pine-only features remain marked as pending instead of discarding the login.
      developer = false;
      warning = 'Pine Accounts valido la cuenta pero no entrego pine_session; la sesion del portal esta activa, aunque las funciones que necesitan la sesion de Pine quedan pendientes.';
      console.error('Pine auth response did not include the pine_session cookie');
    }

    const local = await ensureLocalIdentity(env, data.user);
    const localCookie = await createLocalSession(env, local.account.id);
    const headers = setCookies(localCookie, pineSession || undefined);
    return new Response(JSON.stringify({ account: local.account, team: local.team, developer, ...(warning ? { warning } : {}) }), { status: 200, headers });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'error desconocido';
    const timedOut = error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError');
    return json({
      error: timedOut
        ? 'Pine Accounts no respondio en 12 segundos. La solicitud se ha cancelado; revisa la disponibilidad de https://pineaccounts.pages.dev.'
        : 'Pine Developer: ' + message
    }, 502);
  }
}

export async function pineCurrent(request: Request, env: Env) {
  try {
    // The portal's own session is issued only after Pine has authenticated the user.
    // Prefer it for page reloads so a missing/expired upstream cookie does not log
    // the user out of the portal or make every navigation depend on Pine availability.
    const localAccount = await current(request, env);
    const pineSession = pineCookieFromRequest(request);

    if (localAccount) {
      const team = await teamFor(env, localAccount.id);
      if (!pineSession) {
        return json({
          account: localAccount,
          team,
          developer: false,
          warning: 'sesion del portal activa; Pine no envio pine_session, asi que las funciones que dependen directamente de Pine estan pendientes'
        });
      }
      return json({ account: localAccount, team, developer: true });
    }

    const upstream = await callPine('/api/auth/me', 'GET', request);
    const data = await upstream.json().catch(() => ({})) as PineAuthResponse;
    if (!upstream.ok || !data.user) return json({ error: 'inicia sesion para continuar' }, 401);

    let developer = Boolean(pineSession);
    let warning: string | undefined;
    if (pineSession) {
      try {
        await ensureDeveloperAccount(data.user, pineSession);
      } catch (error) {
        developer = false;
        warning = error instanceof Error ? error.message : 'no se pudo preparar la Developer Account';
        console.error('Pine Developer Account setup failed:', warning);
      }
    } else {
      developer = false;
      warning = 'Pine Accounts valido la sesion pero no entrego la cookie pine_session';
    }

    const local = await ensureLocalIdentity(env, data.user);
    const localCookie = await createLocalSession(env, local.account.id);
    const headers = setCookies(localCookie, pineSession || undefined);
    return new Response(JSON.stringify({ account: local.account, team: local.team, developer, ...(warning ? { warning } : {}) }), { headers });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'error desconocido';
    return json({ error: 'Pine Developer no pudo verificar la sesion: ' + message }, 502);
  }
}
export async function pineLogout(request: Request, env: Env) {
  try {
    await callPine('/api/auth/logout', 'POST', request, {});
  } catch {}
  const raw = request.headers.get('Cookie') || '';
  const localMatch = raw.match(/(?:^|;\\s*)pine_dev_session=([^;]+)/);
  if (localMatch) {
    const token = decodeURIComponent(localMatch[1]);
    await env.developer.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(token)).run().catch(() => {});
  }
  const headers = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  headers.append('set-cookie', 'pine_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  headers.append('set-cookie', 'pine_dev_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  return new Response(JSON.stringify({ ok: true }), { headers });
}

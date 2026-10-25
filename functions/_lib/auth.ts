export type Env = { developer: D1Database; certificates: D1Database };
export type Account = { id:string; email:string; display_name:string };
export const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
export const now=()=>new Date().toISOString();
export const id=()=>crypto.randomUUID();
const hex=(b:ArrayBuffer)=>Array.from(new Uint8Array(b),v=>v.toString(16).padStart(2,'0')).join('');
export async function sha(value:string){return hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)))}
export async function passwordHash(password:string,salt:string){const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:100000,hash:'SHA-256'},key,256);return btoa(String.fromCharCode(...new Uint8Array(bits)))}
export async function body(request:Request){try{return await request.json() as Record<string,unknown>}catch{return {}}}
export async function current(request:Request,env:Env):Promise<Account|null>{
 await ensureSchemas(env);
 const cookieHeader=request.headers.get('Cookie')||'';const match=cookieHeader.match(/(?:^|;\s*)pine_dev_session=([^;]+)/);if(!match)return null;
 const token=decodeURIComponent(match[1]);if(token.length<32)return null;
 const tokenHash=await sha(token);const row=await env.developer.prepare('SELECT a.id,a.email,a.display_name,s.expires_at FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=?').bind(tokenHash).first<Account&{expires_at:string}>();
 if(!row||row.expires_at<=now()){if(row)await env.developer.prepare('DELETE FROM sessions WHERE token_hash=?').bind(tokenHash).run();return null}
 return {id:row.id,email:row.email,display_name:row.display_name};
}
export async function requireAccount(request:Request,env:Env){const account=await current(request,env);if(!account)throw new Error('UNAUTHORIZED');return account}
export async function teamFor(env:Env,accountId:string){return await env.developer.prepare('SELECT id,name,role,team_type FROM teams WHERE owner_id=? ORDER BY created_at LIMIT 1').bind(accountId).first<{id:string;name:string;role:string;team_type:string}>()}
export function cookie(token:string,maxAge:number){return 'pine_dev_session='+encodeURIComponent(token)+'; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age='+maxAge}
export const clearCookie='pine_dev_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';

let schemaReady: Promise<void> | undefined;
export async function ensureSchemas(env: Env) {
 if (!schemaReady) schemaReady = (async () => {
  const developerSql = [
   "CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)",
   "CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, name TEXT NOT NULL, legal_name TEXT NOT NULL, team_type TEXT NOT NULL DEFAULT 'individual', role TEXT NOT NULL DEFAULT 'Account Holder', created_at TEXT NOT NULL)",
   "CREATE INDEX IF NOT EXISTS idx_teams_owner ON teams(owner_id)",
   "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL)",
   "CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id)",
   "CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)",
   "CREATE TABLE IF NOT EXISTS apps (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE, name TEXT NOT NULL, bundle_id TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'masOS', sku TEXT, status TEXT NOT NULL DEFAULT 'development', description TEXT, created_at TEXT NOT NULL, updated_at TEXT, UNIQUE(team_id,bundle_id))",
   "CREATE INDEX IF NOT EXISTS idx_apps_team_created ON apps(team_id,created_at)",
   "CREATE TABLE IF NOT EXISTS identifiers (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE, identifier TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'explicit', capabilities TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, UNIQUE(team_id,identifier))",
   "CREATE INDEX IF NOT EXISTS idx_identifiers_team_created ON identifiers(team_id,created_at)",
   "CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE, name TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'masOS', udid TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'enabled', created_at TEXT NOT NULL, UNIQUE(team_id,udid))",
   "CREATE INDEX IF NOT EXISTS idx_devices_team_created ON devices(team_id,created_at)",
   "CREATE TABLE IF NOT EXISTS submissions (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE, app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE, version TEXT NOT NULL, build TEXT NOT NULL, notes TEXT, status TEXT NOT NULL DEFAULT 'draft', created_at TEXT NOT NULL, updated_at TEXT)",
   "CREATE INDEX IF NOT EXISTS idx_submissions_team_created ON submissions(team_id,created_at)"
  ];
  const certificatesSql = [
   "CREATE TABLE IF NOT EXISTS signing_certificates (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, name TEXT NOT NULL, certificate_type TEXT NOT NULL, fingerprint TEXT NOT NULL, public_key TEXT NOT NULL, algorithm TEXT NOT NULL DEFAULT 'ECDSA-P256-SHA256', status TEXT NOT NULL DEFAULT 'active', expires_at TEXT, created_at TEXT NOT NULL, UNIQUE(team_id,fingerprint))",
   "CREATE INDEX IF NOT EXISTS idx_signing_certificates_team_created ON signing_certificates(team_id,created_at)",
   "CREATE TABLE IF NOT EXISTS provisioning_profiles (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, name TEXT NOT NULL, profile_type TEXT NOT NULL, app_identifier TEXT NOT NULL, certificate_ids TEXT NOT NULL DEFAULT '[]', device_ids TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'active', expires_at TEXT, created_at TEXT NOT NULL)",
   "CREATE INDEX IF NOT EXISTS idx_profiles_team_created ON provisioning_profiles(team_id,created_at)"
  ];
  for (const sql of developerSql) await env.developer.prepare(sql).run();
  for (const sql of certificatesSql) await env.certificates.prepare(sql).run();
 })();
 try { await schemaReady; } catch (error) { schemaReady = undefined; throw error; }
}

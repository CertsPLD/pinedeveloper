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

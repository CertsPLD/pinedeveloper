import {body,cookie,id,json,now,passwordHash,sha,teamFor,type Env} from '../../_lib/auth';
export const onRequestPost:PagesFunction<Env>=async({request,env})=>{
 const data=await body(request);const email=String(data.email||'').trim().toLowerCase();const name=String(data.name||'').trim();const password=String(data.password||'');
 if(!/^\\S+@\\S+\\.\\S+$/.test(email)||email.length>254)return json({error:'introduce un correo valido'},400);
 if(name.length<2||name.length>80)return json({error:'el nombre debe tener entre 2 y 80 caracteres'},400);
 if(password.length<10||password.length>128)return json({error:'la contraseña debe tener entre 10 y 128 caracteres'},400);
 if(await env.developer.prepare('SELECT id FROM accounts WHERE email=?').bind(email).first())return json({error:'ya existe una cuenta con ese correo'},409);
 const accountId=id(),salt=crypto.randomUUID()+crypto.randomUUID(),hash=await passwordHash(password,salt),created=now(),teamId=id();
 try{
 await env.developer.batch([
 env.developer.prepare('INSERT INTO accounts(id,email,display_name,password_salt,password_hash,created_at) VALUES(?,?,?,?,?,?)').bind(accountId,email,name,salt,hash,created),
 env.developer.prepare('INSERT INTO teams(id,owner_id,name,legal_name,team_type,role,created_at) VALUES(?,?,?,?,?,?,?)').bind(teamId,accountId,name+' Team',name,'individual','Account Holder',created)
 ]);
 const token=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');await env.developer.prepare('INSERT INTO sessions(token_hash,account_id,expires_at,created_at) VALUES(?,?,?,?)').bind(await sha(token),accountId,new Date(Date.now()+30*86400000).toISOString(),created).run();
 return new Response(JSON.stringify({account:{id:accountId,email,display_name:name},team:await teamFor(env,accountId)}),{headers:{'content-type':'application/json','cache-control':'no-store','set-cookie':cookie(token,30*86400)}});
 }catch{return json({error:'no se pudo crear la cuenta'},500)}
};

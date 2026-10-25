import {current,json,teamFor,id,now,body,type Env} from '../_lib/auth';
const allowed=['apps','identifiers','devices','submissions','certificates','profiles'];
const specs:Record<string,{db:'developer'|'certificates';table:string;fields:string[];required:string[]}>={
 apps:{db:'developer',table:'apps',fields:['name','bundle_id','platform','sku','status','description'],required:['name','bundle_id']},
 identifiers:{db:'developer',table:'identifiers',fields:['identifier','name','kind','capabilities'],required:['identifier','name']},
 devices:{db:'developer',table:'devices',fields:['name','platform','udid','status'],required:['name','udid']},
 submissions:{db:'developer',table:'submissions',fields:['app_id','version','build','notes','status'],required:['app_id','version','build']},
 certificates:{db:'certificates',table:'signing_certificates',fields:['name','certificate_type','fingerprint','public_key','algorithm','status','expires_at'],required:['name','certificate_type','fingerprint','public_key']},
 profiles:{db:'certificates',table:'provisioning_profiles',fields:['name','profile_type','app_identifier','certificate_ids','device_ids','status','expires_at'],required:['name','profile_type','app_identifier']}
};
const decode=(row:any)=>{for(const key of ['capabilities','certificate_ids','device_ids'])if(typeof row[key]==='string'){try{row[key]=JSON.parse(row[key])}catch{row[key]=[]}}return row};
export async function handleResource(request:Request,env:Env,resource:string,itemId?:string){
 const account=await current(request,env);if(!account)return json({error:'sesion no valida; inicia sesion de nuevo'},401);
 const team=await teamFor(env,account.id);if(!team)return json({error:'la cuenta no tiene equipo'},403);
 const pathItemId=itemId;
 if(resource==='overview'&&request.method==='GET'){const [apps,identifiers,devices,submissions,certificates,profiles]=await Promise.all([
 env.developer.prepare('SELECT COUNT(*) n FROM apps WHERE team_id=?').bind(team.id).first<{n:number}>(),
 env.developer.prepare('SELECT COUNT(*) n FROM identifiers WHERE team_id=?').bind(team.id).first<{n:number}>(),
 env.developer.prepare('SELECT COUNT(*) n FROM devices WHERE team_id=?').bind(team.id).first<{n:number}>(),
 env.developer.prepare('SELECT COUNT(*) n FROM submissions WHERE team_id=?').bind(team.id).first<{n:number}>(),
 env.certificates.prepare('SELECT COUNT(*) n FROM signing_certificates WHERE team_id=? AND status=?').bind(team.id,'active').first<{n:number}>(),
 env.certificates.prepare('SELECT COUNT(*) n FROM provisioning_profiles WHERE team_id=? AND status=?').bind(team.id,'active').first<{n:number}>()
 ]);return json({team,counts:{apps:apps?.n||0,identifiers:identifiers?.n||0,devices:devices?.n||0,submissions:submissions?.n||0,certificates:certificates?.n||0,profiles:profiles?.n||0}})}
 if(!allowed.includes(resource))return json({error:'endpoint no encontrado'},404);
 const spec=specs[resource],db=env[spec.db],method=request.method;
 if(method==='GET'){const rows=await db.prepare('SELECT * FROM '+spec.table+' WHERE team_id=? ORDER BY created_at DESC').bind(team.id).all();return json({items:(rows.results||[]).map(decode)})}
 if(method==='POST'){const data=await body(request);for(const key of spec.required)if(data[key]===undefined||String(data[key]).trim()==='')return json({error:'falta el campo '+key},400);
 if(resource==='apps'&&!/^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$/.test(String(data.bundle_id)))return json({error:'identificador invalido; usa formato com.ejemplo.app'},400);
 if(resource==='identifiers'&&!/^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$/.test(String(data.identifier)))return json({error:'identificador no valido'},400);
 if(resource==='devices'&&!/^[A-Fa-f0-9-]{12,64}$/.test(String(data.udid)))return json({error:'UDID no valido'},400);
 if(resource==='submissions'&&!await env.developer.prepare('SELECT id FROM apps WHERE id=? AND team_id=?').bind(String(data.app_id),team.id).first())return json({error:'la app no pertenece a este equipo'},400);
 const itemId=id(),created=now(),fields=spec.fields.filter(k=>data[k]!==undefined),values=fields.map(k=>['capabilities','certificate_ids','device_ids'].includes(k)?JSON.stringify(data[k]):String(data[k]));const cols=['id','team_id',...fields,'created_at'],vals=[itemId,team.id,...values,created];
 try{await db.prepare('INSERT INTO '+spec.table+'('+cols.join(',')+') VALUES('+cols.map(()=>'?').join(',')+')').bind(...vals).run();return json({item:{id:itemId,team_id:team.id,...Object.fromEntries(fields.map((k,i)=>[k,data[k]])),created_at:created}},201)}catch{return json({error:'no se pudo crear; comprueba que el identificador no exista ya'},409)}}
 if(method==='PATCH'||method==='PUT'){const targetId=pathItemId;if(!targetId)return json({error:'falta el id'},400);const data=await body(request),fields=spec.fields.filter(k=>data[k]!==undefined);if(!fields.length)return json({error:'no hay campos para actualizar'},400);const vals=fields.map(k=>['capabilities','certificate_ids','device_ids'].includes(k)?JSON.stringify(data[k]):String(data[k]));if(['apps','submissions'].includes(resource))fields.push('updated_at'),vals.push(now());const result=await db.prepare('UPDATE '+spec.table+' SET '+fields.map(k=>k+'=?').join(',')+' WHERE id=? AND team_id=?').bind(...vals,targetId,team.id).run();if(!result.meta.changes)return json({error:'registro no encontrado'},404);return json({ok:true})}
 if(method==='DELETE'){const targetId=pathItemId;if(!targetId)return json({error:'falta el id'},400);const result=await db.prepare('DELETE FROM '+spec.table+' WHERE id=? AND team_id=?').bind(targetId,team.id).run();if(!result.meta.changes)return json({error:'registro no encontrado'},404);return json({ok:true})}
 return json({error:'metodo no permitido'},405)
}

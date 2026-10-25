import {current,json,teamFor,type Env} from '../../_lib/auth';
export const onRequestGet:PagesFunction<Env>=async({request,env})=>{const account=await current(request,env);if(!account)return json({error:'inicia sesion para continuar'},401);return json({account,team:await teamFor(env,account.id)})};

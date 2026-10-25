import {handleResource} from '../_lib/resources';
import type {Env} from '../_lib/auth';
export const onRequest:PagesFunction<Env>=async({request,env,params})=>handleResource(request,env,String(params.resource||''));

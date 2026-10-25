import {body, json, type Env} from '../../_lib/auth';
import {pineAuthenticate} from '../../_lib/pine';

export const onRequestPost: PagesFunction<Env> = async ({request, env}) => {
  const data = await body(request);
  const email = String(data.email || '').trim().toLowerCase();
  const password = String(data.password || '');
  if (!email || !password) return json({error:'introduce el correo y la contraseña'},400);
  return pineAuthenticate(request, env, '/api/auth/login', {email, password});
};

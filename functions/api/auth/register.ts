import {body, json, type Env} from '../../_lib/auth';
import {pineAuthenticate} from '../../_lib/pine';

export const onRequestPost: PagesFunction<Env> = async ({request, env}) => {
  const data = await body(request);
  const email = String(data.email || '').trim().toLowerCase();
  const name = String(data.name || '').trim();
  const password = String(data.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email) || email.length > 254) return json({error:'introduce un correo valido'},400);
  if (name.length < 2 || name.length > 80) return json({error:'el nombre debe tener entre 2 y 80 caracteres'},400);
  if (password.length < 8 || password.length > 128) return json({error:'la contraseña debe tener entre 8 y 128 caracteres'},400);
  return pineAuthenticate(request, env, '/api/auth/register', {name, email, password});
};

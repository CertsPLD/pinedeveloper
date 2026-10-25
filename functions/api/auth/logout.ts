import {type Env} from '../../_lib/auth';
import {pineLogout} from '../../_lib/pine';

export const onRequestPost: PagesFunction<Env> = async ({request, env}) => pineLogout(request, env);

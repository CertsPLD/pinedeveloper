import {type Env} from '../../_lib/auth';
import {pineCurrent} from '../../_lib/pine';

export const onRequestGet: PagesFunction<Env> = async ({request, env}) => pineCurrent(request, env);

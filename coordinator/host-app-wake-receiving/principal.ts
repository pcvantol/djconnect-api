import {findInstallTokenByBearer} from '../../src/repositories/installTokens';
import {need} from '../host-app-wake/wire';
import {RequestWindow} from './request-window';
/** Actual existing djci lookup, without token issuance, rotation or inherited
 * purpose permissions. SQL mutations must recheck this record atomically. */
export async function authenticateCore(request:Request,db:D1Database,window:RequestWindow):Promise<Readonly<{id:string;ha_install_id:string}>>{
 window.check();const auth=request.headers.get('authorization');need(auth&&/^Bearer djci_[A-Za-z0-9_-]{43}$/.test(auth),'host_wake_core_auth',401);
 const row=await window.run(()=>findInstallTokenByBearer(db,auth.slice(7)));need(row&&!row.disabled,'host_wake_core_auth',401);window.check();
 return Object.freeze({id:row.id,ha_install_id:row.ha_install_id});
}

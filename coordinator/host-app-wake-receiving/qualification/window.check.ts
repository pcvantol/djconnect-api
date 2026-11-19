import {describe,it,expect,vi} from 'vitest';
import {RequestWindow} from '../request-window';
describe('one mandatory original per-request deadline, not native clock qualification',()=>{
 it('captures before the first body/auth await and never starts work after its original deadline',async()=>{
  let at=1000;const w=new RequestWindow(()=>at,new AbortController().signal);try{
   expect(w.capturedAt).toBe(1000);await w.run(async()=>{at=16000;});expect(w.expiresAt).toBe(31000);
   at=31000;const action=vi.fn(async()=>1);await expect(w.run(action)).rejects.toThrow('host_wake_transport_expired');expect(action).not.toHaveBeenCalled();
  }finally{w.close();}
 });
 it('denies a late crypto/auth reply without granting a fresh stage window',async()=>{
  let at=1000;const w=new RequestWindow(()=>at,new AbortController().signal);try{
   await expect(w.run(async()=>{at=31000;return 'late-proof';})).rejects.toThrow('host_wake_transport_expired');expect(w.expiresAt).toBe(31000);
  }finally{w.close();}
 });
 it('settles cancellation even when a body/crypto supplier ignores its AbortSignal',async()=>{
  const c=new AbortController(),w=new RequestWindow(()=>1000,c.signal);let resolve:(v:string)=>void=()=>{};
  try{const pending=w.run(()=>new Promise<string>(r=>{resolve=r;}));c.abort();await expect(pending).rejects.toThrow('host_wake_cancelled');resolve('late');await Promise.resolve();expect(()=>w.check()).toThrow('host_wake_cancelled');}finally{w.close();}
 });
 it('detects regression between later observations, not only before initial capture',async()=>{
  let at=1000;const w=new RequestWindow(()=>at,new AbortController().signal);try{at=2000;w.check();at=1500;expect(()=>w.check()).toThrow('host_wake_clock_regressed');}finally{w.close();}
 });
 it('does not invent a default clock or permit a cancelled initial attempt',()=>{
  expect(()=>new RequestWindow(undefined as never,new AbortController().signal)).toThrow('host_wake_clock_required');
  const c=new AbortController();c.abort();expect(()=>new RequestWindow(()=>1000,c.signal)).toThrow('host_wake_cancelled');
 });
});

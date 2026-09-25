import test from 'node:test';
import assert from 'node:assert/strict';
import { SessionManager } from '../src/session-manager.js';
const savedUid='11111111-1111-4111-8111-111111111111';
const freshUid='22222222-2222-4222-8222-222222222222';
const domainUid='33333333-3333-4333-8333-333333333333';
function fixture({target={},current={},switchError=false,wrongIdentity=false}={}) {
  const calls=[];let switched=false;
  const saved={uid:savedUid,state:'open',changes:12,'in-work':false,domain:{uid:domainUid},...target};
  const fresh={uid:freshUid,state:'open',changes:0,domain:{uid:domainUid},...current};
  const manager=new SessionManager();
  const client={command:async(command,body,version)=>{
    calls.push({command,body,version});
    if(command==='show-session')return body.uid===savedUid||switched?saved:fresh;
    if(command==='switch-session'){
      if(switchError)throw new Error('connection lost');
      switched=!wrongIdentity;return saved;
    }
    if(command==='show-task')return {tasks:[{'task-id':body['task-id'],status:'succeeded'}]};
    return {message:'OK'};
  }};
  manager.sessions.set('id',{domain:domainUid,sids:{primary:'secret'},baseClient:{withSid:()=>client},capabilities:{primary:{supported:['v2.1']}}});
  return {manager,calls};
}
test('recovery inspection uses a nonsecret session object UID and sanitized output',async()=>{
  const {manager,calls}=fixture({target:{sid:'must-not-escape',password:'must-not-escape'}});
  const snapshot=await manager.inspectSession('id',savedUid,'primary','v2.1');
  assert.equal(snapshot.uid,savedUid);assert.equal(snapshot.changes,12);assert.equal(snapshot.state,'open');
  assert.ok(!JSON.stringify(snapshot).includes('must-not-escape'));
  assert.deepEqual(calls,[{command:'show-session',body:{uid:savedUid},version:'v2.1'}]);
});
test('recovery resumes only the exact disconnected same-administrator session through switch-session',async()=>{
  const {manager,calls}=fixture();
  assert.equal((await manager.resumeSession('id',savedUid,'primary','v2.1')).uid,savedUid);
  assert.deepEqual(calls.map(c=>c.command),['show-session','show-session','switch-session','show-session']);
  assert.ok(calls.every(c=>c.version==='v2.1'));
  assert.deepEqual(calls[2].body,{uid:savedUid});
});
test('recovery refuses terminal, dirty and wrong-domain sessions before switching',async()=>{
  for(const settings of [{target:{state:'published'}},{target:{state:'pending_approval'}},{current:{changes:1}},{target:{domain:{uid:freshUid}}}]) {
    const {manager,calls}=fixture(settings);
    await assert.rejects(manager.resumeSession('id',savedUid,'primary','v2.1'));
    assert.ok(!calls.some(c=>c.command==='switch-session'));
  }
});
test('uncertain or mismatched switch disables further use of that authenticated context',async()=>{
  for(const settings of [{switchError:true},{wrongIdentity:true}]) {
    const {manager}=fixture(settings);
    await assert.rejects(manager.resumeSession('id',savedUid,'primary','v2.1'));
    await assert.rejects(async()=>manager.command('id','discard',{}),/could not verify/);
  }
});
test('inspection preserves unknown and invalid fields without declaring terminal recovery',async()=>{
  const {manager}=fixture({target:{state:undefined,changes:-1,'in-work':undefined}});
  const info=await manager.inspectSession('id',savedUid,'primary','v2.1');
  assert.equal(info.state,'unknown');assert.equal(info.changes,null);assert.equal(info.inWork,null);
  await assert.rejects(manager.inspectSession('id','not-a-session-uid'),/valid session/);
});
test('keepalive and task polling forward the pinned version',async()=>{
  const {manager,calls}=fixture();
  await manager.keepAlive('id','primary','v2.1');
  await manager.waitForTask('id','task','primary','v2.1');
  assert.deepEqual(calls.map(c=>[c.command,c.version]),[['keepalive','v2.1'],['show-task','v2.1']]);
});

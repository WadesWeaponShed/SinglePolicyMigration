import test from 'node:test';
import assert from 'node:assert/strict';
import {Workbench} from '../src/workflows/workbench.js';
import {OperationJournal} from '../src/workflows/journal.js';

function fixture({state='staged',observed={state:'open',changes:3},afterDiscard={state:'discarded',changes:0},resumeError,taskId,taskOutcome='failed',apiVersion='v2.1',supported=['2.1']}={}) {
  const journal=new OperationJournal(),calls=[];
  const domain={uid:'domain-a',name:'Destination'};
  let record=journal.begin({host:'https://mds.example',targetDomain:domain,targetName:'Copy',sessionUid:'original-session',apiVersion});
  record=journal.update(record,{state,...(taskId?{taskId}:{})});
  let discarded=false;
  const sessions={
    login:async options=>{calls.push({name:'login',options});return {sessionId:'authenticated-recovery'};},
    command:async(id,command,body,context,version)=>{
      calls.push({name:command,id,body,context,version});
      if(command==='show-api-versions')return {'supported-versions':supported,'current-version':supported.at(-1)};
      if(command==='discard'){discarded=true;return {};}
      if(command==='show-session')return {uid:'current-session',...(discarded?afterDiscard:observed)};
      throw new Error(`Unexpected command ${command}`);
    },
    inspectSession:async(id,uid,context,version)=>{calls.push({name:'inspect',id,uid,context,version});return {uid,...(discarded?afterDiscard:observed)};},
    resumeSession:async(id,uid,context,version)=>{calls.push({name:'resume',id,uid,context,version});if(resumeError)throw new Error(resumeError);return {uid,state:'open',changes:3};},
    waitForTask:async(id,task,context,version)=>{calls.push({name:'task',id,task,context,version});if(taskOutcome==='succeeded')return {};const error=new Error('Task outcome');error.taskOutcome=taskOutcome;throw error;},
    logout:async id=>{calls.push({name:'logout',id});return {};}
  };
  const w=new Workbench(sessions,{journal});
  w.connections.set('connection',{host:record.host,domains:[domain],credentials:{host:record.host,username:'admin',password:'secret'},lastUsed:Date.now()});
  const request={operationId:record.id,action:'inspect'};
  return {w,journal,calls,record,request};
}

test('recovery requires authenticated connection and matching host/domain visibility',async()=>{
  for(const mutate of [c=>{c.demo=true;},c=>{c.host='https://other.example';},c=>{c.domains=[{uid:'other-domain'}];}]) {
    const f=fixture();mutate(f.w.connections.get('connection'));
    await assert.rejects(f.w.recover('connection',f.request),/authenticated|unavailable/);
    assert.equal(f.calls.length,0);
    assert.equal(f.journal.unresolved().length,1);
  }
  const f=fixture();await assert.rejects(f.w.recover('missing',f.request),/expired/);
  assert.equal(f.calls.length,0);
});

test('verified terminal original session releases journal reservation without mutations',async()=>{
  for(const state of ['published','discarded']) {
    const f=fixture({observed:{state,changes:0}});
    const result=await f.w.recover('connection',f.request);
    assert.equal(result.inspection.state,state);
    assert.deepEqual(result.recoveries,[]);
    assert.equal(f.journal.list()[0].state,state);
    assert.ok(!f.calls.some(c=>['discard','resume','task'].includes(c.name)));
    assert.equal(f.calls[0].options.domain,'domain-a');
    assert.equal(f.calls[0].options.readOnly,true);
    assert.equal(f.calls.at(-1).name,'logout');
  }
});

test('inspection preserves unresolved reservations, including inconsistent terminal state',async()=>{
  for(const observed of [{state:'open',changes:3},{state:'published',changes:1},{state:'discarded',changes:null},{state:'unknown',changes:0}]) {
    const f=fixture({observed});const result=await f.w.recover('connection',f.request);
    assert.equal(result.recoveries.length,1);
    assert.match(result.message,/unresolved/);
    assert.ok(!f.calls.some(c=>['discard','resume'].includes(c.name)));
    assert.equal(f.journal.unresolved().length,1);
  }
});

test('discard recovery requires exact policy confirmation before authenticating',async()=>{
  for(const confirmName of [undefined,'Wrong','copy']) {
    const f=fixture();await assert.rejects(f.w.recover('connection',{...f.request,action:'discard',confirmName}),/exact recorded/);
    assert.equal(f.calls.length,0);
    assert.equal(f.journal.unresolved().length,1);
  }
});

test('unknown publish without recorded task blocks discard and preserves reservation',async()=>{
  for(const state of ['publishing','publish-unknown']) {
    const f=fixture({state});
    await assert.rejects(f.w.recover('connection',{...f.request,action:'discard',confirmName:'Copy'}),/no task ID/);
    assert.ok(!f.calls.some(c=>['discard','resume'].includes(c.name)));
    assert.equal(f.journal.unresolved().length,1);
    assert.equal(f.calls.at(-1).name,'logout');
  }
});

test('discard resumes and verifies original session identity before pinned discard',async()=>{
  const f=fixture();
  const result=await f.w.recover('connection',{...f.request,action:'discard',confirmName:'Copy'});
  assert.equal(result.inspection.state,'discarded');
  assert.equal(f.journal.unresolved().length,0);
  const resume=f.calls.findIndex(c=>c.name==='resume'),discard=f.calls.findIndex(c=>c.name==='discard');
  assert.ok(resume>=0 && resume<discard);
  assert.equal(f.calls[resume].uid,'original-session');
  assert.equal(f.calls[discard].id,'authenticated-recovery');
  assert.equal(f.calls[discard].version,'v2.1');
  assert.equal(f.calls[discard+1].name,'show-session');
  assert.deepEqual(f.calls[discard+1].body,{});
  assert.equal(f.calls[0].options.readOnly,false);
});

test('resume identity failure prevents discard and retains reservation',async()=>{
  const f=fixture({resumeError:'Resumed migration session identity could not be verified'});
  await assert.rejects(f.w.recover('connection',{...f.request,action:'discard',confirmName:'Copy'}),/identity/);
  assert.ok(!f.calls.some(c=>c.name==='discard'));
  assert.equal(f.journal.unresolved().length,1);
  assert.equal(f.calls.at(-1).name,'logout');
});

test('unverified discard keeps journal unresolved and blocks fresh ownership',async()=>{
  for(const afterDiscard of [{state:'discarded',changes:2},{state:'discarded',changes:null}]) {
    const f=fixture({afterDiscard});
    await assert.rejects(f.w.recover('connection',{...f.request,action:'discard',confirmName:'Copy'}),/could not be verified/);
    assert.equal(f.journal.unresolved().length,1);
    assert.throws(()=>f.journal.begin({host:f.record.host,targetDomain:f.record.targetDomain,targetName:'Other',sessionUid:'another'}),/unfinished migration/);
  }
});

test('publish recovery permits discard only after definitive task failure',async()=>{
  for(const taskOutcome of ['succeeded','uncertain','failed']) {
    const f=fixture({state:'publish-unknown',taskId:'task',taskOutcome});
    const action=f.w.recover('connection',{...f.request,action:'discard',confirmName:'Copy'});
    if(taskOutcome==='failed') {await action;assert.equal(f.journal.unresolved().length,0);}
    else {await assert.rejects(action);assert.ok(!f.calls.some(c=>c.name==='discard'));assert.equal(f.journal.unresolved().length,1);}
    assert.equal(f.calls.find(c=>c.name==='task').version,'v2.1');
  }
});

test('active owner prevents concurrent recovery before session login',async()=>{
  const f=fixture();f.w.connections.set('owner',{operation:f.record,job:{state:'staging'}});
  await assert.rejects(f.w.recover('connection',f.request),/still running/);
  assert.equal(f.calls.length,0);
});

test('different connections cannot recover one record concurrently',async()=>{
  const f=fixture();f.w.connections.set('second',{...f.w.connections.get('connection')});
  let release;const barrier=new Promise(resolve=>{release=resolve;});
  const inspect=f.w.sessions.inspectSession;
  f.w.sessions.inspectSession=async(...args)=>{await barrier;return inspect(...args);};
  const first=f.w.recover('connection',f.request);
  await new Promise(resolve=>setImmediate(resolve));
  await assert.rejects(f.w.recover('second',f.request),/Another recovery/);
  release();await first;
  assert.equal(f.w.recoveryLocks.size,0);
});


test('recovery pins persisted v1.9 across inspection, task, resume, and discard even when newer versions are supported',async()=>{
  const f=fixture({state:'publish-unknown',taskId:'task',apiVersion:'v1.9',supported:['1.9','2.1','2.2']});
  await f.w.recover('connection',{...f.request,action:'discard',confirmName:'Copy'});
  const calls=f.calls.filter(c=>['inspect','task','resume','discard','show-session'].includes(c.name));
  assert.ok(calls.length>=5);
  assert.ok(calls.every(c=>c.version==='v1.9'));
  assert.equal(f.journal.list()[0].apiVersion,'v1.9');
});

test('recovery refuses missing recorded API support instead of switching schemas',async()=>{
  const f=fixture({apiVersion:'v1.9',supported:['2.1','2.2']});
  await assert.rejects(f.w.recover('connection',f.request));
  assert.ok(!f.calls.some(c=>['inspect','task','resume','discard','show-session'].includes(c.name)));
  assert.equal(f.journal.unresolved().length,1);
});

test('publish and keepalive retain preview API v1.9 when server advertises newer schemas',async()=>{
  const calls=[],domain={uid:'target',name:'Target'};
  const sessions={
    command:async(id,name,body,context,version)=>{
      calls.push({name,version});
      if(name==='show-api-versions')return {'supported-versions':['1.9','2.1','2.2'],'current-version':'2.2'};
      if(name==='show-global-assignments')return {objects:[],total:0};
      if(name==='publish')return {'task-id':'task'};
      throw new Error(`Unexpected ${name}`);
    },
    waitForTask:async(id,task,context,version)=>{calls.push({name:'task',version});return {tasks:[{status:'succeeded'}]};},
    keepAlive:async(id,context,version)=>{calls.push({name:'keepalive',version});}
  };
  const w=new Workbench(sessions),c={host:'https://mds',rootId:'root',sourceId:'source',targetId:'target',sourceDomain:{uid:'source',name:'Source'},targetDomain:domain,plan:{targetName:'Copy',apiVersion:'v1.9'},job:{state:'staged'},lastUsed:Date.now()};
  w.connections.set('id',c);
  await w.expire();
  await w.finish('id',{action:'publish',confirmName:'Copy'});
  assert.equal(c.job.state,'published');
  assert.ok(calls.filter(c=>c.name!=='show-api-versions').every(c=>c.version==='v1.9'));
  c.job={state:'publish-unknown',taskId:'task'};
  await w.reconcile('id');
  assert.equal(calls.at(-1).version,'v1.9');
});

test('Python recovery discards the resumed session after an earlier batch task succeeded',async()=>{
  const f=fixture({state:'publish-unknown',taskId:'last-batch',taskOutcome:'succeeded'});
  f.record=f.journal.update(f.record,{engine:'python',pendingCommand:'add-objects-batch'});
  const result=await f.w.recover('connection',{...f.request,action:'discard',confirmName:'Copy'});
  assert.deepEqual(result.recoveries,[]);assert.match(result.message,/Earlier Python import batches/);
  assert.ok(f.calls.some(c=>c.name==='resume'));assert.ok(f.calls.some(c=>c.name==='discard'));
});
test('native creation recovery waits for terminal tasks before resuming and discarding',async()=>{
 for(const command of ['add-objects-batch','add-threat-profile'])for(const taskOutcome of ['succeeded','failed','unknown']) {
  const f=fixture({state:'recovery-required',taskId:'creation-task',taskOutcome});
  f.record=f.journal.update(f.record,{pendingCommand:command});
  const request={...f.request,action:'discard',confirmName:'Copy'};
  if(taskOutcome==='unknown') {
   await assert.rejects(f.w.recover('connection',request),/Task outcome/);
   assert.ok(!f.calls.some(c=>['resume','discard'].includes(c.name)));assert.equal(f.journal.unresolved().length,1);
  }else {
   const result=await f.w.recover('connection',request);assert.deepEqual(result.recoveries,[]);
   assert.ok(f.calls.findIndex(c=>c.name==='task')<f.calls.findIndex(c=>c.name==='resume'));
   assert.ok(f.calls.some(c=>c.name==='discard'));
  }
 }
});
test('native asynchronous submission without a recorded task ID cannot be blindly discarded',async()=>{
 const f=fixture({state:'recovery-required'});f.journal.update(f.record,{pendingCommand:'add-objects-batch'});
 await assert.rejects(f.w.recover('connection',{...f.request,action:'discard',confirmName:'Copy'}),/without a recorded task ID/);
 assert.ok(!f.calls.some(c=>['resume','discard'].includes(c.name)));
});

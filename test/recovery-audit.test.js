import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { CheckPointClient } from '../src/check-point-client.js';
import { SessionManager } from '../src/session-manager.js';
import { Workbench } from '../src/workflows/workbench.js';
import { demoPlan } from '../src/workflows/demo.js';

test('truncated API response rejects instead of leaving a migration locked', async t => {
  const server=createServer((req,res)=>{
    res.writeHead(200,{'Content-Type':'application/json','Content-Length':'500'});
    res.write('{"uid":"');
    setTimeout(()=>res.destroy(),10);
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const client=new CheckPointClient({baseUrl:`http://127.0.0.1:${server.address().port}`,timeoutMs:100});
  let timer;
  try {
    await assert.rejects(Promise.race([
      client.command('add-host',{}),
      new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('response remained pending')),1000);})
    ]),error=>error.phase==='response-interrupted');
  } finally {clearTimeout(timer);}
});

test('task polling preserves definitive failure versus partial success', async()=>{
  const sessions=new SessionManager({taskPollAttempts:1});
  sessions.command=async()=>({tasks:[{'task-id':'t',status:'failed'}]});
  await assert.rejects(sessions.waitForTask('s','t'),error=>error.taskOutcome==='failed');
  for(const statuses of [['partially succeeded'],['failed','succeeded'],['failed','in progress']]) {
    sessions.command=async()=>({tasks:statuses.map(status=>({'task-id':'t',status}))});
    await assert.rejects(sessions.waitForTask('s','t'),error=>error.taskOutcome==='uncertain');
  }
});

function stagedWorkbench({outcome='failed',changes=1,inspectionFails=false}={}) {
  const sessions={
    command:async(id,command)=>{
      if(command==='show-api-versions')return {'supported-versions':['2.1'],'current-version':'2.1'};
      if(command==='show-global-assignments')return {objects:[],total:0};
      if(command==='show-session') {if(inspectionFails)throw new Error('Session unavailable');return {changes};}
      if(command==='publish')return {'task-id':'task'};
      if(command==='discard'){changes=0;return {};}
      return {};
    },
    waitForTask:async()=>{const error=new Error('Task failed');error.taskOutcome=outcome;error.taskResult={tasks:[{status:outcome}]};throw error;}
  };
  const w=new Workbench(sessions),plan=demoPlan({scenario:'clean'});
  w.connections.set('c',{host:'https://mds',sourceDomain:plan.sourceDomain,targetDomain:plan.targetDomain,plan,job:{state:'staged'},lastUsed:Date.now(),rootId:'root',targetId:'t'});
  return {w,plan};
}

test('definitive publish failure automatically discards unpublished changes',async()=>{
  const {w,plan}=stagedWorkbench();
  assert.equal((await w.finish('c',{action:'publish',confirmName:plan.targetName})).job.state,'failed');
  assert.equal((await w.sessions.command('t','show-session')).changes,0);
});

test('definitive publish failure with clean session leaves a terminal failed state',async()=>{
  const {w,plan}=stagedWorkbench({changes:0});
  assert.equal((await w.finish('c',{action:'publish',confirmName:plan.targetName})).job.state,'failed');
});

test('partial or unverifiable publish failures remain non-discardable',async()=>{
  for(const settings of [{outcome:'uncertain'},{inspectionFails:true},{changes:undefined},{changes:-1}]) {
    const {w,plan}=stagedWorkbench(settings);
    if(Object.hasOwn(settings,'changes')&&settings.changes===undefined) w.sessions.command=async(id,cmd)=>cmd==='show-api-versions'?{'supported-versions':['2.1'],'current-version':'2.1'}:cmd==='show-global-assignments'?{objects:[],total:0}:cmd==='publish'?{'task-id':'task'}:{};
    assert.equal((await w.finish('c',{action:'publish',confirmName:plan.targetName})).job.state,'publish-unknown');
    await assert.rejects(w.finish('c',{action:'discard',confirmName:plan.targetName}),/no staged/);
  }
});

test('reconcile can resolve an earlier unknown outcome into verified failed recovery',async()=>{
  const {w,plan}=stagedWorkbench();
  const c=w.connections.get('c');c.job={state:'publish-unknown',taskId:'task'};
  assert.equal((await w.reconcile('c')).job.state,'failed');
  assert.equal(plan.state,'failed');
});

test('another connection cannot stage into a destination with unresolved migration changes',async()=>{
  for(const state of ['staging','staged','publishing','publish-unknown','recovery-required']) {
    const {w,plan}=stagedWorkbench();
    w.connections.get('c').job=null;
    const other={...w.connections.get('c'),job:{state}};
    w.connections.set('other',other);
    await assert.rejects(w.stage('c',{planId:plan.id,confirmName:plan.targetName}),/Another migration owns/);
    assert.equal(plan.state,'preview');
  }
});

test('discard acknowledgement with remaining changes does not release recovery',async()=>{
  const {w,plan}=stagedWorkbench();const original=w.sessions.command;
  w.sessions.command=async(id,command,...args)=>command==='discard'?{}:original(id,command,...args);
  const result=await w.finish('c',{action:'discard',confirmName:plan.targetName});
  assert.equal(result.job.state,'recovery-required');
  assert.match(result.job.message,/could not be verified/);
});

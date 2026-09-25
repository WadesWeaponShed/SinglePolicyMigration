import test from 'node:test';
import assert from 'node:assert/strict';
import { Workbench } from '../src/workflows/workbench.js';
import { createApp } from '../src/server.js';
import { collection } from '../src/workflows/migration.js';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

test('client status ignores old staged results while publish is pending and keeps polling after interruptions',async()=>{
  const elements=new Map();let timer,reply={job:{state:'staged',message:'Old staged result'}};
  const context=vm.createContext({
    document:{querySelector:selector=>{
      if(!elements.has(selector))elements.set(selector,{textContent:'',hidden:false,classList:{toggle(){}}});
      return elements.get(selector);
    }},Date,setInterval(){},clearTimeout(){},setTimeout:fn=>{timer=fn;},
    api:async()=>{if(reply instanceof Error)throw reply;return reply;}
  });
  const source=readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  vm.runInContext(source.slice(0,source.indexOf('async function api(')),context);
  vm.runInContext("connection={};beginActivity('finish');",context);
  await timer();assert.equal(vm.runInContext('activity.running',context),true);
  assert.equal(elements.get('#activityTitle').textContent,'Updating destination session');
  reply=new Error('Network interrupted');await timer();
  assert.equal(vm.runInContext('activity.running',context),true);
  assert.match(elements.get('#activityHeartbeat').textContent,/do not repeat/);
  reply={job:{state:'publishing',message:'Waiting for publish task'}};await timer();
  assert.equal(elements.get('#activityTitle').textContent,'Publishing changes');
  vm.runInContext("endActivity(activity.token,{job:{state:'published',message:'Published successfully'}});",context);
  assert.equal(vm.runInContext('activity.running',context),false);
  assert.equal(elements.get('#activityTitle').textContent,'Migration published');
  vm.runInContext("beginActivity('preview');endActivity(activity.token,{plan:{ruleCount:100,blockers:4,ready:false}});",context);
  assert.equal(elements.get('#activityTitle').textContent,'Scan complete · review required');
  assert.match(elements.get('#activityMessage').textContent,/Blockers: 4/);
});

test('status stays readable during a locked operation and retains failures',async t=>{
  const workbench=new Workbench({});
  const {id}=await workbench.connect({demo:true});
  const server=createApp(workbench);
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  t.after(()=>new Promise(r=>server.close(r)));
  const base=`http://127.0.0.1:${server.address().port}`;
  let release;
  const gate=new Promise(r=>{release=r;});
  const operation=workbench.locked(id,async c=>{
    workbench.progress(c,'Destination definitions: 25 of 80 objects read.');
    await gate;
    throw new Error('Destination session expired.');
  });
  const rejected=assert.rejects(operation,/session expired/);
  const poll=async()=>fetch(`${base}/api/job`,{method:'POST',headers:{'content-type':'application/json',cookie:`cma_session=${id}`},body:'{}'});
  const response=await poll();assert.equal(response.status,200);
  const running=(await response.json()).activity;
  assert.equal(running.state,'running');assert.match(running.message,/25 of 80/);
  assert.ok(running.startedAt<=running.updatedAt);
  await assert.rejects(workbench.locked(id,async()=>{}),/in progress/);
  release();await rejected;
  const failed=(await (await poll()).json()).activity;
  assert.equal(failed.state,'failed');assert.match(failed.message,/session expired/);
  await workbench.locked(id,async()=>{});
  const completed=(await (await poll()).json()).activity;
  assert.equal(completed.state,'completed');assert.notEqual(completed.id,running.id);
  const unauthorized=await fetch(`${base}/api/job`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  assert.equal(unauthorized.status,401);
});

test('inventory progress reports actual validated page counts',async()=>{
  const updates=[];
  const sessions={command:async(id,cmd,{offset})=>({objects:offset===0?[{uid:'one'},{uid:'two'}]:[{uid:'three'}],total:3})};
  const objects=await collection(sessions,'id','show-objects','objects',{},'primary',p=>updates.push(p));
  assert.equal(objects.length,3);
  assert.deepEqual(updates,[{completed:2,total:3},{completed:3,total:3}]);
});

test('rescan preserves an archive source instead of switching to the selected live policy',async()=>{
 const source=readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
 let handler;const calls=[];
 const context=vm.createContext({$:()=>({addEventListener:(event,fn)=>{handler=fn;}}),plan:{sourceDomain:{archive:true}},previewArchive:()=>calls.push('archive'),preview:()=>calls.push('live')});
 vm.runInContext(source.split('\n').find(line=>line.startsWith("$('#rescanButton').addEventListener")),context);
 handler();assert.deepEqual(calls,['archive']);
 context.plan={sourceDomain:{archive:false}};handler();assert.deepEqual(calls,['archive','live']);
});

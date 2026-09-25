import test from 'node:test';
import assert from 'node:assert/strict';
import { compareObjects, overlap, semantic, translate, hash } from '../src/workflows/objects.js';
import { globalCheck, collection, readRulebase, stagePlan, buildPlan, rulePayload } from '../src/workflows/migration.js';
import { demoPlan, demoObjects } from '../src/workflows/demo.js';
import { Workbench } from '../src/workflows/workbench.js';
import { SessionManager } from '../src/session-manager.js';
import { createApp } from '../src/server.js';

const host=(uid,name,ip)=>({uid,name,type:'host','ipv4-address':ip});
test('DNS names are traffic semantics, including inside groups, and cannot be renamed to resolve conflicts',()=>{
  const source={uid:'s',name:'.one.invalid',type:'dns-domain','is-sub-domain':true};
  const other={...source,uid:'d',name:'.two.invalid'};
  assert.equal(compareObjects([source],[other])[0].status,'create');
  assert.equal(compareObjects([source],[{...source,uid:'d',comments:'different metadata'}])[0].status,'reuse');
  const conflict=compareObjects([source],[{...source,uid:'d','is-sub-domain':false}])[0];
  assert.equal(conflict.status,'conflict');
  assert.equal(conflict.renameAllowed,false);
  const srcGroup={uid:'sg',name:'DNS',type:'group',members:['s']};
  const dstGroup={uid:'dg',name:'DNS',type:'group',members:['d']};
  assert.equal(compareObjects([source,srcGroup],[other,dstGroup])[1].status,'conflict');
});
test('same name with different address blocks; same definition with different UID reuses',()=>{
  const src=host('s','web','10.1.1.1');
  assert.equal(compareObjects([src],[host('d','web','10.1.1.2')])[0].status,'conflict');
  assert.equal(compareObjects([src],[host('d','web','10.1.1.1')])[0].status,'reuse');
  assert.equal(compareObjects([src],[host('d','web-alt','10.1.1.1')])[0].status,'reuse');
});
test('same name of another type, case-insensitive names and ambiguous equivalents block',()=>{
  const src=host('s','web','10.1.1.1');
  assert.equal(compareObjects([src],[{uid:'d',name:'WEB',type:'group',members:[]}])[0].status,'conflict');
  assert.equal(compareObjects([src],[host('a','one','10.1.1.1'),host('b','two','10.1.1.1')])[0].status,'conflict');
});
test('nested groups compare member definitions, not same-named members or domain UIDs',()=>{
  const source=[host('s','web','10.1.1.1'),{uid:'sg',name:'group',type:'group',members:['s']}];
  const dest=[host('d','web','10.1.1.2'),{uid:'dg',name:'group',type:'group',members:['d']}];
  assert.equal(compareObjects(source,dest)[1].status,'conflict');
  dest[0]['ipv4-address']='10.1.1.1';assert.equal(compareObjects(source,dest)[1].status,'reuse');
});
test('unknown properties, unsupported types, export placeholders and global objects block',()=>{
  for(const o of [{...host('a','web','10.0.0.1'),mystery:true},{uid:'b',name:'x',type:'simple-gateway'},{...host('c','export_error_1','10.0.0.1')},{...host('d','global','10.0.0.1'),domain:{'domain-type':'global domain'}}])assert.equal(compareObjects([o],[])[0].status,'blocked');
});
test('address ranges, subnet containment and protocol-specific service overlaps',()=>{
  const h=host('h','x','10.0.0.9');
  assert.ok(overlap(h,{type:'network',subnet4:'10.0.0.0','mask-length4':24}));
  assert.ok(overlap(h,{type:'address-range','ipv4-address-first':'10.0.0.8','ipv4-address-last':'10.0.0.10'}));
  assert.ok(overlap({type:'service-tcp',port:'443'},{type:'service-tcp',port:'400-500'}));
  assert.ok(!overlap({type:'service-tcp',port:'443'},{type:'service-udp',port:'443'}));
});
test('cyclic groups are blocked and references translate recursively',()=>{
  const g={uid:'g',name:'cycle',type:'group',members:['g']};
  assert.equal(compareObjects([g],[])[0].status,'blocked');
  assert.deepEqual(translate({members:[{uid:'s'},'s']},new Map([['s','d']])),{members:['d','d']});
  assert.throws(()=>translate({uid:'unknown'},new Map()),/Unresolved/);
});
test('global assignment checks fail on source or target including unrecognized data',()=>{
  const d={uid:'d',name:'Domain'};
  assert.ok(!globalCheck([{'dependent-domain':{uid:'d'}}],d,[]).ok);
  assert.ok(!globalCheck([],d,[{'access-layers':[{domain:{'domain-type':'global domain'}}]}]).ok);
  assert.throws(()=>globalCheck(null,d,[]),/unknown/);
  assert.throws(()=>globalCheck([{}],d,[]),/Unrecognized/);
  assert.ok(globalCheck([],d,[]).ok);
});
test('collection reads all pages and rejects incomplete inventory responses',async()=>{
  const offsets=[];const sessions={command:async(id,cmd,b)=>{offsets.push(b.offset);return {objects:b.offset===0?Array.from({length:500},(_,i)=>({uid:i})):[{uid:500}],total:501};}};
  assert.equal((await collection(sessions,'id','show-objects','objects')).length,501);assert.deepEqual(offsets,[0,500]);
  await assert.rejects(collection({command:async()=>({objects:[],total:1})},'id','show-objects','objects'),/pagination/);
  await assert.rejects(collection({command:async()=>({})},'id','show-objects','objects'),/Incomplete/);
});
test('rulebase pages preserve sections once and all rule order',async()=>{
  const sessions={command:async(id,c,b)=>({total:2,rulebase:[{uid:'section',type:'access-section',name:'Applications',rulebase:[{uid:b.offset?'rule101':'rule1',type:'access-rule'}]}]})};
  const result=await readRulebase(sessions,'s','show-access-rulebase',{});
  assert.deepEqual(result.items.map(x=>x.uid),['section','rule1','rule101']);
});
test('demo scenarios exercise real blockers and counts, not static success states',()=>{
  const conflict=demoPlan();assert.equal(conflict.counts.conflict,1);assert.equal(conflict.ready,false);
  const clean=demoPlan({scenario:'clean'});assert.equal(clean.ready,true);assert.equal(clean.ruleCount,5);assert.equal(clean.counts.create,7);assert.equal(clean.counts.reuse,6);
  assert.equal(demoPlan({scenario:'global'}).ready,false);
});
test('staging rejects blocked plan and dirty destination without mutations',async()=>{
  const calls=[];const sessions={command:async(id,c)=>{calls.push(c);return {changes:1};}};
  await assert.rejects(stagePlan({sessions,targetId:'t',plan:demoPlan()}),/blockers/);assert.deepEqual(calls,[]);
  await assert.rejects(stagePlan({sessions,targetId:'t',plan:demoPlan({scenario:'clean'})}),/empty/);assert.deepEqual(calls,['show-session']);
});
test('staging failure discards and never publishes or modifies reused objects',async()=>{
  const calls=[];const sessions={command:async(id,c,b)=>{calls.push({c,b});if(c==='show-session')return {changes:0};if(c==='add-host')throw new Error('Permission denied');return {};}};
  await assert.rejects(stagePlan({sessions,targetId:'t',plan:demoPlan({scenario:'clean'})}),/discarded/);
  assert.deepEqual(calls.slice(-2).map(x=>x.c),['discard','show-session']);assert.ok(!calls.some(x=>x.c==='publish'||x.c.startsWith('set-host')));
});
test('failed discard reports recovery required, never claims rollback',async()=>{
  const sessions={command:async(id,c)=>{if(c==='show-session')return {changes:0};throw new Error('Connection lost');}};
  await assert.rejects(stagePlan({sessions,targetId:'t',plan:demoPlan({scenario:'clean'})}),e=>e.state==='recovery-required'&&e.message.includes('discard could not be verified'));
});
test('track.type is translated to API enum rather than destination UID',()=>{
  const rule={type:'access-rule',action:{uid:'a'},track:{type:{uid:'l',name:'Log'}}};
  assert.deepEqual(rulePayload(rule,new Map([['a','new-a'],['l','new-l']])),{action:'new-a',track:{type:'log'}});
});
test('demo workflow requires matching confirmation, blocks replays and keeps publish separate',async()=>{
  const w=new Workbench({});const c=await w.connect({demo:true});
  await assert.rejects(w.select(c.id,{source:c.domains[0].uid,target:c.domains[0].uid}),/different/);
  await w.select(c.id,{source:c.domains[0].uid,target:c.domains[1].uid});
  const {plan}=await w.preview(c.id,{packageUid:'pkg-corp',targetName:'Migrated',scenario:'clean'});
  await assert.rejects(w.stage(c.id,{planId:plan.id,confirmName:'wrong'}),/Confirm/);
  await w.stage(c.id,{planId:plan.id,confirmName:'Migrated'});assert.equal(w.get(c.id).job.state,'staged');
  await assert.rejects(w.stage(c.id,{planId:plan.id,confirmName:'Migrated'}),/consumed/);
  await assert.rejects(w.logout(c.id),/Resolve/);
  const final=await w.finish(c.id,{action:'publish',confirmName:'Migrated'});assert.equal(final.job.state,'published');
  await w.logout(c.id);assert.throws(()=>w.get(c.id),/expired/);
});
test('expired previews and missing packages cannot be staged',async()=>{
  const w=new Workbench({}),c=await w.connect({demo:true});await w.select(c.id,{source:c.domains[0].uid,target:c.domains[1].uid});
  await assert.rejects(w.preview(c.id,{packageUid:'missing',targetName:'P'}),/available/);
  const {plan}=await w.preview(c.id,{packageUid:'pkg-corp',targetName:'P',scenario:'clean'});w.get(c.id).plan.expiresAt='2000-01-01';
  await assert.rejects(w.stage(c.id,{planId:plan.id,confirmName:'P'}),/expired/);
});
test('framework source session requests read-only contexts and never describes SIDs',async()=>{
  const calls=[];class Client{constructor(o){Object.assign(this,o);}withSid(sid){return new Client({...this,sid});}async command(c,b){calls.push({c,b});return {sid:'secret-cp-sid'};}}
  const s=new SessionManager({clientFactory:o=>new Client(o)});const data=await s.login({host:'mds.example.com',mdsMode:true,domain:'d',authMode:'api-key',apiKey:'secret-key',readOnly:true});
  assert.ok(calls.every(x=>x.b['read-only']===true));assert.ok(!JSON.stringify(data).includes('secret'));
});
test('publish task polling distinguishes succeeded, failed and timed out',async()=>{
  const s=new SessionManager({taskPollAttempts:2,taskPollIntervalMs:1});
  let count=0;s.command=async()=>({tasks:[{'task-id':'t',status:++count===2?'succeeded':'in progress'}]});assert.equal((await s.waitForTask('x','t')).tasks[0].status,'succeeded');
  s.command=async()=>({tasks:[{'task-id':'t',status:'failed'}]});await assert.rejects(s.waitForTask('x','t'),/failed/);
  s.command=async()=>({tasks:[{'task-id':'t',status:'in progress'}]});await assert.rejects(s.waitForTask('x','t'),/timed out/);
});
test('HTTP app requires session, rejects cross-origin writes and uses HttpOnly cookie',async t=>{
  const server=createApp(new Workbench({}));await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(r=>server.close(r)));
  const base=`http://127.0.0.1:${server.address().port}`;
  const post=(path,body,headers={})=>fetch(base+path,{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)});
  const page=await fetch(base+'/');assert.equal(page.status,200);assert.match(await page.text(),/Single Policy Move/);
  assert.equal((await fetch(base+'/migration.css')).status,200);
  assert.equal((await post('/api/preview',{})).status,401);
  assert.equal((await post('/api/connect',{demo:true},{origin:'https://evil.example'})).status,403);
  const login=await post('/api/connect',{demo:true});assert.equal(login.status,200);assert.match(login.headers.get('set-cookie'),/HttpOnly; SameSite=Strict/);
  const cookie=login.headers.get('set-cookie').split(';')[0];const body=await login.json();assert.ok(!body.id);
  const session=await post('/api/session',{}, {cookie});assert.equal((await session.json()).demo,true);
  const health=await (await fetch(base+'/api/health')).json();assert.ok(health.features.includes('dynamic-api-versions'));
  const catalog=await post('/api/catalog/status',{}, {cookie});assert.equal(catalog.status,200);assert.ok((await catalog.json()).installed.includes('v1.9'));
  const coverage=await post('/api/catalog/coverage',{version:'v1.9'}, {cookie});assert.equal(coverage.status,200);assert.equal((await coverage.json()).version,'v1.9');
  assert.equal((await post('/api/command',{}, {cookie})).status,404);
});

function fixture() {
  const calls=[],built={hosts:[],layers:[],rules:[],sections:[],nat:[]};let changed=false;
  const src={uid:'source',name:'Source'},dst={uid:'target',name:'Target'};
  const builtinDomain={'domain-type':'data domain',name:'Check Point Data'};
  const sourceObjects=[host('host-s','web','10.1.1.1'),{uid:'any',name:'Any',type:'CpmiAnyObject',domain:builtinDomain},{uid:'accept',name:'Accept',type:'RulebaseAction',domain:builtinDomain}];
  const baseRule={uid:'r',type:'access-rule',name:'HTTPS access',source:['any'],destination:['host-s'],service:['any'],action:'accept',enabled:true,track:{type:'Log'}};
  const pkg={uid:'pkg',name:'SourcePolicy',access:true,'access-layers':[{uid:'layer',name:'Network'}],'nat-policy':false,'threat-prevention':false};
  const sessions={command:async(id,cmd,b={})=>{
    calls.push({id,cmd,b});
    if(cmd==='show-api-versions')return {'current-version':'2.1','supported-versions':['2.1']};
    if(cmd==='show-global-assignments')return {objects:[],total:0};
    if(cmd==='show-packages')return {packages:id==='s'?[pkg]:[],total:id==='s'?1:0};
    if(cmd==='show-package')return b.uid==='new-package'?{uid:'new-package','access-layers':built.attached?[{uid:'new-layer',name:'Copy / Network'}]:[{uid:'auto-layer',name:'Generated Network'}]}:pkg;
    if(cmd==='show-objects')return {objects:sourceObjects.slice(1),total:2};
    if(cmd==='show-object')return {object:id==='t' && b.uid==='new-host'?{...built.hosts[0],uid:'new-host',type:'host'}:sourceObjects.find(x=>x.uid===b.uid)};
    if(cmd==='show-access-layer'){
      if(id==='t' && b.uid==='new-layer') {const {'add-default-rule':ignored,...settings}=built.layers[0];return {...settings,uid:'new-layer',type:'access-layer'};}
      return {uid:'layer',type:'access-layer',name:'Network',firewall:true};
    }
    if(cmd==='show-access-rulebase')return id==='s'?{total:1,rulebase:[{...baseRule,name:changed?'Changed':baseRule.name}],'objects-dictionary':sourceObjects}:{total:built.rules.length,rulebase:built.rules.map((r,i)=>({...r,uid:`new-rule-${i}`,type:'access-rule','rule-number':i+1})).map(({layer,position,...r})=>r),'objects-dictionary':[]};
    if(cmd==='show-session')return {uid:'fixture-session',changes:0,state:built.discarded?'discarded':'open'};
    if(cmd==='add-host'){built.hosts.push(b);return {uid:'new-host'};}
    if(cmd==='add-access-layer'){built.layers.push(b);return {uid:'new-layer'};}
    if(cmd==='add-package')return {uid:'new-package'};
    if(cmd==='add-access-rule'){built.rules.push(b);return {uid:`rule-${built.rules.length}`};}
    if(cmd==='set-package'){
      const change=b['access-layers'];
      assert.ok(!(change.add&&change.remove),'layer add/remove must be separate');
      if(change.add)built.added=true;
      if(change.remove){assert.equal(built.added,true);assert.deepEqual(change.remove,['Generated Network']);built.attached=true;}
      return {};
    }
    if(cmd==='discard'){built.discarded=true;return {};}
    if(cmd==='delete-access-layer'){assert.equal(built.attached,true,'detach before deletion');return {};}
    throw new Error(`Unexpected fixture command ${cmd}`);
  }};
  return {sessions,calls,built,src,dst,change:()=>{changed=true;},input:{host:'fixture.invalid',sessions,sourceId:'s',targetId:'t',rootId:'root',sourceDomain:src,targetDomain:dst,packageUid:'pkg',targetName:'Copy'}};
}
test('live adapter scans a package and stages verified rules using destination UIDs without publishing',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture();
  const progress=[];
  const plan=await scan({...f.input,onProgress:update=>progress.push(update.message)});assert.equal(plan.ready,true);assert.equal(plan.counts.create,1);assert.equal(plan.counts.reuse,2);
  assert.ok(progress.some(message=>message.startsWith('Source definitions:')));
  assert.ok(progress.some(message=>message.startsWith('Destination definitions:')));
  assert.match(progress.at(-1),/Comparing definitions/);
  const before=f.calls.length;const result=await stagePlan({sessions:f.sessions,targetId:'t',plan});
  assert.equal(result.state,'staged');assert.deepEqual(f.built.rules[0].destination,['new-host']);
  assert.equal(f.built.layers[0]['add-default-rule'],false);
  assert.ok(f.calls.slice(before).filter(c=>c.cmd.startsWith('add-')||c.cmd.startsWith('set-')||c.cmd.startsWith('delete-')).every(c=>c.id==='t'));
  assert.ok(!f.calls.some(c=>c.cmd==='publish'||c.cmd==='install-policy'||c.cmd==='discard'));
});
test('source drift invalidates a reviewed plan before any migration write',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture(),w=new Workbench(f.sessions);const plan=await scan(f.input);
  w.connections.set('connection',{...f.input,plan,input:{sourceDomain:f.src,targetDomain:f.dst,packageUid:'pkg',targetName:'Copy'},lastUsed:Date.now()});
  f.change();const before=f.calls.length;
  await w.stage('connection',{planId:plan.id,confirmName:'Copy'});
  while(w.locks.has('connection'))await new Promise(r=>setTimeout(r,1));
  assert.equal(w.get('connection').job.state,'failed');assert.match(w.get('connection').job.message,/changed after preview/);
  assert.ok(!f.calls.slice(before).some(c=>/^(add|set|delete|publish|discard)-?/.test(c.cmd)));
});

test('destination scan inventories all names without expanding unrelated Data Center objects',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture();
  const original=f.sessions.command;
  const external={uid:'external-dc',name:'web',type:'data-center-server'};
  f.sessions.command=async(id,cmd,body={},...rest)=>{
    if(cmd==='show-objects') {
      assert.equal(body['details-level'],'standard');
      assert.equal(body['dereference-group-members'],false);
      const page=await original(id,cmd,body,...rest);
      return {...page,objects:[...page.objects,external],total:page.total+1};
    }
    if(cmd==='show-object'&&body.uid===external.uid)throw new Error('Data Center service unavailable');
    return original(id,cmd,body,...rest);
  };
  const plan=await scan(f.input);
  const collision=plan.objects.find(o=>o.name==='web');
  assert.equal(collision.status,'conflict');assert.equal(collision.target.type,'data-center-server');
  assert.ok(plan.inventory.some(o=>o.uid===external.uid));
  assert.ok(!f.calls.some(c=>c.cmd.startsWith('add-')||c.cmd==='publish'));
});

test('destination definition failures still stop the scan with object and command context',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture();
  const original=f.sessions.command;
  f.sessions.command=async(id,cmd,body={},...rest)=>{
    if(cmd==='show-objects') {
      const page=await original(id,cmd,body,...rest);
      return {...page,objects:[...page.objects,host('required-host','existing','10.2.0.1')],total:page.total+1};
    }
    if(cmd==='show-object'&&body.uid==='required-host')throw new Error('Service unavailable');
    return original(id,cmd,body,...rest);
  };
  await assert.rejects(scan(f.input),/Cannot read destination definition existing \(show-object\): Service unavailable/);
});
test('global assignment prevents even source object/rule collection',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture(),original=f.sessions.command;
  f.sessions.command=async(id,cmd,b)=>cmd==='show-global-assignments'?{objects:[{'dependent-domain':'target'}],total:1}:original(id,cmd,b);
  const plan=await scan(f.input);assert.equal(plan.ready,false);assert.equal(plan.objects.length,0);assert.ok(!f.calls.some(c=>c.cmd==='show-access-rulebase'));
});
test('unknown publish outcome is not offered as discardable unpublished changes',async()=>{
  const w=new Workbench({command:async(id,c)=>c==='show-api-versions'?{'current-version':'2.1','supported-versions':['2.1']}:c==='show-global-assignments'?{objects:[],total:0}:{'task-id':'task'},waitForTask:async()=>{throw new Error('timed out');}});
  const plan=demoPlan({scenario:'clean'});plan.demo=false;
  w.connections.set('c',{sourceDomain:plan.sourceDomain,targetDomain:plan.targetDomain,plan,job:{state:'staged'},lastUsed:Date.now(),rootId:'root',targetId:'t'});
  const result=await w.finish('c',{action:'publish',confirmName:plan.targetName});assert.equal(result.job.state,'publish-unknown');
  await assert.rejects(w.finish('c',{action:'discard',confirmName:plan.targetName}),/no staged/);
  await assert.rejects(w.logout('c'),/Resolve/);
});
test('built-in services compare actual behavior and service expressions are conservative',()=>{
  const domain={'domain-type':'data domain',name:'Check Point Data'};
  const service={uid:'s',name:'https',type:'service-tcp',port:'443',domain};
  assert.equal(compareObjects([service],[{...service,uid:'t',port:'444'}])[0].status,'conflict');
  assert.ok(overlap(service,{type:'service-tcp',port:'>440'}));
  assert.ok(overlap(service,{type:'service-tcp',port:'80,443,8080-8090'}));
  assert.ok(!overlap(service,{type:'service-tcp',port:'<443'}));
  assert.ok(overlap(service,{type:'service-tcp',port:'unrecognized'}));
});

test('rename resolves a name collision, preserves source data and is reversible',async()=>{
  const w=new Workbench({}), c=await w.connect({demo:true});
  await w.select(c.id,{source:c.domains[0].uid,target:c.domains[1].uid});
  const first=(await w.preview(c.id,{packageUid:'pkg-corp',targetName:'Copy',scenario:'conflict'})).plan;
  const renamed=(await w.rename(c.id,{planId:first.id,objectUid:'db',newName:'database-migrated'})).plan;
  const row=renamed.objects.find(o=>o.uid==='db');
  assert.equal(row.status,'create');assert.equal(row.importName,'database-migrated');assert.equal(row.source.name,'database-primary');
  assert.equal(renamed.ready,true);assert.notEqual(renamed.id,first.id);assert.equal(renamed.expiresAt,first.expiresAt);
  assert.equal(w.describe(w.get(c.id)).plan.renames.db,'database-migrated');
  await assert.rejects(w.stage(c.id,{planId:first.id,confirmName:'Copy'}),/Confirm/);
  const rescanned=(await w.preview(c.id,{packageUid:'pkg-corp',targetName:'Copy',scenario:'conflict'})).plan;
  assert.equal(rescanned.objects.find(o=>o.uid==='db').importName,'database-migrated');
  const undone=(await w.rename(c.id,{planId:rescanned.id,objectUid:'db',reset:true})).plan;
  assert.equal(undone.ready,false);assert.equal(undone.objects.find(o=>o.uid==='db').status,'conflict');
  assert.equal(undone.objects.find(o=>o.uid==='db').importName,undefined);
});
test('rename validates destination, planned objects, reserved names and input without changing prior plan',async()=>{
  const w=new Workbench({}), c=await w.connect({demo:true});
  await w.select(c.id,{source:c.domains[0].uid,target:c.domains[1].uid});
  const {plan}=await w.preview(c.id,{packageUid:'pkg-corp',targetName:'Copy',scenario:'conflict'});
  for(const name of ['','   ','x'.repeat(101),'bad\nname','HTTPS','WEB-PROD-01','Copy','Copy / Network']){
    await assert.rejects(w.rename(c.id,{planId:plan.id,objectUid:'db',newName:name}));
    assert.equal(w.get(c.id).plan.id,plan.id);
  }
  await assert.rejects(w.rename(c.id,{planId:plan.id,objectUid:'https',newName:'NewService'}),/cannot be resolved/);
  await assert.rejects(w.rename(c.id,{planId:'stale',objectUid:'db',newName:'new'}),/current/);
  w.get(c.id).plan.expiresAt='2000-01-01';await assert.rejects(w.rename(c.id,{planId:plan.id,objectUid:'db',newName:'new'}),/expired/);
});
test('renaming resolves name collisions despite address containment but still rejects duplicate incoming names',async()=>{
  const {resolveObjectRenames}=await import('../src/workflows/objects.js');
  const source=[host('a','web','10.1.1.1'),host('b','db','10.2.1.1')];
  const dest=[host('x','web','10.3.1.1'),host('y','db','10.4.1.1'),{uid:'n',name:'network',type:'network',subnet4:'10.1.1.0','mask-length4':24}];
  const rows=compareObjects(source,dest);
  const renamed=resolveObjectRenames(rows,dest,{a:'imported-web'});
  assert.equal(renamed[0].status,'create');assert.equal(renamed[0].target,null);
  assert.throws(()=>resolveObjectRenames(rows,dest,{a:'same',b:'SAME'}),/Another object/);
});
test('rename stages the new name and keeps dependent rule UID mapping and drift checking intact',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture(),old=f.sessions.command;
  const conflict=host('host-d','web','10.8.1.1');
  f.sessions.command=async(id,cmd,b)=>{
    if(cmd==='show-objects'){const response=await old(id,cmd,b);return {...response,objects:[...response.objects,conflict],total:response.total+1};}
    if(id==='t'&&cmd==='show-object'&&b.uid===conflict.uid)return {object:conflict};
    return old(id,cmd,b);
  };
  const w=new Workbench(f.sessions),plan=await scan(f.input);
  w.connections.set('c',{...f.input,plan,input:{sourceDomain:f.src,targetDomain:f.dst,packageUid:'pkg',targetName:'Copy'},lastUsed:Date.now()});
  const resolved=(await w.rename('c',{planId:plan.id,objectUid:'host-s',newName:'web-copy'})).plan;
  assert.equal(resolved.ready,true);
  await w.stage('c',{planId:resolved.id,confirmName:'Copy'});
  while(w.locks.has('c'))await new Promise(r=>setTimeout(r,1));
  assert.equal(w.get('c').job.state,'staged',w.get('c').job.message);
  assert.equal(f.built.hosts[0].name,'web-copy');assert.deepEqual(f.built.rules[0].destination,['new-host']);
  assert.ok(!f.calls.some(c=>c.cmd==='set-host'));
});

test('rule expiration is blocked rather than silently omitted',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture();
  const command=f.sessions.command;
  f.sessions.command=async(id,cmd,b)=>{
    const response=await command(id,cmd,b);
    if(id==='s' && cmd==='show-access-rulebase') response.rulebase[0]['expiration-date-settings']={enabled:true};
    return response;
  };
  const plan=await scan(f.input);
  assert.equal(plan.ready,false);
  assert.ok(plan.checks.some(c=>!c.ok && c.detail.includes('expiration-date-settings')));
});
test('source object identity mismatch aborts scan before migration writes',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture();
  const command=f.sessions.command;
  f.sessions.command=async(id,cmd,b)=>{
    const response=await command(id,cmd,b);
    if(id==='s' && cmd==='show-object') return {object:{...response.object,uid:'unexpected'}};
    return response;
  };
  await assert.rejects(scan(f.input),/Cannot resolve/);
  assert.ok(!f.calls.some(c=>c.cmd.startsWith('add-')));
});

test('complete supported-policy scan and stage use negotiated v1.9 and v2.2',async()=>{
  const {scan}=await import('../src/workflows/migration.js');
  const {migrationApi}=await import('../src/workflows/compatibility.js');
  for(const version of ['1.9','2.2']) {
    const f=fixture(),original=f.sessions.command,versions=[];
    f.sessions.command=async(id,command,body,context,apiVersion)=>{
      if(command==='show-api-versions')return {'supported-versions':[version],'current-version':version};
      versions.push(apiVersion);return original(id,command,body,context);
    };
    const plan=await scan(f.input);
    assert.equal(plan.apiVersion,`v${version}`);
    assert.equal(plan.ready,true,JSON.stringify(plan.checks.filter(c=>!c.ok)));
    const api=await migrationApi(f.sessions,[{id:'t'}],{version:plan.apiVersion});
    assert.equal((await stagePlan({sessions:api,targetId:'t',plan})).state,'staged');
    assert.ok(versions.every(v=>v===`v${version}`));
  }
});

test('enabled HTTPS and TP blades with missing layer definitions block an incomplete scan',async()=>{
  const {scan}=await import('../src/workflows/migration.js');
  for(const flag of ['https-inspection-policy','threat-prevention']) {
    const f=fixture(),original=f.sessions.command;
    f.sessions.command=async(id,cmd,b)=>{const response=await original(id,cmd,b);return id==='s'&&cmd==='show-package'?{...response,[flag]:true}:response;};
    const plan=await scan(f.input);assert.equal(plan.ready,false);assert.ok(plan.checks.some(c=>!c.ok&&c.detail.includes(flag)));
    assert.ok(!f.calls.some(c=>c.cmd.startsWith('add-')));
  }
});

test('generated NAT alone does not import its owners; required objects keep NAT settings through staging',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture(),original=f.sessions.command;
  const natSettings={'auto-rule':true,method:'hide','hide-behind':'gateway','install-on':'All'};
  f.sessions.command=async(id,cmd,b)=>{
    if(cmd==='show-nat-rulebase')return {total:2,rulebase:[{uid:'auto-section',type:'nat-section',name:'Automatic',rulebase:[{uid:'auto1',type:'nat-rule','auto-generated':true,'original-source':'unused'},{uid:'auto2',type:'nat-rule','auto-generated':true,'original-source':'host-s'}]}],'objects-dictionary':[{uid:'unused',type:'network',name:'Unrelated pool'}]};
    const result=await original(id,cmd,b);
    if(id==='s'&&cmd==='show-package')return {...result,'nat-policy':true};
    if(id==='s'&&cmd==='show-object'&&b.uid==='host-s')return {object:{...result.object,'nat-settings':natSettings}};
    return result;
  };
  const plan=await scan(f.input);
  assert.equal(plan.ready,true);assert.deepEqual(plan.nat,[]);
  assert.ok(!plan.objects.some(o=>o.uid==='unused'));
  assert.ok(plan.checks.some(c=>c.name==='Automatic NAT'&&c.ok));
  await stagePlan({sessions:f.sessions,targetId:'t',plan});
  assert.deepEqual(f.built.hosts[0]['nat-settings'],natSettings);
  assert.ok(!f.calls.some(c=>c.cmd==='add-nat-rule'));
});

test('automatic NAT settings affect reuse and gateway-specific NAT stays blocked',()=>{
  const settings={'auto-rule':true,method:'static','ipv4-address':'203.0.113.1','install-on':'All'};
  const source={...host('s','web','10.0.0.1'),'nat-settings':settings};
  assert.equal(compareObjects([source],[{...source,uid:'d'}])[0].status,'reuse');
  assert.equal(compareObjects([source],[{...source,uid:'d','nat-settings':{...settings,'ipv4-address':'203.0.113.2'}}])[0].status,'conflict');
  assert.equal(compareObjects([{...source,'nat-settings':{...settings,'install-on':'source-gateway'}}],[])[0].status,'blocked');
});

test('manual NAT selection preserves manual sections and order around generated rows',async()=>{
  const {manualNatItems}=await import('../src/workflows/migration.js');
  const items=[{uid:'s',type:'nat-section'},{uid:'a',type:'nat-rule','auto-generated':true},{uid:'m',type:'nat-rule','auto-generated':false},{uid:'s2',type:'nat-section'},{uid:'a2',type:'nat-rule','auto-generated':true}];
  assert.deepEqual(manualNatItems(items).map(r=>r.uid),['s','m']);
});

test('broad address and service ranges do not conflict with or replace narrower definitions',()=>{
  const source=[host('h','web','10.1.2.3'),{uid:'n',name:'subnet',type:'network',subnet4:'10.1.2.0','mask-length4':24},{uid:'r',name:'range',type:'address-range','ipv4-address-first':'10.1.2.1','ipv4-address-last':'10.1.2.10'},...['tcp','udp'].map(p=>({uid:p,name:`app-${p}`,type:`service-${p}`,port:'50001'}))];
  const destination=[{uid:'all',name:'All_Internet',type:'address-range','ipv4-address-first':'0.0.0.0','ipv4-address-last':'255.255.255.255'},...['tcp','udp'].map(p=>({uid:`high-${p}`,name:`${p}-high-ports`,type:`service-${p}`,port:'>1023'}))];
  for(const row of compareObjects(source,destination)){assert.equal(row.status,'create');assert.equal(row.target,null);}
  for(const obj of source){
    assert.equal(compareObjects([obj],[...destination,{...obj,uid:`exact-${obj.uid}`,name:`exact-${obj.name}`}])[0].status,'reuse');
    assert.equal(compareObjects([obj],[...destination,{uid:`collision-${obj.uid}`,name:obj.name,type:'group',members:[]}])[0].status,'conflict');
  }
});

test('a default layer that remains attached is never deleted',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture(),original=f.sessions.command;
  const plan=await scan(f.input);
  f.sessions.command=async(id,cmd,b)=>{
    const response=await original(id,cmd,b);
    if(cmd==='show-package'&&b.uid==='new-package')return {...response,'access-layers':[...(f.built.attached?[{uid:'new-layer',name:'Copy / Network'}]:[]),{uid:'auto-layer',name:'Generated Network'}]};
    return response;
  };
  await assert.rejects(stagePlan({sessions:f.sessions,targetId:'t',plan}),/attachment or order differs/);
  assert.ok(!f.calls.some(c=>c.cmd==='delete-access-layer'));
  assert.equal(f.built.discarded,true);
});

test('NAT filtering excludes empty R82.10 generated and default headers without dropping manual sections',async()=>{
  const {manualNatItems}=await import('../src/workflows/migration.js');
  const headers=['Automatic Generated Rules : Machine Static NAT','Automatic Generated Rules : Machine Hide NAT','Automatic Generated Rules : Address Range Static NAT','Automatic Generated Rules : Network Static NAT','Automatic Generated Rules : Address Range Hide NAT','Manual Lower Rules'].map((name,i)=>({uid:`header-${i}`,name,type:'nat-section'}));
  assert.deepEqual(manualNatItems(headers),[]);
  const manual=[{uid:'custom',name:'Custom manual NAT',type:'nat-section'},{uid:'rule',type:'nat-rule','auto-generated':false}];
  assert.deepEqual(manualNatItems([...headers,...manual]),manual);
  assert.deepEqual(manualNatItems([...headers,...manual,{uid:'empty',name:'Empty trailing section',type:'nat-section'}]),manual);
});

test('empty NAT headers cause no NAT writes or false readback failure during staging',async()=>{
  const {scan}=await import('../src/workflows/migration.js');const f=fixture(),original=f.sessions.command;
  f.sessions.command=async(id,cmd,b)=>{
    if(cmd==='show-nat-rulebase')return {total:0,rulebase:[{uid:'empty',type:'nat-section',name:'Manual Lower Rules'}],'objects-dictionary':[]};
    const response=await original(id,cmd,b);
    return id==='s'&&cmd==='show-package'?{...response,'nat-policy':true}:response;
  };
  const plan=await scan(f.input);assert.deepEqual(plan.nat,[]);
  assert.equal((await stagePlan({sessions:f.sessions,targetId:'t',plan})).state,'staged');
  assert.ok(!f.calls.some(c=>c.cmd==='add-nat-section'||c.cmd==='add-nat-rule'));
});
test('inline Apply Layer actions omit inactive action/user-check settings and preserve the child reference',()=>{
 for(const name of ['Inner Layer','Apply Layer']) {
  const objects=new Map([['action',{uid:'action',name}]]),mapping=new Map([['action','target-action'],['child','target-child']]);
  const payload=rulePayload({type:'access-rule',action:'action','inline-layer':'child','action-settings':{},'user-check':{enabled:false}},mapping,objects);
  assert.equal(payload.action,'target-action');assert.equal(payload['inline-layer'],'target-child');assert.ok(!('action-settings' in payload));assert.ok(!('user-check' in payload));
 }
 const accepted=rulePayload({type:'access-rule',action:'Accept','action-settings':{'enable-identity-captive-portal':true}},new Map());
 assert.equal(accepted['action-settings']['enable-identity-captive-portal'],true);
});

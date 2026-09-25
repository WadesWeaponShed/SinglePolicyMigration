import test from 'node:test';
import assert from 'node:assert/strict';
import {readComparisonObject} from '../src/workflows/migration.js';
import {compareObjects} from '../src/workflows/objects.js';
const profile={uid:'profile',name:'Optimized',type:'threat-profile',domain:{uid:'data', 'domain-type':'data domain'},'anti-virus':true};
test('profile comparison reads typed full definitions on both endpoints',async()=>{
 const calls=[];
 const sessions={command:async(id,cmd,body)=>{calls.push({id,cmd,body});return cmd==='show-object'?{object:profile}:{...profile,'anti-virus-settings':{protocols:{'web-protocol':true}}};}};
 const source=(await readComparisonObject(sessions,'source','profile')).object;
 const target=(await readComparisonObject(sessions,'target','profile')).object;
 const schema={'threat-profile':['name','anti-virus','anti-virus-settings']};
 assert.equal(compareObjects([source],[target],schema)[0].status,'reuse');
 assert.equal(compareObjects([source],[{...target,'anti-virus-settings':{protocols:{'web-protocol':false}}}],schema)[0].status,'conflict');
 assert.deepEqual(calls.map(c=>c.cmd),['show-object','show-threat-profile','show-object','show-threat-profile']);
 assert.ok(calls.every(c=>c.body['details-level']==='full'));
});
test('profile discovery rejects changed identity and failed typed reads',async()=>{
 for(const patch of [{uid:'other'},{name:'Other'},{type:'host'},{domain:{uid:'other'}}])await assert.rejects(readComparisonObject({command:async(id,cmd)=>cmd==='show-object'?profile:{...profile,...patch}},'source','profile'),/identity changed/);
 await assert.rejects(readComparisonObject({command:async(id,cmd)=>{if(cmd==='show-object')return profile;throw new Error('Read denied');}},'source','profile'),/Read denied/);
});
test('builtin profile differences identify destination-only DNS settings without treating missing as false',()=>{
 const source={...profile,'advanced-dns-settings':{enabled:true,'dga-detection':'true'}};
 const target={...source,'advanced-dns-settings':{...source['advanced-dns-settings'],'activate-dns-trap':true,'trap-ipv4-address':''}};
 const row=compareObjects([source],[target],{'threat-profile':['name','advanced-dns-settings']})[0];
 assert.equal(row.status,'conflict');assert.match(row.reason,/advanced-dns-settings.activate-dns-trap \(not reported by source\)/);
 assert.match(row.reason,/advanced-dns-settings.trap-ipv4-address/);
});

test('explicit profile resolutions permit destination reuse or a validated unique custom copy',async()=>{
 const {resolveObjectRenames}=await import('../src/workflows/objects.js');
 const source={...profile,'advanced-dns-settings':{'dga-detection':'true'}};
 const target={...source,'advanced-dns-settings':{'dga-detection':'false'}};
 const schema={'threat-profile':['name','anti-virus','advanced-dns-settings']};
 const rows=compareObjects([source],[target],schema);
 const resolve=choice=>resolveObjectRenames(rows,[target],{profile:choice},[],schema);
 const reused=resolve({action:'reuse-profile',targetUid:'profile'})[0];assert.equal(reused.status,'reuse');assert.equal(reused.target,target);
 const copied=resolve({action:'copy-profile',name:'Optimized_MIGRATED'})[0];assert.equal(copied.status,'create');assert.equal(copied.importName,'Optimized_MIGRATED');assert.equal(copied.source,source);
 assert.throws(()=>resolve({action:'reuse-profile',targetUid:'missing'}),/unavailable/);
 assert.throws(()=>resolve({action:'copy-profile',name:'Optimized'}),/unique/);
 assert.throws(()=>resolve({action:'copy-profile',name:'New\nProfile'}),/profile name/);
 const unknown={...source,'unknown-active-setting':true};
 assert.throws(()=>resolveObjectRenames(compareObjects([unknown],[target],schema),[target],{profile:{action:'copy-profile',name:'New'}},[],schema),/Cannot preserve/);
 assert.equal(resolveObjectRenames(rows,[target],{},[],schema)[0].status,'conflict');
});

test('profile choices survive plan rebuilding, remap references, and affect the fingerprint',async()=>{
 const {buildPlan,rulePayload}=await import('../src/workflows/migration.js');
 const target={...profile,uid:'target-profile','anti-virus':false};
 const schema={'threat-profile':['name','anti-virus']};
 const snapshot={targetName:'Copy',sourceDomain:{uid:'s'},targetDomain:{uid:'t'},checks:[],objects:compareObjects([profile],[target],schema),inventory:[target],layers:[],nat:[],package:{},options:{},objectSchema:schema};
 const initial=buildPlan(snapshot);assert.equal(initial.ready,false);assert.equal(initial.objects[0].profileResolutionAllowed,true);
 const choice={profile:{action:'reuse-profile',targetUid:'target-profile'}};
 const reused=buildPlan({...initial,renames:choice});assert.equal(reused.ready,true);assert.notEqual(initial.digest,reused.digest);
 assert.equal(buildPlan(reused).digest,reused.digest);
 assert.equal(rulePayload({type:'threat-rule',action:'profile'},new Map([['profile',reused.objects[0].target.uid]])).action,'target-profile');
 const copy=buildPlan({...initial,renames:{profile:{action:'copy-profile',name:'Custom'}}});assert.equal(copy.ready,true);assert.equal(copy.objects[0].status,'create');
 assert.equal(buildPlan({...copy,renames:{}}).ready,false);
});

test('workbench profile resolution requires the current unstaged plan and supports undo',async()=>{
 const {Workbench}=await import('../src/workflows/workbench.js');
 const {buildPlan}=await import('../src/workflows/migration.js');
 const w=new Workbench({}),login=await w.connect({demo:true}),c=w.get(login.id);
 const target={...profile,'anti-virus':false},schema={'threat-profile':['name','anti-virus']};
 c.plan=buildPlan({targetName:'Copy',sourceDomain:{uid:'s'},targetDomain:{uid:'t'},checks:[],objects:compareObjects([profile],[target],schema),inventory:[target],layers:[],nat:[],package:{},options:{},objectSchema:schema});c.input={};
 const old=c.plan.id;
 await w.rename(login.id,{planId:old,objectUid:'profile',profileAction:'reuse-profile'});assert.equal(c.plan.ready,true);
 await assert.rejects(w.rename(login.id,{planId:old,objectUid:'profile',profileAction:'copy-profile',newName:'New'}),/current/);
 await w.rename(login.id,{planId:c.plan.id,objectUid:'profile',reset:true});assert.equal(c.plan.ready,false);assert.deepEqual(c.input.renames,{});
 c.job={state:'staged'};await assert.rejects(w.rename(login.id,{planId:c.plan.id,objectUid:'profile',profileAction:'reuse-profile'}),/unstaged/);
});

test('missing built-in profiles offer a custom copy but cannot reuse an absent target',async()=>{
 const {resolveObjectRenames}=await import('../src/workflows/objects.js');const schema={'threat-profile':['name','anti-virus']};
 const rows=compareObjects([profile],[],schema);assert.equal(rows[0].profileResolutionAllowed,true);
 assert.equal(resolveObjectRenames(rows,[],{profile:{action:'copy-profile',name:'Optimized_Copy'}},[],schema)[0].status,'create');
 assert.throws(()=>resolveObjectRenames(rows,[],{profile:{action:'reuse-profile',targetUid:'missing'}},[],schema),/unavailable/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {runNativeBatch,batchRulePayload,canBatchRule} from '../src/workflows/batch.js';
import {stagePlan} from '../src/workflows/migration.js';
const clear={warnings:[],errors:[],'blocking-errors':[],'warnings-total':0,'errors-total':0,'blocking-errors-total':0};
function fixture({validation=clear,status='succeeded',response={'task-id':'task'}}={}) {
 const calls=[],progress=[];
 return {calls,progress,input:{targetId:'target',command:'add-objects-batch',body:{objects:[]},pollAttempts:2,pollIntervalMs:0,onProgress:update=>progress.push(update),sessions:{command:async(id,command,body)=>{
  calls.push({id,command,body});if(command==='add-objects-batch')return response;
  if(command==='show-task')return {tasks:[{'task-id':'task',status}]};
  if(command==='show-validations')return validation;throw new Error('Unexpected command');
 }}}};
}
test('native batches require terminal success and zero validations before accepting results',async()=>{
 const f=fixture();assert.equal((await runNativeBatch(f.input)).taskId,'task');
 assert.deepEqual(f.calls.map(c=>c.command),['add-objects-batch','show-task','show-validations']);
 assert.ok(f.progress.some(p=>p.taskId==='task'));assert.equal(f.progress.at(-1).taskId,undefined);
});
test('batch warnings, errors, truncated totals and missing validation fields all fail closed',async()=>{
 for(const validation of [{...clear,warnings:[{message:'unexpected'}],'warnings-total':1},{...clear,'errors-total':501},{...clear,'blocking-errors-total':1},{}]) {
  const f=fixture({validation});await assert.rejects(runNativeBatch(f.input),error=>!error.batchPending);
 }
});
test('validation results distinguish other sessions without hiding new or truncated warnings',async()=>{
 const existing=fixture({validation:{...clear,warnings:[{message:'Existing policy warning','current-session':false}],'warnings-total':1}});
 await runNativeBatch(existing.input);
 for(const warnings of [[{message:'New warning','current-session':true}],[{message:'No session identity'}]]) {
  const f=fixture({validation:{...clear,warnings,'warnings-total':1}});await assert.rejects(runNativeBatch(f.input),/current-session warnings/);
 }
 const truncated=fixture({validation:{...clear,warnings:[{message:'Existing','current-session':false}],'warnings-total':501}});
 await assert.rejects(runNativeBatch(truncated.input),/truncated/);
});
test('active or unidentified batch tasks retain their identity for recovery; terminal failures can discard',async()=>{
 for(const args of [{status:'in progress'},{response:{}},{status:'unknown'}]) {
  const f=fixture(args);await assert.rejects(runNativeBatch(f.input),error=>error.batchPending&&error.pendingCommand==='add-objects-batch');
 }
 const failed=fixture({status:'failed'});await assert.rejects(runNativeBatch(failed.input),error=>!error.batchPending&&/task failed/.test(error.message));
});
test('an already dispatched asynchronous creation is polled without sending it twice',async()=>{
 const f=fixture();await runNativeBatch({...f.input,initialResponse:{'task-id':'task'}});
 assert.deepEqual(f.calls.map(c=>c.command),['show-task','show-validations']);
});
test('task registration delays retry reads without redispatching writes',async()=>{
 const f=fixture(),base=f.input.sessions.command;let attempts=0;
 f.input.sessions.command=async(id,command,body)=>{
  if(command==='show-task'&&attempts++===0){const error=new Error('Requested object [task] not found');Object.assign(error,{command,phase:'api-response',response:{code:'generic_err_object_not_found'}});throw error;}
  return base(id,command,body);
 };
 assert.equal((await runNativeBatch(f.input)).taskId,'task');
 assert.equal(attempts,2);assert.equal(f.calls.filter(c=>c.command==='add-objects-batch').length,1);
 const partial=fixture({status:'partially succeeded'});await assert.rejects(runNativeBatch(partial.input),error=>!error.batchPending&&/partially succeeded/.test(error.message));
});

function stagingFixture({warnings=false,asynchronous=false,ruleBatches=false,corruptRules=false,corruptTracking=false}={}) {
 const calls=[],stored=new Map(),rules=[];let attached=false,layer;
 const objects=Array.from({length:asynchronous?1:10},(_,i)=>({uid:`source-${i}`,name:`Host ${i}`,type:'host','ipv4-address':`192.0.2.${i+1}`}));
 const plan={ready:true,blockers:0,targetName:'Batch copy',objects:objects.map(source=>({uid:source.uid,name:source.name,type:source.type,status:'create',source})),inventory:[],nat:[],layers:[{uid:'source-layer',kind:'access',type:'access-layer',name:'Access',targetName:'Batch Access',firewall:true,ordered:true,items:[]}]};
 if(ruleBatches)plan.layers[0].items=Array.from({length:3},(_,group)=>[{uid:`section${group}`,type:'access-section',name:`Section ${group}`},...Array.from({length:12},(_,i)=>({uid:`rule${group}-${i}`,name:`Rule ${group}-${i}`,type:'access-rule',source:['source-0'],enabled:false}))]).flat();
 const command=async(id,cmd,body={})=>{
  calls.push({cmd,body});
  if(cmd==='show-session')return {changes:0};
  if(cmd==='add-objects-batch'){for(const group of body.objects)for(const payload of group.list)stored.set(payload.name,{...payload,type:group.type,uid:`created-${stored.size}`});return {'task-id':'task'};}
  if(cmd==='add-host'&&asynchronous){stored.set(body.name,{...body,type:'host',uid:'created-async'});return {'task-id':'task'};}
  if(cmd==='show-task')return {tasks:[{'task-id':'task',status:'succeeded'}]};
  if(cmd==='show-validations')return warnings?{...clear,'warnings-total':1,warnings:[{message:'Unexpected batch warning'}]}:clear;
  if(cmd==='show-host')return stored.get(body.name);
  if(cmd==='show-object')return {object:[...stored.values()].find(o=>o.uid===body.uid)};
  if(cmd==='add-access-section'){rules.push({...body,type:'access-section',uid:`section-${rules.length}`});return {uid:rules.at(-1).uid};}
  const returnedRule=payload=>({...payload,...payload.track?.type==='log'?{track:{'enable-firewall-session':false,'per-connection':!corruptTracking,'per-session':false,...payload.track}}:{},type:'access-rule',uid:`rule-${rules.length}`});
  if(cmd==='add-access-rule'){rules.push(returnedRule(body));return {uid:rules.at(-1).uid};}
  if(cmd==='add-rules-batch'){for(const group of body.objects)for(const payload of corruptRules?[...group.list].reverse():group.list)rules.push(returnedRule(payload));return {'task-id':'task'};}
  if(cmd==='add-access-layer'){const {'add-default-rule':ignored,...payload}=body;layer={...payload,uid:'created-layer',type:'access-layer'};return {uid:layer.uid};}
  if(cmd==='show-access-layer')return layer;
  if(cmd==='add-package')return {uid:'package'};
  if(cmd==='set-package'){attached=true;return {};}
  if(cmd==='show-package')return {'access-layers':attached?[{uid:layer.uid,name:layer.name}]:[]};
  if(cmd==='show-access-rulebase')return {rulebase:rules,total:rules.filter(r=>r.type==='access-rule').length};
  if(cmd==='discard')return {};
  throw new Error(`Unexpected ${cmd}`);
 };
 return {calls,plan,sessions:{command,catalog:{commands:[{name:'add-host',asynchronous},...['add-objects-batch',...(ruleBatches?['add-rules-batch']:[]),'show-task','show-validations'].map(name=>({name}))]}}};
}
test('staging batches independent objects, resolves each new identity, and verifies definitions',async()=>{
 const f=stagingFixture();const result=await stagePlan({...f,targetId:'target'});
 assert.equal(result.state,'staged');assert.equal(f.calls.filter(c=>c.cmd==='add-objects-batch').length,1);
 assert.equal(f.calls.filter(c=>c.cmd==='show-host').length,10);assert.equal(f.calls.filter(c=>c.cmd==='show-object').length,10);
 assert.ok(!f.calls.some(c=>['add-host','publish','discard'].includes(c.cmd)));
});
test('batch validation warnings discard before creating policy layers',async()=>{
 const f=stagingFixture({warnings:true});await assert.rejects(stagePlan({...f,targetId:'target'}),/Unexpected batch warning.*discarded/);
 assert.ok(f.calls.some(c=>c.cmd==='discard'));assert.ok(!f.calls.some(c=>c.cmd==='add-access-layer'));
});
test('asynchronous single-object creation resolves its identity after task success',async()=>{
 const f=stagingFixture({asynchronous:true}),progress=[];
 assert.equal((await stagePlan({...f,targetId:'target',onProgress:update=>progress.push(update)})).state,'staged');
 assert.equal(f.calls.filter(c=>c.cmd==='add-host').length,1);assert.ok(progress.some(update=>update.taskId==='task'));
 assert.ok(f.calls.findIndex(c=>c.cmd==='show-task')<f.calls.findIndex(c=>c.cmd==='show-host'));
});
test('rule batches preserve section boundaries and are independently checked after task success',async()=>{
 for(const corruptRules of [false,true]) {
  const f=stagingFixture({ruleBatches:true,corruptRules});
  if(corruptRules){await assert.rejects(stagePlan({...f,targetId:'target'}),/rule verification failed.*discarded/);assert.ok(f.calls.some(c=>c.cmd==='discard'));}
  else {assert.equal((await stagePlan({...f,targetId:'target'})).state,'staged');assert.equal(f.calls.filter(c=>c.cmd==='add-rules-batch').length,3);assert.equal(f.calls.filter(c=>c.cmd==='add-access-section').length,3);assert.equal(f.calls.filter(c=>c.cmd==='show-validations').length,2);}
 }
});


test('batch transport only omits verified default logging flags; non-default flags use individual rules',()=>{
 const body={name:'Rule',track:{type:'log','enable-firewall-session':false,'per-connection':true,'per-session':false,accounting:false,alert:'none'}};
 const copy=structuredClone(body),batch=batchRulePayload(body);
 assert.deepEqual(body,copy);assert.deepEqual(batch.track,{type:'log',accounting:false,alert:'none'});
 for(const track of [{type:'log','enable-firewall-session':true},{type:'log','per-connection':false},{type:'log','per-session':true},{type:'detailed log','per-connection':true}]){
  assert.equal(canBatchRule({track}),false);assert.throws(()=>batchRulePayload({track}),/individual creation/);
 }
});

test('non-default tracking is created individually and batch defaults are verified, not assumed',async()=>{
 for(const corruptTracking of [false,true]) {
  const f=stagingFixture({ruleBatches:true,corruptTracking});
  for(const rule of f.plan.layers[0].items.filter(r=>r.type==='access-rule'))rule.track={type:'log','enable-firewall-session':false,'per-connection':true,'per-session':false};
  f.plan.layers[0].items[1].track['per-session']=true;
  if(corruptTracking)await assert.rejects(stagePlan({...f,targetId:'target'}),/track.*discarded/);
  else {assert.equal((await stagePlan({...f,targetId:'target'})).state,'staged');assert.equal(f.calls.filter(c=>c.cmd==='add-access-rule').length,1);assert.equal(f.calls.filter(c=>c.cmd==='add-rules-batch').length,3);}
 }
});
test('explicit asynchronous request rejection allows discard; uncertain failures still retain recovery',async()=>{
 for(const code of ['err_validation_failed','generic_err_missing_required_parameters','generic_err_invalid_parameter','generic_err_object_not_found']) {
  const f=fixture();f.input.sessions.command=async()=>{throw Object.assign(new Error('Rejected'),{phase:'api-response',response:{code}});};
  await assert.rejects(runNativeBatch(f.input),error=>!error.batchPending);
 }
 const f=fixture();f.input.sessions.command=async()=>{throw Object.assign(new Error('Server failure'),{phase:'api-response',response:{code:'internal_error'}});};
 await assert.rejects(runNativeBatch(f.input),error=>error.batchPending);
});

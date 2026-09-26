import test from 'node:test';
import assert from 'node:assert/strict';
import {Workbench} from '../src/workflows/workbench.js';
function fixture({task=true,failWait=false}={}) {
 const calls=[];const sessions={command:async(id,cmd,body,context,version)=>{
  calls.push({id,cmd,body,version});assert.equal(id,'destination');
  if(cmd==='show-api-versions')return {'current-version':'2.1','supported-versions':['2.1']};
  if(cmd==='run-ips-update')return task?{'task-id':'task'}:{};
  if(cmd==='show-updatable-objects-repository-content')return {objects:[],total:0};
  throw new Error(`Unexpected ${cmd}`);
 },waitForTask:async(id,taskId,context,version)=>{calls.push({id,cmd:'wait',taskId,version});if(failWait)throw new Error('Task polling timed out');return {tasks:[{'task-id':taskId,status:'succeeded'}]};}};
 const w=new Workbench(sessions);w.connections.set('connection',{host:'local-test',targetId:'destination',plan:{id:'preview',state:'preview',apiVersion:'v2.1',expiresAt:new Date(Date.now()+60000).toISOString(),inventory:[]}});
 return {w,calls,sessions,c:w.get('connection')};
}
test('IPS update is destination-only, pins API, waits for task and expires preview',async()=>{
 const {w,calls,c}=fixture({task:true});const result=await w.updateIps('connection',{planId:'preview'});
 assert.equal(Date.parse(result.plan.expiresAt),0);assert.match(result.message,/Rescan/);assert.equal(c.ipsUpdate,undefined);
 assert.deepEqual(calls.map(c=>c.cmd),['show-api-versions','run-ips-update','wait']);
 assert.equal(calls.find(c=>c.cmd==='wait').version,'v2.1');assert.equal(c.activity.state,'completed');
});
test('IPS update rejects stale previews and active migrations before sending commands',async()=>{
 for(const patch of [{demo:true},{targetId:null},{job:{state:'staged'}},{plan:{id:'different',state:'preview'}},{plan:{id:'preview',state:'staged'}}]){
  const {w,c,calls}=fixture();Object.assign(c,patch);await assert.rejects(w.updateIps('connection',{planId:'preview'}));assert.equal(calls.length,0);
 }
});
test('uncertain task polling retries status without submitting another IPS update',async()=>{
 const {w,c,calls,sessions}=fixture({task:true,failWait:true});await assert.rejects(w.updateIps('connection',{planId:'preview'}),/timed out/);
 assert.equal(c.ipsUpdate.taskId,'task');sessions.waitForTask=async()=>({tasks:[{status:'succeeded'}]});
 await w.updateIps('connection',{planId:'preview'});assert.equal(calls.filter(c=>c.cmd==='run-ips-update').length,1);
});
test('IPS update with a missing task ID stays unconfirmed and is not resubmitted',async()=>{
 const {w,calls,c}=fixture({task:false});
 await assert.rejects(w.updateIps('connection',{planId:'preview'}),/no task ID/);
 await assert.rejects(w.updateIps('connection',{planId:'preview'}),/no task ID/);
 assert.equal(calls.filter(c=>c.cmd==='run-ips-update').length,1);
 assert.equal(Date.parse(c.plan.expiresAt),0);
});
test('failed IPS task permits a new request; changed destination cannot poll old task',async()=>{
 const {w,c,sessions,calls}=fixture({failWait:true});
 await assert.rejects(w.updateIps('connection',{planId:'preview'}));
 c.targetId='other';await assert.rejects(w.updateIps('connection',{planId:'preview'}),/another destination/);
 c.targetId='destination';sessions.waitForTask=async()=>{const e=new Error('Task failed');e.taskOutcome='failed';throw e;};
 await assert.rejects(w.updateIps('connection',{planId:'preview'}),/Task failed/);
 assert.equal(c.ipsUpdate,undefined);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {Workbench} from '../src/workflows/workbench.js';
function fixture({task=false,failWait=false}={}) {
 const calls=[];const sessions={command:async(id,cmd,body,context,version)=>{
  calls.push({id,cmd,body,version});assert.equal(id,'destination');
  if(cmd==='show-api-versions')return {'current-version':'2.1','supported-versions':['2.1']};
  if(cmd==='update-updatable-objects-repository-content')return task?{'task-id':'task'}:{};
  if(cmd==='show-updatable-objects-repository-content')return {objects:[],total:0};
  throw new Error(`Unexpected ${cmd}`);
 },waitForTask:async(id,taskId,context,version)=>{calls.push({id,cmd:'wait',taskId,version});if(failWait)throw new Error('Task polling timed out');return {tasks:[{'task-id':taskId,status:'succeeded'}]};}};
 const w=new Workbench(sessions);w.connections.set('connection',{host:'local-test',targetId:'destination',plan:{id:'preview',state:'preview',apiVersion:'v2.1',expiresAt:new Date(Date.now()+60000).toISOString(),inventory:[]}});
 return {w,calls,sessions,c:w.get('connection')};
}
test('repository update is destination-only, pins API, waits for task and expires preview',async()=>{
 const {w,calls,c}=fixture({task:true});const result=await w.updateRepository('connection',{planId:'preview'});
 assert.equal(Date.parse(result.plan.expiresAt),0);assert.match(result.message,/Rescan/);assert.equal(c.repositoryUpdate,undefined);
 assert.deepEqual(calls.map(c=>c.cmd),['show-api-versions','update-updatable-objects-repository-content','wait','show-updatable-objects-repository-content']);
 assert.equal(calls.find(c=>c.cmd==='wait').version,'v2.1');assert.equal(c.activity.state,'completed');
});
test('repository update rejects stale previews and active migrations before sending commands',async()=>{
 for(const patch of [{demo:true},{targetId:null},{job:{state:'staged'}},{plan:{id:'different',state:'preview'}},{plan:{id:'preview',state:'staged'}}]){
  const {w,c,calls}=fixture();Object.assign(c,patch);await assert.rejects(w.updateRepository('connection',{planId:'preview'}));assert.equal(calls.length,0);
 }
});
test('uncertain task polling retries status without submitting another repository update',async()=>{
 const {w,c,calls,sessions}=fixture({task:true,failWait:true});await assert.rejects(w.updateRepository('connection',{planId:'preview'}),/timed out/);
 assert.equal(c.repositoryUpdate.taskId,'task');sessions.waitForTask=async()=>({tasks:[{status:'succeeded'}]});
 await w.updateRepository('connection',{planId:'preview'});assert.equal(calls.filter(c=>c.cmd==='update-updatable-objects-repository-content').length,1);
});
test('repository update does not report success when repository readback fails',async()=>{
 const {w,sessions,c}=fixture();const command=sessions.command;
 sessions.command=async(id,cmd,...args)=>{if(cmd==='show-updatable-objects-repository-content')throw new Error('Repository unavailable');return command(id,cmd,...args);};
 await assert.rejects(w.updateRepository('connection',{planId:'preview'}),/unavailable/);assert.equal(c.activity.state,'failed');assert.equal(Date.parse(c.plan.expiresAt),0);
});

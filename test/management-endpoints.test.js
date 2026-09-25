import test from 'node:test';
import assert from 'node:assert/strict';
import {Workbench} from '../src/workflows/workbench.js';
import {endpointCredentials,managementContext} from '../src/workflows/endpoints.js';
import {scan} from '../src/workflows/migration.js';
function fixture({failDestination=false}={}) {
 const calls=[],sessionsById=new Map();
 const sessions={login:async payload=>{calls.push({command:'login',payload});if(failDestination&&payload.host.includes('target'))throw new Error('Target unavailable');const sessionId=`session-${sessionsById.size}`;sessionsById.set(sessionId,payload);return {sessionId,baseUrl:payload.host.replace(/\/$/,'')};},logout:async id=>{calls.push({command:'logout',id});return {};},command:async(id,command,body,context)=>{
  calls.push({id,command,body,context});
  if(command==='show-domains')return {objects:[{uid:'domain',name:'CMA'}],total:1};
  if(command==='show-session')return {uid:'session',changes:0,domain:{uid:'same-standalone-uid',name:'Management','domain-type':'domain'}};
  if(command==='show-packages')return {packages:[],total:0};
  throw new Error(command);
 }};
 return {w:new Workbench(sessions),calls};
}
const request={mode:'pair',source:{host:'source.example',username:'source-admin',password:'source-secret'},target:{host:'target.example',authMode:'api-key',apiKey:'target-secret'}};
test('separate endpoints isolate credentials, source read-only access and target recovery identity',async()=>{
 const {w,calls}=fixture(),result=await w.connect(request),c=w.get(result.id);
 assert.equal(result.mode,'pair');assert.equal(result.host,'https://target.example');assert.equal(result.sourceHost,'https://source.example');
 assert.equal(c.sourceDomain.uid,c.targetDomain.uid);assert.notEqual(c.sourceDomain.endpoint,c.targetDomain.endpoint);
 assert.equal(calls[0].payload.readOnly,true);assert.equal(calls[2].payload.readOnly,false);
 assert.equal(c.credentials.apiKey,'target-secret');assert.ok(!JSON.stringify(result).includes('secret'));
 assert.deepEqual(managementContext(c),{rootId:null,sourceRootId:null,targetRootId:null});
 await assert.rejects(w.select(result.id,{}),/Reconnect/);await w.logout(result.id);
 assert.equal(calls.filter(c=>c.command==='logout').length,2);
});
test('separate MDS endpoints retain both management roots and resolve named domains',async()=>{
 const {w,calls}=fixture();const result=await w.connect({...request,source:{...request.source,domain:'CMA'},target:{...request.target,domain:'CMA'}}),c=w.get(result.id);
 assert.notEqual(c.sourceRootId,c.rootId);assert.equal(calls.filter(c=>c.command==='show-domains').length,2);
 assert.deepEqual(calls.filter(c=>c.command==='login').map(c=>c.payload.domain),['','domain','','domain']);
 await w.logout(result.id);assert.equal(calls.filter(c=>c.command==='logout').length,4);
});
test('failed endpoint setup closes every opened session and cannot retain a half-connection',async()=>{
 const {w,calls}=fixture({failDestination:true});await assert.rejects(w.connect(request),/Target unavailable/);
 assert.equal(w.connections.size,0);assert.equal(calls.filter(c=>c.command==='logout').length,1);
});
test('endpoint addresses preserve cloud tenant paths and reject embedded credentials and non-HTTPS',()=>{
 assert.equal(endpointCredentials({host:'https://tenant.example/tenant/token',smart1Cloud:true}).host,'https://tenant.example/tenant/token');
 for(const host of ['https://user:pass@example.com','https://example.com/path','https://example.com/?secret=1','http://example.com'])assert.throws(()=>endpointCredentials({host}));
});
test('global assignment reads use the correct root independently, and missing contexts never bypass checks',async()=>{
 const calls=[];
 const sessions={command:async(id,cmd)=>{
 calls.push([id,cmd]);
 if(cmd==='show-api-versions')return {'supported-versions':['2.1'],'current-version':'2.1'};
 if(cmd==='show-global-assignments')return {objects:id==='source-root'?[{'dependent-domain':{uid:'source'},'global-domain':{name:'Global'}}]:[],total:id==='source-root'?1:0};
 if(cmd==='show-packages')return {packages:[],total:0};
 throw new Error(cmd);
 }};
 const input={sessions,sourceId:'source-session',targetId:'target-session',sourceDomain:{uid:'source',name:'Source'},targetDomain:{uid:'target',name:'Target'},sourceRootId:'source-root',targetRootId:'target-root',targetName:'Copy'};
 const plan=await scan(input);assert.equal(plan.ready,false);assert.ok(plan.checks.some(c=>c.name==='Global policy · Source'&&!c.ok));
 assert.deepEqual(calls.filter(c=>c[1]==='show-global-assignments').map(c=>c[0]),['source-root','target-root']);
 await assert.rejects(scan({...input,sourceRootId:undefined,targetRootId:undefined}),/Explicit management contexts/);
});

test('native migration opens only the authenticated contexts it needs',async()=>{
 const {SessionManager}=await import('../src/session-manager.js');const logins=[];
 const manager=new SessionManager({clientFactory:()=>({command:async(command,body)=>{assert.equal(command,'login');logins.push(body);return {sid:'session-'+logins.length};}})});
 await manager.login({host:'mds.example',username:'admin',password:'test',mdsMode:true,auxiliaryContexts:false,readOnly:true});
 await manager.login({host:'mds.example',username:'admin',password:'test',domain:'CMA',mdsMode:false,auxiliaryContexts:false,readOnly:true});
 assert.equal(logins.length,2);assert.ok(!logins.some(body=>['Global','System Data'].includes(body.domain)));
});

test('expired read sessions refresh without replacing a destination session or replaying mutations',async()=>{
 const {w,calls}=fixture(),result=await w.connect(request),c=w.get(result.id),originalTarget=c.targetId,originalSource=c.sourceId;
 w.sessions.keepAlive=async id=>{if(id===originalSource){const error=new Error('Wrong session id');Object.assign(error,{phase:'api-response',response:{code:'generic_err_wrong_session_id'}});throw error;}};
 await w.refreshExpiredReads(c);assert.notEqual(c.sourceId,originalSource);assert.equal(c.targetId,originalTarget);
 const lastLogin=calls.filter(c=>c.command==='login').at(-1).payload;assert.equal(lastLogin.readOnly,true);assert.equal(lastLogin.host,'https://source.example');assert.equal(lastLogin.mdsMode,false);
 w.sessions.keepAlive=async()=>{throw new Error('Network unavailable');};await assert.rejects(w.refreshExpiredReads(c),/Network unavailable/);
});

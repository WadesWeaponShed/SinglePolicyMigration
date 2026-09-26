import test from 'node:test';
import assert from 'node:assert/strict';
import {resolveNatGateway,normalizeLayerResponse,readComparisonObject,buildPlan,plannedObjectPayload} from '../src/workflows/migration.js';
import {compareObjects} from '../src/workflows/objects.js';
const uid='12345678-1234-1234-1234-123456789abc';
const network={uid:'network',type:'network',name:'LAN',subnet4:'192.0.2.0','mask-length4':24,'nat-settings':{'auto-rule':true,'hide-behind':'gateway',method:'hide','install-on':'Gateway'}};
test('named automatic NAT resolves one exact gateway and remaps it through rebuild choices',async()=>{
 const gateway={uid,type:'simple-gateway',name:'Gateway'};let calls=0;
 const sessions={command:async(id,cmd,body)=>{calls++;assert.equal(cmd,'show-objects');assert.equal(body.filter,'Gateway');return {objects:[gateway,{uid:'other',type:'host',name:'Gateway-other'}],total:2};}};
 const cache=new Map();const resolved=await resolveNatGateway(sessions,'source',network,cache);
 await resolveNatGateway(sessions,'source',{...network,name:'LAN 2'},cache);assert.equal(calls,1);
 assert.equal(network['nat-settings']['install-on'],'Gateway');assert.equal(resolved['nat-settings']['install-on'],uid);
 const schema={'simple-gateway':['name','ipv4-address']},target={...gateway,uid:'target',name:'Destination'};
 const plan=buildPlan({apiVersion:'v2.1',objects:compareObjects([resolved,gateway],[target],schema),inventory:[target],objectSchema:schema,checks:[],layers:[],nat:[],package:{},sourceDomain:{uid:'s'},targetDomain:{uid:'t'},targetName:'Copy',options:{rebuildGateways:true},renames:{[uid]:{action:'reuse-gateway',targetUid:'target'}}});
 assert.equal(plan.ready,true);assert.equal(plannedObjectPayload(plan.objects.find(o=>o.uid==='network'),plan,new Map([[uid,'target']]))['nat-settings']['install-on'],'target');
 for(const objects of [[],[{...gateway,type:'host'}],[gateway,{...gateway,uid:'duplicate'}]])await assert.rejects(resolveNatGateway({command:async()=>({objects,total:objects.length})},'s',network),/one exact/);
});
test('NAT All, resolved UIDs and disabled NAT never trigger gateway lookup',async()=>{
 const sessions={command:async()=>{throw new Error('Unexpected read');}};
 for(const nat of [{'auto-rule':true,'install-on':'All'},{'auto-rule':true,'install-on':uid},{'auto-rule':false,'install-on':'Old'}]){const object={'nat-settings':nat};assert.equal(await resolveNatGateway(sessions,'s',object),object);}
});
test('only empty nonwritable threat-layer permissions and false sharing are omitted',()=>{
 const layer={kind:'threat',type:'threat-layer',name:'Threat',shared:false,'permissions-profiles':[]};
 assert.deepEqual(normalizeLayerResponse(layer,{'threat-layer':['name']}),{kind:'threat',type:'threat-layer',name:'Threat'});
 assert.equal(layer.shared,false);
 for(const patch of [{shared:true},{'permissions-profiles':['permission']},{shared:null}]){const result=normalizeLayerResponse({...layer,...patch},{'threat-layer':['name']});for(const [key,value] of Object.entries(patch))assert.deepEqual(result[key],value);}
 assert.deepEqual(normalizeLayerResponse(layer,{'threat-layer':['name','shared','permissions-profiles']}),layer);
});
test('IPS overview lookup uses typed fallback only for missing built-in protections',async()=>{
 const reference={uid,name:'Protection',type:'CpmiSdTopicPerProfileDynamic',domain:{'domain-type':'data domain'}};
 const calls=[];const sessions={command:async(id,cmd)=>{calls.push(cmd);if(cmd==='show-object')throw new Error('Object overview not found');return reference;}};
 assert.deepEqual(await readComparisonObject(sessions,'target',uid,reference),reference);assert.deepEqual(calls,['show-object','show-threat-protection']);
 for(const referenceOverride of [undefined,{...reference,type:'host'}])await assert.rejects(readComparisonObject(sessions,'target',uid,referenceOverride),/not found/);
 await assert.rejects(readComparisonObject({command:async()=>{throw new Error('Permission denied');}},'target',uid,reference),/Permission denied/);
 await assert.rejects(readComparisonObject({command:async(id,cmd)=>{if(cmd==='show-object')throw new Error('not found');return {...reference,name:'Wrong'};}},'target',uid,reference),/identity/);
});
test('shared built-in IPS layers are isolated copies but ordinary shared threat layers remain blocked',()=>{
 const schema={'threat-layer':['name']};
 const ips={kind:'threat',name:'IPS','ips-layer':true,shared:true,'permissions-profiles':[]};
 assert.deepEqual(normalizeLayerResponse(ips,schema),{kind:'threat',name:'IPS','ips-layer':true});
 assert.equal(normalizeLayerResponse({...ips,'ips-layer':false},schema).shared,true);
 assert.deepEqual(normalizeLayerResponse({...ips,'permissions-profiles':['restricted']},schema)['permissions-profiles'],['restricted']);
});
test('destination IPS lookup may resolve a changed UID by exact name and built-in type only',async()=>{
 const reference={uid,name:'Protection',type:'CpmiSdTopicPerProfileDynamic',domain:{'domain-type':'data domain'}};
 const sessions={command:async(id,cmd,body)=>{if(!body.name)throw new Error('Requested object not found');assert.equal(cmd,'show-threat-protection');return {...reference,uid:'destination-id'};}};
 assert.equal((await readComparisonObject(sessions,'t',uid,reference,{allowNameFallback:true})).uid,'destination-id');
 await assert.rejects(readComparisonObject(sessions,'s',uid,reference),/not found/);
 for(const patch of [{name:'Other'},{type:'host'},{domain:{'domain-type':'domain'}}])await assert.rejects(readComparisonObject({command:async(id,cmd,body)=>{if(!body.name)throw new Error('not found');return {...reference,...patch};}},'t',uid,reference,{allowNameFallback:true}),/identity/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeMigrationOptions} from '../src/workflows/options.js';
import {buildPlan,plannedObjectPayload,changedPlanSections,scan} from '../src/workflows/migration.js';
import {compareObjects,resolveObjectRenames} from '../src/workflows/objects.js';
import {archiveSessions} from '../src/workflows/archives.js';
const host={uid:'host',name:'Host',type:'host','ipv4-address':'10.0.0.1'};
const base={apiVersion:'v2.1',sourceDomain:{uid:'source'},targetDomain:{uid:'target'},targetName:'Copy',package:{uid:'package',name:'Source'},layers:[],nat:[],inventory:[],checks:[],renames:{}};
test('options reject unknown controls, malformed values and empty scope',()=>{
 assert.equal(normalizeMigrationOptions().https,true);
 for(const value of [{all:true},{access:'false'},{objectSuffix:'\n'},{access:false,threat:false,https:false,nat:false}])assert.throws(()=>normalizeMigrationOptions(value));
});
test('explicit suffix creates requested copies and follows all dependency identities',()=>{
 const source=[host,{uid:'group',type:'group',name:'Group',members:[host.uid]}];
 const rows=compareObjects(source,[{...host,uid:'dest'}]);
 const renamed=resolveObjectRenames(rows,[{...host,uid:'dest'}],{},[],undefined,{objectSuffix:'_COPY'});
 assert.equal(renamed[0].status,'create');assert.equal(renamed[0].importName,'Host_COPY');
 assert.equal(renamed[1].importName,'Group_COPY');assert.deepEqual(renamed[1].source.members,['host']);
 assert.throws(()=>resolveObjectRenames(rows,[],{},[],undefined,{objectSuffix:'x'.repeat(100)}),/exceeds/);
});
test('suffix preserves DNS matching names and built-ins',()=>{
 const objects=[{uid:'dns',name:'.example.com',type:'dns-domain','is-sub-domain':true},{uid:'any',name:'Any',type:'CpmiAnyObject',domain:{'domain-type':'data domain'}}];
 const rows=resolveObjectRenames(compareObjects(objects,[objects[1]]),[objects[1]],{},[],undefined,{objectSuffix:'_COPY'});
 assert.equal(rows[0].importName,undefined);assert.equal(rows[1].importName,undefined);
});
test('explicit suffix makes a new copy despite multiple differently named equivalents',()=>{
 const destination=[{...host,uid:'one',name:'Other one'},{...host,uid:'two',name:'Other two'}];
 const [row]=resolveObjectRenames(compareObjects([host],destination),destination,{},[],undefined,{objectSuffix:'_COPY'});
 assert.equal(row.status,'create');assert.equal(row.target,null);assert.equal(row.importName,host.name+'_COPY');
 const collision=[...destination,{...host,uid:'collision',name:host.name+'_COPY','ipv4-address':'192.0.2.99'}];
 assert.equal(resolveObjectRenames(compareObjects([host],collision),collision,{},[],undefined,{objectSuffix:'_COPY'})[0].status,'conflict');
});
test('tagging is previewed, mapped before creation, and does not tag reused objects',()=>{
 const options=normalizeMigrationOptions({importTag:'Migration'});
 const plan=buildPlan({...base,options,objects:compareObjects([host],[])});
 assert.equal(plan.counts.create,2);assert.equal(plan.objects[0].type,'tag');
 const body=plannedObjectPayload(plan.objects[1],plan,new Map([[plan.importTagUid,'destination-tag']]));
 assert.deepEqual(body.tags,['destination-tag']);
 const reused=buildPlan({...base,options,inventory:[host],objects:compareObjects([host],[host])});
 assert.equal(reused.importTagUid,undefined);assert.equal(reused.counts.create,0);
 const changed=buildPlan({...base,options:normalizeMigrationOptions({importTag:'Other'}),objects:compareObjects([host],[])});
 assert.ok(changedPlanSections(plan,changed).includes('migration options'));
});
test('selected components are the only rulebases read and section omission preserves rules',async()=>{
 const any={uid:'any',name:'Any',type:'CpmiAnyObject',domain:{'domain-type':'data domain'}};
 const pkg={uid:'package',name:'Source',access:true,'access-layers':[{uid:'access',name:'Access'}],'threat-prevention':true,'threat-layers':[{uid:'threat',name:'Threat'}],'https-inspection-policy':true,'nat-policy':true};
 const snapshot={apiVersion:'v2.1',package:pkg,objects:[any],nat:[{uid:'nat',type:'nat-rule','original-source':'any',natPosition:'lower'}],layers:[{uid:'access',name:'Access',type:'access-layer',kind:'access',items:[{uid:'section',name:'Header',type:'access-section'},{uid:'rule',type:'access-rule',source:['any']}]},{uid:'threat',name:'Threat',type:'threat-layer',kind:'threat',items:[]}]};
 const calls=[];
 const real={command:async(id,cmd,body={})=>{
  calls.push([id,cmd]);
  if(cmd==='show-api-versions')return {'current-version':'2.1','supported-versions':['2.1']};
  if(cmd==='show-global-assignments'||cmd==='show-objects')return {objects:cmd==='show-objects'?[any]:[],total:cmd==='show-objects'?1:0};
  if(cmd==='show-packages')return {packages:[],total:0};
  if(cmd==='show-object')return {object:any};
  throw new Error(`Unexpected ${cmd}`);
 }};
 const wrapped=archiveSessions(real,'source',snapshot,'target');
 const sourceCalls=[];const sessions={command:async(id,cmd,...rest)=>{if(id==='source')sourceCalls.push(cmd);return wrapped.command(id,cmd,...rest);}};
 const input={sessions,sourceId:'source',targetId:'target',rootId:'root',sourceDomain:{uid:'s',name:'Archive',archive:true},targetDomain:{uid:'t',name:'Target'},packageUid:'package',targetName:'Copy'};
 const access=await scan({...input,options:{threat:false,https:false,nat:false,includeSections:false}});
 assert.equal(access.ready,true,JSON.stringify(access.checks));assert.equal(access.layers.length,1);assert.equal(access.layers[0].items.length,1);assert.equal(access.layers[0].items[0].uid,'rule');
 assert.ok(!sourceCalls.some(c=>c.includes('threat')||c.includes('https')||c.includes('nat')));
 const nat=await scan({...input,options:{access:false,threat:false,https:false,nat:true}});
 assert.equal(nat.ready,true,JSON.stringify(nat.checks));assert.equal(nat.nat.length,1);assert.equal(nat.layers[0].items.length,0);assert.equal(nat.layers[0].name,'NAT context');
});

test('known profile tagging API limitation is visible before staging, never silently lost',()=>{
 const source={uid:'profile',name:'Profile',type:'threat-profile',tags:[]},schema={'threat-profile':['name','tags'],tag:['name','tags','color','comments']};
 const plan=buildPlan({...base,objects:compareObjects([source],[],schema),objectSchema:schema,options:{importTag:'Migration'}});
 assert.equal(plan.importTagUid,undefined);assert.ok(plan.checks.some(c=>c.name==='Profile tagging compatibility'&&c.ok));
 assert.deepEqual(plannedObjectPayload(plan.objects[0],plan,new Map()).tags,[]);
 const blocked=buildPlan({...base,objects:compareObjects([{...source,tags:['source-tag']}],[],schema),objectSchema:schema});
 assert.ok(blocked.checks.some(c=>c.name==='Profile tagging preservation'&&!c.ok));assert.equal(blocked.ready,false);
});

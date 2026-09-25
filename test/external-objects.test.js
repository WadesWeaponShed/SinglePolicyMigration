import test from 'node:test';
import assert from 'node:assert/strict';
import {catalogsReady} from '../src/catalogs.js';
import {objectAdapters} from '../src/workflows/adapters.js';
import {objectPayload,unsupported,compareObjects,resolveObjectRenames} from '../src/workflows/objects.js';
import {verifyCreatedDefinition} from '../src/workflows/migration.js';
import {scan} from '../src/workflows/migration.js';
import {archiveSessions} from '../src/workflows/archives.js';
const schema=objectAdapters((await catalogsReady).get('v2.1'));
test('profile DNS response marker is omitted without dropping writable protection switches',()=>{
 const source={uid:'p',name:'Profile',type:'threat-profile','advanced-dns-settings':{enabled:true,'dga-detection':'false','dns-domain-tunneling':'true'}};
 assert.deepEqual(objectPayload(source,new Map(),schema)['advanced-dns-settings'],{'dga-detection':'false','dns-domain-tunneling':'true'});
 assert.match(unsupported({...source,'advanced-dns-settings':{...source['advanced-dns-settings'],enabled:false}},schema),/no writable API equivalent/);
 assert.equal(source['advanced-dns-settings'].enabled,true);
});
test('updatable objects retain repository identity without a writable name or suffix',()=>{
 const source={uid:'source',type:'updatable-object',name:'Repository object','uid-in-updatable-objects-repository':'repository-id',comments:'',color:'black',tags:[],'name-in-updatable-objects-repository':'Repository object','additional-properties':{},'updatable-object-meta-info':{}};
 assert.equal(unsupported(source,schema),'');
 const body=objectPayload(source,new Map(),schema);assert.equal(body.name,undefined);assert.equal(body['uid-in-updatable-objects-repository'],'repository-id');
 assert.equal(resolveObjectRenames(compareObjects([source],[],schema),[],{},[],schema,{objectSuffix:'_COPY'})[0].importName,undefined);
 verifyCreatedDefinition(body,{...source,uid:'target'},{uid:'target',type:source.type,objectSchema:schema,expectedName:source.name});
 assert.throws(()=>verifyCreatedDefinition(body,{...source,uid:'target','uid-in-updatable-objects-repository':'other'},{uid:'target',type:source.type,objectSchema:schema}),/verification failed/);
});
test('data-center objects preserve external URI and connection name while blocking deleted objects',()=>{
 const source={uid:'source',type:'data-center-object',name:'VM','uid-in-data-center':'external-vm','data-center':{uid:'source-connection',name:'vCenter'},deleted:false,'name-in-data-center':'VM','additional-properties':[],comments:'',color:'black',tags:[]};
 assert.equal(unsupported(source,schema),'');const body=objectPayload(source,new Map(),schema);
 assert.equal(body['data-center-name'],'vCenter');assert.equal(body['uid-in-data-center'],'external-vm');assert.equal(body['data-center'],undefined);
 verifyCreatedDefinition(body,{...source,uid:'target','data-center':{uid:'destination-connection',name:'vCenter'}},{uid:'target',type:source.type,objectSchema:schema,expectedName:'VM'});
 assert.match(unsupported({...source,deleted:true},schema),/inaccessible/);
 assert.throws(()=>objectPayload({...source,'data-center-name':'Other'},new Map(),schema),/Conflicting/);
});

test('updatable repository UUIDs are validated externally rather than fetched as management dependencies',async()=>{
 const repositoryId='12345678-1234-1234-1234-123456789abc';
 const object={uid:'updatable',name:'Repository item',type:'updatable-object','uid-in-updatable-objects-repository':repositoryId,comments:'',color:'black',tags:[]};
 const snapshot={apiVersion:'v2.1',package:{uid:'p',name:'Policy',access:true,'access-layers':[{uid:'l',name:'Layer'}]},objects:[object],layers:[{uid:'l',name:'Layer',type:'access-layer',kind:'access',firewall:true,items:[{uid:'r',name:'Rule',type:'access-rule',destination:['updatable']}]}],nat:[]};
 const queries=[];const real={command:async(id,cmd,body={})=>{
  queries.push({id,cmd,body});
  if(cmd==='show-api-versions')return {'current-version':'2.1','supported-versions':['2.1']};
  if(cmd==='show-global-assignments'||cmd==='show-objects')return {objects:[],total:0};
  if(cmd==='show-packages')return {packages:[],total:0};
  if(cmd==='show-updatable-objects-repository-content')return {objects:[{'uid-in-updatable-objects-repository':repositoryId}],total:1};
  throw new Error(`Unexpected ${cmd} ${body.uid}`);
 }};
 const plan=await scan({sessions:archiveSessions(real,'source',snapshot,'target'),sourceId:'source',targetId:'target',rootId:'root',sourceDomain:{uid:'s',name:'Archive',archive:true},targetDomain:{uid:'t',name:'Target'},packageUid:'p',targetName:'Copy'});
 assert.equal(plan.ready,true,JSON.stringify(plan.checks));
 assert.equal(queries.filter(q=>q.cmd==='show-updatable-objects-repository-content').length,1);
 assert.ok(!queries.some(q=>q.cmd==='show-object'&&q.body.uid===repositoryId));
});

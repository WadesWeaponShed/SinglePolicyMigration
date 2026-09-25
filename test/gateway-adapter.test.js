import test from 'node:test';
import assert from 'node:assert/strict';
import {objectPayload,unsupported,compareObjects} from '../src/workflows/objects.js';
import {buildPlan,plannedObjectPayload,verifyCreatedDefinition,verifyInheritedGatewaySettings} from '../src/workflows/migration.js';
const schema={'simple-gateway':['name','ipv4-address','firewall','vpn','interfaces','logs-settings','platform-portal-settings','https-inspection'], 'simple-cluster':['name','ipv4-address','members']};
const gateway={uid:'gateway',name:'Gateway',type:'simple-gateway','ipv4-address':'192.0.2.1',firewall:true,vpn:false,platform:'open server','sic-state':'initialized','dynamic-ip':false,'network-policy-management':false,'log-server':false,'externally-managed':false,'policy-server':false,'legacy-url-filtering':false,'autonomous-system-number':'0',interfaces:[{name:'eth0','ipv4-address':'192.0.2.1','ipv4-mask-length':24,topology:'external'}],'logs-settings':{'alert-when-free-disk-space-below-metrics':'mbytes','delete-when-free-disk-space-below-metrics':'mbytes'},'platform-portal-settings':{enabled:true},'https-inspection':{'outbound-certificate':{'override-profile':false,'profile-value':'inherited'}}};
test('gateway native payload preserves interfaces and blades and converts only explicit response metadata',()=>{
 const copy=structuredClone(gateway),body=objectPayload(gateway,new Map(),schema);
 assert.equal(unsupported(gateway,schema),'');assert.deepEqual(gateway,copy);
 assert.deepEqual(body.interfaces,gateway.interfaces);assert.equal(body.vpn,false);assert.equal(body.firewall,true);
 assert.deepEqual(body['logs-settings'],{'free-disk-space-metrics':'mbytes'});assert.deepEqual(body['https-inspection'],{'outbound-certificate':{'override-profile':false}});
 assert.ok(!('sic-state' in body));assert.ok(!('platform' in body));
 assert.doesNotThrow(()=>verifyCreatedDefinition(body,{...gateway,'sic-state':'uninitialized'},{uid:gateway.uid,type:gateway.type,objectSchema:schema}));
 for(const modified of [{...gateway,'dynamic-ip':true},{...gateway,'log-server':true},{...gateway,'autonomous-system-number':'65001'},{...gateway,'platform-portal-settings':{enabled:false}},{...gateway,'logs-settings':{'alert-when-free-disk-space-below-metrics':'mbytes','delete-when-free-disk-space-below-metrics':'percent'}}])assert.ok(unsupported(modified,schema));
});
test('cluster member definitions do not carry source identities or reuse colliding destination members',()=>{
 const source={uid:'cluster',type:'simple-cluster',name:'Cluster','ipv4-address':'192.0.2.10','cluster-members':[{uid:'source-member',name:'Member','ipv4-address':'192.0.2.11','sic-state':'initialized','auto-generate-ip':false}]};
 const data={apiVersion:'v2.1',sourceDomain:{uid:'s'},targetDomain:{uid:'t'},targetName:'Copy',package:{},layers:[],nat:[],checks:[],inventory:[{uid:'existing',type:'host',name:'Member'}],objectSchema:schema};
 let plan=buildPlan({...data,objects:compareObjects([source],data.inventory,schema)});
 assert.equal(plan.ready,false);assert.ok(plan.checks.some(c=>c.name==='Cluster member · Member'&&!c.ok));
 plan=buildPlan({...data,objects:compareObjects([source],data.inventory,schema),options:{objectSuffix:'_COPY'}});
 assert.equal(plan.ready,true);assert.deepEqual(plannedObjectPayload(plan.objects[0],plan,new Map()).members,[{name:'Member_COPY','ipv4-address':'192.0.2.11'}]);
 assert.ok(plan.checks.some(c=>c.name==='Gateway trust'&&c.severity==='notice'));
});
test('automatic firewall sizing excludes inactive manual limits while manual sizing preserves them',()=>{
 const settings={'auto-maximum-limit-for-concurrent-connections':true,'maximum-limit-for-concurrent-connections':25000,'auto-calculate-connections-hash-table-size-and-memory-pool':true,'connections-hash-size':8192,'memory-pool-size':100,'maximum-memory-pool-size':200};
 const input={...gateway,'firewall-settings':settings},fields={...schema,'simple-gateway':[...schema['simple-gateway'],'firewall-settings']};
 const body=objectPayload(input,new Map(),fields);
 assert.deepEqual(body['firewall-settings'],{'auto-maximum-limit-for-concurrent-connections':true,'auto-calculate-connections-hash-table-size-and-memory-pool':true});
 assert.equal(settings['maximum-limit-for-concurrent-connections'],25000);
 const manual={...settings,'auto-maximum-limit-for-concurrent-connections':false,'auto-calculate-connections-hash-table-size-and-memory-pool':false};
 assert.deepEqual(objectPayload({...gateway,'firewall-settings':manual},new Map(),fields)['firewall-settings'],manual);
 assert.doesNotThrow(()=>verifyCreatedDefinition(body,input,{uid:gateway.uid,type:gateway.type,objectSchema:fields}));
});
test('disabled gateway inspection and SAM purge omit API-rejected inactive parameters',()=>{
 const fields={...schema,'simple-gateway':[...schema['simple-gateway'],'enable-https-inspection','advanced-settings']};
 const input={...gateway,'enable-https-inspection':false,'advanced-settings':{sam:{'purge-sam-file':{enabled:false,'purge-when-size-reaches-to':100}}}};
 const body=objectPayload(input,new Map(),fields);
 assert.ok(!('enable-https-inspection' in body));assert.deepEqual(body['advanced-settings'].sam['purge-sam-file'],{enabled:false});
 assert.doesNotThrow(()=>verifyCreatedDefinition(body,input,{uid:gateway.uid,type:gateway.type,objectSchema:fields}));
 assert.throws(()=>verifyCreatedDefinition(body,{...input,'enable-https-inspection':true},{uid:gateway.uid,type:gateway.type,objectSchema:fields}));
});
test('monitoring-disabled gateway ignores inactive RTM fields but preserves enabled reporting',()=>{
 const fields={...schema,'simple-gateway':[...schema['simple-gateway'],'monitoring','rtm-counters-report','rtm-traffic-report','rtm-traffic-report-per-connection']};
 const obj={...gateway,monitoring:false,'rtm-counters-report':true,'rtm-traffic-report':false};
 assert.deepEqual(objectPayload(obj,new Map(),fields),objectPayload({...gateway,monitoring:false},new Map(),fields));
 assert.equal(objectPayload({...obj,monitoring:true},new Map(),fields)['rtm-counters-report'],true);
});
test('QoS-disabled gateway drops inactive logging options; ClusterXL agrees with its mode',()=>{
 const fields={...schema,'simple-gateway':[...schema['simple-gateway'],'qos']};
 const obj={...gateway,qos:false,'logs-settings':{'turn-on-qos-logging':true,'detect-new-citrix-ica-application-names':false}};
 assert.deepEqual(objectPayload(obj,new Map(),fields)['logs-settings'],{});
 assert.equal(objectPayload({...obj,qos:true},new Map(),fields)['logs-settings']['turn-on-qos-logging'],true);
 const cluster={type:'simple-cluster',name:'Cluster','cluster-mode':'cluster-xl-ha','cluster-xl':true,'save-logs-locally':false};
 assert.equal(unsupported(cluster,{'simple-cluster':['name','cluster-mode']}),'');
 assert.ok(unsupported({...cluster,'cluster-xl':false},{'simple-cluster':['name','cluster-mode']}));
 assert.ok(unsupported({...cluster,'save-logs-locally':true},{'simple-cluster':['name','cluster-mode']}));
});
test('gateway policy/log references remap the source management name and block unknown named servers',()=>{
 const source={...gateway,'send-logs-to-server':['Source'],'fetch-policy':['Source']},fields={...schema,'simple-gateway':[...schema['simple-gateway'],'send-logs-to-server','fetch-policy']};
 const data={apiVersion:'v2.1',sourceDomain:{uid:'s',name:'Source'},targetDomain:{uid:'t',name:'Target'},targetName:'Copy',package:{},layers:[],nat:[],checks:[],inventory:[],objectSchema:fields};
 const plan=buildPlan({...data,objects:compareObjects([source],[],fields)});
 assert.equal(plan.ready,true);const body=plannedObjectPayload(plan.objects[0],plan,new Map());assert.deepEqual(body['send-logs-to-server'],['Target']);assert.deepEqual(body['fetch-policy'],['Target']);
 const blocked=buildPlan({...data,objects:compareObjects([{...source,'send-logs-to-server':['Unknown']}],[],fields)});assert.equal(blocked.ready,false);assert.ok(blocked.checks.some(c=>!c.ok&&c.name.startsWith('Gateway management')));
});

test('gateway inherited profile values must retain effective behavior in the destination',()=>{
 const source={'https-inspection':{'bypass-on-failure':{'override-profile':false,'profile-value':true}}};
 assert.doesNotThrow(()=>verifyInheritedGatewaySettings(source,structuredClone(source)));
 assert.throws(()=>verifyInheritedGatewaySettings(source,{'https-inspection':{'bypass-on-failure':{'override-profile':false,'profile-value':false}}}),/Inherited gateway setting differs/);
 const reference={'override-profile':false,'profile-value':{uid:'source-cert'}};
 assert.doesNotThrow(()=>verifyInheritedGatewaySettings(reference,{'profile-value':{uid:'target-cert'}},new Map([['source-cert','target-cert']])));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {stagePlan,buildPlan,validatePlanCommands,ipsManualImpact,applyManualIps} from '../src/workflows/migration.js';
import {objectAdapters} from '../src/workflows/adapters.js';
import {catalogsReady} from '../src/catalogs.js';
import {validateCommand} from '../src/workflows/compatibility.js';
import {compareObjects,objectPayload} from '../src/workflows/objects.js';
import {exportArchive,importArchive,archiveSessions} from '../src/workflows/archives.js';
const domain={'domain-type':'data domain'};
const any={uid:'any',name:'Any',type:'CpmiAnyObject',domain};
const profile={uid:'profile',name:'Optimized',type:'threat-profile',domain};
function planFixture() {
 const rule=(type,uid,extra={})=>({uid,type,name:uid,source:['any'],destination:['any'],service:['any'],enabled:true,...extra});
 return buildPlan({apiVersion:'v2.1',sourceDomain:{uid:'s',name:'Source'},targetDomain:{uid:'t',name:'Target'},targetName:'Copy',checks:[],objects:[any,profile].map(source=>({uid:source.uid,name:source.name,type:source.type,source,target:source,status:'reuse'})),inventory:[],nat:[],package:{uid:'source-package',name:'Source','https-inspection-layers':{}},layers:[
  {uid:'ac',type:'access-layer',kind:'access',name:'Access',targetName:'Copy Access',ordered:true,firewall:true,items:[rule('access-rule','a',{action:'any',track:{type:'None','enable-firewall-session':true}})]},
  {uid:'tp',type:'threat-layer',kind:'threat',name:'Threat',targetName:'Copy Threat',ordered:true,items:[rule('threat-rule','t',{action:'profile',track:'Log','protected-scope':['any']})],exceptionSets:[{ruleUid:'t',groups:[],items:[rule('threat-exception','e',{action:'profile',track:'Log','protection-or-site':['any']})]}]},
  {uid:'in',type:'https-layer',kind:'https',slot:'inbound-https-layer',name:'Inbound',targetName:'Copy Inbound','layer-type':'inbound',items:[]},
  {uid:'out',type:'https-layer',kind:'https',slot:'outbound-https-layer',name:'Outbound',targetName:'Copy Outbound','layer-type':'outbound',items:[rule('https-rule','h1',{action:'Bypass',track:'Log'}),rule('https-rule','h2',{action:'Inspect',track:'None'})]}
 ]});
}
function destination() {
 const calls=[],layers=new Map(),exceptions=new Map(),groups=new Map(),groupRows=new Map();let count=0,pkg;
 const rules=(uid)=>layers.get(uid).items;
 const command=async(id,cmd,body={})=>{
  calls.push({cmd,body:structuredClone(body)});
  if(cmd==='show-session')return {changes:0};
  if(cmd==='discard')return {};
  if(/^add-(access|threat|https)-layer$/.test(cmd)) {
   const type=cmd.slice(4),uid='layer-'+(++count),{'add-default-rule':ignored,...config}=body;
   const items=type==='https-layer'&&body['layer-type']==='outbound'?[{uid:'generated1',type:'https-rule',name:'Generated 1'},{uid:'generated2',type:'https-rule',name:'Generated 2'}]:[];
   layers.set(uid,{...config,uid,type,items});return {uid};
  }
  if(cmd==='add-package') {
   layers.set('ips',{uid:'ips',name:'IPS',type:'threat-layer',items:[]});
   layers.set('generated-tp',{uid:'generated-tp',name:'Copy Threat Prevention',type:'threat-layer',items:[{uid:'default-tp-rule',type:'threat-rule',enabled:true}]});
   pkg={uid:'package','access-layers':[],'threat-layers':[{uid:'ips',name:'IPS'},{uid:'generated-tp',name:'Copy Threat Prevention'}]};return {uid:'package'};
  }
  if(cmd==='show-package')return structuredClone(pkg);
  if(cmd==='set-package') {
   for(const field of ['access-layers','threat-layers'])if(body[field]?.add)pkg[field].push(...body[field].add.map(x=>{const l=[...layers.values()].find(l=>l.name===x.name);return {name:l.name,uid:l.uid};}));
   if(body['https-inspection-layers'])pkg['https-inspection-layers']=structuredClone(body['https-inspection-layers']);return {};
  }
  if(/^show-(access|threat|https)-layer$/.test(cmd)){const {items,...config}=layers.get(body.uid);return config;}
  if(cmd==='show-threat-rule-exception-rulebase'){
   const items=[...(exceptions.get(body['rule-uid'])||[])],total=items.reduce((n,item)=>n+(item.rulebase?.length??1),0);
   return {rulebase:structuredClone(items),total};
  }
  if(cmd==='add-exception-group'){const uid='group-'+(++count);groups.set(uid,{...body,uid});return {uid};}
  if(cmd==='set-exception-group'){
   const group=groups.get(body.uid);group['applied-threat-rules'].push(...body['applied-threat-rules'].add);
   for(const attachment of body['applied-threat-rules'].add){const items=exceptions.get(attachment.uid)||[];let count=1,index=0;
    for(;index<items.length&&count<attachment.position;index++)count+=items[index].rulebase?.length??1;
    items.splice(index,0,{uid:body.uid,name:group.name,type:'threat-exception-section',rulebase:groupRows.get(body.uid)||[]});exceptions.set(attachment.uid,items);
   }return {};
  }
  if(cmd==='show-exception-group')return structuredClone(groups.get(body.uid));
  if(/^show-(access|threat|https)-rulebase$/.test(cmd)){const items=rules(body.uid);return {rulebase:structuredClone(items),total:items.filter(r=>!r.type.endsWith('section')).length};}
  if(cmd==='add-threat-exception'){const {layer,position,'rule-uid':ruleUid,'exception-group-uid':groupUid,...r}=body;const store=groupUid?groupRows:exceptions,key=groupUid||ruleUid,list=store.get(key)||[];list.push({...r,uid:'exception-'+(++count),type:'threat-exception'});store.set(key,list);return {uid:list.at(-1).uid};}
  if(/^add-(access|threat|https)-rule$/.test(cmd)){const {layer,position,...r}=body;const uid='rule-'+(++count);rules(layer).push({...r,uid,type:cmd.slice(4)});return {uid};}
  if(cmd==='set-threat-rule'){Object.assign(rules(body.layer).find(r=>r.uid===body.uid),{enabled:body.enabled});return {};}
  if(cmd==='delete-https-rule'){const list=rules(body.layer),i=list.findIndex(r=>r.uid===body.uid);assert.ok(i>=0);list.splice(i,1);return {};}
  throw Error('Unexpected '+cmd);
 };
 return {command,calls,layers};
}
test('native Access/TP/HTTPS and exception staging preserves rules, removes only generated defaults, and never publishes',async()=>{
 const plan=planFixture(),sessions=destination();
 const catalog=(await catalogsReady).get('v2.1');
 const checks=validatePlanCommands({validate:(c,b)=>validateCommand(catalog,c,b)},plan);
 assert.ok(checks.every(c=>c.ok),JSON.stringify(checks));
 const result=await stagePlan({sessions,targetId:'target',plan});assert.equal(result.state,'staged');
 assert.equal(sessions.calls.filter(c=>c.cmd==='add-threat-exception').length,1);
 assert.deepEqual(sessions.calls.filter(c=>c.cmd==='delete-https-rule').map(c=>c.body.uid),['generated1','generated2']);
 assert.ok(sessions.calls.some(c=>c.cmd==='set-threat-rule'&&c.body.enabled===false));
 assert.ok(!sessions.calls.some(c=>['publish','install-policy','discard'].includes(c.cmd)));
});
test('new catalog fields extend native named CRUD adapters without changing prior schema snapshots',async()=>{
 const catalog=(await catalogsReady).get('v2.1'),before=objectAdapters(catalog);
 const newer=structuredClone(catalog);newer.commands.find(c=>c.name==='add-service-sctp').optionalFields.push({name:'new-setting',type:'boolean'});
 const after=objectAdapters(newer),source={uid:'sctp',name:'SCTP',type:'service-sctp',port:'443','new-setting':true};
 assert.equal(compareObjects([source],[],before)[0].status,'blocked');
 assert.equal(compareObjects([source],[],after)[0].status,'create');
 assert.equal(objectPayload(source,new Map(),after)['new-setting'],true);
 assert.equal(before['service-sctp'].includes('new-setting'),false);
});
test('native archive round trip preserves policy structures and source reads cannot escape the archive',async()=>{
 const plan=planFixture(),snapshot=importArchive(exportArchive(plan));
 assert.deepEqual(snapshot.layers,plan.layers);assert.equal(snapshot.objects.length,2);
 const calls=[],sessions=archiveSessions({command:async(...args)=>{calls.push(args);return {}; }},'s',snapshot,'t');
 const tp=await sessions.command('s','show-threat-rulebase',{uid:'tp'});assert.equal(tp.total,1);
 const exceptions=await sessions.command('s','show-threat-rule-exception-rulebase',{uid:'tp','rule-uid':'t'});assert.equal(exceptions.total,1);
 await assert.rejects(sessions.command('s','show-object',{uid:'missing'}),/Archive cannot resolve/);assert.equal(calls.length,0);
});

test('selective native export removes package references to omitted components',()=>{
 const plan=planFixture();plan.package['access-layers']=[{uid:'ac',name:'Access'}];plan.package['https-inspection-policy']=true;
 plan.layers=plan.layers.filter(l=>l.kind==='threat');
 const snapshot=importArchive(exportArchive(plan));
 assert.deepEqual(snapshot.package['access-layers'],[]);assert.deepEqual(snapshot.package['https-inspection-layers'],{});
 assert.equal(snapshot.package.access,false);assert.equal(snapshot.package['https-inspection-policy'],false);
 assert.deepEqual(snapshot.package['threat-layers'],[{uid:'tp',name:'Threat'}]);
 assert.equal(plan.package['https-inspection-policy'],true);
});

test('native live-source scan discovers TP/HTTPS dependencies and exceptions before staging',async()=>{
 const {scan}=await import('../src/workflows/migration.js');
 const expected=planFixture(),target=destination();
 const threat=expected.layers.find(l=>l.kind==='threat');threat['ips-layer']=false;threat.items[0]['exceptions-layer']='response-exception-layer';
 const pkg={...expected.package,access:true,'threat-prevention':true,'https-inspection-policy':true,'nat-policy':false,'access-layers':[{uid:'ac',name:'Access'}],'threat-layers':[{uid:'tp',name:'Threat'}],'https-inspection-layers':{'inbound-https-layer':{uid:'in',name:'Inbound'},'outbound-https-layer':{uid:'out',name:'Outbound'}}};
 const sessions={command:async(id,cmd,body={})=>{
  if(cmd==='show-api-versions')return {'current-version':'2.1','supported-versions':['2.1']};
  if(cmd==='show-global-assignments')return {objects:[],total:0};
  if(cmd==='show-packages')return {packages:id==='source'?[pkg]:[],total:id==='source'?1:0};
  if(cmd==='show-package'&&id==='source')return pkg;
  if(cmd==='show-objects')return {objects:[any,profile],total:2};
  if(cmd==='show-object')return {object:[any,profile].find(o=>o.uid===body.uid)};
  if(cmd==='show-threat-profile')return profile;
  if(id==='source') {
   const layer=expected.layers.find(l=>l.uid===body.uid);
   if(cmd.endsWith('-layer')){const {kind,slot,ordered,targetName,items,exceptionSets,...config}=layer;return config;}
   const items=cmd==='show-threat-rule-exception-rulebase'?layer.exceptionSets?.find(e=>e.ruleUid===body['rule-uid'])?.items||[]:layer.items;
   return {rulebase:items,total:items.filter(r=>!r.type.endsWith('section')).length,'objects-dictionary':[any,profile]};
  }
  return target.command(id,cmd,body);
 }};
 const plan=await scan({sessions,sourceId:'source',targetId:'target',rootId:'root',sourceDomain:{uid:'s',name:'Source'},targetDomain:{uid:'t',name:'Target'},packageUid:pkg.uid,targetName:'Copy'});
 assert.equal(plan.ready,true,JSON.stringify(plan.checks.filter(c=>!c.ok)));
 assert.equal(plan.ruleCount,5);assert.equal(plan.layers.find(l=>l.kind==='threat').exceptionSets[0].items.length,1);
 assert.equal(plan.layers[0]['detect-using-x-forward-for'],false);assert.equal(plan.layers[0]['implicit-cleanup-action'],'drop');
 assert.equal((await stagePlan({sessions,targetId:'target',plan})).state,'staged');
 const gateway={uid:'a1234567-1234-1234-1234-123456789abc',name:'Cloud Gateway',type:'simple-gateway','ipv4-address':'192.0.2.1','autonomous-system-number':'65001'};
 const blockedSessions={command:async(id,cmd,body={})=>{
  if(cmd==='show-object'&&body.uid===gateway.uid)return {object:gateway};
  const reply=await sessions.command(id,cmd,body);
  if(id==='source'&&cmd==='show-access-rulebase')return {...reply,rulebase:reply.rulebase.map(rule=>rule.type==='access-rule'?{...rule,source:[gateway.uid]}:rule)};
  return reply;
 }};
 const blocked=await scan({sessions:blockedSessions,sourceId:'source',targetId:'target',rootId:'root',sourceDomain:{uid:'s',name:'Source'},targetDomain:{uid:'t',name:'Target'},packageUid:pkg.uid,targetName:'Copy'});
 assert.equal(blocked.ready,false);
 const row=blocked.objects.find(o=>o.uid===gateway.uid);
 assert.equal(row.status,'blocked');assert.match(row.reason,/Cloud Gateway.*65001/);
 for(const gatewayType of ['simple-gateway','simple-cluster']) {
 gateway.type=gatewayType;
 const writes=[],rebuiltDestination=destination();let createdGateway;
 gateway['https-inspection']={'outbound-certificate':{uid:'b1234567-1234-1234-1234-123456789abc'}};
 gateway['vpn-settings']={certificates:[{name:'defaultCert',domain:{uid:'c1234567-1234-1234-1234-123456789abc',name:'Source management'}}]};
 const rebuildSessions={command:async(id,cmd,body={})=>{
  if(id==='target'&&cmd===`add-${gatewayType}`){writes.push({cmd,body});createdGateway={...body,uid:'destination-gateway',type:gatewayType,'autonomous-system-number':'65002','cloud-generated-setting':true};return createdGateway;}
  if(id==='target'&&cmd==='show-object'&&body.uid===createdGateway?.uid)return {object:createdGateway};
  if(id==='target'&&cmd===`set-${gatewayType}`)throw new Error('Rebuild must not configure gateway settings.');
  if(id==='target'&&!['show-api-versions','show-packages','show-objects','show-object','show-threat-profile'].includes(cmd))return rebuiltDestination.command(id,cmd,body);
  return blockedSessions.command(id,cmd,body);
 }};
 const rebuilt=await scan({sessions:rebuildSessions,sourceId:'source',targetId:'target',rootId:'root',sourceDomain:{uid:'s',name:'Source'},targetDomain:{uid:'t',name:'Target'},packageUid:pkg.uid,targetName:'Copy',options:{rebuildGateways:true},renames:{[gateway.uid]:{action:'create-gateway',name:'Minimal Gateway',address:'192.0.2.2'}}});
 assert.equal(rebuilt.ready,true,JSON.stringify(rebuilt.checks.filter(c=>!c.ok)));
 assert.equal((await stagePlan({sessions:rebuildSessions,targetId:'target',plan:rebuilt})).state,'staged');
 assert.equal(writes.length,1);assert.equal(writes[0].body['ipv4-address'],'192.0.2.2');
 assert.ok(!('https-inspection' in writes[0].body));assert.ok(!('autonomous-system-number' in writes[0].body));
 assert.ok(!('vpn-settings' in writes[0].body));assert.equal(writes[0].cmd,`add-${gatewayType}`);
 }
});

test('shared TP exception groups are created once and retain separate direct exceptions',async()=>{
 const plan=planFixture(),layer=plan.layers.find(l=>l.kind==='threat'),exception=layer.exceptionSets[0].items[0];
 layer.items.push({...layer.items[0],uid:'t2',name:'Second'});
 const group={uid:'source-group',sectionUid:'source-section',name:'Shared',targetName:'Copy Shared',position:1};
 layer.exceptionSets=[{ruleUid:'t',groups:[group],items:[{uid:group.sectionUid,name:group.name,type:'threat-exception-section'},{...exception,uid:'group-exception',name:'Shared exception',parentSectionUid:group.sectionUid},exception]},
 {ruleUid:'t2',groups:[group],items:[{uid:group.sectionUid,name:group.name,type:'threat-exception-section'},{...exception,uid:'group-exception',name:'Shared exception',parentSectionUid:group.sectionUid}]}];
 const sessions=destination();assert.equal((await stagePlan({sessions,targetId:'target',plan})).state,'staged');
 assert.equal(sessions.calls.filter(c=>c.cmd==='add-exception-group').length,1);
 const writes=sessions.calls.filter(c=>c.cmd==='add-threat-exception');assert.equal(writes.length,2);assert.equal(writes.filter(c=>c.body['exception-group-uid']).length,1);
 const attached=sessions.calls.find(c=>c.cmd==='add-exception-group').body;assert.equal(attached['apply-on'],'manually-select-threat-rules');assert.equal(attached['applied-threat-rules'].length,0);
 assert.equal(sessions.calls.filter(c=>c.cmd==='set-exception-group').length,2);
 assert.ok(sessions.calls.findIndex(c=>c.cmd==='add-threat-exception'&&!c.body['exception-group-uid'])<sessions.calls.findIndex(c=>c.cmd==='add-exception-group'));
});

test('outbound HTTPS creation omits its managed certificate but readback still checks it',async()=>{
 const {layerRulePayload,rulePayload}=await import('../src/workflows/migration.js');
 const rule={type:'https-rule',certificate:'source-cert',action:'Inspect'};
 const mapping=new Map([['source-cert','target-cert']]);
 assert.equal(layerRulePayload(rule,{kind:'https',slot:'outbound-https-layer'},mapping).certificate,undefined);
 assert.equal(layerRulePayload(rule,{kind:'https',slot:'inbound-https-layer'},mapping).certificate,'target-cert');
 assert.equal(rulePayload(rule,mapping).certificate,'target-cert');
});

test('shared exception groups can have opposite orders in different threat rules',async()=>{
 const plan=planFixture(),layer=plan.layers.find(l=>l.kind==='threat'),exception=layer.exceptionSets[0].items[0];
 layer.items.push({...layer.items[0],uid:'t2',name:'Second'});
 const groups=['A','B'].map(name=>({uid:`g${name}`,sectionUid:`s${name}`,name,targetName:`Copy ${name}`}));
 const entries=group=>[{uid:group.sectionUid,name:group.name,type:'threat-exception-section'},{...exception,uid:`e${group.name}`,name:group.name,parentSectionUid:group.sectionUid}];
 layer.exceptionSets=[{ruleUid:'t',groups,items:[...entries(groups[0]),exception,...entries(groups[1])]},
 {ruleUid:'t2',groups,items:[...entries(groups[1]),...entries(groups[0]),{...exception,uid:'direct2'}]}];
 const sessions=destination();assert.equal((await stagePlan({sessions,targetId:'target',plan})).state,'staged');
 assert.equal(sessions.calls.filter(c=>c.cmd==='add-exception-group').length,2);
 assert.equal(sessions.calls.filter(c=>c.cmd==='set-exception-group').length,4);
});

test('upstream built-ins missing from inventory resolve from rule dictionaries with verified identities',async()=>{
 const {scan}=await import('../src/workflows/migration.js');
 const plan=planFixture();plan.layers=[plan.layers[0]];plan.package={uid:'source-package',name:'Source',access:true,'access-layers':[{uid:'ac',name:'Access'}]};
 const snapshot=importArchive(exportArchive(plan));snapshot.objects=[{...any,type:'archive-reference'}];
 const child={uid:'builtin-child',name:'Builtin HTTPS',type:'service-tcp',port:'443',domain};
 const targetAny={...any,uid:'destination-any',type:'service-group',members:[child]};
 const existing={uid:'existing',name:'Existing','access-layers':[{uid:'existing-layer',name:'Existing Access'}]};
 const sessions={command:async(id,cmd,body={})=>{
  assert.ok(!Object.hasOwn(body,'name')||cmd!=='show-object');
  if(cmd==='show-api-versions')return {'current-version':'2.1','supported-versions':['2.1']};
  if(cmd==='show-global-assignments')return {objects:[],total:0};
  if(cmd==='show-packages')return {packages:[existing],total:1};
  if(cmd==='show-package')return existing;
  if(cmd==='show-objects')return {objects:[],total:0};
  if(cmd==='show-access-rulebase')return {rulebase:[],total:0,'objects-dictionary':[targetAny]};
  if(cmd==='show-object'&&body.uid===targetAny.uid)return {object:targetAny};
  if(cmd==='show-object'&&body.uid===child.uid)return {object:child};
  throw new Error(`Unexpected ${cmd}`);
 }};
 const result=await scan({sessions:archiveSessions(sessions,'source',snapshot,'target'),sourceId:'source',targetId:'target',rootId:'root',sourceDomain:{uid:'s',name:'Archive',archive:true},targetDomain:{uid:'t',name:'Target'},packageUid:'source-package',targetName:'Copy'});
 assert.equal(result.ready,true,JSON.stringify(result.checks.filter(c=>!c.ok)));
 assert.equal(result.objects[0].target.uid,'destination-any');
});

test('HTTPS response blade names normalize to API inputs without dropping selected blades',async()=>{
 const {rulePayload,verifyRulebase}=await import('../src/workflows/migration.js');
 const rule={uid:'rule',type:'https-rule',blade:['Anti-Virus','Anti-Bot','URL Filtering','Data Loss Prevention','Content Awareness']};
 assert.deepEqual(rulePayload(rule,new Map()).blade,['Anti Virus','Anti Bot','Url Filtering','DLP','Data Awareness']);
 verifyRulebase([rule],[{...rule,uid:'copy'}],new Map(),new Map(),'HTTPS');
 assert.throws(()=>verifyRulebase([rule],[{...rule,blade:['Anti-Virus']}],new Map(),new Map(),'HTTPS'),/blade/);
});

test('live R82.10 threat-section exception wrappers retain child rules and pagination',async()=>{
 const {readRulebase}=await import('../src/workflows/migration.js');
 const sessions={command:async()=>({total:1,to:1,rulebase:[{uid:'global',name:'Global Exceptions',type:'threat-section',rulebase:[{uid:'exception',name:'Ex',type:'threat-exception'}]}]})};
 const result=await readRulebase(sessions,'target','show-threat-rule-exception-rulebase',{});
 assert.deepEqual(result.items.map(r=>r.type),['threat-exception-section','threat-exception']);
 assert.equal(result.items[1].parentSectionUid,'global');
});

test('NAT Original enum readback accepts only the verified built-in representation',async()=>{
 const {verifyRulebase}=await import('../src/workflows/migration.js');
 const expected={uid:'n',type:'nat-rule','translated-source':'Original'};
 const original={uid:'original',name:'Original',type:'Global',domain};
 verifyRulebase([expected],[{...expected,'translated-source':original.uid}],new Map(),new Map(),'NAT',[original]);
 assert.throws(()=>verifyRulebase([expected],[{...expected,'translated-source':{...original,domain:{'domain-type':'domain'}}}],new Map(),new Map(),'NAT'),/translated-source/);
});

test('offline source API negotiation uses the archive version instead of the connected source domain',async()=>{
 const snapshot={apiVersion:'v1.9',objects:[],layers:[]};
 const sessions=archiveSessions({command:async()=>{throw new Error('No live source query expected');}},'source',snapshot,'target');
 assert.deepEqual(await sessions.command('source','show-api-versions'),{'current-version':'1.9','supported-versions':['1.9']});
});

test('acknowledged IPS exceptions are absent from staged payload and verified rule counts',async()=>{
 const plan=planFixture(),layer=plan.layers.find(l=>l.kind==='threat');
 layer.exceptionSets[0].items[0]['protection-or-site']=['missing'];
 const impact=ipsManualImpact(plan.layers,'missing');
 plan.manualFollowups=applyManualIps(plan.layers,[{uid:'missing',fingerprint:impact.fingerprint}],new Map([['missing',{uid:'missing',name:'Missing',type:'CpmiSdTopicPerProfileDynamic'}]]));
 const rebuilt=buildPlan(plan),sessions=destination();
 assert.equal(rebuilt.ruleCount,4);
 const result=await stagePlan({sessions,targetId:'target',plan:rebuilt});
 assert.equal(result.state,'staged');assert.equal(sessions.calls.filter(c=>c.cmd==='add-threat-exception').length,0);
 assert.equal(rebuilt.manualFollowups[0].affected[0].exception.uid,'e');
});

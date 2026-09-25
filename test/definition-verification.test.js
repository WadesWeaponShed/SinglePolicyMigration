import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyCreatedDefinition, stagePlan } from '../src/workflows/migration.js';
import { objectPayload } from '../src/workflows/objects.js';

const host={name:'Imported host','ipv4-address':'10.1.1.1',comments:'Retain this',color:'blue',tags:['tag-a','tag-b'],'nat-settings':{'auto-rule':false}};
const actualHost={...host,uid:'created-host',type:'host','meta-info':{creator:'admin'},domain:{uid:'domain'},tags:[{uid:'tag-b',name:'B'},{uid:'tag-a',name:'A'}]};
const identity={uid:'created-host',type:'host'};
test('created definitions preserve settings and normalize expanded references and set order',()=>{
  assert.doesNotThrow(()=>verifyCreatedDefinition(host,actualHost,identity));
  assert.doesNotThrow(()=>verifyCreatedDefinition({name:'Group',members:['a','b']},{uid:'group',type:'group',name:'Group',members:[{uid:'b'},{uid:'a'}]},{uid:'group',type:'group'}));
  assert.throws(()=>verifyCreatedDefinition(host,{...actualHost,'ipv4-address':'10.1.1.2'},identity),/ipv4-address/);
  assert.throws(()=>verifyCreatedDefinition(host,{...actualHost,tags:[]},identity),/tags/);
  assert.throws(()=>verifyCreatedDefinition(host,{...actualHost,comments:''},identity),/comments/);
  assert.throws(()=>verifyCreatedDefinition(host,{...actualHost,name:'Old name'},identity),/name/);
});
test('created definitions reject missing fields, unexpected writable settings and incorrect identity',()=>{
  const {'ipv4-address':ignored,...missing}=actualHost;
  assert.throws(()=>verifyCreatedDefinition(host,missing,identity),/ipv4-address/);
  assert.throws(()=>verifyCreatedDefinition(host,{...actualHost,'host-servers':{web:{enabled:true}}},identity),/host-servers/);
  assert.throws(()=>verifyCreatedDefinition(host,{...actualHost,'new-server-feature':true},identity),/unmapped settings/);
  assert.throws(()=>verifyCreatedDefinition(host,{...actualHost,uid:'wrong'},identity),/identity/);
  assert.throws(()=>verifyCreatedDefinition(host,{...actualHost,type:'network'},identity),/identity/);
  assert.throws(()=>verifyCreatedDefinition(host,{},identity),/identity/);
});
test('service readback normalizes inactive settings but detects active behavior changes',()=>{
  const service={uid:'service',type:'service-tcp',name:'TLS',port:'443','aggressive-aging':{'use-default-timeout':true,timeout:3600},'use-delayed-sync':false,'delayed-sync-value':5};
  const expected=objectPayload(service);
  assert.doesNotThrow(()=>verifyCreatedDefinition(expected,{...service,'aggressive-aging':{'use-default-timeout':true,timeout:123},'delayed-sync-value':20},{uid:'service',type:'service-tcp'}));
  assert.throws(()=>verifyCreatedDefinition(expected,{...service,port:'444'},{uid:'service',type:'service-tcp'}),/port/);
});
test('layer readback validates blade switches and cleanup action while ignoring response metadata',()=>{
  const expected={name:'Copy / Network',firewall:true,'applications-and-url-filtering':false,'implicit-cleanup-action':'drop',shared:false,tags:['tag']};
  const actual={...expected,uid:'layer',type:'access-layer','implicit-cleanup-action':{uid:'drop',name:'Drop'},tags:[{uid:'tag'}],'meta-info':{creator:'admin'}};
  assert.doesNotThrow(()=>verifyCreatedDefinition(expected,actual,{uid:'layer',type:'access-layer'}));
  assert.throws(()=>verifyCreatedDefinition(expected,{...actual,firewall:false},{uid:'layer',type:'access-layer'}),/firewall/);
  assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'implicit-cleanup-action':'accept'},{uid:'layer',type:'access-layer'}),/implicit-cleanup-action/);
});

function stageFixture({corruptObject=false,corruptLayer=false,failReadback=false,failDiscard=false}={}) {
  const calls=[],created=new Map();let attached=false;
  const source={uid:'source-host',type:'host',name:'Original','ipv4-address':'10.2.2.2'};
  const layer={uid:'source-layer',name:'Network',targetName:'Copy / Network',ordered:true,firewall:true,items:[]};
  const plan={ready:true,blockers:0,targetName:'Copy',inventory:[],nat:[],layers:[layer],objects:[{uid:source.uid,name:source.name,type:source.type,status:'create',source,importName:'Renamed host'}]};
  const sessions={command:async(id,command,body={})=>{
    calls.push({id,command,body});
    if(command==='show-session') return {changes:0};
    if(command==='add-host'){created.set('host',{...body,uid:'host',type:'host'});return {uid:'host'};}
    if(command==='add-access-layer'){const {'add-default-rule':ignored,...settings}=body;created.set('layer',{...settings,uid:'layer',type:'access-layer'});return {uid:'layer'};}
    if(command==='add-package') return {uid:'package'};
    if(command==='set-package'){attached=true;return {};}
    if(command==='show-package') return {'access-layers':attached?[{uid:'layer'}]:[]};
    if(command==='show-access-rulebase') return {total:0,rulebase:[]};
    if(command==='show-object') {
      if(failReadback) throw new Error('Readback permission denied');
      return {object:{...created.get('host'),...(corruptObject?{'ipv4-address':'10.2.2.3'}:{})}};
    }
    if(command==='show-access-layer') return {...created.get('layer'),...(corruptLayer?{firewall:false}:{})};
    if(command==='discard'){if(failDiscard)throw new Error('Disconnected');return {};}
    throw new Error(`Unexpected command ${command}`);
  }};
  return {calls,plan,sessions};
}
test('staging verifies created renamed objects and layers in destination session only',async()=>{
  const fixture=stageFixture();
  const result=await stagePlan({...fixture,targetId:'target'});
  assert.equal(result.state,'staged');
  assert.ok(fixture.calls.some(c=>c.command==='show-object' && c.body.uid==='host'));
  assert.ok(fixture.calls.some(c=>c.command==='show-access-layer' && c.body.uid==='layer'));
  assert.ok(fixture.calls.every(c=>c.id==='target'));
  assert.ok(!fixture.calls.some(c=>['publish','discard'].includes(c.command)));
});
test('NAT readback treats empty address-family fields as absent and still detects changed translations',()=>{
 const expected={name:'NAT host','ipv4-address':'192.0.2.1','nat-settings':{'auto-rule':true,method:'static','ipv4-address':'203.0.113.1','install-on':'All'}};
 const actual={...expected,uid:'host',type:'host','nat-settings':{...expected['nat-settings'],'ipv6-address':''}};
 verifyCreatedDefinition(expected,actual,{uid:'host',type:'host'});
 assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'nat-settings':{...actual['nat-settings'],'ipv6-address':'2001:db8::1'}},{uid:'host',type:'host'}),/nat-settings/);
});
test('only previewed exact duplicate-IP warnings can be acknowledged for explicit suffix copies',async()=>{
 for(const extraWarning of [false,true]) {
  const fixture=stageFixture(),row=fixture.plan.objects[0];fixture.plan.options={objectSuffix:'_COPY'};row.importName=row.name+'_COPY';
  fixture.plan.inventory=[{...row.source,uid:'existing'}];const requests=[];
  const base=fixture.sessions.command;fixture.sessions.command=async(id,command,body)=>{
   if(command==='add-host') {
    requests.push(body);
    if(!body['ignore-warnings']){const error=new Error('Validation failed');error.response={code:'err_validation_failed',warnings:[{message:'Multiple objects have the same IP address 10.2.2.2'},...(extraWarning?[{message:'Unexpected NAT warning'}]:[])]};throw error;}
    const {'ignore-warnings':ignored,...payload}=body;return base(id,command,payload);
   }
   return base(id,command,body);
  };
  if(extraWarning){await assert.rejects(stagePlan({...fixture,targetId:'target'}),/Unexpected NAT warning.*discarded/);assert.equal(requests.length,1);}
  else {assert.equal((await stagePlan({...fixture,targetId:'target'})).state,'staged');assert.equal(requests.length,2);assert.equal(requests[1]['ignore-warnings'],true);}
 }
});
test('definition mismatch or unreadable readback discards and cannot become publishable',async()=>{
  for(const options of [{corruptObject:true},{corruptLayer:true},{failReadback:true}]) {
    const fixture=stageFixture(options);
    await assert.rejects(stagePlan({...fixture,targetId:'target'}),error=>error.state==='failed' && /discarded/.test(error.message));
    assert.deepEqual(fixture.calls.slice(-2).map(c=>c.command),['discard','show-session']);
    assert.ok(!fixture.calls.some(c=>c.command==='publish'));
  }
});
test('definition mismatch with failed discard retains recovery-required state',async()=>{
  const fixture=stageFixture({corruptObject:true,failDiscard:true});
  await assert.rejects(stagePlan({...fixture,targetId:'target'}),error=>error.state==='recovery-required' && /discard could not be verified/.test(error.message));
});
test('acknowledged staging discard must verify the current session has no changes',async()=>{
  for(const inspected of [
    {uid:'original',state:'discarded',changes:2},
    {uid:'original',state:'discarded'},
    null,
  ]) {
    const calls=[];let discarded=false;
    const sessions={command:async(id,command,body={})=>{
      calls.push({command,body});
      if(command==='show-session') {
        if(!discarded)return {uid:'original',state:'open',changes:0};
        if(!inspected)throw new Error('Readback unavailable');
        return inspected;
      }
      if(command==='discard'){discarded=true;return {};}
      throw new Error('Write failed');
    }};
    const source={uid:'host',type:'host',name:'Host','ipv4-address':'10.0.0.1'};
    const plan={ready:true,blockers:0,objects:[{uid:'host',type:'host',source,status:'create'}],layers:[],nat:[],inventory:[],targetName:'Copy'};
    await assert.rejects(stagePlan({sessions,targetId:'target',plan}),error=>error.state==='recovery-required' && !error.message.includes('were discarded'));
    assert.deepEqual(calls.at(-1),{command:'show-session',body:{}});
  }
});
test('verified discarded original session permits terminal failed staging state',async()=>{
  let discarded=false;
  const sessions={command:async(id,command)=>{
    if(command==='show-session')return {uid:'original',state:discarded?'discarded':'open',changes:0};
    if(command==='discard'){discarded=true;return {};}
    throw new Error('Write failed');
  }};
  const source={uid:'host',type:'host',name:'Host','ipv4-address':'10.0.0.1'};
  const plan={ready:true,blockers:0,objects:[{uid:'host',type:'host',source,status:'create'}],layers:[],nat:[],inventory:[],targetName:'Copy'};
  await assert.rejects(stagePlan({sessions,targetId:'target',plan}),error=>error.state==='failed' && error.message.includes('were discarded'));
});

 test('profile verification preserves extended attribute categories before resolving references',()=>{
 const schema={'threat-profile':['name','activate-protections-by-extended-attributes','deactivate-protections-by-extended-attributes']};
 const actual={uid:'profile',type:'threat-profile',name:'Custom', 'extended-attributes-to-activate':[{uid:'category',name:'Family',values:[{uid:'value',name:'B'},{uid:'value2',name:'A'}]}],'extended-attributes-to-deactivate':[]};
 const expected={name:'Custom','activate-protections-by-extended-attributes':[{category:'Family',name:'A'},{category:'Family',name:'B'}],'deactivate-protections-by-extended-attributes':[]};
 assert.doesNotThrow(()=>verifyCreatedDefinition(expected,actual,{uid:'profile',type:'threat-profile',objectSchema:schema}));
 assert.throws(()=>verifyCreatedDefinition({...expected,'activate-protections-by-extended-attributes':[]},actual,{uid:'profile',type:'threat-profile',objectSchema:schema}),/activate-protections/);
 });
test('Access layer ignores inactive X-Forwarded-For settings only when both dependent blades are disabled',()=>{
 const actual={uid:'layer',type:'access-layer',name:'Network',firewall:true,'applications-and-url-filtering':false,'content-awareness':false,'detect-using-x-forward-for':false};
 const {uid,type,'detect-using-x-forward-for':inactive,...expected}=actual;
 assert.doesNotThrow(()=>verifyCreatedDefinition(expected,actual,{uid,type}));
 assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'applications-and-url-filtering':true},{uid,type}));
});
test('gateway log settings are applied after creation and still require independent exact readback',async()=>{
 for(const ignoreSet of [false,true]) {
  const fixture=stageFixture(),row=fixture.plan.objects[0];row.type='simple-gateway';row.source={...row.source,type:row.type,'logs-settings':{'alert-when-free-disk-space-below-threshold':20}};
  fixture.plan.objectSchema={'simple-gateway':['name','ipv4-address','logs-settings']};
  let gateway;const base=fixture.sessions.command;fixture.sessions.command=async(id,command,body)=>{
   if(command==='add-simple-gateway'){gateway={...body,uid:'gateway',type:row.type,'logs-settings':{'alert-when-free-disk-space-below-threshold':3000}};return {uid:gateway.uid};}
   if(command==='set-simple-gateway'){assert.equal(body.uid,'gateway');if(!ignoreSet)gateway['logs-settings']=body['logs-settings'];return {uid:'gateway'};}
   if(command==='show-object')return {object:gateway};
   return base(id,command,body);
  };
  if(ignoreSet)await assert.rejects(stagePlan({...fixture,targetId:'target'}),/logs-settings.*discarded/);
  else assert.equal((await stagePlan({...fixture,targetId:'target'})).state,'staged');
 }
});
test('inline parent relationships must resolve to a migrated parent at readback',async()=>{
 const fixture=stageFixture();fixture.plan.layers[0]['parent-layer']='unmapped-parent';
 await assert.rejects(stagePlan({...fixture,targetId:'target'}),/inline layer parent differs.*discarded/);
 assert.ok(fixture.calls.some(c=>c.command==='discard'));
});

test('named threat exception actions verify against builtin identities without accepting a different action',async()=>{
 const {verifyRulebase}=await import('../src/workflows/migration.js');
 const expected=[{type:'threat-exception',action:'Detect'}];
 const detect={uid:'detect-id',name:'Detect',type:'ThreatExceptionAction',domain:{'domain-type':'data domain'}};
 const verify=(action,dictionary)=>verifyRulebase(expected,[{type:'threat-exception',action}],new Map(),new Map(),'Exceptions',dictionary);
 assert.doesNotThrow(()=>verify('detect-id',[detect]));
 assert.doesNotThrow(()=>verify(detect,[]));
 assert.throws(()=>verify('prevent-id',[{...detect,uid:'prevent-id',name:'Prevent'}]),/action/);
 assert.throws(()=>verify('detect-id',[{...detect,domain:{'domain-type':'domain'}}]),/action/);
 assert.throws(()=>verify('unknown-id',[]),/action/);
});

test('profile readback permits only known destination-generated sections absent from the source and API',()=>{
 const source={uid:'source',type:'threat-profile',name:'Custom','anti-virus':true};
 const expected={name:'Custom','anti-virus':true};
 const actual={...source,uid:'created','anti-virus-settings':{protocols:{'web-protocol':true}},'mail-general':{'scan-emails':true}};
 const context={uid:'created',type:'threat-profile',sourceDefinition:source,objectSchema:{'threat-profile':['name','anti-virus']}};
 assert.doesNotThrow(()=>verifyCreatedDefinition(expected,actual,context));
 assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'anti-virus':false},context),/anti-virus/);
 assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'unknown-security-settings':{}},context),/unknown-security-settings/);
 assert.throws(()=>verifyCreatedDefinition(expected,actual,{...context,sourceDefinition:{...source,'anti-virus-settings':{}}}),/anti-virus-settings/);
 assert.throws(()=>verifyCreatedDefinition(expected,actual,{...context,sourceDefinition:undefined}),/anti-virus-settings/);
 assert.throws(()=>verifyCreatedDefinition(expected,actual,{...context,objectSchema:{'threat-profile':['name','anti-virus','anti-virus-settings']}}),/anti-virus-settings/);
});

test('v2.1 profile readback recognizes only the absent-source default DNS trap pair',()=>{
 const dns={'dga-detection':'true','dns-domain-tunneling':'true','dns-over-https':'true','nxns-attack-detection':'true'};
 const expected={name:'Custom','advanced-dns-settings':dns};
 const actual={...expected,uid:'created',type:'threat-profile','advanced-dns-settings':{...dns,enabled:true,'activate-dns-trap':true,'trap-ipv4-address':''}};
 const context={uid:'created',type:'threat-profile',apiVersion:'v2.1',sourceDefinition:expected,objectSchema:{'threat-profile':['name','advanced-dns-settings']}};
 assert.doesNotThrow(()=>verifyCreatedDefinition(expected,actual,context));
 for(const patch of [{'dga-detection':'false'},{'activate-dns-trap':false},{'trap-ipv4-address':'192.0.2.1'},{'unknown-setting':true}])assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'advanced-dns-settings':{...actual['advanced-dns-settings'],...patch}},context),/advanced-dns-settings/);
 assert.throws(()=>verifyCreatedDefinition(expected,actual,{...context,apiVersion:'v2.2'}),/advanced-dns-settings/);
 assert.throws(()=>verifyCreatedDefinition(expected,actual,{...context,sourceDefinition:{...expected,'advanced-dns-settings':{...dns,'activate-dns-trap':false}}}),/advanced-dns-settings/);
 assert.equal(actual['advanced-dns-settings']['activate-dns-trap'],true);
});

test('layer readback accepts no additional permission profiles but rejects real assignments',()=>{
 const expected={name:'Layer'},actual={uid:'layer',type:'access-layer',name:'Layer','additional-permission-profiles':[]};
 const context={uid:'layer',type:'access-layer',policySchema:{'access-layer':['name']}};
 assert.doesNotThrow(()=>verifyCreatedDefinition(expected,actual,context));
 assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'additional-permission-profiles':['permission']},context),/additional-permission-profiles/);
 assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'additional-permission-profiles':null},context),/additional-permission-profiles/);
});

test('threat layer readback accepts absent-schema nonshared and empty permissions only',()=>{
 const expected={name:'IPS'},actual={uid:'layer',type:'threat-layer',name:'IPS',shared:false,'permissions-profiles':[]};
 const context={uid:'layer',type:'threat-layer',policySchema:{'threat-layer':['name']}};
 assert.doesNotThrow(()=>verifyCreatedDefinition(expected,actual,context));
 assert.throws(()=>verifyCreatedDefinition(expected,{...actual,shared:true},context),/shared/);
 assert.throws(()=>verifyCreatedDefinition(expected,{...actual,'permissions-profiles':['admin']},context),/permissions-profiles/);
});

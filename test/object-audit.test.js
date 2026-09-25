import test from 'node:test';
import assert from 'node:assert/strict';
import { compareObjects, objectPayload, semantic } from '../src/workflows/objects.js';

test('unrelated tags are created instead of reused as arbitrary destination tags', () => {
  const source = {uid:'s', name:'Production', type:'tag'};
  assert.equal(compareObjects([source], [{uid:'d', name:'Development', type:'tag'}])[0].status, 'create');
  assert.equal(compareObjects([source], [{uid:'d', name:'Production', type:'tag'}])[0].status, 'reuse');
});

test('service payload removes only documented inactive fields without mutating the snapshot', () => {
  const service = {uid:'s', name:'HTTPS', type:'service-tcp', port:'443',
    'aggressive-aging':{'use-default-timeout':true, timeout:3600},
    'use-delayed-sync':false, 'delayed-sync-value':30};
  const body = objectPayload(service);
  assert.deepEqual(body['aggressive-aging'], {'use-default-timeout':true});
  assert.ok(!('delayed-sync-value' in body));
  assert.equal(service['aggressive-aging'].timeout, 3600);
  assert.equal(service['delayed-sync-value'], 30);
  const enabled = {...service, 'aggressive-aging':{'use-default-timeout':false, timeout:3600}, 'use-delayed-sync':true};
  assert.equal(objectPayload(enabled)['aggressive-aging'].timeout, 3600);
  assert.equal(objectPayload(enabled)['delayed-sync-value'], 30);
  assert.ok(!('delayed-sync-value' in objectPayload({...enabled, 'sync-connections-on-cluster':false})));
  const destination = {...service, uid:'d', 'aggressive-aging':{'use-default-timeout':true, timeout:7200}, 'delayed-sync-value':60};
  assert.equal(compareObjects([service], [destination])[0].status, 'reuse');
});

test('group equivalence cannot hide unsupported nested object settings', () => {
  const source = [{uid:'s', name:'Web', type:'host', 'ipv4-address':'10.0.0.1'}, {uid:'sg', name:'Servers', type:'group', members:['s']}];
  const destination = [{...source[0], uid:'d', mystery:'unmapped behavior'}, {uid:'dg', name:'Servers', type:'group', members:['d']}];
  assert.equal(compareObjects(source, destination)[1].status, 'conflict');
  assert.throws(() => semantic(destination[1], new Map(destination.map(o => [o.uid,o]))), /Unmapped attributes/);
  const globalDestination = [{...source[0], uid:'d', domain:{'domain-type':'global domain'}}, destination[1]];
  assert.equal(compareObjects(source, globalDestination)[1].status, 'conflict');
});

test('placeholders produced by either upstream export or import are blocked', () => {
  for (const name of ['export_error_host_123', 'partial_export_error_gateway_123', 'import_error_due_to_missing_fields_web']) {
    const row = compareObjects([{uid:'s', name, type:'host', 'ipv4-address':'10.0.0.1'}], [])[0];
    assert.equal(row.status, 'blocked');
    assert.match(row.reason, /placeholder/);
  }
});

test('built-in UID and type take priority over duplicate display names in other namespaces',()=>{
 const domain={'domain-type':'data domain'},source={uid:'track-log',name:'Log',type:'Track',domain};
 const destination=[{uid:'global-log',name:'Log',type:'Global',domain},{...source}];
 const row=compareObjects([source],destination)[0];assert.equal(row.status,'reuse');assert.equal(row.target.uid,'track-log');
});
test('built-in category descriptions are display metadata while service port differences still block',()=>{
 const domain={'domain-type':'data domain'},schema={'application-site-category':['name','description']};
 const category={uid:'cat',name:'Health',type:'application-site-category',description:'A\nB',domain};
 assert.equal(compareObjects([category],[{...category,description:'A B'}],schema)[0].status,'reuse');
 const service={uid:'service',name:'Built-in',type:'service-tcp',port:'443',domain};
 assert.equal(compareObjects([service],[{...service,port:'444'}])[0].status,'blocked');
});

test('a repeated migration can reuse the exact requested renamed object without writing over it',async()=>{
 const {resolveObjectRenames}=await import('../src/workflows/objects.js');
 const source={uid:'source-host',name:'Host',type:'host','ipv4-address':'10.1.1.1'};
 const destination=[{...source,uid:'conflict','ipv4-address':'10.2.2.2'},{...source,uid:'prior-copy',name:'Host_MIGRATED'}];
 const rows=compareObjects([source],destination),resolved=resolveObjectRenames(rows,destination,{'source-host':'Host_MIGRATED'});
 assert.equal(resolved[0].status,'reuse');assert.equal(resolved[0].target.uid,'prior-copy');assert.equal(resolved[0].source.name,'Host');
});

test('native threat profile conversion preserves extended selections and protection overrides',()=>{
 const schema={'threat-profile':['name','activate-protections-by-extended-attributes','deactivate-protections-by-extended-attributes','overrides']};
 const source={uid:'profile',name:'Custom TP',type:'threat-profile','extended-attributes-to-activate':[{name:'Family',values:[{name:'A'},{name:'B'}]}],'extended-attributes-to-deactivate':[],overrides:[{protection:'protection-uid',override:{action:'detect',track:'log'}}]};
 const body=objectPayload(source,new Map([['protection-uid','destination-protection']]),schema);
 assert.deepEqual(body['activate-protections-by-extended-attributes'],[{category:'Family',name:'A'},{category:'Family',name:'B'}]);
 assert.deepEqual(body.overrides,[{protection:'destination-protection',action:'detect',track:'log'}]);
 assert.ok(source.overrides[0].override);
 const destination={...source,uid:'destination-profile',...objectPayload(source,new Map(),schema)};
 delete destination['extended-attributes-to-activate'];delete destination['extended-attributes-to-deactivate'];
 assert.equal(compareObjects([source],[destination],schema)[0].status,'reuse');
 assert.equal(compareObjects([{...source,'activate-protections-by-extended-attributes':[]}],[],schema)[0].status,'blocked');
});

test('archive comparisons normalize empty interfaces, equivalent masks and unoverridden service metadata',()=>{
 const schema={host:['name','ipv4-address','interfaces'],network:['name','subnet4','mask-length4','subnet-mask'],'service-tcp':['name','port','override-default-settings']};
 for(const [source,extras] of [
 [{uid:'s',name:'Host',type:'host','ipv4-address':'10.0.0.1'},{interfaces:[]}],
 [{uid:'s',name:'Net',type:'network',subnet4:'10.0.0.0','mask-length4':26},{'subnet-mask':'255.255.255.192'}],
 [{uid:'s',name:'TCP',type:'service-tcp',port:'443'},{'override-default-settings':false}]
 ])assert.equal(compareObjects([source],[{...source,uid:'d',...extras}],schema)[0].status,'reuse');
 const net={uid:'s',name:'Net',type:'network',subnet4:'10.0.0.0','mask-length4':26};
 assert.equal(compareObjects([net],[{...net,uid:'d','subnet-mask':'255.255.255.0'}],schema)[0].status,'conflict');
});
test('comparison caches definitions within one scan but invalidates them for the next snapshot',()=>{
 let reads=0;
 const destination=Array.from({length:10},(_,i)=>({uid:'d'+i,name:'Destination '+i,type:'service-tcp',get port(){reads++;return String(20000+i);}}));
 const source=Array.from({length:100},(_,i)=>({uid:'s'+i,name:'Source '+i,type:'service-tcp',port:String(10000+i)}));
 assert.ok(compareObjects(source,destination).every(row=>row.status==='create'));
 assert.ok(reads<100,`Destination definitions were repeatedly recomputed: ${reads}`);
 const modified=destination.map((o,i)=>({...o,port:i===0?'10000':o.port}));
 const changed=compareObjects(source,modified);assert.equal(changed[0].status,'reuse');assert.equal(changed[0].target.uid,'d0');
 const ambiguous=compareObjects([source[0]],[...modified,{uid:'duplicate',name:'Another',type:'service-tcp',port:'10000'}]);assert.equal(ambiguous[0].status,'conflict');
});

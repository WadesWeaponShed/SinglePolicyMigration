import test from 'node:test';
import assert from 'node:assert/strict';
import { buildPlan, validatePlanCommands } from '../src/workflows/migration.js';

const plan=()=>({apiVersion:'v2.2',targetName:'Copy',checks:[],inventory:[],objects:[{uid:'host',type:'host',status:'create',importName:'renamed',source:{uid:'host',type:'host',name:'original','ipv4-address':'10.0.0.1'}}],layers:[{uid:'layer',name:'Network',targetName:'Copy / Network',ordered:true,firewall:true,items:[{uid:'section',type:'access-section',name:'Section'},{uid:'rule',type:'access-rule',name:'Allow',destination:['host']}]}],nat:[{uid:'nat-section',type:'nat-section',name:'NAT section'},{uid:'nat',type:'nat-rule',method:'static','original-source':['host']} ]});

test('preview validates object, layer, rule, section, package and recovery request shapes',()=>{
  const calls=[];
  const checks=validatePlanCommands({validate:(command,body)=>calls.push({command,body})},plan());
  assert.equal(checks[0].ok,true);
  assert.match(checks[0].detail,/v2.2/);
  for(const command of ['add-host','add-access-layer','add-access-rule','add-access-section','add-nat-rule','add-nat-section','add-package','set-package','delete-access-layer','publish','discard'])assert.ok(calls.some(c=>c.command===command),command);
  assert.equal(calls.find(c=>c.command==='add-host').body.name,'renamed');
  assert.deepEqual(calls.find(c=>c.command==='add-access-rule').body.destination,['host']);
});

test('catalog validation failures block the preview before staging',()=>{
  const data=plan();
  data.checks=validatePlanCommands({validate:command=>{if(command==='add-host')throw new Error('Unsupported field for selected API');}},data);
  const preview=buildPlan(data);
  assert.equal(preview.ready,false);
  assert.match(preview.checks[0].detail,/Unsupported field/);
});

test('negotiated API version is part of the reviewed plan fingerprint',()=>{
  const first=buildPlan(plan()),second=buildPlan({...plan(),apiVersion:'v2.1'});
  assert.notEqual(first.digest,second.digest);
  assert.equal(first.apiVersion,'v2.2');
});

test('drift comparison ignores inventory/set ordering and response-only permissions',()=>{
  const first=plan();
  first.inventory=[{uid:'a',name:'a',type:'host','ipv4-address':'10.0.0.1','read-only':true,'available-actions':{edit:false}},{uid:'b',name:'b',type:'host','ipv4-address':'10.0.0.2'}];
  first.layers[0].items[1].source=['a','b'];
  first.objects[0].source.groups=[{uid:'x',name:'x'},{uid:'y',name:'y'}];
  const second=structuredClone(first);
  second.inventory.reverse();second.inventory[1]['read-only']=false;second.inventory[1]['available-actions']={edit:true};
  second.layers[0].items[1].source.reverse();second.objects[0].source.groups.reverse();
  assert.equal(buildPlan(first).digest,buildPlan(second).digest);
});

test('drift comparison retains addresses, NAT, rename choices, inventory changes and rule order',async()=>{
  const {changedPlanSections}=await import('../src/workflows/migration.js');
  const base=plan();
  for(const mutate of [
    p=>p.objects[0].source['ipv4-address']='10.0.0.9',
    p=>p.objects[0].source['nat-settings']={'auto-rule':true},
    p=>p.objects[0].importName='other',
    p=>p.inventory.push({uid:'new',name:'collision',type:'host'}),
    p=>p.layers[0].items.reverse(),
    p=>p.layers[0].items[1].enabled=false,
    p=>p.nat.reverse()
  ]){
    const changed=structuredClone(base);mutate(changed);
    assert.notEqual(buildPlan(base).digest,buildPlan(changed).digest);
    assert.ok(changedPlanSections(base,changed).length);
  }
});

test('opaque content and normalized VPN collections remain valid under detailed catalogs',async()=>{
 const {catalogsReady}=await import('../src/catalogs.js');const {rulePayload}=await import('../src/workflows/migration.js');const {validateCommand}=await import('../src/workflows/compatibility.js');
 const objects=new Map([['any',{uid:'any',name:'Any'}]]);
 for(const version of ['v1.9','v2.1','v2.2']) {
  const catalog=(await catalogsReady).get(version);
  const body=rulePayload({type:'access-rule',content:['any'],vpn:['any'],track:{type:'None','enable-firewall-session':false}},new Map([['any','target-any']]),objects);
  assert.equal(body.vpn,'Any');assert.doesNotThrow(()=>validateCommand(catalog,'add-access-rule',{...body,layer:'layer',position:'bottom'}));
 }
});

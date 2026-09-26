import test from 'node:test';
import assert from 'node:assert/strict';
import { rulePayload, verifyRulebase } from '../src/workflows/migration.js';

const mapping=new Map([['source','destination']]);
const objects=new Map();
test('NAT verification rejects changed translations and order despite equal rule count',()=>{
  const first={type:'nat-rule',name:'first','original-source':['source'],'translated-source':'source',method:'static',enabled:true};
  const second={...first,name:'second'};
  const actual=[first,second].map(r=>({...rulePayload(r,mapping),type:r.type}));
  assert.doesNotThrow(()=>verifyRulebase([first,second],actual,mapping,objects,'NAT'));
  assert.throws(()=>verifyRulebase([first,second],[{...actual[0],'translated-source':'wrong'},actual[1]],mapping,objects,'NAT'),/translated-source/);
  assert.throws(()=>verifyRulebase([first,second],actual.toReversed(),mapping,objects,'NAT'),/name/);
});
test('rulebase verification detects missing, renamed, moved and retagged sections',()=>{
  const expected=[{type:'access-section',name:'Production',tags:['source']},{type:'access-rule',name:'Allow',enabled:true}];
  const actual=[{...expected[0],tags:[{uid:'destination'}]},expected[1]];
  assert.doesNotThrow(()=>verifyRulebase(expected,actual,mapping,objects,'Access'));
  assert.throws(()=>verifyRulebase(expected,actual.slice(1),mapping,objects,'Access'),/count/);
  assert.throws(()=>verifyRulebase(expected,actual.toReversed(),mapping,objects,'Access'),/order/);
  assert.throws(()=>verifyRulebase(expected,[{...actual[0],name:'Other'},actual[1]],mapping,objects,'Access'),/name/);
  assert.throws(()=>verifyRulebase(expected,[{...actual[0],tags:[]},actual[1]],mapping,objects,'Access'),/tags/);
});
test('Drop response settings follow upstream normalization without mutating source',()=>{
  const rule={type:'access-rule',action:'drop','action-settings':{'enable-identity-captive-portal':false},'user-check':{frequency:'once-a-day','custom-frequency':1,confirm:'Continue',interaction:'keep'},track:{type:{uid:'track',name:'Log'}}};
  const before=structuredClone(rule);
  const payload=rulePayload(rule,new Map([['drop','new-drop']]),new Map([['drop',{name:'Drop'}]]));
  assert.deepEqual(payload,{action:'new-drop','user-check':{interaction:'keep'},track:{type:'log'}});
  assert.deepEqual(rule,before);
});
test('track verification accepts expanded enum values without requiring dictionary UID entries',()=>{
  const expected=[{type:'access-rule',action:'source',track:{type:{uid:'log',name:'Log'}}}];
  const actual=[{type:'access-rule',action:{uid:'destination'},track:{type:{uid:'different-log',name:'Log'}}}];
  assert.doesNotThrow(()=>verifyRulebase(expected,actual,mapping,objects,'Access'));
  assert.throws(()=>verifyRulebase(expected,[{...actual[0],track:{type:'None'}}],mapping,objects,'Access'),/track/);
});
test('staging discards when package attachment readback does not match preview',async()=>{
  const {stagePlan}=await import('../src/workflows/migration.js');
  const calls=[];
  const sessions={command:async(id,command)=>{
    calls.push(command);
    if(command==='show-session')return {changes:0};
    if(command==='add-access-layer')return {uid:'new-layer'};
    if(command==='add-package')return {uid:'new-package'};
    if(command==='show-package')return {'access-layers':[]};
    return {};
  }};
  const plan={ready:true,blockers:0,objects:[],layers:[{uid:'layer',name:'Network',targetName:'Copy / Network',ordered:true,items:[]}],inventory:[],nat:[],targetName:'Copy'};
  await assert.rejects(stagePlan({sessions,targetId:'target',plan}),/layer attachment.*discarded/);
  assert.deepEqual(calls.slice(-2),['discard','show-session']);
  assert.ok(!calls.includes('publish'));
});
test('staging discards equal-count NAT content corruption',async()=>{
  const {stagePlan}=await import('../src/workflows/migration.js');
  const calls=[];
  const nat={uid:'nat',type:'nat-rule',name:'NAT',method:'static',enabled:true};
  const sessions={command:async(id,command)=>{
    calls.push(command);
    if(command==='show-session')return {changes:0};
    if(command==='add-package')return {uid:'new-package'};
    if(command==='show-package')return {'access-layers':[]};
    if(command==='show-nat-rulebase')return {total:1,rulebase:[{...nat,method:'hide'}]};
    return {};
  }};
  const plan={ready:true,blockers:0,objects:[],layers:[],inventory:[],nat:[nat],targetName:'Copy'};
  await assert.rejects(stagePlan({sessions,targetId:'target',plan}),/method.*discarded/);
  assert.deepEqual(calls.slice(-2),['discard','show-session']);
});
test('layer cleanup enum is normalized before UID translation',async()=>{
  const {stagePlan}=await import('../src/workflows/migration.js');
  let createdLayer,attached=false;
  const sessions={command:async(id,command,body)=>{
    if(command==='show-session')return {changes:0};
    if(command==='add-access-layer'){createdLayer=body;return {uid:'new-layer'};}
    if(command==='add-package')return {uid:'new-package'};
    if(command==='set-package'){attached=true;return {};}
    if(command==='show-package')return {'access-layers':attached?[{uid:'new-layer'}]:[]};
    if(command==='show-access-rulebase')return {total:0,rulebase:[]};
    if(command==='show-access-layer') {const {'add-default-rule':ignored,...settings}=createdLayer;return {...settings,uid:'new-layer',type:'access-layer'};}
    return {};
  }};
  const layer={uid:'layer',name:'Network',targetName:'Copy / Network',ordered:true,items:[],'implicit-cleanup-action':{uid:'unreferenced-drop',name:'Drop'}};
  const result=await stagePlan({sessions,targetId:'target',plan:{ready:true,blockers:0,objects:[],layers:[layer],inventory:[],nat:[],targetName:'Copy'}});
  assert.equal(result.state,'staged');
  assert.equal(createdLayer['implicit-cleanup-action'],'drop');
});

test('logging UID strings resolve to API enums before object translation and readback',()=>{
  const mapping=new Map([['log-source','log-target'],['log','must-not-translate-enum']]);
  for(const name of ['None','Log','Extended Log','Detailed Log']) {
    const objects=new Map([['log-source',{uid:'log-source',name,type:'Track'}]]);
    const rule={uid:'r',type:'access-rule',track:{type:'log-source','accounting':true}};
    assert.deepEqual(rulePayload(rule,mapping,objects).track,name==='None'?{type:'none'}:{type:name.toLowerCase(),accounting:true});
    verifyRulebase([rule],[{...rule,track:{type:'log-target',accounting:true}}],mapping,objects,'Access');
    verifyRulebase([rule],[{...rule,track:{type:'new-log',accounting:true}}],mapping,objects,'Access',[{uid:'new-log',name}]);
  }
  assert.throws(()=>rulePayload({type:'access-rule',track:{type:'unresolved-uid'}},mapping),/logging type/);
});

test('None omits inactive log-generation settings and verifies against expanded response defaults',()=>{
  const settings={'per-session':false,'per-connection':false,accounting:false,'enable-firewall-session':false,alert:'none'};
  const source={uid:'r',type:'access-rule',track:{type:{uid:'none',name:'None'},...settings}};
  const original=structuredClone(source);
  assert.deepEqual(rulePayload(source,new Map()).track,{type:'none'});
  assert.deepEqual(source,original);
  verifyRulebase([source],[{...source,track:{type:'None',...settings,'per-session':false}}],new Map(),new Map(),'Access');
  assert.throws(()=>verifyRulebase([source],[{...source,track:{type:'Log'}}],new Map(),new Map(),'Access'),/track/);
  for(const type of ['Log','Extended Log','Detailed Log']){
    assert.deepEqual(rulePayload({...source,track:{type,...settings}},new Map()).track,{type:type.toLowerCase(),...settings});
  }
});

// Actual R82.10 fixture response shape from CMA_LAB_Rule_4.
test('R82.10 None track payload omits enable-firewall-session even when false',()=>{
  const uid='29e53e3d-23bf-48fe-b6b1-d59bd88036f9';
  const rule={type:'access-rule',track:{type:uid,'per-session':false,'per-connection':false,accounting:false,'enable-firewall-session':false,alert:'none'}};
  const objects=new Map([[uid,{uid,type:'Track',name:'None'}]]);
  const payload=rulePayload(rule,new Map([[uid,'destination-none']]),objects);
  assert.deepEqual(payload.track,{type:'none'});
  verifyRulebase([rule],[rule],new Map(),objects,'Network');
});

test('NAT upper/lower boundaries survive empty automatic headers and readback checks placement',async()=>{
  const {natItemsForMigration}=await import('../src/workflows/migration.js');
  const raw=[{uid:'default1',type:'nat-section',name:'Manual Upper Rules'},
    {uid:'a',type:'nat-rule',name:'before'},
    {uid:'auto',type:'nat-section',name:'Automatic Generated Rules : host'},
    {uid:'default2',type:'nat-section',name:'Manual Lower Rules'},
    {uid:'b',type:'nat-rule',name:'after'}];
  const selected=natItemsForMigration(raw);
  assert.deepEqual(selected.map(x=>[x.name,x.natPosition]),[['before','upper'],['after','lower']]);
  assert.doesNotThrow(()=>verifyRulebase(selected,selected,new Map(),new Map(),'NAT'));
  assert.throws(()=>verifyRulebase(selected,[{...selected[0],natPosition:'lower'},selected[1]],new Map(),new Map(),'NAT'),/placement/);
  assert.ok(!Object.hasOwn(rulePayload(selected[0],new Map()),'natPosition'));
});

test('staging retains multiple NAT sections and unsectioned rules on each side of generated rules',async()=>{
  const {stagePlan}=await import('../src/workflows/migration.js');
  const rule=(uid,pos)=>({uid,name:uid,type:'nat-rule',natPosition:pos,method:'static',enabled:true});
  const section=(uid,pos)=>({uid,name:uid,type:'nat-section',natPosition:pos});
  const nat=[rule('u1','upper'),rule('u2','upper'),section('s1','upper'),rule('u3','upper'),rule('u4','upper'),section('s2','upper'),rule('u5','upper'),rule('l1','lower'),section('s3','lower'),rule('l2','lower')];
  const rows=[{uid:'auto',type:'nat-section',name:'Automatic Generated Rules : host'},{uid:'generated',type:'nat-rule','auto-generated':true,name:'auto'}];
  const writes=[];
  const sessions={command:async(id,command,body)=>{
    if(command==='show-session')return {changes:0};
    if(command==='add-package')return {uid:'pkg'};
    if(command==='show-package')return {'access-layers':[]};
    if(command==='set-package')return {};
    if(command==='add-nat-section'||command==='add-nat-rule'){
      writes.push(body);const {position,package:pkg,...definition}=body;
      const item={...definition,uid:'new-'+body.name,type:command.slice(4)};
      if(position==='top')rows.unshift(item);
      else if(position==='bottom')rows.push(item);
      else {
        const start=rows.findIndex(x=>x.uid===position.bottom);assert.ok(start>=0);
        let end=start+1;while(end<rows.length&&rows[end].type!=='nat-section')end++;rows.splice(end,0,item);
      }
      return {uid:item.uid};
    }
    if(command==='show-nat-rulebase')return {total:rows.filter(x=>x.type==='nat-rule').length,rulebase:rows};
    throw new Error('Unexpected '+command);
  }};
  const job=await stagePlan({sessions,targetId:'t',plan:{ready:true,objects:[],inventory:[],layers:[],nat,targetName:'Copy'}});
  assert.equal(job.state,'staged');
  assert.deepEqual(rows.map(x=>x.name),['u1','u2','s1','u3','u4','s2','u5','Automatic Generated Rules : host','auto','l1','s3','l2']);
  assert.ok(writes.every(x=>!Object.hasOwn(x,'natPosition')));
});

test('exception verification accepts reordered mapped object sets but rejects changed membership',()=>{
 const members=['one','two','three','four','five'];
 const mapping=new Map(members.map(x=>[x,'target-'+x]));
 const expected={uid:'exception',name:'RubrikBackupRule',type:'threat-exception',destination:members,source:members,'destination-negate':false};
 const actual={...expected,uid:'copy',source:members.map(x=>({uid:mapping.get(x)})),destination:members.toReversed().map(x=>({uid:mapping.get(x)}))};
 assert.doesNotThrow(()=>verifyRulebase([expected],[actual],mapping,new Map(),'Exceptions'));
 for(const destination of [actual.destination.slice(1),[...actual.destination,{uid:'extra'}],[...actual.destination.slice(1),{uid:'wrong'}],[...actual.destination.slice(1),actual.destination[1]]]) {
  assert.throws(()=>verifyRulebase([expected],[{...actual,destination}],mapping,new Map(),'Exceptions'),/RubrikBackupRule.*destination.*Expected.*received/);
 }
 assert.throws(()=>verifyRulebase([expected],[{...actual,'destination-negate':true}],mapping,new Map(),'Exceptions'),/destination-negate/);
});
test('rule order remains significant when match-object order is normalized',()=>{
 const first={uid:'a',name:'First',type:'threat-exception',destination:['a','b']},second={...first,uid:'b',name:'Second'};
 assert.throws(()=>verifyRulebase([first,second],[second,first],new Map(),new Map(),'Exceptions'),/name/);
});

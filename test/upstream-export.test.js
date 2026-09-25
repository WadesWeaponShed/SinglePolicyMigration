import test from 'node:test';
import assert from 'node:assert/strict';
import {exportUpstreamArchive} from '../src/workflows/upstream-export.js';
import {importArchive} from '../src/workflows/archives.js';
import {coerceUpstream} from '../src/workflows/upstream-archive.js';
import {catalogsReady} from '../src/catalogs.js';
import {objectAdapters} from '../src/workflows/adapters.js';
import {rulePayload} from '../src/workflows/migration.js';
const any={uid:'any',name:'Any',type:'CpmiAnyObject',domain:{'domain-type':'data domain'}};
const host={uid:'host',type:'host',name:'Quoted "host", one',comments:'first\nsecond','ipv4-address':'192.0.2.1'};
function fixture(){return {apiVersion:'v2.1',objects:[any,host].map(source=>({uid:source.uid,source})),layers:[{uid:'layer',name:'A / '+ 'long name '.repeat(12),type:'access-layer',kind:'access',ordered:true,firewall:true,items:[{uid:'section',name:'Section',type:'access-section'},{uid:'rule',name:'Rule',type:'access-rule',source:['host'],destination:['any'],service:['any'],action:'any',track:{type:'None'},enabled:false}]}],nat:[{uid:'nat',name:'Lower',type:'nat-rule',natPosition:'lower','original-source':'host','original-destination':'any','original-service':'any','translated-source':'Original','translated-destination':'Original','translated-service':'Original',enabled:false}]};}
test('native upstream writer preserves named dependencies, CSV escaping, long paths, sections and NAT',async()=>{
 const plan=fixture(),catalog=(await catalogsReady).get('v2.1');plan.objectSchema=objectAdapters(catalog);
 const copy=structuredClone(plan),snapshot=coerceUpstream(importArchive(exportUpstreamArchive(plan)),catalog);
 assert.deepEqual(plan,copy);assert.equal(snapshot.layers[0].name,plan.layers[0].name);
 const imported=snapshot.objects.find(o=>o.name===host.name);assert.equal(imported.comments,host.comments);
 assert.deepEqual(snapshot.layers[0].items.map(i=>i.type),['access-section','access-rule']);
 assert.deepEqual(snapshot.layers[0].items[1].source,[imported.uid]);assert.equal(snapshot.layers[0].items[1].enabled,false);
 assert.equal(snapshot.nat[0].natPosition,'lower');assert.equal(snapshot.nat[0]['translated-source'],'Original');
});
test('upstream export refuses ambiguous names and unsafe layer paths',()=>{
 const plan=fixture();plan.objects.push({uid:'duplicate',source:{...host,uid:'duplicate'}});
 assert.throws(()=>exportUpstreamArchive(plan),/duplicate names/);
 const unsafe=fixture();unsafe.layers[0].name='../escape';assert.throws(()=>exportUpstreamArchive(unsafe),/safely/);
});
test('archive VPN enum references remain enums on native creation',()=>{
 const source=new Map([['any',any]]),mapping=new Map([['any','destination-any-uid']]);
 assert.equal(rulePayload({type:'access-rule',vpn:'any'},mapping,source).vpn,'Any');
 assert.equal(rulePayload({type:'access-rule',vpn:{uid:'any',name:'Any'}},mapping,source).vpn,'Any');
});

test('upstream writer retains TP direct exceptions and shared group attachments',()=>{
 const plan=fixture(),profile={uid:'profile',name:'Optimized',type:'threat-profile',domain:{'domain-type':'data domain'}};
 plan.objects.push({uid:profile.uid,source:profile});
 const group={uid:'group',sectionUid:'section',name:'Exceptions',comments:'Shared'};
 const direct={uid:'direct',type:'threat-exception',name:'Direct',action:'profile',source:['any'],enabled:false};
 const child={...direct,uid:'child',name:'Grouped',parentSectionUid:'section'};
 plan.layers=[{uid:'tp',name:'Threat',type:'threat-layer',kind:'threat',items:[{uid:'r1',name:'One',type:'threat-rule',action:'profile'},{uid:'r2',name:'Two',type:'threat-rule',action:'profile'}],exceptionSets:['r1','r2'].map(ruleUid=>({ruleUid,groups:[group],items:[direct,{uid:'section',type:'threat-exception-section',name:group.name},child]}))}];
 const snapshot=importArchive(exportUpstreamArchive(plan));
 assert.equal(snapshot.layers[0].exceptionSets.length,2);
 for(const set of snapshot.layers[0].exceptionSets){assert.equal(set.groups.length,1);assert.deepEqual(set.items.map(i=>i.name),['Direct','Exceptions','Grouped']);}
});

test('gateway VPN blade booleans are not mistaken for Access VPN references',async()=>{
 const plan=fixture();plan.objectSchema=objectAdapters((await catalogsReady).get('v2.1'));
 plan.objects.push({uid:'gateway',source:{uid:'gateway',name:'Gateway',type:'simple-gateway','ipv4-address':'192.0.2.5',vpn:false,firewall:true}});
 const snapshot=coerceUpstream(importArchive(exportUpstreamArchive(plan)),(await catalogsReady).get('v2.1'));
 assert.equal(snapshot.objects.find(o=>o.name==='Gateway').vpn,false);
 assert.ok(!snapshot.objects.some(o=>o.name==='false'));
});

test('upstream gateway VPN dependencies survive a native round trip without losing their imported identity',async()=>{
 const plan=fixture();plan.objectSchema=objectAdapters((await catalogsReady).get('v2.1'));
 plan.objects.push({uid:'gateway',source:{uid:'gateway',type:'simple-gateway',name:'Gateway','ipv4-address':'192.0.2.5',vpn:true,'vpn-settings':{'vpn-domain':'host','remote-access':{'nat-traversal-service':'service'}}}},{uid:'service',source:{uid:'service',type:'service-tcp',name:'VPN transport',port:'4500'}});
 const snapshot=coerceUpstream(importArchive(exportUpstreamArchive(plan)),(await catalogsReady).get('v2.1'));
 const gateway=snapshot.objects.find(o=>o.name==='Gateway');
 assert.equal(gateway['vpn-settings']['vpn-domain'],snapshot.objects.find(o=>o.name===host.name).uid);
 assert.equal(gateway['vpn-settings']['remote-access']['nat-traversal-service'],snapshot.objects.find(o=>o.name==='VPN transport').uid);
 assert.equal(gateway.vpn,true);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {ipsManualImpact,applyManualIps,changedPlanSections} from '../src/workflows/migration.js';
import {normalizeMigrationOptions} from '../src/workflows/options.js';
const source=new Map([['missing',{uid:'missing',name:'Missing IPS',type:'CpmiSdTopicPerProfileDynamic'}]]);
function layers(){return [{uid:'l',name:'IPS',items:[{uid:'r',type:'threat-rule'}],exceptionSets:[{ruleUid:'r',groups:[],items:[{uid:'e',name:'Exception',type:'threat-exception','protection-or-site':['missing','other'],action:'Detect'},{uid:'keep',type:'threat-exception','protection-or-site':['other']}]}]}];}
test('manual IPS acknowledgment removes the entire selected exception and retains full definition',()=>{
 const data=layers(),impact=ipsManualImpact(data,'missing');
 const report=applyManualIps(data,[{uid:'missing',fingerprint:impact.fingerprint}],source);
 assert.deepEqual(data[0].exceptionSets[0].items.map(x=>x.uid),['keep']);
 assert.deepEqual(report[0].affected[0].exception['protection-or-site'],['missing','other']);
 assert.equal(data[0].items[0].uid,'r');
});
test('manual IPS decisions are explicit, type constrained and invalidated by changed exceptions',()=>{
 const data=layers(),impact=ipsManualImpact(data,'missing');
 assert.deepEqual(applyManualIps(data,[],source),[]);assert.equal(data[0].exceptionSets[0].items.length,2);
 data[0].exceptionSets[0].items[0].action='Prevent';
 assert.throws(()=>applyManualIps(data,[{uid:'missing',fingerprint:impact.fingerprint}],source),/changed/);
 assert.throws(()=>applyManualIps(layers(),[{uid:'missing',fingerprint:impact.fingerprint}],new Map([['missing',{type:'host'}]])),/changed/);
 assert.throws(()=>normalizeMigrationOptions({manualIps:[{uid:'missing',fingerprint:'bad'}]}),/Invalid/);
});
test('shared exception occurrences are all identified without removing another group member',()=>{
 const data=layers();data[0].exceptionSets.push({...structuredClone(data[0].exceptionSets[0]),ruleUid:'r2'});
 const impact=ipsManualImpact(data,'missing');assert.equal(impact.affected.length,2);
 applyManualIps(data,[{uid:'missing',fingerprint:impact.fingerprint}],source);
 assert.ok(data[0].exceptionSets.every(set=>set.items.length===1&&set.items[0].uid==='keep'));
});
test('other reference fields are not treated as deferrable protection exceptions',()=>{
 const data=layers();data[0].exceptionSets[0].items[0]['protection-or-site']=['other'];data[0].exceptionSets[0].items[0].source=['missing'];
 assert.equal(ipsManualImpact(data,'missing').affected.length,0);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {collection,readRulebase,globalCheck} from '../src/workflows/migration.js';
const rule=uid=>({uid,type:'access-rule'});
test('capped rulebase pages advance by actual returned rules',async()=>{
  const offsets=[];
  const sessions={command:async(id,cmd,b)=>{offsets.push(b.offset);const n=Math.min(50,120-b.offset);return {total:120,to:b.offset+n,rulebase:Array.from({length:n},(_,i)=>rule(`r${b.offset+i}`))};}};
  assert.equal((await readRulebase(sessions,'s','show-access-rulebase',{})).items.length,120);
  assert.deepEqual(offsets,[0,50,100]);
});
test('rulebase rejects repeated, missing, drifting and inconsistent pages',async()=>{
  for(const pages of [
    [{total:2,rulebase:[rule('r')]},{total:2,rulebase:[rule('r')]}],
    [{total:2,rulebase:[rule('r')]},{total:2,rulebase:[]}],
    [{total:2,rulebase:[rule('r')]},{total:3,rulebase:[rule('q')]}],
    [{total:2,to:2,rulebase:[rule('r')]}]
  ]) {
    await assert.rejects(readRulebase({command:async()=>pages.shift()},'s','show-access-rulebase',{}));
  }
});
test('inventory rejects total drift and repeated objects across pages',async()=>{
  for(const pages of [
    [{total:2,objects:[{uid:'a'}]},{total:3,objects:[{uid:'b'}]}],
    [{total:2,objects:[{uid:'a'}]},{total:2,objects:[{uid:'a'}]}]
  ]) await assert.rejects(collection({command:async()=>pages.shift()},'s','show-objects','objects'));
});
test('malformed dependent domain cannot imply global policy absence',()=>{
  for(const value of [{},[],5,null]) assert.throws(()=>globalCheck([{'dependent-domain':value}],{uid:'d',name:'D'},[]),/Unrecognized/);
});

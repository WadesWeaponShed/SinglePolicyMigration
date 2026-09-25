import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

const source=readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
const handler=source.slice(source.indexOf('async function renameAllConflicts()'),source.indexOf("$('#renameAllConflicts').addEventListener"));
function setup(failAt=0) {
  const elements=new Map(),calls=[];
  const objects=[{uid:'a',name:'Host',status:'conflict',renameAllowed:true},{uid:'b',name:'Net',status:'conflict',renameAllowed:true},{uid:'c',name:'Overlap',status:'conflict'},{uid:'d',name:'Manual',status:'conflict',renameAllowed:true,importName:'Custom'}];
  const context=vm.createContext({busy:false,job:null,plan:{id:'first',state:'preview',objects,counts:{conflict:4}},
    $:id=>{if(!elements.has(id))elements.set(id,{});return elements.get(id);},updateControls(){},renderPlan(){},status(){},
    api:async(path,body)=>{calls.push(body);if(calls.length===failAt)throw new Error('Name already exists');return {plan:{id:`next-${calls.length}`,state:'preview',objects:objects.map(o=>o.uid===body.objectUid?{...o,importName:body.newName}:o),counts:{conflict:4-calls.length}}};}
  });
  vm.runInContext(handler,context);return {context,calls,elements};
}
test('bulk rename uses current preview IDs and skips overlaps and existing renames',async()=>{
  const {context,calls,elements}=setup();await vm.runInContext('renameAllConflicts()',context);
  assert.deepEqual(calls.map(c=>[c.planId,c.objectUid,c.newName]),[['first','a','Host_MIGRATED'],['next-1','b','Net_MIGRATED']]);
  assert.equal(context.busy,false);assert.match(elements.get('#bulkRenameStatus').textContent,/Renamed 2 incoming/);
  assert.equal(elements.get('#confirmReviewed').checked,false);
});
test('bulk rename stops on rejected name and retains accepted preview',async()=>{
  const {context,calls,elements}=setup(2);await vm.runInContext('renameAllConflicts()',context);
  assert.equal(calls.length,2);assert.equal(context.plan.id,'next-1');assert.equal(context.busy,false);
  assert.match(elements.get('#bulkRenameStatus').textContent,/Renamed 1 of 2.*Name already exists/);
});
test('bulk rename refuses staged previews',async()=>{
  const {context,calls}=setup();context.job={state:'staged'};await vm.runInContext('renameAllConflicts()',context);assert.equal(calls.length,0);
});

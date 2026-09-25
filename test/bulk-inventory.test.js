import test from 'node:test';
import assert from 'node:assert/strict';
import {bulkDestinationDefinitions} from '../src/workflows/migration.js';
const objects=Array.from({length:510},(_,i)=>({uid:'host-'+i,name:'Host '+i,type:'host','ipv4-address':`10.0.${Math.floor(i/255)}.${i%255}`}));
test('typed full inventory pagination replaces per-object reads without changing identities',async()=>{
 const calls=[];const sessions={catalog:{commands:[{name:'show-hosts'}]},command:async(id,command,body)=>{calls.push({id,command,body});return {objects:objects.slice(body.offset,body.offset+body.limit),total:objects.length};}};
 const result=await bulkDestinationDefinitions(sessions,'target',objects.map(({uid,name,type})=>({uid,name,type})));
 assert.equal(result.size,510);assert.equal(calls.length,2);assert.ok(calls.every(c=>c.command==='show-hosts'&&c.body['details-level']==='full'));
 assert.deepEqual(result.get('host-509'),objects[509]);
});
test('missing or changed full-page identities fail closed; unavailable and small collections retain individual reads',async()=>{
 const candidates=objects.slice(0,20),sessions={catalog:{commands:[{name:'show-hosts'}]},command:async()=>({objects:candidates.slice(1),total:19})};
 await assert.rejects(bulkDestinationDefinitions(sessions,'target',candidates),/identity changed/);
 sessions.command=async()=>({objects:candidates.map(o=>({...o,name:'Changed'})),total:20});await assert.rejects(bulkDestinationDefinitions(sessions,'target',candidates),/identity changed/);
 sessions.command=async()=>{throw new Error('Must not call');};
 assert.equal((await bulkDestinationDefinitions(sessions,'target',candidates.slice(0,19))).size,0);
 assert.equal((await bulkDestinationDefinitions({...sessions,catalog:{commands:[]}},'target',candidates)).size,0);
});

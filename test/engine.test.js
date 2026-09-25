import test from 'node:test';
import assert from 'node:assert/strict';
import {nativeEngine} from '../src/workflows/engine.js';
import {Workbench} from '../src/workflows/workbench.js';
import {demoPlan} from '../src/workflows/demo.js';
test('native engine loads trusted modules and reuses an unchanged revision',async()=>{
 const engine=await nativeEngine();assert.match(engine.revision,/^[a-f0-9]{64}$/);assert.equal(typeof engine.scan,'function');assert.equal(await nativeEngine(),engine);
});
test('a reviewed plan from a different engine revision is rejected before management calls',async()=>{
 const calls=[],workbench=new Workbench({command:async(...args)=>{calls.push(args);throw Error('Should not contact management');}});
 const plan={...demoPlan({scenario:'clean'}),demo:false,engineRevision:'old-revision'};
 workbench.connections.set('connection',{host:'fixture.invalid',targetDomain:plan.targetDomain,plan,lastUsed:Date.now()});
 await workbench.stage('connection',{planId:plan.id,confirmName:plan.targetName});
 while(workbench.locks.has('connection'))await new Promise(resolve=>setTimeout(resolve,1));
 assert.match(workbench.get('connection').job.message,/engine was updated/);assert.deepEqual(calls,[]);
});

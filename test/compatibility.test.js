import test from 'node:test';
import assert from 'node:assert/strict';
import {checkMigrationCapability,migrationApi,validateCommand} from '../src/workflows/compatibility.js';
import {scan} from '../src/workflows/migration.js';
const caps=versions=>({'current-version':versions.at(-1),'supported-versions':versions});
test('capability normalization accepts advertised older and newer API versions',()=>{
 assert.deepEqual(checkMigrationCapability(caps(['2.2','1.9','2.1'])).supported,['v1.9','v2.1','v2.2']);
 for(const response of [{},caps([]),caps([2.1])])assert.throws(()=>checkMigrationCapability(response),/malformed/);
});
test('migration selects highest common version and pins every command',async()=>{
 const calls=[];const sessions={command:async(...args)=>{calls.push(args);return caps(args[0]==='target'?['1.9','2.1']:['1.9','2.1','2.2']);}};
 const api=await migrationApi(sessions,[{id:'root',context:'mds'},{id:'source'},{id:'target'}]);
 assert.equal(api.version,'v2.1');
 await api.command('target','add-host',{name:'Copy','ipv4-address':'10.0.0.1'});
 assert.equal(calls.at(-1)[4],'v2.1');
 assert.throws(()=>api.command('root','show-session'),/unverified/);
 assert.throws(()=>api.command('target','add-host',{name:'Copy',invented:true}),/not documented/);
});
test('v1.9-only manager uses v1.9 and newer manager uses newest advertised version',async()=>{
 for(const v of ['1.9','2.2']){
 const calls=[];const sessions={command:async(...args)=>{calls.push(args);return caps([v]);}};
 const api=await migrationApi(sessions,[{id:'source'},{id:'target'}]);
 assert.equal(api.version,`v${v}`);await api.command('source','show-object',{uid:'object'});assert.equal(calls.at(-1)[4],`v${v}`);
 }
});
test('reviewed version stays pinned and removed support fails instead of upgrading',async()=>{
 const s={command:async()=>caps(['1.9','2.1','2.2'])};
 assert.equal((await migrationApi(s,[{id:'s'}],{version:'v1.9'})).version,'v1.9');
 await assert.rejects(migrationApi({command:async()=>caps(['2.1'])},[{id:'s'}],{version:'v1.9'}),/no longer supported/);
});
test('no common version or inaccessible catalog blocks before policy access',async()=>{
 const calls=[];const sessions={command:async(id,c)=>{calls.push(c);return caps([id==='t'?'1.9':'2.1']);}};
 await assert.rejects(scan({sessions,rootId:'root',sourceId:'s',targetId:'t',sourceDomain:{uid:'source'},targetDomain:{uid:'target'},targetName:'Copy',packageUid:'p'}),/No common API/);
 assert.ok(calls.every(c=>c==='show-api-versions'));
 await assert.rejects(migrationApi({command:async()=>caps(['1.9'])},[{id:'s'}],{catalogs:{ensure:async()=>{throw new Error('catalog offline');}}}),/catalog offline/);
});
test('request validation accepts required alternatives and rejects missing fields',()=>{
 const catalog={apiVersion:'v1.9',commands:[{name:'show-host',requiredFields:[{name:'uid',alternatives:['name']}],optionalFields:[]}]};
 validateCommand(catalog,'show-host',{name:'host'});
 assert.throws(()=>validateCommand(catalog,'show-host',{}),/requires/);
 assert.throws(()=>validateCommand(catalog,'new-command',{}),/not documented/);
});

test('engine constraints choose the highest common implemented version instead of assuming 2.1',async()=>{
 const sessions={command:async()=>caps(['1.9','2.2'])};
 assert.equal((await migrationApi(sessions,[{id:'source'},{id:'target'}],{allowedVersions:['1.9','2.1']})).version,'v1.9');
 await assert.rejects(migrationApi(sessions,[{id:'source'}],{allowedVersions:['2.1']}),/No common API/);
 assert.equal((await migrationApi(sessions,[{id:'source'}])).version,'v2.2');
});

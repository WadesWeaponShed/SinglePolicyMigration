import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {CatalogManager,validateCatalog} from '../src/catalog-manager.js';

const apis={commands:[{name:{web:'show-host'},type:'show',request:'ShowHost'}],objects:[{name:'ShowHost','required-fields':[{name:'uid',types:[{name:'string'}]}]}]};
const content={chapters:[{name:'Hosts','commands-data':[{name:{web:'show-host'}}]}]};
async function temporary(t) {const path=await mkdtemp(join(tmpdir(),'cma-catalog-'));t.after(()=>rm(path,{recursive:true,force:true}));return path;}
function fetcher(calls,override) {return async(url,options)=>{calls.push({url,options});if(override)return override(url);return {ok:true,text:async()=>JSON.stringify(url.endsWith('apis.json')?apis:content)};};}

test('ensure returns bundled versions without network access including official v1.9',async()=>{
  const manager=await new CatalogManager({directory:'/nonexistent-cma-ensure-cache',fetcher:async()=>{throw new Error('Unexpected network');}}).init();
  const catalog=await manager.ensure('v1.9');
  assert.equal(catalog.apiVersion,'v1.9');
  assert.equal(catalog.commandCount,666);
  assert.ok(catalog.commands.some(c=>c.name==='show-host'));
  assert.doesNotThrow(()=>validateCatalog(catalog,'v1.9'));
});

test('ensure downloads only fixed-origin version documents, validates and atomically caches',async t=>{
  const directory=await temporary(t),calls=[];
  const manager=new CatalogManager({directory,fetcher:fetcher(calls)});
  const catalog=await manager.ensure('v1.8.1');
  assert.equal(catalog.apiVersion,'v1.8.1');
  assert.deepEqual(catalog.commands[0].requiredFields.map(f=>f.name),['uid']);
  assert.deepEqual(calls.map(c=>c.url).sort(),[
    'https://sc1.checkpoint.com/documents/latest/APIs/data/v1.8.1/dynamic/apis.json',
    'https://sc1.checkpoint.com/documents/latest/APIs/data/v1.8.1/dynamic/content.json'
  ]);
  assert.ok(calls.every(c=>c.options.redirect==='error' && c.options.signal));
  assert.deepEqual(await readdir(directory),['check-point-api-v1.8.1.json']);
  const reloaded=await new CatalogManager({directory,bundled:directory,fetcher:async()=>{throw new Error('Offline');}}).init();
  assert.equal((await reloaded.ensure('v1.8.1')).commandCount,1);
});

test('same-version concurrent ensure calls share one download and cached subsequent call',async t=>{
  const directory=await temporary(t),calls=[];
  let release;const gate=new Promise(resolve=>{release=resolve;});
  const manager=new CatalogManager({directory,fetcher:fetcher(calls,async url=>{await gate;return {ok:true,text:async()=>JSON.stringify(url.endsWith('apis.json')?apis:content)};})});
  const requests=Array.from({length:12},()=>manager.ensure('v1.8'));
  assert.equal(calls.length,2);
  release();const results=await Promise.all(requests);
  assert.ok(results.every(c=>c.apiVersion==='v1.8'));
  await manager.ensure('v1.8');
  assert.equal(calls.length,2);
  assert.equal(manager.installing.size,0);
});

test('invalid versions cannot influence download URLs or cache paths',async t=>{
  const directory=await temporary(t),calls=[];
  const manager=new CatalogManager({directory,fetcher:fetcher(calls)});
  for(const version of ['1.9','v1.9/../../outside','https://other.example','v1.9?x','v1.9#x','v1.2.3.4','',null]) await assert.rejects(manager.ensure(version),/Invalid catalog version/);
  assert.equal(calls.length,0);
  assert.deepEqual(await readdir(directory),[]);
});

test('network, malformed and invalid catalogs do not install or select a guessed fallback',async t=>{
  const directory=await temporary(t);
  for(const override of [
    async()=>{throw new Error('Offline');},
    async()=>({ok:false,status:404}),
    async()=>({ok:true,text:async()=>'{invalid'}),
    async()=>({ok:true,text:async()=>JSON.stringify({commands:[],objects:[],chapters:[]})}),
    async()=>({ok:true,text:async()=>JSON.stringify({unexpected:true})})
  ]) {
    const manager=new CatalogManager({directory,fetcher:fetcher([],override)});
    await assert.rejects(manager.ensure('v1.8'));
    assert.equal(manager.catalogs.size,0);
    assert.equal(manager.installing.size,0);
    assert.throws(()=>manager.get('v1.8'),/not installed/);
    assert.deepEqual(await readdir(directory),[]);
  }
});

test('failed ensure is retryable and cache-write failure never activates downloaded catalog',async t=>{
  const directory=await temporary(t);let fail=true;
  const manager=new CatalogManager({directory,fetcher:fetcher([],async url=>{if(fail)throw new Error('Offline');return {ok:true,text:async()=>JSON.stringify(url.endsWith('apis.json')?apis:content)};})});
  await assert.rejects(manager.ensure('v1.8'),/Offline/);
  fail=false;assert.equal((await manager.ensure('v1.8')).commandCount,1);
  const invalidDirectory=join(directory,'not-a-directory');await writeFile(invalidDirectory,'file');
  const unwritable=new CatalogManager({directory:invalidDirectory,fetcher:fetcher([])});
  await assert.rejects(unwritable.ensure('v1.8'));
  assert.equal(unwritable.catalogs.size,0);
  assert.equal(unwritable.installing.size,0);
});

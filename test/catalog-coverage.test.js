import test from 'node:test';
import assert from 'node:assert/strict';
import {CatalogManager} from '../src/catalog-manager.js';
import {catalogCoverage} from '../src/workflows/catalog-coverage.js';
import {fields} from '../src/workflows/objects.js';
test('catalog discovery distinguishes documented commands from implemented migration adapters',async()=>{
 const manager=await new CatalogManager({directory:'/nonexistent-cma-test-cache'}).init();
 const baseline=catalogCoverage(manager,'v2.1',['v2.1']);
 assert.equal(baseline.advertised,true);
 assert.equal(baseline.candidates.find(c=>c.type==='access-layer').status,'adapter-implemented');
 assert.equal(baseline.candidates.find(c=>c.type==='host').status,'catalog-candidate');
 assert.ok(baseline.candidates.some(c=>c.status==='adapter-needed'));
 const newer=catalogCoverage(manager,'v2.2',['v2.1']);
 assert.equal(newer.advertised,false);
 assert.equal(newer.candidates.find(c=>c.type==='host').status,'catalog-candidate');
 assert.ok(newer.candidates.some(c=>c.newSinceBaseline));
 assert.equal(newer.executionVersion,'v2.1');
});
test('failed catalog refresh preserves cached coverage and never creates adapters',async()=>{
 const before=Object.keys(fields);
 const manager=await new CatalogManager({directory:'/nonexistent-cma-test-cache',fetcher:async()=>{throw new Error('offline');}}).init();
 const snapshot=catalogCoverage(manager,'v2.2');
 await assert.rejects(manager.update(),/offline/);
 assert.deepEqual(catalogCoverage(manager,'v2.2'),snapshot);
 assert.deepEqual(Object.keys(fields),before);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {gzipSync} from 'node:zlib';
import {importArchive} from '../src/workflows/archives.js';
import {coerceUpstream} from '../src/workflows/upstream-archive.js';
import {catalogsReady} from '../src/catalogs.js';
function tar(entries) {
 const chunks=[];
 for(const [name,content,type='0'] of entries){const bytes=Buffer.from(content),header=Buffer.alloc(512);header.write(name);header.write(bytes.length.toString(8).padStart(11,'0')+'\0',124);header.fill(32,148,156);header.write(type,156);header.write('ustar\0',257);header.write(header.reduce((n,v)=>n+v,0).toString(8).padStart(6,'0')+'\0 ',148);chunks.push(header,bytes,Buffer.alloc((512-bytes.length%512)%512));}
 return gzipSync(Buffer.concat([...chunks,Buffer.alloc(1024)]));
}
const file=(type,body)=>[`01____add-${type}__2026.csv`,body];
function fixture(extra=[]) {
 const layer=tar([['version.txt','2.1'],file('access-rule','name,position,source.0,destination.0,service.0,action,track.type,enabled\nAllow,1,Host,Any,Any,Accept,None,false\n'),file('access-section','name,position\nHeader,1\n')]);
 return tar([['version.txt','2.1'],file('host','name,ipv4-address\nHost,10.0.0.1\n'),file('access-layer','name,firewall,__ordered_access_control_layer\nNetwork,true,true\n'),['exported__access_layer__Network__2026.tar.gz',layer],...extra]);
}
test('upstream archives are parsed natively with sections before rules and typed values',async()=>{
 const snapshot=coerceUpstream(importArchive(fixture()),(await catalogsReady).get('v2.1'));
 const [layer]=snapshot.layers;assert.equal(layer.firewall,true);assert.deepEqual(layer.items.map(r=>r.type),['access-section','access-rule']);
 assert.equal(layer.items[1].enabled,false);assert.equal(layer.items[1].track.type,'None');assert.equal(layer.items[1].source[0],snapshot.objects.find(o=>o.name==='Host').uid);
 assert.ok(snapshot.objects.some(o=>o.name==='Any'&&o.type==='archive-reference'));
});
test('native upstream reader rejects unsafe paths, links, duplicate members and malformed rows',()=>{
 for(const entries of [[['../x.json','{}']],[['link.json','','2']],[['version.txt','2.1']],[file('host','name,ipv4-address\nMissing\n')]])assert.throws(()=>importArchive(fixture(entries)));
});
test('archive parser rejects malformed compressed data, unsupported format and prototype keys',()=>{
 for(const bytes of [Buffer.from('bad'),gzipSync(Buffer.from('{}')),gzipSync(Buffer.from('{"__proto__":{}}'))])assert.throws(()=>importArchive(bytes));
});
test('empty and mixed versions are rejected by upstream archive validation',()=>{
 assert.throws(()=>importArchive(tar([])),/version/);
 const nested=tar([['version.txt','1.9']]);assert.throws(()=>importArchive(fixture([['extra.tar.gz',nested]])),/consistent API/);
});

test('upstream HTTPS action and track stay enums while content remains an object reference',async()=>{
 const https=tar([['version.txt','2.1'],file('https-rule','name,position,source.0,destination.0,service.0,action,track\nInspect,1,Any,Any,Any,Inspect,Log\n')]);
 const access=tar([['version.txt','2.1'],file('access-rule','name,position,source.0,destination.0,service.0,content.0,action,track.type\nAllow,1,Any,Any,Any,Any,Accept,None\n')]);
 const bytes=tar([['version.txt','2.1'],file('package','name\nPolicy\n'),file('access-layer','name\nAccess\n'),['02____add-https-layer__2026.csv','name,layer-type\nOutbound,outbound\n'],['1__access_layer__Access__2026.tar.gz',access],['2__https_layer__Outbound__2026.tar.gz',https]]);
 const snapshot=importArchive(bytes),any=snapshot.objects.find(o=>o.name==='Any');
 assert.equal(snapshot.layers.find(l=>l.kind==='https').items[0].action,'Inspect');
 assert.equal(snapshot.layers.find(l=>l.kind==='https').items[0].track,'Log');
 assert.equal(snapshot.layers.find(l=>l.kind==='access').items[0].content[0],any.uid);
 assert.equal(snapshot.objects.some(o=>['Inspect','Log'].includes(o.name)),false);
});

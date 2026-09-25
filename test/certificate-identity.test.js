import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {X509Certificate} from 'node:crypto';
import {compareObjects,resolveObjectRenames,certificateFingerprint} from '../src/workflows/objects.js';
import {redactSecrets} from '../src/check-point-client.js';
const pem=readFileSync(new URL('./fixtures/proxy/cert.pem',import.meta.url));
const source={uid:'source',type:'server-certificate',name:'Server certificate','base64-public-certificate':pem.toString('base64'),'issued-by':'CN=localhost',subject:'CN=localhost'};
const schema={'server-certificate':['name','base64-certificate','base64-password','color','comments','tags']};
test('HTTPS certificate reuse requires exact public certificate identity, never only its display name',()=>{
 const dest={...source,uid:'destination',name:'Existing certificate'};
 assert.equal(compareObjects([source],[dest],schema)[0].status,'reuse');
 assert.equal(resolveObjectRenames(compareObjects([source],[dest],schema),[dest],{},[],schema,{objectSuffix:'_COPY'})[0].status,'reuse');
 const changed=Buffer.from(new X509Certificate(pem).raw);changed[changed.length-1]^=1;
 assert.notEqual(certificateFingerprint(source),certificateFingerprint({...source,'base64-public-certificate':changed.toString('base64')}));
 assert.equal(compareObjects([source],[{...source,uid:'other','base64-public-certificate':changed.toString('base64')}],schema)[0].status,'conflict');
 assert.equal(compareObjects([source],[],schema)[0].status,'blocked');
 assert.equal(compareObjects([{...source,'base64-public-certificate':''}],[dest],schema)[0].status,'blocked');
});
test('API diagnostics and public previews redact certificate and connection secrets recursively',()=>{
 assert.deepEqual(redactSecrets({source:{'base64-password':'secret','base64-certificate':'bundle','base64-public-certificate':'public'},proxyUrl:'http://user:pass@proxy','one-time-password':'trust'}),{source:{'base64-password':'[redacted]','base64-certificate':'[redacted]','base64-public-certificate':'public'},proxyUrl:'[redacted]','one-time-password':'[redacted]'});
});

test('the built-in outbound certificate marker uses verified vendor identity, not absent private material',()=>{
 const marker={uid:'built-in-marker',name:'Outbound Certificate',type:'outbound-inspection-certificate',domain:{'domain-type':'data domain'}};
 assert.equal(compareObjects([marker],[marker],{'outbound-inspection-certificate':['name']})[0].status,'reuse');
 assert.equal(compareObjects([marker],[],{'outbound-inspection-certificate':['name']})[0].status,'blocked');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,readdirSync,writeFileSync,rmSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {OperationJournal} from '../src/workflows/journal.js';
const input={host:'https://mds.example',targetDomain:{uid:'domain-uid',name:'Destination'},targetName:'Migrated',sessionUid:'session-object-uid'};
function directory(t){const path=mkdtempSync(join(tmpdir(),'cma-journal-test-'));t.after(()=>rmSync(path,{recursive:true,force:true}));return path;}

test('journal survives reopening and reserves unresolved destination',t=>{
  const dir=directory(t),first=new OperationJournal(dir);
  const record=first.begin(input);
  first.update(record,{state:'publishing',taskId:'task-uid'});
  const reopened=new OperationJournal(dir),pending=reopened.unresolved(input.host);
  assert.equal(pending.length,1);assert.equal(pending[0].id,record.id);assert.equal(pending[0].state,'publishing');assert.equal(pending[0].taskId,'task-uid');
  assert.throws(()=>reopened.begin(input),/unfinished migration/);
  assert.equal(statSync(join(dir,`${record.id}.json`)).mode&0o777,0o600);
});

test('journal writes only explicit nonsecret metadata fields',t=>{
  const dir=directory(t),journal=new OperationJournal(dir);
  const record=journal.begin({...input,password:'secret-password',apiKey:'secret-key',sid:'secret-sid',credentials:{password:'secret'},raw:{sid:'secret'},plan:{objects:['sensitive-policy']},targetDomain:{...input.targetDomain,sid:'nested-secret'}});
  journal.update(record,{state:'staged',taskId:'task',packageUid:'pkg',credentials:{password:'update-secret'},raw:{sid:'update-secret'}});
  const text=readFileSync(join(dir,`${record.id}.json`),'utf8'),persisted=JSON.parse(text);
  assert.ok(!/secret|sensitive-policy|password|credentials|"sid"|"raw"|"plan"/.test(text));
  assert.deepEqual(Object.keys(persisted).sort(),['version','id','host','targetDomain','targetName','sessionUid','apiVersion','state','createdAt','updatedAt','taskId','packageUid'].sort());
  assert.deepEqual(persisted.targetDomain,input.targetDomain);
});

test('corrupt journal fails closed for both listing and new migration',t=>{
  const dir=directory(t),journal=new OperationJournal(dir);
  writeFileSync(join(dir,'corrupt.json'),'{not-json');
  assert.throws(()=>journal.list(),/cannot be read/);
  assert.throws(()=>journal.begin(input),/cannot be read/);
});

test('journal rejects schema and record filename mismatches',t=>{
  for(const mutate of [r=>({...r,version:2}),r=>({...r,state:'assumed-success'}),r=>({...r,id:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'})]) {
    const dir=directory(t),journal=new OperationJournal(dir),record=journal.begin(input);
    writeFileSync(join(dir,`${record.id}.json`),JSON.stringify(mutate(record)));
    assert.throws(()=>new OperationJournal(dir).list(),/cannot be read/);
  }
});

test('terminal journal states release destination reservation for subsequent migrations',t=>{
  for(const state of ['published','discarded','failed']) {
    const dir=directory(t),journal=new OperationJournal(dir),record=journal.begin(input);
    journal.update(record,{state});
    assert.equal(journal.unresolved().length,0);
    assert.ok(!readdirSync(dir).some(name=>name.endsWith('.lock')));
    assert.notEqual(new OperationJournal(dir).begin(input).id,record.id);
  }
});

test('unknown outcomes and independent processes keep exclusive destination reservation',t=>{
  const dir=directory(t),a=new OperationJournal(dir),b=new OperationJournal(dir),record=a.begin(input);
  a.update(record,{state:'publish-unknown'});
  assert.throws(()=>b.begin(input),/unfinished migration/);
  const other=b.begin({...input,targetDomain:{uid:'other-domain',name:'Other'}});
  assert.equal(b.unresolved().length,2);
  a.update(record,{state:'discarded'});
  assert.ok(b.unresolved().some(r=>r.id===other.id));
});

test('orphan destination lock blocks staging rather than guessing prior operation outcome',t=>{
  const dir=directory(t),journal=new OperationJournal(dir),record=journal.begin(input);
  rmSync(join(dir,`${record.id}.json`));
  assert.throws(()=>new OperationJournal(dir).begin(input),/recovery lock exists/);
});

test('stale terminal update never releases another operation lock',t=>{
  const dir=directory(t),journal=new OperationJournal(dir),first=journal.begin(input);
  journal.update(first,{state:'discarded'});
  const second=journal.begin(input);
  journal.update(first,{state:'discarded'});
  const lock=readdirSync(dir).find(name=>name.endsWith('.lock'));
  assert.equal(readFileSync(join(dir,lock),'utf8'),second.id);
});

test('reading the journal preserves the last persisted timestamp',t=>{
  const dir=directory(t),journal=new OperationJournal(dir),record=journal.begin(input);
  assert.equal(new OperationJournal(dir).list()[0].updatedAt,record.updatedAt);
});


test('journal persists negotiated API version across restart and terminal updates',t=>{
  const dir=directory(t),journal=new OperationJournal(dir);
  const record=journal.begin({...input,apiVersion:'v1.9'});
  assert.equal(new OperationJournal(dir).unresolved()[0].apiVersion,'v1.9');
  journal.update(record,{state:'discarded'});
  assert.equal(new OperationJournal(dir).list()[0].apiVersion,'v1.9');
});

test('only pre-version journal records retain legacy v2.1 during recovery',t=>{
  const dir=directory(t),journal=new OperationJournal(dir),record=journal.begin({...input,apiVersion:'v1.9'});
  const path=join(dir,`${record.id}.json`),legacy=JSON.parse(readFileSync(path,'utf8'));
  delete legacy.apiVersion;writeFileSync(path,JSON.stringify(legacy));
  assert.equal(new OperationJournal(dir).list()[0].apiVersion,'v2.1');
  legacy.apiVersion='latest';writeFileSync(path,JSON.stringify(legacy));
  assert.throws(()=>new OperationJournal(dir).list(),/cannot be read/);
});

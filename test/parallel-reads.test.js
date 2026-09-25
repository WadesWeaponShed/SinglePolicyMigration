import test from 'node:test';
import assert from 'node:assert/strict';
import {readDependencyFrontiers} from '../src/workflows/migration.js';

test('dependency reads are bounded, deterministic, and visit cycles once',async()=>{
  const pending=new Set(['a','b','c']),seen=[],reads=[];let active=0,peak=0;
  await readDependencyFrontiers(pending,async uid=>{
    reads.push(uid);peak=Math.max(peak,++active);
    await new Promise(resolve=>setTimeout(resolve,uid==='a'?8:1));active--;return uid;
  },(uid,value)=>{assert.equal(uid,value);seen.push(uid);if(uid==='a')pending.add('d');if(uid==='d')pending.add('a');},2);
  assert.equal(peak,2);assert.deepEqual(seen,['a','b','c','d']);assert.deepEqual(reads,seen);
});

test('failed frontier drains in-flight reads and does not consume partial results',async()=>{
  let finished=false,consumed=false;
  await assert.rejects(readDependencyFrontiers(new Set(['bad','slow','later']),async uid=>{
    if(uid==='bad')throw new Error('read failed');
    await new Promise(resolve=>setTimeout(resolve,10));finished=true;
  },()=>{consumed=true;},2),/read failed/);
  assert.equal(finished,true);assert.equal(consumed,false);
});

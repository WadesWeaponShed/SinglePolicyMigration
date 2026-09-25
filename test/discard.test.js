import test from 'node:test';
import assert from 'node:assert/strict';
import {discardChanges} from '../src/workflows/discard.js';

test('successful discard verifies the current empty session after old session object disappears',async()=>{
  const calls=[];
  const api={command:async(id,command,body)=>{
    calls.push(command);
    if(command==='discard')return {message:'OK'};
    assert.deepEqual(body,{});
    return {uid:'replacement-session',state:'open',changes:0};
  }};
  assert.equal((await discardChanges(api,'dedicated')).changes,0);
  assert.deepEqual(calls,['discard','show-session']);
});

test('discard failures and unverifiable responses never claim cleanup',async()=>{
  for(const mode of ['discard-error','inspection-error','remaining','missing','warning']){
    const api={command:async(id,command)=>{
      if(command==='discard'){
        if(mode==='discard-error')throw new Error('discard failed');
        return mode==='warning'?{warnings:[{message:'warning'}]}:{};
      }
      if(mode==='inspection-error')throw new Error('inspection unavailable');
      return {changes:mode==='remaining'?1:undefined};
    }};
    await assert.rejects(discardChanges(api,'dedicated'));
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {CheckPointClient,CheckPointApiError} from '../src/check-point-client.js';
test('transient read failures retry a bounded number of times; writes never replay',async()=>{
 const client=new CheckPointClient({baseUrl:'https://example.invalid'});let calls=0;
 client.requestCommand=async()=>{if(++calls<3)throw new CheckPointApiError('Interrupted',{phase:'socket'});return {objects:[]};};
 assert.deepEqual(await client.command('show-objects',{}),{objects:[]});assert.equal(calls,3);
 calls=0;await client.command('keepalive',{});assert.equal(calls,3);
 for(const command of ['add-host','add-objects-batch','publish','discard','login']){
  calls=0;await assert.rejects(client.command(command,{}),/Interrupted/);assert.equal(calls,1);
 }
 calls=0;client.requestCommand=async()=>{calls++;throw new CheckPointApiError('Interrupted',{phase:'socket'});};
 await assert.rejects(client.command('show-session',{}),/Interrupted/);assert.equal(calls,3);
 calls=0;client.requestCommand=async()=>{calls++;throw new CheckPointApiError('Forbidden',{phase:'api-response',statusCode:403});};
 await assert.rejects(client.command('show-objects',{}),/Forbidden/);assert.equal(calls,1);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer as httpsServer} from 'node:https';
import {createServer as httpServer} from 'node:http';
import {connect} from 'node:net';
import {readFile} from 'node:fs/promises';
import {CheckPointClient} from '../src/check-point-client.js';
import {normalizeProxy} from '../src/proxy-agent.js';
const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server.address().port)));
const close=server=>new Promise(resolve=>server.close(resolve));
test('native proxy tunnels management TLS and never forwards proxy credentials to management',async()=>{
 const sockets=new Set(),seen=[];
 const target=httpsServer({key:await readFile(new URL('./fixtures/proxy/key.pem',import.meta.url)),cert:await readFile(new URL('./fixtures/proxy/cert.pem',import.meta.url))},(request,response)=>{
  seen.push(request.headers);let raw='';request.on('data',chunk=>raw+=chunk);request.on('end',()=>{assert.deepEqual(JSON.parse(raw),{limit:1});response.writeHead(200,{'content-type':'application/json'});response.end('{"objects":[]}');});
 });
 const targetPort=await listen(target),proxy=httpServer();let authorization;
 proxy.on('connect',(request,socket)=>{
  authorization=request.headers['proxy-authorization'];assert.equal(request.url,`127.0.0.1:${targetPort}`);
  const upstream=connect(targetPort,'127.0.0.1',()=>{socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');socket.pipe(upstream);upstream.pipe(socket);});
  sockets.add(socket);sockets.add(upstream);socket.on('error',()=>{});upstream.on('error',()=>{});
 });
 const proxyPort=await listen(proxy);
 try{
  const client=new CheckPointClient({baseUrl:`https://127.0.0.1:${targetPort}`,proxyUrl:`http://proxy-user:proxy-secret@127.0.0.1:${proxyPort}`,rejectUnauthorized:false});
  assert.deepEqual(await client.withSid('session-id').command('show-objects',{limit:1}),{objects:[]});
  assert.equal(authorization,'Basic '+Buffer.from('proxy-user:proxy-secret').toString('base64'));
  assert.equal(seen[0]['x-chkp-sid'],'session-id');assert.equal(seen[0]['proxy-authorization'],undefined);
  await assert.rejects(new CheckPointClient({baseUrl:client.baseUrl,proxyUrl:client.proxyUrl}).command('show-objects',{limit:1}),/self-signed|certificate/);
 }finally{for(const socket of sockets)socket.destroy();await Promise.all([close(proxy),close(target)]);}
});
test('proxy refusal fails without exposing proxy credentials or sending a management request',async()=>{
 const proxy=httpServer();proxy.on('connect',(_request,socket)=>socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'));const port=await listen(proxy);
 try{await assert.rejects(new CheckPointClient({baseUrl:'https://management.invalid',proxyUrl:`http://user:secret@127.0.0.1:${port}`}).command('login',{}),error=>/407/.test(error.message)&&!error.message.includes('secret'));}finally{await close(proxy);}
});
test('proxy configuration accepts only explicit HTTP CONNECT endpoints',()=>{
 assert.equal(normalizeProxy(''),'');assert.equal(normalizeProxy('http://proxy:8080'),'http://proxy:8080/');
 for(const value of ['socks5://proxy','http://proxy/path','http://proxy?x=1','no-scheme'])assert.throws(()=>normalizeProxy(value));
});

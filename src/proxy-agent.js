import {Agent,request as httpsRequest} from 'node:https';
import {request as httpRequest} from 'node:http';
import {connect as tlsConnect} from 'node:tls';
import {isIP} from 'node:net';
export function normalizeProxy(value) {
 if(!value)return '';
 let url;try{url=new URL(String(value));}catch{throw new Error('Use an HTTP or HTTPS proxy URL.');}
 if(!['http:','https:'].includes(url.protocol)||url.pathname!=='/'||url.search||url.hash)throw new Error('Proxy must be an HTTP or HTTPS address without a path, query or fragment.');
 return url.toString();
}
// TLS is established end-to-end to management after the proxy opens CONNECT.
// Proxy credentials are sent only in the CONNECT header, never to management.
export class ManagementProxyAgent extends Agent {
 constructor(proxyUrl,{timeoutMs=45000}={}) {super({keepAlive:false});this.proxy=new URL(normalizeProxy(proxyUrl));this.timeoutMs=timeoutMs;}
 createConnection(options,callback) {
  const proxy=this.proxy,host=options.hostname||options.host,authority=`${isIP(host)===6?'['+host+']':host}:${options.port||443}`;
  const headers={host:authority};
  if(proxy.username||proxy.password)headers['proxy-authorization']='Basic '+Buffer.from(decodeURIComponent(proxy.username)+':'+decodeURIComponent(proxy.password)).toString('base64');
  let completed=false;
  const finish=(error,socket)=>{if(completed){if(error)socket?.destroy();return;}completed=true;callback(error,socket);};
  const request=(proxy.protocol==='https:'?httpsRequest:httpRequest)({hostname:proxy.hostname,port:proxy.port||(proxy.protocol==='https:'?443:80),method:'CONNECT',path:authority,headers,agent:false},()=>{});
  request.setTimeout(this.timeoutMs,()=>request.destroy(new Error('Management proxy connection timed out.')));
  request.once('error',error=>finish(error));
  request.once('connect',(response,socket,head)=>{
   if(response.statusCode!==200){socket.destroy();finish(new Error(`Management proxy refused CONNECT (HTTP ${response.statusCode}).`));return;}
   if(head.length)socket.unshift(head);
   const tls=tlsConnect({socket,servername:isIP(host)?undefined:host,rejectUnauthorized:options.rejectUnauthorized!==false});
   tls.setTimeout(this.timeoutMs,()=>tls.destroy(new Error('Management TLS handshake timed out.')));
   tls.once('error',error=>finish(error));
   tls.once('secureConnect',()=>{tls.setTimeout(0);finish(null,tls);});
  });
  request.end();
 }
}

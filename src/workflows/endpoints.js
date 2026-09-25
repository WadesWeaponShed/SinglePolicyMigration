import {normalizeProxy} from '../proxy-agent.js';
// Connection descriptors deliberately contain no credentials. Credentials stay in
// the Workbench's in-memory connection and are never placed in recovery journals.
export function endpointCredentials(body={}) {
  const cloud=body.smart1Cloud===true;
  const url=new URL(/^https:\/\//i.test(body.host||'')?body.host:`https://${body.host||''}`);
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||(!cloud&&url.pathname!=='/'))throw new Error('Use an HTTPS management address without embedded credentials. Paths are allowed for Smart-1 Cloud tenants.');
  const domain=String(body.domain||'').trim();
  return {auxiliaryContexts:false,proxyUrl:normalizeProxy(body.proxyUrl),host:cloud?url.toString():url.origin,port:body.port,smart1Cloud:cloud,domain,mdsMode:!!domain,username:body.username,password:body.password,authMode:body.authMode,apiKey:body.apiKey,ignoreTls:body.ignoreTls===true,largeEnvironmentMode:body.largeEnvironmentMode===true};
}
export function managementContext(connection) {
  return connection.mode==='pair'?{rootId:null,sourceRootId:connection.sourceRootId||null,targetRootId:connection.rootId||null}:{rootId:connection.rootId};
}
export function managementSessions(connection) {
  return [...new Set([connection.rootId,connection.sourceRootId].filter(Boolean))].map(id=>({id,context:'mds',label:'Management domain directory'}));
}

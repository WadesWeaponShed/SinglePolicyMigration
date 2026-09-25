import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, sep, extname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { SessionManager } from './session-manager.js';
import { redactSecrets } from './check-point-client.js';
import { compareVersions } from './catalog-manager.js';
import { catalogsReady } from './catalogs.js';
import { catalogCoverage } from './workflows/catalog-coverage.js';
import { OperationJournal } from './workflows/journal.js';
import { MAX_ARCHIVE } from './workflows/archives.js';
import { Workbench } from './workflows/workbench.js';
const publicDir=resolve(fileURLToPath(new URL('../public/',import.meta.url)));
export function createApp(workbench=new Workbench(new SessionManager({taskPollAttempts:120}),{journal:new OperationJournal(resolve(fileURLToPath(new URL('../.recovery/',import.meta.url))))})) {
  const json=(res,code,data)=>{res.writeHead(code,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(redactSecrets(data)));};
  const server=createServer(async(req,res)=>{
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    const requestId=randomUUID().slice(0,8);
    try {
      const host=req.headers.host;
      const hostname=new URL(`http://${host}`).hostname;
      if(!['127.0.0.1','localhost','[::1]'].includes(hostname))return json(res,403,{error:'This workbench accepts localhost requests only.'});
      if(req.url==='/api/health'&&req.method==='GET')return json(res,200,{ok:true,apiRevision:5,features:['catalogs','dynamic-api-versions','durable-recovery','native-policy-archives','native-tp-https','catalog-object-adapters','nat-placement','native-batches','independent-endpoints','management-proxy','native-upstream-export']});
      if(req.url.startsWith('/api/')) {
        if(req.method!=='POST')return json(res,405,{error:'Use POST.'});
        const uploading=req.url==='/api/archive/upload';
        if(!req.headers['content-type']?.startsWith(uploading?'application/gzip':'application/json'))return json(res,415,{error:uploading?'A gzip archive is required.':'JSON is required.'});
        if(req.headers.origin&&req.headers.origin!==`http://${host}`)return json(res,403,{error:'Cross-origin requests are not allowed.'});
        if(req.headers['sec-fetch-site']==='cross-site')return json(res,403,{error:'Cross-site requests are not allowed.'});
        const sessionId=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('cma_session='))?.slice(12);
        if(uploading){
          if(!sessionId||!workbench.connections.has(sessionId))return json(res,401,{error:'Connect to the MDS to continue.'});
          const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>MAX_ARCHIVE)return json(res,413,{error:'Archive limit is 128 MiB.'});chunks.push(chunk);}
          return json(res,200,await workbench.uploadArchive(sessionId,Buffer.concat(chunks)));
        }
        let data='';for await(const chunk of req){data+=chunk;if(data.length>32_768)return json(res,413,{error:'Request is too large.'});}
        let body;try{body=JSON.parse(data||'{}');}catch{return json(res,400,{error:'Invalid JSON.'});}
        const id=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('cma_session='))?.slice(12);
        let result;
        if(req.url==='/api/connect') {
          if(id&&workbench.connections.has(id))throw new Error('Disconnect the existing session before connecting again.');
          const c=await workbench.connect(body);
          res.setHeader('Set-Cookie',`cma_session=${c.id}; HttpOnly; SameSite=Strict; Path=/`);
          const {id:ignored,...description}=c;result=description;
        } else {
          if(!id||!workbench.connections.has(id))return json(res,401,{error:'Connect to the MDS to continue.',requestId});
          switch(req.url) {
            case '/api/catalog/status':result=(await catalogsReady).status();break;
            case '/api/catalog/update':result=await (await catalogsReady).update();break;
            case '/api/catalog/coverage':{
              const c=workbench.get(id);const capabilities=[];
              if(!c.demo)for(const [label,sid,context] of [['Source MDS',c.sourceRootId,'mds'],['Destination MDS',c.rootId,'mds'],['Source',c.sourceId,'primary'],['Destination',c.targetId,'primary']])if(sid){
                const capability=await workbench.sessions.capabilities(sid,context);capabilities.push({label,...capability});
              }
              const common=capabilities.length?capabilities.reduce((all,c)=>all.filter(v=>c.supported.includes(v)),capabilities[0].supported).sort(compareVersions):null;
              const manager=await catalogsReady;
              const selected=body.version||common?.at(-1)||manager.status().installed.at(-1);
              await manager.ensure(selected);
              result={...catalogCoverage(manager,selected,common,c.plan?.apiVersion),capabilities};break;
            }
            case '/api/archive/export':result=await workbench.exportPolicy(id,body);break;
            case '/api/archive/download':{const bytes=await workbench.downloadArchive(id,body.token);res.writeHead(200,{'content-type':'application/gzip','content-disposition':'attachment; filename=policy-package.cma.gz','cache-control':'no-store'});res.end(bytes);return;}
            case '/api/session':result=workbench.describe(workbench.get(id));break;
            case '/api/select':result=await workbench.select(id,body);break;
            case '/api/preview':result=await workbench.preview(id,body);break;
            case '/api/rename':result=await workbench.rename(id,body);break;
            case '/api/stage':result=await workbench.stage(id,body);break;
            case '/api/job':{const c=workbench.get(id);result={job:c.job||null,activity:c.activity||null};break;}
            case '/api/recover':result=await workbench.recover(id,body);break;
            case '/api/reconcile':result=await workbench.reconcile(id);break;
            case '/api/finish':result=await workbench.finish(id,body);break;
            case '/api/logout':result=await workbench.logout(id);res.setHeader('Set-Cookie','cma_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');break;
            default:return json(res,404,{error:'Unknown API route.'});
          }
        }
        return json(res,200,{...result,requestId});
      }
      if(req.method!=='GET')return json(res,405,{error:'Use GET.'});
      const path=resolve(publicDir,req.url==='/'?'index.html':decodeURIComponent(new URL(req.url,'http://localhost').pathname).slice(1));
      if(!path.startsWith(publicDir+sep))return json(res,403,{error:'Forbidden.'});
      const content=await readFile(path);
      res.writeHead(200,{'cache-control':'no-store','content-type':({'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8'})[extname(path)]||'application/octet-stream'});res.end(content);
    }catch(e){json(res,e.code==='ENOENT'?404:400,{error:e.code==='ENOENT'?'Not found.':e.message,requestId});}
  });
  const timer=setInterval(()=>void workbench.expire(),60_000);timer.unref();
  server.on('close',()=>clearInterval(timer));return server;
}
export const server=createApp();
if(process.argv[1]===fileURLToPath(import.meta.url))server.listen(Number(process.env.PORT||3000),'127.0.0.1',()=>console.log(`Single Policy Move · http://127.0.0.1:${process.env.PORT||3000}`));

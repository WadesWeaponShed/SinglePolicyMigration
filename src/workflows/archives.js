import {readUpstreamArchive} from './upstream-archive.js';
import {gzipSync,gunzipSync} from 'node:zlib';
import {randomUUID,createHash} from 'node:crypto';
export const MAX_ARCHIVE=128*1024*1024;
const MAX_EXPANDED=256*1024*1024;
export function exportArchive(plan) {
  const policy=structuredClone(plan.package);
  policy['access-layers']=plan.layers.filter(l=>(l.kind||'access')==='access'&&l.ordered!==false).map(l=>({uid:l.uid,name:l.name}));
  policy['threat-layers']=plan.layers.filter(l=>l.kind==='threat').map(l=>({uid:l.uid,name:l.name}));
  delete policy['https-inspection-layer'];
  policy['https-inspection-layers']=Object.fromEntries(plan.layers.filter(l=>l.kind==='https').map(l=>[l.slot||`${l['layer-type']}-https-layer`,{uid:l.uid,name:l.name}]));
  policy['https-inspection-policy']=!!Object.keys(policy['https-inspection-layers']).length;
  policy['nat-policy']=plan.nat.length>0||plan.objects.some(o=>o.source?.['nat-settings']?.['auto-rule']===true);
  policy.access=!!policy['access-layers'].length;policy['threat-prevention']=!!policy['threat-layers'].length;
  const snapshot={format:'cma-policy',version:1,apiVersion:plan.apiVersion,sourceDomain:plan.sourceDomain,package:policy,objects:plan.objects.filter(o=>o.uid!==plan.importTagUid).map(o=>o.source),layers:plan.layers,nat:plan.nat};
  const bytes=Buffer.from(JSON.stringify(snapshot));
  if(bytes.length>MAX_EXPANDED)throw new Error('Policy archive exceeds the expanded size limit.');
  return gzipSync(bytes);
}
export function importArchive(bytes) {
  if(bytes.length>MAX_ARCHIVE)throw new Error('Archive limit is 128 MiB.');
  const raw=gunzipSync(bytes,{maxOutputLength:MAX_EXPANDED});
  if(raw[0]!==123)return readUpstreamArchive(bytes);
  const value=JSON.parse(raw.toString('utf8'),(key,value)=>{
    if(['__proto__','prototype','constructor'].includes(key))throw new Error('Invalid archive property.');
    return value;
  });
  if(value.format!=='cma-policy'||value.version!==1||!/^v\d+(?:\.\d+){0,2}$/.test(value.apiVersion||'')||!value.package?.uid||!value.package?.name||!value.sourceDomain?.uid||!Array.isArray(value.objects)||!Array.isArray(value.layers)||!Array.isArray(value.nat))throw new Error('Invalid native policy archive.');
  const ids=new Set();
  for(const object of [...value.objects,...value.layers]) {
    if(!object?.uid||!object.name||!object.type||ids.has(object.uid))throw new Error('Invalid or duplicate archive object identity.');
    ids.add(object.uid);
  }
  for(const layer of value.layers) {
    if(!['access','threat','https'].includes(layer.kind||'access')||!Array.isArray(layer.items))throw new Error('Invalid archive policy layer.');
    for(const item of layer.items)if(!item.uid||!item.type)throw new Error('Invalid archive rule identity.');
  }
  return value;
}
export function archiveDescriptor(bytes,snapshot) {
  const counts={};for(const object of [...snapshot.objects,...snapshot.layers,...snapshot.layers.flatMap(l=>l.items),...snapshot.nat])counts[object.type]=(counts[object.type]||0)+1;
  return {token:randomUUID(),fileName:snapshot.upstream?'exported__package__Policy__native.tar.gz':'policy-package.cma.gz',size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),manifest:{versions:[snapshot.apiVersion],counts}};
}
function rulePage(items,body) {
  const offset=body.offset||0,limit=body.limit||100,selected=[];let number=0;
  let section;
  for(const item of items) {
    if(item.type.endsWith('section')){section=item;continue;}
    if(number>=offset&&number<offset+limit){if(section&&!selected.some(r=>r.uid===section.uid))selected.push(section);selected.push(item);}
    number++;
  }
  return {rulebase:selected,total:number,to:Math.min(number,offset+limit)};
}
export function archiveSessions(sessions,sourceId,snapshot,targetId) {
  const objects=new Map(snapshot.objects.map(o=>[o.uid,o]));
  const layers=new Map(snapshot.layers.map(l=>[l.uid,l]));
  return {command:async(id,command,body={},...rest)=>{
    if(id!==sourceId)return sessions.command(id,command,body,...rest);
    if(command==='show-api-versions') {
      const version=snapshot.apiVersion.replace(/^v/,'');
      return {'current-version':version,'supported-versions':[version]};
    }
    if(command==='show-packages')return {packages:[snapshot.package],total:1};
    if(command==='show-package'&&[snapshot.package.uid,snapshot.package.name].includes(body.uid||body.name))return structuredClone(snapshot.package);
    if(command==='show-object'&&objects.has(body.uid)) {
      // The native planner resolves omitted upstream built-ins against the
      // destination inventory, verifying UID, exact name and data-domain type.
      return {object:structuredClone(objects.get(body.uid))};
    }
    const layer=layers.get(body.uid)||snapshot.layers.find(l=>l.name===body.name);
    if(/^show-(access|threat|https)-layer$/.test(command)&&layer){const {items,kind,slot,ordered,targetName,exceptionSets,...config}=layer;return structuredClone(config);}
    if(command==='show-nat-rulebase')return {...rulePage(snapshot.nat,body),'objects-dictionary':snapshot.objects};
    if(command==='show-threat-rule-exception-rulebase'&&layer)return {...rulePage(layer.exceptionSets?.find(e=>e.ruleUid===body['rule-uid'])?.items||[],body),'objects-dictionary':snapshot.objects};
    if(/^show-(access|threat|https)-rulebase$/.test(command)&&layer)return {...rulePage(layer.items,body),'objects-dictionary':snapshot.objects};
    if(command==='show-exception-group') {
      const group=snapshot.layers.flatMap(l=>(l.exceptionSets||[]).flatMap(e=>e.groups||[])).find(g=>g.uid===body.uid||g.name===body.name);
      if(group)return structuredClone(group);
    }
    throw new Error(`Archive cannot resolve ${command}; no source management call was made.`);
  }};
}

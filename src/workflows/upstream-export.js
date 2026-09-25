import {gzipSync} from 'node:zlib';
import {builtin,certificateTypes,objectPayload,pick,refs,translate} from './objects.js';
import {writableFields} from './adapters.js';
import {fields} from './objects.js';
import {layerRulePayload,rulePayload,layerFields} from './migration.js';
import {policyLayerFields} from './policy-types.js';

function csv(rows) {
  const flatten=(value,path='',out={})=>{
    if(value&&typeof value==='object')for(const [key,child] of Object.entries(value))flatten(child,path?`${path}.${key}`:key,out);
    else if(value!==undefined&&value!==null)out[path]=String(value);
    return out;
  };
  const flat=rows.map(row=>flatten(row)),keys=[...new Set(flat.flatMap(row=>Object.keys(row)))];
  const quote=value=>'"'+String(value??'').replaceAll('"','""')+'"';
  return Buffer.from([keys,...flat.map(row=>keys.map(key=>row[key]??''))].map(row=>row.map(quote).join(',')).join('\r\n')+'\r\n');
}
function tar(entries) {
  const chunks=[];let total=0;
  const append=(name,content,type='0')=>{
    const bytes=Buffer.from(content),header=Buffer.alloc(512);
    header.write(name,0,100);header.write('0000600\0',100);header.write(bytes.length.toString(8).padStart(11,'0')+'\0',124);
    header.fill(32,148,156);header.write(type,156);header.write('ustar\0',257);header.write('00',263);
    header.write(header.reduce((sum,b)=>sum+b,0).toString(8).padStart(6,'0')+'\0 ',148);
    chunks.push(header,bytes,Buffer.alloc((512-bytes.length%512)%512));total+=512+Math.ceil(bytes.length/512)*512;
    if(total>256*1024*1024)throw new Error('Policy archive exceeds the expanded size limit.');
  };
  let index=0;
  for(const [name,content] of entries) {
    if(name.startsWith('/')||name.includes('\\')||/[\x00-\x1f]/.test(name)||name.split('/').includes('..'))throw new Error('Layer name cannot be represented safely in an upstream archive.');
    if(Buffer.byteLength(name)>100) {
      const body=`path=${name}\n`;let length=Buffer.byteLength(body)+3;
      while(length!==Buffer.byteLength(body)+String(length).length+1)length=Buffer.byteLength(body)+String(length).length+1;
      append(`PaxHeader${index}`,`${length} ${body}`,'x');append(`member${index++}`,content);
    } else append(name,content);
  }
  return gzipSync(Buffer.concat([...chunks,Buffer.alloc(1024)]));
}

// Serialize the reference tool's CSV/tar contract without running it. All values
// come from the native snapshot and writable payload conversions.
export function exportUpstreamArchive(plan) {
  const objects=plan.objects.filter(row=>row.uid!==plan.importTagUid).map(row=>row.source);
  const source=new Map([...objects,...plan.layers].map(o=>[o.uid,o]));
  const names=new Map([...source].map(([uid,o])=>[uid,o.name]));
  const seen=new Map();
  for(const object of source.values()) {
    if(seen.has(object.name)&&seen.get(object.name)!==object.uid)throw new Error(`Upstream archives cannot distinguish duplicate names: ${object.name}. Use the native archive format.`);
    seen.set(object.name,object.uid);
  }
  if(objects.some(o=>certificateTypes.has(o.type)&&!builtin(o)))throw new Error('Use the native archive format to retain certificate fingerprints. The legacy CSV format cannot verify certificate identity.');
  const version=plan.apiVersion.replace(/^v/,'');
  let serial=0;
  const file=(type,rows)=>[`${String(++serial).padStart(5,'0')}____add-${type}__native.csv`,csv(rows)];
  const entries=[['version.txt',version]],pending=objects.filter(o=>!builtin(o)),done=new Set(objects.filter(builtin).map(o=>o.uid));
  while(pending.length) {
    const index=pending.findIndex(o=>[...refs(pick(o,writableFields(o.type,plan.objectSchema,fields)),source)].every(uid=>done.has(uid)));
    if(index<0)throw new Error('Archive contains circular or unresolved object dependencies.');
    const [object]=pending.splice(index,1);
    const payload=objectPayload(object,names,plan.objectSchema);
    if(object.type==='updatable-object')payload.name=object.name;
    entries.push(file(object.type,[payload]));done.add(object.uid);
  }
  // Match the reference importer's inbound-before-outbound attachment order.
  const layers=[...plan.layers].sort((a,b)=>a.kind==='https'&&b.kind==='https'?String(a['layer-type']).localeCompare(String(b['layer-type'])):0);
  for(const layer of layers) {
    if(layer.name.startsWith('/')||layer.name.includes('\\')||/[\x00-\x1f]/.test(layer.name)||layer.name.split('/').includes('..'))throw new Error('Layer name cannot be represented safely in an upstream archive.');
    const payload=translate(pick(layer,policyLayerFields(layer,layerFields,plan.policySchema)),names);
    if((layer.kind||'access')==='access')payload.__ordered_access_control_layer=layer.ordered!==false;
    entries.push(file(layer.type,[payload]));
  }
  for(const layer of layers) {
    const emittedGroups=new Set();
    const nested=[['version.txt',version]];let position=1;
    for(const item of layer.items) {
      const payload=item.type.endsWith('section')?translate(pick(item,['name','comments','tags']),names):layerRulePayload(item,layer,names,source,plan.policySchema);
      nested.push(file(item.type,[{...payload,position}]));
      if(!item.type.endsWith('section'))position++;
    }
    for(const set of layer.exceptionSets||[]) {
      const ruleNumber=layer.items.filter(i=>i.type==='threat-rule').findIndex(i=>i.uid===set.ruleUid)+1;
      if(ruleNumber<1)throw new Error('Exception owner is absent from the exported threat layer.');
      for(const group of set.groups||[]) {
        if(emittedGroups.has(group.uid))continue;
        const attachments=[];const positions=[];
        for(const owner of layers)for(const exceptions of owner.exceptionSets||[])if(exceptions.groups.some(g=>g.uid===group.uid)) {
          attachments.push({layer:owner.name,'rule-number':owner.items.filter(i=>i.type==='threat-rule').findIndex(i=>i.uid===exceptions.ruleUid)+1});
          positions.push(exceptions.items.findIndex(i=>i.uid===group.sectionUid)+1);
        }
        nested.push(file('exception-group',[{...translate(pick(group,['color','comments','tags']),names),name:group.name,'apply-on':'manually-select-threat-rules','applied-threat-rules':attachments,positions}]));
        let childPosition=1;
        for(const item of set.items.filter(i=>i.type==='threat-exception'&&i.parentSectionUid===group.sectionUid))nested.push(file('threat-exception',[{...rulePayload(item,names,source,plan.policySchema),'exception-group-name':group.name,position:childPosition++}]));
        emittedGroups.add(group.uid);
      }
      let exceptionPosition=1;
      for(const item of set.items) {
        if(item.type==='threat-exception'&&!item.parentSectionUid)nested.push(file('threat-exception',[{...rulePayload(item,names,source,plan.policySchema),'rule-number':ruleNumber,position:exceptionPosition}]));
        exceptionPosition++;
      }
    }
    entries.push([`exported__${layer.kind||'access'}_layer__${layer.name}__native.tar.gz`,tar(nested)]);
  }
  if(plan.nat.length)entries.push(['exported__nat_layer__NAT__native.tar.gz',tar([['version.txt',version],...plan.nat.map((item,i)=>file(item.type,[{...rulePayload(item,names,source,plan.policySchema),position:i+1,__before_auto_rules:item.natPosition==='upper'}]))])]);
  const bytes=tar(entries);if(bytes.length>128*1024*1024)throw new Error('Archive limit is 128 MiB.');return bytes;
}

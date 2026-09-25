// Read the upstream archive format in-process. No extraction or external runtime.
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
const uid=(kind,name)=>{const h=createHash('sha256').update(kind+'\0'+name).digest('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20,32)}`;};
function csv(text) {
  const rows=[];let row=[],value='',quoted=false;
  for(let i=0;i<text.length;i++) {
    const c=text[i];
    if(c==='"'){if(quoted&&text[i+1]==='"'){value+='"';i++;}else if(quoted||!value)quoted=!quoted;else throw new Error('Malformed CSV quoting.');}
    else if(c===','&&!quoted){row.push(value);value='';}
    else if((c==='\n'||c==='\r')&&!quoted){if(c==='\r'&&text[i+1]==='\n')i++;row.push(value);if(row.some(v=>v!==''))rows.push(row);row=[];value='';}
    else value+=c;
  }
  if(quoted)throw new Error('Unterminated CSV string.');
  if(value||row.length){row.push(value);rows.push(row);}
  const header=rows.shift();if(!header?.length||header.some(v=>!v)||new Set(header).size!==header.length)throw new Error('Invalid CSV headers.');
  return rows.map(row=>{if(row.length!==header.length)throw new Error('CSV column count differs from header.');return Object.fromEntries(header.map((key,i)=>[key,row[i]]));});
}
function bodyOf(row) {
  const root={};
  for(const [path,raw] of Object.entries(row)) {
    if(raw==='')continue;
    const parts=path.split('.');if(parts.some(p=>['__proto__','constructor','prototype'].includes(p)))throw new Error('Unsafe archive field.');
    let parent=root;
    for(let i=0;i<parts.length;i++) {
      const key=Array.isArray(parent)?Number(parts[i]):parts[i];
      if(Array.isArray(parent)&&(!Number.isInteger(key)||key<0||key>100000))throw new Error('Invalid CSV list index.');
      if(i===parts.length-1)parent[key]=raw;
      else parent=parent[key]??=(/^\d+$/.test(parts[i+1])?[]:{});
    }
  }
  return root;
}
export function readUpstreamArchive(compressed) {
  const records=[],versions=new Set(),budget={bytes:0,members:0};
  function visit(bytes,layer=null,depth=0) {
    if(depth>8)throw new Error('Archive nesting limit exceeded.');
    const data=gunzipSync(bytes,{maxOutputLength:256*1024*1024-budget.bytes});budget.bytes+=data.length;
    const seen=new Set();let pendingPath;
    for(let offset=0;offset+512<=data.length;) {
      const header=data.subarray(offset,offset+512);if(header.every(v=>v===0))break;
      let name=header.subarray(0,100).toString().split('\0')[0];const prefix=header.subarray(345,500).toString().split('\0')[0];if(prefix)name=prefix+'/'+name;
      const size=parseInt(header.subarray(124,136).toString().replace(/\0/g,'').trim(),8),type=header[156];
      const sum=parseInt(header.subarray(148,156).toString().replace(/\0/g,'').trim(),8);
      const actual=header.reduce((n,b,i)=>n+(i>=148&&i<156?32:b),0);
      if(sum!==actual||!Number.isSafeInteger(size)||size<0||offset+512+size>data.length)throw new Error('Invalid tar header or member size.');
      const content=data.subarray(offset+512,offset+512+size);offset+=512+Math.ceil(size/512)*512;
      if(++budget.members>100000)throw new Error('Archive member limit exceeded.');
      if(type===120){for(const line of content.toString().split('\n')){const m=line.match(/^\d+ path=(.*)$/);if(m)pendingPath=m[1];}continue;}
      if(pendingPath){name=pendingPath;pendingPath=undefined;}
      if(name.startsWith('/')||name.includes('\\')||name.split('/').some(p=>p==='..')||seen.has(name))throw new Error('Unsafe or duplicate archive path.');seen.add(name);
      if(type===53)continue;
      if(type!==0&&type!==48)throw new Error('Archive links and special files are not allowed.');
      if(name.endsWith('.tar.gz')){const parts=name.split('__');visit(content,{kind:parts[1]?.replace('_layer',''),name:parts.slice(2,-1).join('__')},depth+1);}
      else if(name==='version.txt'){const version=content.toString().trim();if(!/^\d+(?:\.\d+){0,2}$/.test(version))throw new Error('Invalid archive API version.');versions.add('v'+version);}
      else if(name.endsWith('.csv')){const match=name.match(/^\d+____add-([a-z0-9-]+)__.+\.csv$/);if(!match)throw new Error('Invalid archive CSV command.');for(const row of csv(content.toString('utf8')))records.push({type:match[1],layer,body:bodyOf(row)});}
      else if(!/\.(json|txt)$/.test(name))throw new Error('Unexpected file in policy archive.');
    }
  }
  visit(compressed);
  if(versions.size!==1)throw new Error('Archive requires one consistent API version.');
  const definitions=records.filter(r=>!r.layer||r.type.endsWith('-layer'));
  const objects=[],layers=[],names=new Map();
  for(const record of definitions){const {type,body}=record;if(!body.name)throw new Error('Archive object has no name.');if(names.has(body.name))continue;const object={...body,uid:uid(type,body.name),type};names.set(body.name,object);if(type.endsWith('-layer'))layers.push(object);else objects.push(object);}
  const referenceFields=new Set(['source','destination','service','content','action','members','include','except','original-source','original-destination','original-service','translated-source','translated-destination','translated-service','install-on','tags','time','vpn','protected-scope','protection-or-site','inline-layer','site-category','certificate','center-gateways','satellite-gateways','gateways']);
  const referencePaths=new Set(['overrides.protection','indicator-overrides.indicator','vpn-settings.vpn-domain','vpn-settings.remote-access.nat-traversal-service','vpn-settings.remote-access.visitor-mode-service','vpn-settings.authentication.authentication-clients','vpn-settings.office-mode.group','vpn-settings.office-mode.allocate-ip-address-from.manual-network','vpn-settings.office-mode.allocate-ip-address-from.dhcp-server','vpn-settings.office-mode.allocate-ip-address-from.optional-parameters.primary-dns-server','vpn-settings.office-mode.allocate-ip-address-from.optional-parameters.first-backup-dns-server','vpn-settings.office-mode.allocate-ip-address-from.optional-parameters.second-backup-dns-server','vpn-settings.office-mode.allocate-ip-address-from.optional-parameters.primary-wins-server','vpn-settings.office-mode.allocate-ip-address-from.optional-parameters.first-backup-wins-server','vpn-settings.office-mode.anti-spoofing-additional-addresses','interfaces.topology-settings.specific-network','interfaces.anti-spoofing-settings.excluded-network-uid','members.interfaces.topology-settings.specific-network']);
  function translate(value,field,objectType,path='') {
    if(Array.isArray(value))return value.map(v=>translate(v,field,objectType,path));
    if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,translate(v,k,objectType,path?`${path}.${k}`:k)]));
    if(field==='vpn'&&objectType&&objectType!=='access-rule')return value;
    if(typeof value==='string'&&(referenceFields.has(field)||referencePaths.has(path))&&!['All','Original'].includes(value)) {
      if(!names.has(value)){const object={uid:uid('reference',value),name:value,type:'archive-reference',domain:{'domain-type':'data domain'}};names.set(value,object);objects.push(object);}
      return names.get(value).uid;
    }
    return value;
  }
  for(let i=0;i<objects.length;i++)if(objects[i].type!=='archive-reference')Object.assign(objects[i],translate(objects[i],undefined,objects[i].type));
  const nat=[];
  for(const layer of layers) {
    const kind=layer.type.split('-')[0];layer.kind=kind;layer.ordered=String(layer.__ordered_access_control_layer).toLowerCase()!=='false';delete layer.__ordered_access_control_layer;
    if(kind==='https')layer.slot=layer['layer-type']==='inbound'?'inbound-https-layer':'outbound-https-layer';
    const rows=records.filter(r=>r.layer?.name===layer.name&&!r.type.endsWith('-layer')&&r.type!=='exception-group');
    layer.items=rows.filter(r=>r.type!=='threat-exception').sort((a,b)=>Number(a.body.position)-Number(b.body.position)||(a.type.endsWith('section')?-1:b.type.endsWith('section')?1:0)).map((r,i)=>{const {position,...body}=r.body;return {...translate(r.type==='https-rule'?{...body,action:undefined}:body),...r.type==='https-rule'?{action:body.action}:{},uid:uid(r.type,layer.name+'#'+i),type:r.type};});
    if(kind==='threat') {
      const exceptionRows=rows.filter(r=>r.type==='threat-exception');
      const groupRecords=records.filter(r=>r.type==='exception-group'&&(!r.layer||r.layer.name===layer.name));
      layer.exceptionSets=layer.items.map((rule,index)=>{
        const groups=[],entries=[];
        const exception=(record,key)=>{const {position,'rule-name':rn,'rule-number':rnum,'rule-uid':ruid,'exception-group-name':gn,'exception-group-uid':guid,layer:owner,...body}=record.body;return {...translate(body),uid:uid('threat-exception',layer.name+'#'+key),type:'threat-exception'};};
        for(const [i,record] of exceptionRows.entries())if(!record.body['exception-group-name']&&!record.body['exception-group-uid']&&(Number(record.body['rule-number'])===index+1||record.body['rule-name']===rule.name))entries.push({position:Number(record.body.position),items:[exception(record,i)]});
        for(const record of groupRecords) {
          const body=record.body,attachments=body['applied-threat-rules']||[];
          const attachmentIndex=attachments.findIndex(a=>a.layer===layer.name&&(Number(a['rule-number'])===index+1||a.name===rule.name));
          const applies=body['apply-on']==='all-threat-rules'||body['apply-on']==='all-threat-rules-with-specific-profile'&&names.get(body['applied-profile'])?.uid===rule.action||attachmentIndex>=0;
          if(!applies)continue;
          const group={...body,uid:uid('exception-group',body.name),type:'exception-group',sectionUid:uid('exception-section',body.name)};groups.push(group);
          const children=exceptionRows.filter(r=>r.body['exception-group-name']===body.name).sort((a,b)=>Number(a.body.position)-Number(b.body.position));
          entries.push({position:Number(body.positions?.[Math.max(0,attachmentIndex)])||Number.MAX_SAFE_INTEGER,items:[{uid:group.sectionUid,name:body.name,type:'threat-exception-section'},...children.map((r,i)=>({...exception(r,body.name+'#'+i),parentSectionUid:group.sectionUid}))]});
        }
        return {ruleUid:rule.uid,items:entries.sort((a,b)=>a.position-b.position).flatMap(e=>e.items),groups};
      });
    }
  }
  for(const [i,r] of records.filter(r=>r.layer?.kind==='nat'&&r.type.startsWith('nat-')).entries()){const {position,__before_auto_rules,...body}=r.body;nat.push({...translate(body),type:r.type,uid:uid(r.type,'nat#'+i),natPosition:String(__before_auto_rules).toLowerCase()==='true'?'upper':'lower'});}
  const packageName='Archived policy',packageUid=uid('package',packageName);
  return {format:'cma-policy',version:1,apiVersion:[...versions][0],sourceDomain:{uid:uid('domain','archive'),name:'Policy archive'},package:{uid:packageUid,name:packageName,access:layers.some(l=>l.kind==='access'),'nat-policy':nat.length>0,'threat-prevention':layers.some(l=>l.kind==='threat'),'https-inspection-policy':layers.some(l=>l.kind==='https'),'access-layers':layers.filter(l=>l.kind==='access'&&l.ordered).map(l=>({uid:l.uid,name:l.name})),'threat-layers':layers.filter(l=>l.kind==='threat').map(l=>({uid:l.uid,name:l.name})),'https-inspection-layers':Object.fromEntries(layers.filter(l=>l.kind==='https').map(l=>[l.slot,{uid:l.uid,name:l.name}]))},objects,layers,nat,upstream:true};
}

export function coerceUpstream(snapshot,catalog) {
  if(!snapshot.upstream)return snapshot;
  const commands=new Map(catalog.commands.map(c=>[c.name,c]));
  function coerce(value,field) {
    const types=field?.types||[];
    if(Array.isArray(value))return value.map(v=>coerce(v,{types:types.find(t=>t.name==='list')?.items}));
    if(value&&typeof value==='object') {
      const fields=types.filter(t=>t.name==='object').flatMap(t=>t.fields||[]);
      return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,coerce(item,fields.find(f=>f.name===key||f.alternatives?.includes(key)))]));
    }
    const names=types.length?types.map(t=>t.name):String(field?.type||'').split(' | ');
    if(typeof value==='string'&&!names.includes('string')) {
      if(names.includes('boolean')&&/^(true|false)$/i.test(value))return value.toLowerCase()==='true';
      if((names.includes('integer')||names.includes('number'))&&/^-?\d+(\.\d+)?$/.test(value))return Number(value);
    }
    return value;
  }
  const convert=object=>{
    const command=commands.get('add-'+object.type);if(!command)return object;
    const fields=[...command.requiredFields,...command.optionalFields];
    return Object.fromEntries(Object.entries(object).map(([key,value])=>[key,coerce(value,fields.find(f=>f.name===key||f.alternatives?.includes(key)))]));
  };
  snapshot.objects=snapshot.objects.map(convert);
  snapshot.layers=snapshot.layers.map(layer=>({...convert(layer),items:layer.items.map(convert),...(layer.exceptionSets?{exceptionSets:layer.exceptionSets.map(set=>({...set,items:set.items.map(convert)}))}:{})}));
  snapshot.nat=snapshot.nat.map(convert);
  return snapshot;
}

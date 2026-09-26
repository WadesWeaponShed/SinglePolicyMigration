import {writableFields} from './adapters.js';
import { createHash, X509Certificate } from 'node:crypto';
import {isIP} from 'node:net';

export const gatewayTypes=new Set(['simple-gateway','simple-cluster']);
function gatewayResolution(object,destination,choice) {
  if(globalObject(object)||builtin(object))return {uid:object.uid,name:object.name,type:object.type,source:object,target:null,status:'blocked',reason:'Global and built-in gateways cannot be rebuilt or remapped.'};
  const row={uid:object.uid,name:object.name,type:object.type,source:object,target:null,status:'conflict',gatewayResolutionAllowed:true,renameAllowed:false,
    gatewayCandidates:destination.filter(o=>o.type===object.type&&!builtin(o)&&!globalObject(o)).map(o=>pick(o,['uid','name','type'])),
    reason:'Choose an existing destination gateway, or create a minimal gateway with a destination address. Source gateway settings will not be copied.'};
  if(object.type==='simple-cluster')row.reason='Choose an existing destination cluster, or create a minimal cluster with a name and destination IP. Members and source cluster settings are not copied.';
  if(!choice)return row;
  if(choice.action==='reuse-gateway') {
    const target=destination.find(o=>o.uid===choice.targetUid&&o.type===object.type&&!builtin(o)&&!globalObject(o));
    if(!target)throw new Error(`Destination gateway mapping is unavailable for ${object.name}. Rescan and select it again.`);
    return {...row,status:'reuse',target,gatewayResolution:choice.action,reason:`Explicitly map ${object.name} to destination ${target.name}. Its existing settings and SIC remain unchanged; imported references use its UID.`};
  }
  if(choice.action!=='create-gateway')throw new Error('Choose an existing destination object or create a minimal definition.');
  const name=typeof choice.name==='string'?choice.name.trim():'';
  const address=typeof choice.address==='string'?choice.address.trim():'';
  if(!name||name.length>100||/[\x00-\x1f\x7f]/.test(name))throw new Error('Enter a gateway name of 1–100 characters without control characters.');
  if(!isIP(address))throw new Error('Enter the destination gateway IPv4 or IPv6 address. Source or cloud tunnel addresses are not copied automatically.');
  if(destination.some(o=>o.name.toLowerCase()===name.toLowerCase()))throw new Error(`The destination already contains ${name}. Select it for reuse or choose a new name.`);
  const gatewayDefinition={uid:object.uid,type:object.type,name,[isIP(address)===4?'ipv4-address':'ipv6-address']:address};
  return {...row,status:'create',importName:name,gatewayDefinition,gatewayResolution:choice.action,reason:`Create minimal ${object.type==='simple-cluster'?'cluster':'gateway'} ${name} at ${address}. ${object.type==='simple-cluster'?'Add cluster members and configure the cluster mode manually. ':''}Configure SIC, interfaces, topology, blades, routing, NAT and cloud onboarding manually before installing policy. Source gateway settings are omitted.`};
}

export const certificateTypes=new Set(['server-certificate','outbound-inspection-certificate','custom-trusted-ca-certificate']);
export function certificateFingerprint(object) {
  const encoded=object['base64-public-certificate']||object['base64-certificate'];
  if(typeof encoded!=='string'||!encoded)throw new Error('A public certificate is required to verify certificate identity. Import the matching certificate into the destination first.');
  try{return new X509Certificate(Buffer.from(encoded,'base64')).fingerprint256;}
  catch{throw new Error('The public certificate cannot be decoded; certificate reuse cannot be verified.');}
}
export const common = ['name', 'color', 'comments', 'tags'];
const tcp = ['port', 'source-port', 'protocol', 'aggressive-aging', 'keep-connections-open-after-policy-installation', 'match-by-protocol-signature', 'match-for-any', 'override-default-settings', 'session-timeout', 'use-default-session-timeout', 'sync-connections-on-cluster'];
export const fields = {
  host: [...common, 'ipv4-address', 'ipv6-address', 'interfaces', 'nat-settings', 'host-servers'],
  network: [...common, 'subnet4', 'subnet6', 'mask-length4', 'mask-length6', 'nat-settings', 'broadcast'],
  'address-range': [...common, 'ipv4-address-first', 'ipv4-address-last', 'ipv6-address-first', 'ipv6-address-last', 'nat-settings'],
  group: [...common, 'members'],
  'group-with-exclusion': [...common, 'include', 'except'],
  'service-group': [...common, 'members'],
  'service-tcp': [...common, ...tcp, 'enable-tcp-resource', 'use-delayed-sync', 'delayed-sync-value'],
  'service-udp': [...common, ...tcp, 'accept-replies'],
  'service-icmp': [...common, 'icmp-type', 'icmp-code', 'keep-connections-open-after-policy-installation'],
  'service-icmp6': [...common, 'icmp-type', 'icmp-code', 'keep-connections-open-after-policy-installation'],
  'dns-domain': [...common, 'is-sub-domain'],
  tag: [...common.filter(k => k !== 'tags')],
};
export const metadata = new Set(['uid', 'type', 'domain', 'meta-info', 'icon', 'groups', 'read-only', 'available-actions', 'interfaces-topology', 'subnet-mask', 'subnet-mask4', 'subnet-mask6']);
export const equivalentAcrossNames=new Set(['host','network','address-range','group','group-with-exclusion','service-group','service-tcp','service-udp','service-icmp','service-icmp6','service-sctp','service-rpc','service-dce-rpc']);
export const builtin = o => /^(data domain|Check Point Data)$/i.test(o?.domain?.['domain-type'] || o?.domain?.name || '');
export const globalObject = o => o?.domain?.['domain-type'] === 'global domain';
export const uidOf = x => typeof x === 'string' ? x : x?.uid;
export function pick(obj, keys) { return Object.fromEntries(keys.filter(k => obj[k] !== undefined).map(k => [k, obj[k]])); }
// Match upstream clean_objects' documented mutually exclusive service fields.
// These values are inactive when the corresponding default/disabled switch is set.
export function normalizedObject(obj) {
  if(['simple-gateway','simple-cluster'].includes(obj.type)) {
    const stripInherited=value=>Array.isArray(value)?value.map(stripInherited):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).filter(([key])=>!(key==='profile-value'&&typeof value['override-profile']==='boolean')).map(([key,item])=>[key,stripInherited(item)])):value;
    const result=stripInherited(obj);
    // R82.10 validates certificate prerequisites even when this disabled flag
    // is explicitly false. Omission is its disabled creation default.
    if(result['enable-https-inspection']===false)delete result['enable-https-inspection'];
    if(result.monitoring===false)for(const key of ['rtm-traffic-report','rtm-counters-report','rtm-traffic-report-per-connection'])delete result[key];
    if(result['zero-phishing']===false)delete result['zero-phishing-settings'];
    const purge=result['advanced-settings']?.sam?.['purge-sam-file'];
    if(purge?.enabled===false)delete purge['purge-when-size-reaches-to'];
    const firewall=result['firewall-settings'];
    if(firewall?.['auto-maximum-limit-for-concurrent-connections']===true)delete firewall['maximum-limit-for-concurrent-connections'];
    if(firewall?.['auto-calculate-connections-hash-table-size-and-memory-pool']===true) {
      for(const key of ['connections-hash-size','maximum-memory-pool-size','memory-pool-size'])delete firewall[key];
    }
    if(result['platform-portal-settings']?.enabled!==undefined) {
      if(result['platform-portal-settings'].enabled!==true)throw new Error('Disabled platform portal cannot be represented by the gateway creation API.');
      delete result['platform-portal-settings'].enabled;
    }
    if(result['logs-settings']) {
      const logs=result['logs-settings'];
      if(result.qos===false)for(const key of ['turn-on-qos-logging','detect-new-citrix-ica-application-names'])delete logs[key];
      for(const key of ['alert-when-free-disk-space-below-metrics','delete-index-files-when-index-size-above-metrics','delete-when-free-disk-space-below-metrics','stop-logging-when-free-disk-space-below-metrics'])if(logs[key]!==undefined) {
        if(logs['free-disk-space-metrics']!==undefined&&logs['free-disk-space-metrics']!==logs[key])throw new Error('Gateway log thresholds use different units that the creation API cannot preserve.');
        logs['free-disk-space-metrics']=logs[key];delete logs[key];
      }
    }
    // These are observed trust/hardware state, not transferable credentials.
    for(const key of ['platform','sic-state','sic-name','sic-message'])delete result[key];
    for(const key of ['dynamic-ip','network-policy-management','log-server','externally-managed','policy-server','legacy-url-filtering'])if(result[key]!==undefined) {
      if(result[key]!==false)throw new Error(`Gateway setting ${key} has no native writable equivalent.`);
      delete result[key];
    }
    if(result['autonomous-system-number']!==undefined) {
      if(![0,'0'].includes(result['autonomous-system-number']))throw new Error(`Gateway ${obj.name || obj.uid} reports autonomous-system-number=${JSON.stringify(result['autonomous-system-number'])}. Routing configuration cannot currently be preserved by this adapter; migration of this object is blocked.`);
      delete result['autonomous-system-number'];
    }
    if(obj.type==='simple-cluster') {
      if(result['save-logs-locally']===false)delete result['save-logs-locally'];
      if(result['cluster-xl']!==undefined) {
        if(result['cluster-xl']!==String(result['cluster-mode']).startsWith('cluster-xl-'))throw new Error('ClusterXL state conflicts with the cluster mode.');
        delete result['cluster-xl'];
      }
    }
    if(result['cluster-members']!==undefined) {
      if(!Array.isArray(result['cluster-members']))throw new Error('Invalid cluster member definitions.');
      const members=result['cluster-members'].map(member=>{
        const value={...member};
        // Explicit false takes an existing-member path on R82.10. Creation
        // already defaults to manual addresses; retain true for cloud members.
        if(value['auto-generate-ip']===false)delete value['auto-generate-ip'];
        for(const key of ['uid','type','domain','meta-info','icon','read-only','available-actions','sic-state','sic-name','sic-message'])delete value[key];
        if(!value.name)throw new Error('Cluster members require names.');
        return value;
      });
      if(result.members!==undefined&&hash(result.members)!==hash(members))throw new Error('Conflicting cluster member definitions.');
      result.members=members;delete result['cluster-members'];
    }
    return result;
  }

  if(obj.type==='updatable-object'&&obj['uid-in-data-center']!==undefined) {
    const result={...obj,'uid-in-updatable-objects-repository':obj['uid-in-updatable-objects-repository']||obj['uid-in-data-center']};
    delete result['uid-in-data-center'];return result;
  }
  if(obj.type==='data-center-object'&&obj['data-center']?.name) {
    if(obj['data-center-name']&&obj['data-center-name']!==obj['data-center'].name)throw new Error('Conflicting data-center connection names.');
    return {...obj,'data-center-name':obj['data-center'].name};
  }
  if(obj.type!=='threat-profile')return obj;
  const result={...obj};
  if(result['advanced-dns-settings']?.enabled!==undefined) {
    if(result['advanced-dns-settings'].enabled!==true)throw new Error('The disabled Advanced DNS master setting has no writable API equivalent; migration cannot preserve it.');
    result['advanced-dns-settings']={...result['advanced-dns-settings']};delete result['advanced-dns-settings'].enabled;
  }
  for(const [response,request] of [['extended-attributes-to-activate','activate-protections-by-extended-attributes'],['extended-attributes-to-deactivate','deactivate-protections-by-extended-attributes']]) {
    if(result[response]===undefined)continue;
    const converted=result[response].flatMap(category=>category.values.map(value=>({category:category.name,name:value.name})));
    if(result[request]!==undefined&&hash(result[request])!==hash(converted))throw new Error(`Conflicting Threat Prevention profile fields: ${response} and ${request}.`);
    result[request]=converted;delete result[response];
  }
  if(Array.isArray(result.overrides))result.overrides=result.overrides.map(entry=>entry.override?{protection:entry.protection,...entry.override}:entry);
  return result;
}
function writableObject(obj, schema) {
  obj=normalizedObject(obj);
  const body = pick(obj, writableFields(obj.type,schema,fields));
  if(body['nat-settings']) {
    body['nat-settings']={...body['nat-settings']};
    // An empty translated address means no translation for that address family.
    // Check Point emits these empty fields even when the create request omits them.
    for(const key of ['ipv4-address','ipv6-address'])if(body['nat-settings'][key]==='')delete body['nat-settings'][key];
  }
  if(obj.type==='host'&&Array.isArray(body.interfaces)&&body.interfaces.length===0)delete body.interfaces;
  if(obj.type==='network'&&body['mask-length4']!==undefined) {
    const length=Number(body['mask-length4']);
    const dotted=Array.from({length:4},(_,i)=>Math.max(0,256-2**Math.max(0,Math.min(8,8-length+i*8)))).join('.');
    for(const key of ['subnet-mask','subnet-mask4'])if(body[key]===dotted)delete body[key];
  }
  if (obj.type?.startsWith('service-')) {
    if(body['override-default-settings']===false)delete body['override-default-settings'];
    if (body['aggressive-aging']?.['use-default-timeout'] === true) {
      body['aggressive-aging'] = {...body['aggressive-aging']};
      delete body['aggressive-aging'].timeout;
    }
    if (body['use-delayed-sync'] === false || body['sync-connections-on-cluster'] === false) delete body['delayed-sync-value'];
  }
  return body;
}
export function objectPayload(obj, mapping = new Map(), schema) {
  return translate(writableObject(obj,schema), mapping);
}
export function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])]));
  return value;
}
export const hash = value => createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
export function refs(value, objects, out = new Set()) {
  if (typeof value === 'string' && objects.has(value)) out.add(value);
  else if (Array.isArray(value)) value.forEach(v => refs(v, objects, out));
  else if (value && typeof value === 'object') {
    if (value.uid) out.add(value.uid);
    else Object.values(value).forEach(v => refs(v, objects, out));
  }
  return out;
}
export function semantic(obj, objects, stack = new Set(), schema) {
  const reason = unsupported(obj,schema);
  if (reason) throw new Error(`Cannot compare ${obj.name}: ${reason}`);
  if(certificateTypes.has(obj.type)&&!builtin(obj))return {type:obj.type,fingerprint:certificateFingerprint(obj),...(obj.type==='outbound-inspection-certificate'?{'is-default':obj['is-default']===true}:{})};
  if (stack.has(obj.uid)) throw new Error(`Circular object dependency: ${obj.name}.`);
  const seen = new Set(stack).add(obj.uid);
  const resolve = v => {
    if (typeof v === 'string' && objects.has(v)) return semantic(objects.get(v), objects, seen, schema);
    if (Array.isArray(v)) return v.map(resolve).sort((a,b) => JSON.stringify(stable(a)).localeCompare(JSON.stringify(stable(b))));
    if (v && typeof v === 'object') {
      if (v.uid && objects.has(v.uid)) return semantic(objects.get(v.uid), objects, seen, schema);
      return Object.fromEntries(Object.entries(v).map(([k,x]) => [k,resolve(x)]));
    }
    return v;
  };
  const definition = pick(writableObject(obj,schema), writableFields(obj.type,schema,fields).filter(k => !['name','comments','description','color','tags'].includes(k)));
  // DNS names determine traffic matching; tag names determine classification identity.
  if (builtin(obj) || !equivalentAcrossNames.has(obj.type)) return { type: obj.type, name: obj.name, ...resolve(definition) };
  return { type: obj.type, ...resolve(definition) };
}
export function unsupported(obj,schema) {
  if(obj['unresolved-gateway-mapping']===true)return `Resolve the destination gateway mapping for ${obj.name} first. Objects using its automatic NAT or other references will then be compared again.`;
  if (globalObject(obj)) return 'Object belongs to the Global Domain. Remove global policy assignment and scan again.';
  if (builtin(obj)) return '';
  if (!fields[obj.type]&&!schema?.[obj.type]) return `Object type ${obj.type} requires a supported adapter; automatic substitution is disabled.`;
  if (obj.name?.includes('export_error') || obj.name?.startsWith('import_error_due_to_missing_fields_')) return 'Upstream export/import placeholder detected. Replace it with the real object.';
  if (obj['nat-settings']?.['auto-rule'] === true && obj['nat-settings']['install-on'] !== 'All' && typeof obj['nat-settings']['install-on'] === 'string' && !/^[\da-f-]{36}$/i.test(obj['nat-settings']['install-on'])) return 'Automatic NAT on a specific or unresolved gateway requires an explicit destination gateway mapping.';
  try {obj=normalizedObject(obj);}catch(error){return error.message;}
  if(obj.type==='data-center-object'&&obj.deleted===true)return 'The external data-center object is deleted or inaccessible. Restore it before migrating.';
  if(certificateTypes.has(obj.type)) {try{certificateFingerprint(obj);}catch(error){return error.message;}}
  const certificateMetadata=['base64-public-certificate','issued-by','issued-to','subject','valid-from','valid-to','added-by','name','base64-certificate'];
  const responseMetadata={...Object.fromEntries([...certificateTypes].map(type=>[type,certificateMetadata])),'application-site':['application-id','risk','user-defined','primary-category-id','additional-categories-ids'],'application-site-category':['user-defined'],
    'updatable-object':['name','name-in-updatable-objects-repository','additional-properties','updatable-object-meta-info'],
    'data-center-object':['name-in-data-center','data-center','data-center-object-meta-info','deleted','type-in-data-center','additional-properties']};
  const unknown = Object.keys(obj).filter(k => !writableFields(obj.type,schema,fields).includes(k) && !metadata.has(k) && !responseMetadata[obj.type]?.includes(k));
  return unknown.length ? `Unmapped attributes: ${unknown.join(', ')}. Import is blocked to avoid losing settings.` : '';
}
function ip(s) {
  const p = String(s || '').split('.').map(Number);
  if (p.length !== 4 || p.some(x => !Number.isInteger(x) || x<0 || x>255)) return null;
  return p.reduce((n,x) => n*256+x, 0);
}
function range(o) {
  if (o.type === 'host') { const n=ip(o['ipv4-address']); return n === null ? null : [n,n]; }
  if (o.type === 'network') {
    const n=ip(o.subnet4), mask=Number(o['mask-length4']);
    if (n === null || !Number.isInteger(mask) || mask<0 || mask>32) return null;
    const size=2**(32-mask), start=Math.floor(n/size)*size; return [start,start+size-1];
  }
  if(o.type==='address-range') { const a=ip(o['ipv4-address-first']), b=ip(o['ipv4-address-last']); return a===null||b===null?null:[a,b]; }
  return null;
}
export function overlap(a,b) {
  const x=range(a), y=range(b);
  if(x&&y) return x[0]<=y[1] && y[0]<=x[1];
  if (['service-tcp','service-udp'].includes(a.type) && a.type===b.type) {
    const parse = value => {
      const parts=String(value??'').replace(/\s/g,'').split(',');
      const ranges=[];
      for(const part of parts) {
        if(/^\d+(?:-\d+)?$/.test(part)) {const [lo,hi]=part.split('-').map(Number);ranges.push([lo,hi??lo]);}
        else {const m=part.match(/^([<>])(=?)(\d+)$/);if(!m)return null;const n=Number(m[3]);ranges.push(m[1]==='>'?[n+(m[2]?0:1),65535]:[0,n-(m[2]?0:1)]);}
      }
      return ranges;
    };
    const p=parse(a.port), q=parse(b.port);
    // Unrecognized expressions cannot establish non-overlap. Block conservatively.
    return !p||!q||p.some(x=>q.some(y=>x[0]<=y[1]&&y[0]<=x[1]));
  }
  return false;
}
export function compareObjects(source, destination, schema, options={}, gatewayChoices={}) {
  const gatewayRows=new Map(options.rebuildGateways?source.filter(o=>gatewayTypes.has(o.type)).map(o=>[o.uid,gatewayResolution(o,destination,gatewayChoices[o.uid])]):[]);
  // Compare dependencies using the explicitly selected destination identity, not
  // the source device configuration. Unresolved mappings keep parents blocked.
  const sourceIdentity=o=>{
    const row=gatewayRows.get(o.uid);if(!row)return o;
    const unresolved=row.status!=='reuse'&&row.status!=='create';
    return {uid:o.uid,type:o.type,name:unresolved?o.name:row.target?`destination-uid:${row.target.uid}`:`new-gateway:${o.uid}`,...unresolved?{'unresolved-gateway-mapping':true}:{}};
  };
  const targetIdentity=o=>options.rebuildGateways&&gatewayTypes.has(o.type)?{uid:o.uid,type:o.type,name:`destination-uid:${o.uid}`}:o;
  const sm=new Map(source.map(o=>[o.uid,sourceIdentity(o)])), dm=new Map(destination.map(o=>[o.uid,targetIdentity(o)]));
  // Definitions are immutable within a scan. Compute each destination signature
  // once instead of rebuilding recursive groups for every source candidate.
  const byName=new Map(),byType=new Map(),signatures=new Map();
  for(const object of destination) {
    const name=object.name.toLowerCase();
    if(!byName.has(name))byName.set(name,[]);byName.get(name).push(object);
    if(!byType.has(object.type))byType.set(object.type,[]);byType.get(object.type).push(object);
  }
  const signature=object=>{
    if(!signatures.has(object)) {
      let value=null;
      try{if(!unsupported(object,schema))value=hash(semantic(object,dm,new Set(),schema));}catch{/* An unsupported definition cannot be reused. */}
      signatures.set(object,value);
    }
    return signatures.get(object);
  };
  return source.map(o=>{
    if(gatewayRows.has(o.uid))return gatewayRows.get(o.uid);
    const reason=unsupported(o,schema);
    const row={uid:o.uid,name:o.name,type:o.type,source:o,target:null,status:'create',reason:'No matching object in the destination.'};
    if(reason) return {...row,status:'blocked',reason};
    let sig; try { sig=hash(semantic(o,sm,new Set(),schema)); } catch(e) { return {...row,status:'blocked',reason:e.message}; }
    const same=byName.get(o.name.toLowerCase())||[];
    const equal=d=>d.type===o.type&&signature(d)===sig;
    if(builtin(o)) {
      const exact=destination.find(d=>builtin(d)&&d.uid===(o['archive-reference-uid']||o.uid)&&d.type===o.type);
      if(exact) {
        if(equal(exact))return {...row,status:'reuse',target:exact,reason:'Verified built-in UID, type and policy-relevant definition.'};
        const differences=[];
        const walk=(a,b,path='')=>{
          if(a===b||(a!==undefined&&b!==undefined&&hash(a)===hash(b)))return;
          if(a&&b&&typeof a==='object'&&typeof b==='object'&&!Array.isArray(a)&&!Array.isArray(b)) {
            for(const key of new Set([...Object.keys(a),...Object.keys(b)]))walk(a[key],b[key],path?`${path}.${key}`:key);
          }else differences.push(`${path}${a===undefined?' (not reported by source)':b===undefined?' (not reported by destination)':''}`);
        };
        try{walk(semantic(o,sm,new Set(),schema),semantic(exact,dm,new Set(),schema));}catch{/* Keep comparison failures blocked. */}
        return {...row,status:o.type==='threat-profile'?'conflict':'blocked',profileResolutionAllowed:o.type==='threat-profile',target:exact,reason:`Built-in settings could not be verified as equivalent.${differences.length?` Differences: ${differences.slice(0,10).join('; ')}${differences.length>10?'; …':''}.`:''} Matching name and UID alone cannot establish equivalent protection settings.`};
      }
      const matches=same.filter(d=>builtin(d)&&d.type===o.type&&equal(d));
      if(matches.length===1)return {...row,status:'reuse',target:matches[0],reason:'Verified built-in name, type and definition in the destination.'};
      const profiles=same.filter(d=>builtin(d)&&d.type==='threat-profile');
      if(o.type==='threat-profile'&&profiles.length===1)return {...row,status:'conflict',target:profiles[0],profileResolutionAllowed:true,reason:'A destination built-in profile has the same name but different settings. Review and explicitly use it, or create a custom profile with a new name.'};
      if(o.type==='threat-profile'&&!profiles.length)return {...row,status:'conflict',profileResolutionAllowed:true,reason:'No matching destination built-in profile was verified. Create a custom profile with a unique name if the source settings can be preserved.'};
      return {...row,status:same.some(d=>builtin(d)&&d.type===o.type)?'conflict':'blocked',reason:matches.length?'Multiple built-in definitions match; an exact identity could not be verified.':'Built-in object was not verified in the destination.'};
    }
    if(same.length) {
      if(same.length===1&&equal(same[0])) return {...row,status:'reuse',target:same[0],reason:'Same name, type and policy-relevant settings. Reuse destination UID.'};
      return {...row,status:'conflict',conflictKind:'name',renameAllowed:!builtin(o) && !['dns-domain','updatable-object'].includes(o.type)&&!certificateTypes.has(o.type),target:same[0],reason:'This name already exists with a different type or definition.'};
    }
    const equivalents=(byType.get(o.type)||[]).filter(equal);
    if(equivalents.length===1) return {...row,status:'reuse',target:equivalents[0],reason:'Identical definition under a different name. Reuse destination UID.'};
    if(equivalents.length>1) return {...row,status:'conflict',target:equivalents[0],reason:'Multiple equivalent destination objects; resolve ambiguous duplicates before migration.'};
    if(certificateTypes.has(o.type))return {...row,status:'blocked',reason:'Import the matching certificate and its private key into the destination first. Reuse requires the same certificate type and public certificate fingerprint; names alone are insufficient.'};
    return row;
  });
}
export function translate(value, mapping) {
  if(typeof value==='string') return mapping.get(value) || value;
  if(Array.isArray(value)) return value.map(v=>translate(v,mapping));
  if(value&&typeof value==='object') {
    if(value.uid) { if(!mapping.has(value.uid)) throw new Error(`Unresolved reference: ${value.name || value.uid}`); return mapping.get(value.uid); }
    return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,['name','comments','color','custom-fields'].includes(k)?v:translate(v,mapping)]));
  }
  return value;
}

// Renames affect only the imported copy; dependencies retain source UIDs until staging.
export function resolveObjectRenames(rows, destination, renames = {}, reservedNames = [], schema, options = {}) {
  if (!renames || Array.isArray(renames) || typeof renames !== 'object') throw new Error('Invalid rename choices.');
  const source = rows.map(row => row.source);
  const choices=Object.fromEntries(Object.entries(renames).filter(([,v])=>v&&typeof v==='object'));
  const gatewayChoices=Object.fromEntries(Object.entries(choices).filter(([,v])=>['reuse-gateway','create-gateway'].includes(v.action)));
  if(Object.keys(gatewayChoices).length&&!options.rebuildGateways)throw new Error('Gateway mappings require rebuild gateways mode.');
  for(const uid of Object.keys(gatewayChoices))if(!source.some(o=>o.uid===uid&&gatewayTypes.has(o.type)))throw new Error('Gateway mapping requires a gateway or cluster in this preview.');
  const profileChoices=Object.fromEntries(Object.entries(choices).filter(([uid])=>!Object.hasOwn(gatewayChoices,uid)));
  renames=Object.fromEntries(Object.entries(renames).filter(([,v])=>!v||typeof v!=='object'));
  const names = new Map();
  if(options.objectSuffix)for(const object of source)if(!(options.rebuildGateways&&gatewayTypes.has(object.type))&&!builtin(object)&&!['dns-domain','updatable-object'].includes(object.type)&&!certificateTypes.has(object.type)&&object.uid!==options.importTagUid)names.set(object.uid,object.name+options.objectSuffix);
  const original = compareObjects(source.map(o=>names.has(o.uid)?{...o,name:names.get(o.uid)}:o), destination,schema,options,gatewayChoices);
  for (const [uid, value] of Object.entries(renames)) {
    const row = original.find(row => row.uid === uid);
    if (!row?.renameAllowed) throw new Error('Only supported objects with a name conflict can be renamed. Rescan and review this object.');
    if (typeof value !== 'string' || !value.trim() || value.trim().length > 100 || /[\x00-\x1f\x7f]/.test(value)) throw new Error('Enter an object name of 1–100 characters without control characters.');
    const name = value.trim();
    if (destination.some(o => o.name.toLowerCase() === name.toLowerCase())) {
      const candidate=compareObjects(source.map(o=>({...o,name:o.uid===uid?name:names.get(o.uid)||o.name})),destination,schema,options,gatewayChoices).find(o=>o.uid===uid);
      if(candidate.status!=='reuse'||candidate.target.name.toLowerCase()!==name.toLowerCase())throw new Error(`The destination already contains a different object named ${name}. Choose a unique name.`);
    }
    if (reservedNames.some(n => n.toLowerCase() === name.toLowerCase())) throw new Error(`The name ${name} is reserved for a policy or layer in this migration.`);
    names.set(uid, name);
  }
  for (const [uid, name] of names) {
    if(name.length>100)throw new Error(`Suffixed object name exceeds 100 characters: ${name}.`);
    if(reservedNames.some(n=>n.toLowerCase()===name.toLowerCase()))throw new Error(`The name ${name} is reserved for a policy or layer in this migration.`);
    if (source.some(o => o.uid !== uid && (names.get(o.uid) || o.name).toLowerCase() === name.toLowerCase())) throw new Error(`Another object in this migration uses the name ${name}.`);
  }
  const effective = source.map(o => names.has(o.uid) ? {...o, name:names.get(o.uid)} : o);
  const resolved=compareObjects(effective, destination,schema,options,gatewayChoices).map((row, i) => {
    if (!names.has(row.uid)) return row;
    // A rename must not silently become a reuse of a differently named object.
    const reused = row.status === 'reuse' && row.target.name.toLowerCase()!==names.get(row.uid).toLowerCase();
    const explicitCopy=options.objectSuffix&&!Object.hasOwn(renames,row.uid)&&['reuse','conflict'].includes(row.status)&&!destination.some(o=>o.name.toLowerCase()===names.get(row.uid).toLowerCase());
    if(explicitCopy)return {...row,name:source[i].name,source:source[i],importName:names.get(row.uid),renameAllowed:false,status:'create',target:null,reason:`Create the explicitly requested copy ${names.get(row.uid)}; equivalent objects have different names.`};
    return {...row, name:source[i].name, source:source[i], importName:names.get(row.uid), renameAllowed:row.status==='conflict'||Object.hasOwn(renames,row.uid),
      status:reused ? (options.objectSuffix&&!Object.hasOwn(renames,row.uid)?'create':'conflict') : row.status,
      reason:reused&&options.objectSuffix&&!Object.hasOwn(renames,row.uid)?`Create the explicitly requested copy ${names.get(row.uid)}; an equivalent object has a different name.`:row.status==='reuse'&&!reused?`Reuse the verified destination object ${row.target.name}; its definition matches the requested renamed object.`:reused ? 'An equivalent destination object already exists. Renaming cannot resolve this duplicate definition.' : row.status === 'create' ? `Create as ${names.get(row.uid)}. All imported references will use the new object; the existing destination object is unchanged.` : row.reason};
  });
  for(const [uid,choice] of Object.entries(profileChoices)) {
    const index=resolved.findIndex(row=>row.uid===uid),row=resolved[index];
    if(!row||row.type!=='threat-profile'||!builtin(row.source))throw new Error('Profile resolution requires a built-in Threat Prevention profile.');
    if(choice.action==='reuse-profile') {
      const target=destination.find(o=>o.uid===choice.targetUid&&o.type==='threat-profile'&&builtin(o)&&o.name===row.source.name);
      if(!target)throw new Error('The reviewed destination profile is unavailable. Rescan and choose a resolution.');
      resolved[index]={...row,status:'reuse',target,profileResolutionAllowed:true,profileResolution:choice.action,reason:`Explicitly use destination profile ${target.name}. Its protection settings replace the source profile settings for imported references; the destination profile is not modified.`};
    }else if(choice.action==='copy-profile') {
      const name=typeof choice.name==='string'?choice.name.trim():'';
      if(!name||name.length>100||/[\x00-\x1f\x7f]/.test(name))throw new Error('Enter a profile name of 1–100 characters without control characters.');
      if([...destination,...effective.filter(o=>o.uid!==uid)].some(o=>o.name.toLowerCase()===name.toLowerCase())||reservedNames.some(n=>n.toLowerCase()===name.toLowerCase())||source.some(o=>o.name.toLowerCase()===name.toLowerCase()))throw new Error('Choose a unique name for the new custom profile.');
      const reason=unsupported({...row.source,domain:{'domain-type':'domain'}},schema);
      if(reason)throw new Error(`Cannot preserve the source as a custom profile: ${reason}`);
      resolved[index]={...row,status:'create',target:row.target,profileTargetUid:row.target?.uid,importName:name,profileResolutionAllowed:true,profileResolution:choice.action,reason:`Create custom profile ${name} from the source settings. Imported references use the new profile; built-in profiles remain unchanged.`};
    }else throw new Error('Unknown profile resolution.');
  }
  const importNames=resolved.filter(o=>o.status==='create').map(o=>(o.importName||o.name).toLowerCase());
  if(new Set(importNames).size!==importNames.length)throw new Error('Imported object names must be unique.');
  for(const row of resolved.filter(o=>o.gatewayDefinition))if(reservedNames.some(n=>n.toLowerCase()===row.importName.toLowerCase()))throw new Error('Gateway name is reserved for a policy or layer.');
  return resolved;
}

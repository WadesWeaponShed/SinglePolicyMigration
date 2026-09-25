import {compareVersions} from '../catalog-manager.js';
import {catalogsReady} from '../catalogs.js';

function version(value) {
  return typeof value==='string' && /^v?\d+(?:\.\d+){0,2}$/.test(value)?`v${value.replace(/^v/,'')}`:null;
}
export function checkMigrationCapability(response,label='Management context') {
  const supported=response?.['supported-versions'],current=version(response?.['current-version']);
  if(!Array.isArray(supported)||!supported.length||supported.some(v=>!version(v))||!current)throw new Error(`${label}: API capabilities are missing or malformed. Migration is blocked until compatibility can be verified.`);
  return {supported:[...new Set(supported.map(version))].sort(compareVersions),current};
}
function validateValue(value,types,path) {
  if(!types?.length)return;
  const matches=type=>{
    if(type.name==='list')return Array.isArray(value);
    if(type.name==='object')return value!==null&&typeof value==='object'&&(!Array.isArray(value)||!type.fields?.length);
    if(type.name==='integer'||type.name==='number')return typeof value==='number'&&Number.isFinite(value);
    if(['string','boolean'].includes(type.name))return typeof value===type.name;
    return true;
  };
  const candidates=types.filter(matches);
  if(!candidates.length)throw new Error(`${path} has an unsupported value type.`);
  let last;
  for(const type of candidates)try {
    if(type.validValues?.length&&!type.validValues.some(v=>String(v).toLowerCase()===String(value).toLowerCase()))throw new Error(`${path} has an undocumented value.`);
    if(type.name==='list')value.forEach((item,i)=>validateValue(item,type.items,`${path}[${i}]`));
    if(type.name==='object'&&type.fields?.length)for(const [key,item] of Object.entries(value)) {
      const field=type.fields.find(f=>f.name===key||f.alternatives?.includes(key));
      if(!field)throw new Error(`${path}.${key} is not documented in the selected API.`);
      if(field.name===key)validateValue(item,field.types,`${path}.${key}`);
    }
    return;
  }catch(error){last=error;}
  throw last;
}
export function validateCommand(catalog,command,body={}) {
  const schema=catalog.commands.find(c=>c.name===command);
  if(!schema)throw new Error(`${command} is not documented in API ${catalog.apiVersion}.`);
  if(schema.deprecated)throw new Error(`${command} is deprecated in API ${catalog.apiVersion}; migration requires review.`);
  const all=[...schema.requiredFields,...schema.optionalFields];
  const accepted=new Set(all.flatMap(f=>[f.name,...(f.alternatives||[])]));
  for(const key of Object.keys(body))if(!accepted.has(key))throw new Error(`${command}.${key} is not documented in API ${catalog.apiVersion}.`);
  for(const [key,value] of Object.entries(body)){const field=all.find(f=>f.name===key);if(field)validateValue(value,field.types,`${command}.${key}`);}
  const groupException=/^(add|set|delete|show)-threat-exception$/.test(command);
  const inGroup=body['exception-group-uid']!==undefined||body['exception-group-name']!==undefined;
  const required=schema.requiredFields.filter(f=>!groupException||!(inGroup?['layer','rule-uid']:['exception-group-uid']).includes(f.name));
  for(const field of required)if(![field.name,...(field.alternatives||[])].some(k=>body[k]!==undefined))throw new Error(`${command} requires ${[field.name,...(field.alternatives||[])].join(' or ')} in API ${catalog.apiVersion}.`);
}
// Framework capability detection chooses the highest advertised common version.
// A reviewed plan supplies its pinned version so updates cannot change execution.
export async function migrationApi(sessions,contexts,{version:pinned,catalogs,allowedVersions}={}) {
  if(!Array.isArray(contexts)||!contexts.length)throw new Error('Migration API contexts are required.');
  const approved=new Map();
  for(const {id,context='primary',label='Management context'} of contexts) {
    if(!id||!['primary','mds'].includes(context))throw new Error('Invalid migration API context.');
    const key=JSON.stringify([id,context]);if(approved.has(key))continue;
    let response;try{response=await sessions.command(id,'show-api-versions',{},context);}catch(e){throw new Error(`${label}: could not verify API capabilities. Migration is blocked. ${e.message}`);}
    approved.set(key,checkMigrationCapability(response,label));
  }
  const capabilities=[...approved.values()];
  const allowed=allowedVersions?.map(version);
  const common=capabilities[0].supported.filter(v=>capabilities.every(c=>c.supported.includes(v))&&(!allowed||allowed.includes(v))).sort(compareVersions);
  const selected=pinned===undefined?common.at(-1):version(pinned);
  if(!selected||!common.includes(selected))throw new Error(pinned?`Reviewed API ${pinned} is no longer supported by every migration context. Rescan before making changes.`:'No common API version is advertised by MDS, source and destination.');
  const manager=catalogs||await catalogsReady;
  const catalog=await manager.ensure(selected);
  const validate=(command,body={})=>validateCommand(catalog,command,body);
  return {version:selected,catalog,validate,command(id,command,body={},context='primary') {
    if(!approved.has(JSON.stringify([id,context])))throw new Error('Migration command attempted in an unverified API context.');
    validate(command,body);
    return sessions.command(id,command,body,context,selected);
  }};
}

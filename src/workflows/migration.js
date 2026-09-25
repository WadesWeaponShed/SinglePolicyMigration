import {objectAdapters,writableFields} from './adapters.js';
import {normalizeMigrationOptions} from './options.js';
import {batchObjectTypes,batchRulePayload,canBatchRule,creationRejected,runNativeBatch,validateNativeSession} from './batch.js';
import {kindOf,policyFields,policyLayerFields,packagePayload,schemaPolicyFields} from './policy-types.js';
import { discardChanges } from './discard.js';
import { randomUUID } from 'node:crypto';
import { migrationApi } from './compatibility.js';
import { normalizedObject, equivalentAcrossNames, builtin, compareObjects, resolveObjectRenames, fields, hash, semantic, metadata, objectPayload, pick, refs, translate, uidOf, unsupported } from './objects.js';

export const ruleFields = ['name','action','action-settings','content','content-direction','content-negate','custom-fields','destination','destination-negate','enabled','inline-layer','install-on','service','service-negate','service-resource','source','source-negate','tags','time','track','user-check','vpn','comments'];
export const natFields = ['name','enabled','install-on','method','original-destination','original-service','original-source','translated-destination','translated-service','translated-source','comments','tags'];
export const layerFields = ['name','firewall','applications-and-url-filtering','content-awareness','detect-using-x-forward-for','mobile-access','implicit-cleanup-action','dynamic-layer','shared','color','comments','tags'];
const ruleMetadata = new Set([...metadata,'rule-number','rulebase','from','to','hits','hits-settings','rulebase-action','natPosition','exceptions','exceptions-layer','exception-number','parentSectionUid','layer']);
const externalIdentityFields=new Set(['uid-in-data-center','uid-in-updatable-objects-repository','uri']);
const idMatch = (value, domain) => typeof value==='string' ? [domain.uid,domain.name].includes(value) : value?.uid===domain.uid || value?.name===domain.name;
// Read a dependency frontier concurrently, but consume it in discovery order.
// Settle every request before returning an error so retries cannot overlap old reads.
export async function readDependencyFrontiers(pending, read, consume, concurrency=6) {
  if(!Number.isInteger(concurrency)||concurrency<1)throw new Error('Read concurrency must be a positive integer.');
  const visited=new Set();
  for (;;) {
    const batch=[...pending].filter(uid=>!visited.has(uid)).slice(0,concurrency);
    if(!batch.length)return;
    batch.forEach(uid=>visited.add(uid));
    const results=await Promise.allSettled(batch.map(uid=>read(uid)));
    const failure=results.find(result=>result.status==='rejected');
    if(failure)throw failure.reason;
    for(let i=0;i<batch.length;i++)await consume(batch[i],results[i].value);
  }
}
export function globalCheck(assignments, domain, packages) {
  if(!Array.isArray(assignments)) throw new Error('Global assignment status is unknown. Verify MDS permissions and retry.');
  for(const a of assignments) {
    if(!a?.['dependent-domain'] || !(typeof a['dependent-domain']==='string' || typeof a['dependent-domain'].uid==='string' || typeof a['dependent-domain'].name==='string')) throw new Error('Unrecognized global assignment response; cannot establish that the domain is clear.');
    if(!domain.archive&&idMatch(a['dependent-domain'],domain)) return {ok:false,detail:`Global policy is assigned to ${domain.name}. Uninstall/remove the global policy assignment in SmartConsole, then scan again.`};
  }
  if(packages.some(p=>[...(p['access-layers']||[]),...(p['threat-layers']||[])].some(l=>l.domain?.['domain-type']==='global domain'))) {
    return {ok:false,detail:`${domain.name} contains inherited Global Domain layers. Remove the global policy assignment and scan again.`};
  }
  if(domain.archive)return {ok:true,severity:'notice',detail:'Offline archive: original source assignment status cannot be checked. No inherited global layers are present in its definitions. Destination assignments are checked live.'};
  return {ok:true,detail:`No global assignment or inherited global layer found in ${domain.name}.`};
}
// All pages go through SessionManager, preserving its throttling/context boundary.
export async function collection(sessions,id,command,key,body={},context='primary',onProgress=()=>{}) {
  const result=[], seen=new Set(); let offset=0, total;
  while(true) {
    let page;
    try {page=await sessions.command(id,command,{'details-level':'full',...body,limit:500,offset},context);}
    catch(error){error.message=`${command} failed at offset ${offset}: ${error.message}`;throw error;}
    if(!Array.isArray(page[key]) || !Number.isInteger(page.total) || page.total<0) throw new Error(`Incomplete ${command} response. Scan stopped; no changes made.`);
    if(total!==undefined && total!==page.total) throw new Error(`${command} inventory changed during pagination. Scan again.`);
    total=page.total;
    for(const item of page[key]) {
      if(item.uid!==undefined && seen.has(item.uid)) throw new Error(`${command} returned duplicate objects during pagination.`);
      if(item.uid!==undefined) seen.add(item.uid);
    }
    if(offset+page[key].length>total) throw new Error(`Incomplete ${command}: page exceeds reported total.`);
    result.push(...page[key]);
    offset+=page[key].length;
    onProgress({completed:offset,total});
    if(offset>=page.total) break;
    if(page[key].length===0) throw new Error(`${command} pagination ended before all objects were read.`);
  }
  return result;
}
export async function readRulebase(sessions,id,command,body) {
  const ordered=new Map(), dictionary=new Map(); let offset=0, total;
  while(true) {
    const page=await sessions.command(id,command,{...body,offset,limit:100,'details-level':'full','use-object-dictionary':true});
    if(!Array.isArray(page.rulebase)||!Number.isInteger(page.total)||page.total<0) throw new Error(`Cannot read complete ${command}.`);
    if(total!==undefined && total!==page.total) throw new Error('Rulebase changed during pagination. Scan again.');
    total=page.total;
    for(const o of page['objects-dictionary'] || []) dictionary.set(o.uid,o);
    let count=0;
    const add=(items,parentSectionUid)=>{for(const raw of items){
      const item=command==='show-threat-rule-exception-rulebase'&&raw.type==='threat-section'?{...raw,type:'threat-exception-section'}:raw;
      if(!item.uid || !['access-rule','access-section','nat-rule','nat-section','threat-rule','threat-exception','threat-exception-section','https-rule','https-section'].includes(item.type)) throw new Error(`${command}: rulebase item ${item.name||'(unnamed)'} has ${!item.uid?'no UID':`unsupported type ${item.type}`}.`);
      if(item.type.endsWith('section')) {
        if(item.rulebase!==undefined && !Array.isArray(item.rulebase)) throw new Error('Malformed rulebase section.');
        const previous=ordered.get(item.uid);
        if(previous && (previous.name!==item.name || hash(previous.tags||[])!==hash(item.tags||[]))) throw new Error('Rulebase section changed during pagination.');
        if(!previous) ordered.set(item.uid,{...item,rulebase:undefined});
        add(item.rulebase||[],item.uid);
      } else {
        if(ordered.has(item.uid)) throw new Error('Duplicate rule encountered during pagination.');
        ordered.set(item.uid,{...item,...parentSectionUid?{parentSectionUid}:{}}); count++;
      }
    }}; add(page.rulebase);
    const next=offset+count;
    if(next>total || (page.to!==undefined && page.to!==next)) throw new Error('Rulebase pagination is inconsistent with the returned rules.');
    offset=next;
    if(offset===total) break;
    if(count===0) throw new Error('Rulebase pagination ended early.');
  }
  return {items:[...ordered.values()],dictionary:[...dictionary.values()]};
}
// Generated NAT belongs to objects, not to the manually copied rulebase.
export function manualNatItems(items) {
  return items.filter((item,index)=>{
    if(item['auto-generated']===true)return false;
    if(item.type==='nat-section' && (/^Automatic Generated Rules : /.test(item.name||'') || ['Manual Upper Rules','Manual Lower Rules'].includes(item.name)))return false;
    if(item.type!=='nat-section')return true;
    const following=[];
    for(let i=index+1;i<items.length&&items[i].type!=='nat-section';i++)following.push(items[i]);
    return following.some(rule=>rule['auto-generated']!==true);
  });
}

export function natItemsForMigration(items) {
  let region='upper';
  const positions=new Map();
  for(const item of items) {
    if(item['auto-generated']===true || (item.type==='nat-section' && (/^Automatic Generated Rules : /.test(item.name||'') || item.name==='Manual Lower Rules')))region='lower';
    positions.set(item.uid,region);
  }
  return manualNatItems(items).map(item=>({...item,natPosition:['upper','lower'].includes(item.natPosition)?item.natPosition:positions.get(item.uid)}));
}
function layerDefaults(kind,catalog,policySchema) {
  const defaults={comments:'',tags:[]};
  const contract=catalog.commands.find(c=>c.name===`add-${kind}-layer`);
  for(const field of contract?.optionalFields||[]) {
    if(!policySchema[`${kind}-layer`]?.includes(field.name)||field.default==='')continue;
    if(field.type==='boolean'&&['true','false'].includes(field.default))defaults[field.name]=field.default==='true';
    else if(field.type==='string')defaults[field.name]=field.default;
  }
  return defaults;
}
function exceptionGroupSettings(group,mapping,schema) {
  const controls=new Set(['name','apply-on','applied-threat-rules','applied-profile']);
  return translate(pick(group,(schema?.['exception-group']||['color','comments','tags']).filter(key=>!controls.has(key))),mapping);
}

// Full typed pages avoid one round trip per ordinary destination definition.
// Only proven full-list contracts are used; other types keep individual reads.
export async function bulkDestinationDefinitions(sessions,targetId,candidates,onProgress=()=>{}) {
  const commands={host:'show-hosts',network:'show-networks','service-tcp':'show-services-tcp','service-udp':'show-services-udp'};
  const types=Object.keys(commands).filter(type=>candidates.filter(o=>o.type===type).length>=20&&sessions.catalog?.commands.some(c=>c.name===commands[type]));
  const result=new Map();
  await readDependencyFrontiers(new Set(types),async type=>{
    onProgress(`Reading full destination ${type} inventory pages…`);
    return collection(sessions,targetId,commands[type],'objects');
  },(type,objects)=>{
    const full=new Map(objects.map(o=>[o.uid,o]));
    for(const candidate of candidates.filter(o=>o.type===type)) {
      const object=full.get(candidate.uid);
      if(!object||object.type!==candidate.type||object.name!==candidate.name)throw new Error('Destination identity changed between summary and full inventory pages. Scan again.');
      result.set(object.uid,object);
    }
  },4);
  return result;
}

export async function scan({sessions,sourceId,targetId,rootId,sourceRootId=rootId,targetRootId=rootId,sourceDomain,targetDomain,packageUid,targetName,renames={},options={},apiVersion,engineRevision,onProgress=()=>{}}) {
  if(sourceRootId===undefined||targetRootId===undefined)throw new Error('Explicit management contexts are required.');
  options=normalizeMigrationOptions(options);
  const report=(message,counts={})=>onProgress({message,...counts});
  report('Checking supported API versions…');
  if(sourceDomain.uid===targetDomain.uid&&sourceDomain.endpoint===targetDomain.endpoint) throw new Error('Source and destination must be different domains.');
  if(!targetName||targetName.length>100||/[\x00-\x1f]/.test(targetName)) throw new Error('Enter a destination package name (1–100 characters).');
  sessions=await migrationApi(sessions,[...new Set([sourceRootId,targetRootId].filter(Boolean))].map(id=>({id,context:'mds',label:'MDS'})).concat([{id:sourceId,label:'Source domain'},{id:targetId,label:'Destination domain'}]),{version:apiVersion});
  apiVersion=sessions.version;
  const objectSchema=objectAdapters(sessions.catalog), policySchema=schemaPolicyFields(sessions.catalog);
  report('Checking global assignments and policy packages…');
  const assignmentsByRoot=new Map();
  for(const id of new Set([sourceRootId,targetRootId].filter(Boolean)))assignmentsByRoot.set(id,await collection(sessions,id,'show-global-assignments','objects',{},'mds'));
  const sourcePackages=await collection(sessions,sourceId,'show-packages','packages');
  const targetPackages=await collection(sessions,targetId,'show-packages','packages');
  const checks=[];
  checks.push({name:'Migration scope',ok:true,severity:'notice',detail:`Include ${['access','threat','https','nat'].filter(k=>options[k]).join(', ')}. ${options.includeSections?'Preserve section headers.':'Omit Access/HTTPS/NAT section headers; preserve rule order and TP exception-group ownership.'}${options.objectSuffix?` Imported user objects use suffix ${options.objectSuffix}; built-in, DNS-domain and repository-defined names are retained.`:''}${options.importTag?` Tag newly created objects with ${options.importTag}; reused objects are not modified.`:''}`});
  // Full package details are essential: collection summaries can omit inherited layers.
  const expand=async(id,packages)=>{const out=[]; for(const p of packages) out.push(await sessions.command(id,'show-package',{uid:p.uid,'details-level':'full'})); return out;};
  const sp=await expand(sourceId,sourcePackages), tp=await expand(targetId,targetPackages);
  for(const [d,p,root] of [[sourceDomain,sp,sourceRootId],[targetDomain,tp,targetRootId]]) checks.push({name:`Global policy · ${d.name}`,...globalCheck(assignmentsByRoot.get(root)||[],d,p)});
  if(checks.some(c=>!c.ok)) return buildPlan({apiVersion,sourceDomain,targetDomain,targetName,checks,objects:[],layers:[],package:{name:sourcePackages.find(p=>p.uid===packageUid)?.name||'Selected policy'},inventory:[],nat:[]});
  const pkg=sp.find(p=>p.uid===packageUid);
  if(!pkg) throw new Error('Selected package no longer exists. Refresh the policy list.');
  checks.push({name:'Destination package',ok:!tp.some(p=>p.name.toLowerCase()===targetName.toLowerCase()),detail:tp.some(p=>p.name.toLowerCase()===targetName.toLowerCase())?'A destination package with this name already exists. Choose a new name.':'A new, separate package will be created.'});
  const unsupportedBlades=['desktop-security','qos','vpn-traditional-mode'].filter(k=>pkg[k]===true);
  checks.push({name:'Package coverage',ok:unsupportedBlades.length===0,detail:unsupportedBlades.length?`Unsupported package features: ${unsupportedBlades.join(', ')}. This release cannot migrate this entire package.`:'Access Control, NAT, Threat Prevention and HTTPS Inspection use native migration handlers. Source policy will be retained.'});

  report('Reading destination object inventory…');
  // Enumerate every name/type without asking unrelated external services for full
  // definitions. Supported comparison candidates are expanded separately below.
  const destination=await collection(sessions,targetId,'show-objects','objects',{'details-level':'standard','dereference-group-members':false},'primary',({completed,total})=>report(`Destination inventory: ${completed} of ${total} objects read.`));
  if(destination.some(o=>!o.uid||!o.name||!o.type))throw new Error('Destination inventory contains an object without its UID, name or type. Scan stopped; no changes made.');
  const source=new Map(), layers=[], layerIds=new Set();
  async function readLayer(ref,ordered=true,kind='access',slot) {
    const uid=uidOf(ref);
    if(layerIds.has(uid)) return;
    layerIds.add(uid);
    const config=await sessions.command(sourceId,`show-${kind}-layer`,{uid,'details-level':'full'});
    report(`Reading ${kind} rules · ${config.name || 'Selected layer'}`);
    if(config.uid!==uid || !config.name) throw new Error('Access layer identity could not be verified.');
    const data=await readRulebase(sessions,sourceId,`show-${kind}-rulebase`,{uid,package:pkg.uid});
    data.dictionary.forEach(o=>source.set(o.uid,o));
    const defaults=layerDefaults(kind,sessions.catalog,policySchema);
    const layer={...defaults,...config,kind,slot,ordered,items:options.includeSections?data.items:data.items.filter(i=>!i.type.endsWith('section')),targetName:`${targetName} / ${config.name}`};
    layers.push(layer);
    for(const r of data.items) if(r['inline-layer']) await readLayer(r['inline-layer'],false);
    if(kind==='threat') {
      layer.exceptionSets=[];
      for(const rule of data.items.filter(r=>r.type==='threat-rule')) {
        const exceptions=await readRulebase(sessions,sourceId,'show-threat-rule-exception-rulebase',{uid,'rule-uid':rule.uid,package:pkg.uid});
        exceptions.dictionary.forEach(o=>source.set(o.uid,o));
        exceptions.items=exceptions.items.filter(item=>!(item.type.endsWith('section')&&item.name==='Global Exceptions'));
        const groups=[];
        for(const section of exceptions.items.filter(r=>r.type.endsWith('section'))) {
          if(section.name==='Global Exceptions')continue;
          const group=await sessions.command(sourceId,'show-exception-group',{name:section.name,'details-level':'full'});
          groups.push({...group,sectionUid:section.uid,position:section.from||'bottom',targetName:`${targetName} / ${group.name}`});
        }
        layer.exceptionSets.push({ruleUid:rule.uid,items:exceptions.items,groups});
      }
    }
  }
  if(options.access)for(const l of pkg['access-layers']||[]) await readLayer(l);
  if(options.threat)for(const l of pkg['threat-layers']||[]) await readLayer(l,true,'threat');
  if(options.https&&pkg['https-inspection-policy']) {
    if(pkg['https-inspection-layers']){for(const [slot,l] of Object.entries(pkg['https-inspection-layers']))if(l)await readLayer(l,true,'https',slot);}
    else if(pkg['https-inspection-layer'])await readLayer(pkg['https-inspection-layer'],true,'https','outbound-https-layer');
  }
  for(const [flag,kind] of [['threat-prevention','threat'],['https-inspection-policy','https']])if(options[kind]&&pkg[flag]&&!layers.some(l=>kindOf(l)===kind))checks.push({name:`${kind} coverage`,ok:false,detail:`Package enables ${flag} but its layers are missing from the API response.`});
  if(layers.some(l=>kindOf(l)==='threat'))checks.push({name:'Destination Threat Prevention defaults',ok:true,severity:'notice',detail:'Check Point may require generated IPS and first Threat Prevention layers. The IPS layer must be empty; generated Threat Prevention rules are disabled and verified before imported layers are used.'});
  let nat=[];
  if(options.nat&&pkg['nat-policy']) {
    report('Reading manual NAT rules…');
    const data=await readRulebase(sessions,sourceId,'show-nat-rulebase',{package:pkg.uid});
    nat=natItemsForMigration(data.items);
    if(!options.includeSections)nat=nat.filter(r=>!r.type.endsWith('section'));
    const generated=data.items.filter(r=>r.type==='nat-rule'&&r['auto-generated']===true).length;
    if(generated)checks.push({name:'Automatic NAT',ok:true,severity:'notice',detail:`${generated} generated NAT rules are not copied individually. NAT settings follow objects required by the migrated policy; Check Point generates their rules. Objects referenced only by generated rules are excluded.`});
    data.dictionary.forEach(o=>source.set(o.uid,o));
  }
  if(nat.length&&!layers.some(l=>kindOf(l)==='access')) {
    layers.unshift({...layerDefaults('access',sessions.catalog,policySchema),uid:'nat-context-'+hash(targetName).slice(0,24),name:'NAT context',type:'access-layer',kind:'access',ordered:true,items:[],targetName:`${targetName} / NAT context`});
    checks.push({name:'NAT package context',ok:true,severity:'notice',detail:'Create an empty Access layer so Check Point can host the selected NAT rulebase. No source Access rules are copied.'});
  }
  checks.push({name:'Rulebase coverage',ok:layers.length>0||nat.length>0,detail:layers.length||nat.length?`${layers.length} policy layers and ${nat.filter(r=>r.type==='nat-rule').length} manual NAT rules selected.`:'No rules or layers found in the selected scope.'});
  const allItems=[...layers.flatMap(l=>[...l.items,...(l.exceptionSets||[]).flatMap(e=>e.items)]),...nat];
  const archiveDefinitions=new Set(source.keys());
  const needed=new Set();
  function collect(value,key) {
    if(externalIdentityFields.has(key))return;
    if(Array.isArray(value)) return value.forEach(item=>collect(item,key));
    if(value&&typeof value==='object') {if(value.uid){needed.add(value.uid);source.set(value.uid,source.get(value.uid)||value);}else Object.entries(value).forEach(([k,v])=>collect(v,k));}
    else if(typeof value==='string'&&(/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value)||source.has(value))) needed.add(value);
  }
  for(const item of allItems) collect(pick(item,policyFields(item,item.type==='nat-rule'?natFields:ruleFields,policySchema)));
  for(const l of layers) {collect(pick(l,['tags']));for(const set of l.exceptionSets||[])for(const group of set.groups)collect(pick(group,['tags']));}
  // Fetch every referenced object in full and recursively traverse writable dependency fields.
  const fetched=new Set();
  let archiveDictionary;
  const archivedBuiltinCandidates=async name=>{
    let candidates=destination.filter(o=>o.name===name);
    if(!candidates.length)candidates=(await collection(sessions,targetId,'show-objects','objects',{filter:name,'details-level':'full'})).filter(o=>o.name===name);
    if(!candidates.length) {
      if(!archiveDictionary) {
        archiveDictionary=new Map();const seen=new Set();
        for(const targetPackage of tp)for(const [kind,refs] of [['access',targetPackage['access-layers']||[]],['threat',targetPackage['threat-layers']||[]],['https',Object.values(targetPackage['https-inspection-layers']||{}).concat(targetPackage['https-inspection-layer']||[])]])for(const ref of refs) {
          const uid=uidOf(ref);if(!uid||seen.has(uid))continue;seen.add(uid);
          const base=await readRulebase(sessions,targetId,`show-${kind}-rulebase`,{uid});
          for(const object of base.dictionary)archiveDictionary.set(object.uid,object);
        }
      }
      candidates=[...archiveDictionary.values()].filter(o=>o.name===name);
    }
    const verified=[];
    for(const candidate of candidates) {
      const reply=await sessions.command(targetId,'show-object',{uid:candidate.uid,'details-level':'full'}),object=reply.object||reply;
      if(object.uid===candidate.uid&&object.name===name&&builtin(object))verified.push(object);
    }
    return verified;
  };
  report('Resolving source objects and group members…');
  await readDependencyFrontiers(needed,async uid=>{
    if(layerIds.has(uid)||fetched.has(uid)) return null;
    const reference=source.get(uid);
    let result;
    if(sourceDomain.archive&&reference?.type==='archive-reference') {
      // Upstream archives omit built-ins and retain their names. show-object
      // accepts a UID, not a name; require one exact built-in inventory match.
      let matches=await archivedBuiltinCandidates(reference.name);
      if(matches.length>1) {
        const definitions=new Map(matches.map(o=>[o.uid,o]));
        const signatures=new Set(matches.map(o=>hash(semantic(o,definitions,new Set(),objectSchema))));
        if(signatures.size===1)matches=[matches.sort((a,b)=>a.uid.localeCompare(b.uid))[0]];
      }
      if(matches.length!==1)throw new Error(`Archive reference ${reference.name} requires one unambiguous built-in definition; found ${matches.length} (${matches.map(o=>o.type).join(', ')}).`);
      const reply=await sessions.command(targetId,'show-object',{uid:matches[0].uid,'details-level':'full'});
      const found=reply.object||reply;
      if(!builtin(found)||found.name!==reference.name||found.uid!==matches[0].uid)throw new Error(`Archive built-in identity changed: ${reference.name}.`);
      result={object:{...found,uid,'archive-reference-uid':found.uid}};
    } else if(sourceDomain.archive&&!archiveDefinitions.has(uid)) {
      const reply=await sessions.command(targetId,'show-object',{uid,'details-level':'full'});
      const found=reply.object||reply;
      if(!builtin(found))throw new Error(`Archive dependency ${uid} is not a verified built-in; supply its real source definition.`);
      result={object:found};
    } else result=await sessions.command(sourceId,'show-object',{uid,'details-level':'full'});
    return result;
  },(uid,result)=>{
    if(result===null)return;
    const obj=result.object||result;
    if(obj.uid!==uid||!obj.name||!obj.type) throw new Error(`Cannot resolve referenced object ${uid}.`);
    source.set(uid,obj); fetched.add(uid);
    collect(pick(normalizedObject(obj),writableFields(obj.type,objectSchema,fields)));
    report(`Source definitions: ${fetched.size} objects read · ${obj.name}`);
  },sourceDomain.archive?1:6);
  const objects=[...fetched].map(uid=>source.get(uid));
  report('Verifying built-in objects in the destination…');
  // Built-ins are sometimes absent from show-objects. Verify by name in target context.
  for(const obj of objects.filter(builtin)) {
    if(destination.some(d=>d.uid===obj.uid&&d.type===obj.type)) continue;
    try {
      const result=await sessions.command(targetId,'show-object',{uid:obj['archive-reference-uid']||obj.uid,'details-level':'full'});
      const found=result.object||result;
      if(found.uid&&found.name&&found.type) destination.push(found);
    } catch { /* compareObjects will block an unverified built-in. */ }
  }
  // Keep all identities for name collisions, but expand supported definitions
  // and referenced built-ins only. Unsupported group members cannot be reused.
  const dm=new Map(destination.map(o=>[o.uid,o]));
  const requiredBuiltins=objects.filter(builtin);
  const customTypes=new Set(objects.filter(o=>!builtin(o)).map(o=>o.type));
  const expandable=o=>!!(objectSchema[o.type]||fields[o.type])&&customTypes.has(o.type)&&(equivalentAcrossNames.has(o.type)||objects.some(source=>[source.name,source.name+options.objectSuffix].some(n=>n.toLowerCase()===o.name.toLowerCase())))||requiredBuiltins.some(source=>source.uid===o.uid||source.name.toLowerCase()===o.name.toLowerCase())||o.name===options.importTag;
  const pending=new Set(destination.filter(expandable).map(o=>o.uid));
  const bulkDefinitions=await bulkDestinationDefinitions(sessions,targetId,destination.filter(expandable),message=>report(message));
  let destinationRead=0;
  report(`Reading full destination definitions · ${pending.size} objects discovered.`);
  await readDependencyFrontiers(pending,async uid=>{
    if(bulkDefinitions.has(uid))return {object:bulkDefinitions.get(uid)};
    let result;
    try {result=await sessions.command(targetId,'show-object',{uid,'details-level':'full'});}
    catch(error){error.message=`Cannot read destination definition ${dm.get(uid)?.name||uid} (show-object): ${error.message}`;throw error;}
    return result;
  },(uid,result)=>{
    const obj=result.object||result;
    if(obj.uid!==uid||!obj.name||!obj.type) throw new Error('Destination inventory is incomplete.');
    const summary=dm.get(uid);
    if(summary&&(summary.name!==obj.name||summary.type!==obj.type))throw new Error('Destination object identity changed during the scan. Scan again.');
    dm.set(uid,obj);
    const enqueue=uid=>{if(!dm.has(uid)||expandable(dm.get(uid)))pending.add(uid);};
    const walk=(v,key)=>{if(externalIdentityFields.has(key))return;if(Array.isArray(v))v.forEach(item=>walk(item,key));else if(v&&typeof v==='object'){if(v.uid)enqueue(v.uid);else Object.entries(v).forEach(([k,item])=>walk(item,k));}else if(typeof v==='string'&&/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(v))enqueue(v);};
    walk(pick(obj,writableFields(obj.type,objectSchema,fields)));
    report(`Destination definitions: ${++destinationRead} of ${pending.size} discovered objects read · ${obj.name}`);
  });
  report('Comparing definitions and building the migration preview…');
  for(const object of objects.filter(o=>['data-center-object','updatable-object'].includes(o.type))) {
    const payload=objectPayload(object,new Map(),objectSchema),repository=object.type==='updatable-object';
    const name=payload['data-center-name'];
    try {
      if(!repository) {
        if(!name)throw new Error('Source data-center connection name is absent.');
        const server=await sessions.command(targetId,'show-data-center-server',{name,'details-level':'full'});
        if(!server.uid||server.name!==name)throw new Error('Destination connection identity differs.');
        dm.set(server.uid,server);
      }
      const key=repository?'uid-in-updatable-objects-repository':'uid-in-data-center',identity=payload[key]||payload.uri;
      if(!identity)throw new Error('External repository identity is absent.');
      const reply=await sessions.command(targetId,repository?'show-updatable-objects-repository-content':'show-data-center-content',{[key]:identity,...repository?{}:{'data-center-name':name},'details-level':'full'});
      if(!Array.isArray(reply.objects)||reply.objects.filter(o=>o[key]===identity).length!==1)throw new Error('External identity is not uniquely available in the destination inventory. Refresh that inventory before retrying.');
      checks.push({name:`External object prerequisite · ${object.name}`,ok:true,severity:'notice',detail:`Verified external identity ${identity} in ${repository?'the destination Updatable Objects repository':`destination connection ${name}`}. Existing external inventory and credentials are retained.`});
    }catch(error){checks.push({name:`External object prerequisite · ${object.name}`,ok:false,detail:error.message});}
  }
  for(const layer of layers) {
    const collisions=[...dm.values()].some(o=>o.name.toLowerCase()===layer.targetName.toLowerCase());
    checks.push({name:`Layer · ${layer.name}`,ok:!collisions,detail:collisions?'Destination layer name exists. Choose another package name.':`Create ${layer.targetName}`});
    if(layer['dynamic-layer']) checks.push({name:`Dynamic layer · ${layer.name}`,ok:false,detail:'Dynamic layer behavior requires a dedicated migration adapter.'});
    if(kindOf(layer)==='access'&&layer['parent-layer']&&!layers.some(parent=>parent.uid===uidOf(layer['parent-layer'])&&parent.items.some(rule=>uidOf(rule['inline-layer'])===layer.uid)))checks.push({name:`Inline parent · ${layer.name}`,ok:false,detail:'The declared parent and its inline rule must be included in this migration.'});
    const unknown=Object.keys(layer).filter(k=>!policyLayerFields(layer,layerFields,policySchema).includes(k)&&!metadata.has(k)&&!['items','ordered','targetName','kind','slot','exceptionSets',...kindOf(layer)==='threat'?['ips-layer']:[],...kindOf(layer)==='access'?['parent-layer']:[]].includes(k));
    if(unknown.length) checks.push({name:`Layer settings · ${layer.name}`,ok:false,detail:`Unmapped settings: ${unknown.join(', ')}.`});
  }
  for(const r of allItems) {
    if(r.type.endsWith('section')) {
      const extra=Object.keys(r).filter(k=>!['name','tags'].includes(k)&&!ruleMetadata.has(k));
      if(extra.length)checks.push({name:`Section · ${r.name}`,ok:false,detail:`Unmapped section settings: ${extra.join(', ')}.`});
      continue;
    }
    const allowed=policyFields(r,r.type==='nat-rule'?natFields:ruleFields,policySchema);
    const unknown=Object.keys(r).filter(k=>!allowed.includes(k)&&!ruleMetadata.has(k)&&k!=='auto-generated');
    if(unknown.length||r['auto-generated']) checks.push({name:`Rule · ${r.name||r['rule-number']}`,ok:false,detail:r['auto-generated']?'Automatic NAT is not supported.':`Unmapped rule settings: ${unknown.join(', ')}.`});
  }
  for(const layer of layers)for(const set of layer.exceptionSets||[])for(const group of set.groups) {
    const collision=[...dm.values()].some(o=>o.name.toLowerCase()===group.targetName.toLowerCase());
    checks.push({name:`Exception group · ${group.name}`,ok:!collision,detail:collision?'Destination group name exists. Choose a different policy name.':`Create ${group.targetName}, attached only to imported threat rules.`});
  }
  const data={apiVersion,engineRevision,objectSchema,policySchema,sourceDomain,targetDomain,targetName,checks,objects:compareObjects(objects,[...dm.values()],objectSchema),layers,package:pkg,inventory:[...dm.values()],nat,renames,options};
  const prepared=preparePlanObjects(data);
  checks.push(...validatePlanCommands(sessions,prepared));
  return buildPlan(data);
}
// Validate every planned write against the negotiated API catalog before staging.
// Identity references are sufficient here: validation checks request shape, while
// staging replaces those references with the newly created destination UIDs.
export function validatePlanCommands(api,plan) {
  const checks=[];
  const objects=new Map(plan.objects.map(o=>[o.uid,o.source]));
  const mapping=new Map([...objects.keys(),...plan.layers.map(l=>l.uid)].map(uid=>[uid,uid]));
  const validate=(command,payload)=>{
    try {api.validate(command,payload());}
    catch(error) {checks.push({name:`API schema · ${command}`,ok:false,detail:error.message});}
  };
  for(const row of plan.objects.filter(o=>o.status==='create')) {
    validate(`add-${row.type}`,()=>plannedObjectPayload(row,plan,mapping));
    if(['simple-gateway','simple-cluster'].includes(row.type)&&row.source['logs-settings'])validate(`set-${row.type}`,()=>({uid:row.uid,'logs-settings':plannedObjectPayload(row,plan,mapping)['logs-settings']}));
  }
  for(const layer of plan.layers) {
    validate(`add-${kindOf(layer)}-layer`,()=>({...layerPayload(layer,mapping,plan.policySchema),name:layer.targetName,...kindOf(layer)==='https'?{}:{'add-default-rule':false}}));
    for(const rule of layer.items) {
      const section=rule.type.endsWith('section');
      validate(`add-${rule.type}`,()=>({...section?{...translate(pick(rule,['name','tags']),mapping),name:rule.name||'Section'}:layerRulePayload(rule,layer,mapping,objects,plan.policySchema),layer:layer.uid,position:'bottom'}));
    }
  }
  for(const layer of plan.layers)for(const set of layer.exceptionSets||[]) {
    for(const group of set.groups) {
      validate('add-exception-group',()=>({...exceptionGroupSettings(group,mapping,plan.objectSchema),name:group.targetName,'apply-on':'manually-select-threat-rules','applied-threat-rules':[]}));
      validate('set-exception-group',()=>({uid:group.uid,'applied-threat-rules':{add:[{layer:layer.uid,uid:set.ruleUid,position:1}]}}));
    }
    for(const rule of set.items.filter(r=>r.type==='threat-exception'))validate('add-threat-exception',()=>({...rulePayload(rule,mapping,objects,plan.policySchema),layer:layer.uid,'rule-uid':set.ruleUid,position:'bottom'}));
  }
  let upperSection;
  for(const rule of plan.nat) {
    const section=rule.type==='nat-section';
    const position=rule.natPosition==='upper'?(section||!upperSection?'top':{bottom:upperSection}):'bottom';
    if(section&&rule.natPosition==='upper')upperSection=rule.uid;
    validate(section?'add-nat-section':'add-nat-rule',()=>({...section?{...translate(pick(rule,['name','tags']),mapping),name:rule.name||'Section'}:rulePayload(rule,mapping,objects,plan.policySchema),package:'pending-package',position}));
  }
  validate('add-package',()=>packagePayload(plan));
  validate('set-package',()=>({uid:'pending-package','access-layers':{add:plan.layers.filter(l=>l.ordered&&kindOf(l)==='access').map((l,i)=>({name:l.targetName,position:i+1}))}}));
  validate('set-package',()=>({uid:'pending-package','access-layers':{remove:['pending-default-layer-name']}}));
  validate('delete-access-layer',()=>({uid:'pending-default-layer'}));
  if(plan.layers.some(l=>kindOf(l)==='threat')) {
    validate('set-package',()=>({uid:'pending-package','threat-layers':{add:plan.layers.filter(l=>kindOf(l)==='threat').map((l,i)=>({name:l.targetName,position:i+3}))}}));
    validate('set-threat-rule',()=>({layer:'generated-layer',uid:'generated-rule',enabled:false}));
  }
  if(plan.layers.some(l=>kindOf(l)==='https')) {
    validate('set-package',()=>({uid:'pending-package',...plan.package['https-inspection-layers']?{'https-inspection-layers':Object.fromEntries(plan.layers.filter(l=>kindOf(l)==='https').map(l=>[l.slot,l.uid]))}:{'https-layer':'pending-layer'}}));
    validate('delete-https-rule',()=>({layer:'new-layer',uid:'generated-rule'}));
  }
  validate('publish',()=>({}));
  validate('discard',()=>({}));
  if(!checks.length)checks.push({name:'API schema',ok:true,detail:`Planned commands and fields match the ${plan.apiVersion} API catalog.`});
  return checks;
}
const responseOnly = new Set(['meta-info','hits','read-only','available-actions','icon']);
const unorderedFields = new Set(['objects','inventory','members','groups','tags','source','destination','service','content','time','vpn','install-on','installation-targets']);
function fingerprintValue(v,key='') {
  if(Array.isArray(v)) {
    const values=v.map(value=>fingerprintValue(value));
    // Rule/section order and ordered access layers remain significant.
    return unorderedFields.has(key)?values.sort((a,b)=>hash(a).localeCompare(hash(b))):values;
  }
  if(v&&typeof v==='object') return Object.fromEntries(Object.entries(v).filter(([k])=>!responseOnly.has(k)).map(([k,x])=>[k,fingerprintValue(x,k)]));
  return v;
}
const snapshotFields=['apiVersion','sourceDomain','targetDomain','targetName','checks','objects','layers','package','inventory','nat','renames','options','importTagUid','objectSchema','policySchema','engineRevision'];
function planSnapshot(plan) {return fingerprintValue(pick(plan,snapshotFields));}
export function changedPlanSections(before,after) {
  const left=planSnapshot(before),right=planSnapshot(after);
  const labels={apiVersion:'API version',sourceDomain:'source domain',targetDomain:'destination domain',targetName:'destination package name',checks:'preflight checks',objects:'object definitions or mappings',layers:'access layers or rules',package:'source package settings',inventory:'destination inventory',nat:'manual NAT rules',renames:'rename choices',options:'migration options',importTagUid:'import tag',objectSchema:'object API schema',policySchema:'policy API schema',engineRevision:'native engine version'};
  return snapshotFields.filter(key=>hash(left[key]??null)!==hash(right[key]??null)).map(key=>labels[key]);
}
function supportsImportTag(type,plan) {return type!=='tag'&&!(type==='threat-profile'&&plan.apiVersion==='v2.1')&&writableFields(type,plan.objectSchema,fields).includes('tags');}
function preparePlanObjects(data) {
  const objects=data.objects.filter(o=>!data.importTagUid||o.uid!==data.importTagUid);
  let rows=data.renames||data.options?resolveObjectRenames(objects,data.inventory,data.renames||{},[data.targetName,...data.layers.map(l=>l.targetName)],data.objectSchema,data.options):objects;
  let importTagUid;
  if(data.options?.importTag&&rows.some(o=>o.status==='create'&&supportsImportTag(o.type,data))) {
    importTagUid='migration-tag-'+hash(data.options.importTag).slice(0,24);
    const source={uid:importTagUid,name:data.options.importTag,type:'tag',color:'black',comments:'',...(writableFields('tag',data.objectSchema,fields).includes('tags')?{tags:[]}:{})};
    const [tag]=compareObjects([source],data.inventory,data.objectSchema);
    if(tag.status==='conflict')tag.reason='Import tag name is already used by a different object; choose another tag.';
    tag.renameAllowed=false;rows=[tag,...rows];
  }
  const checks=(data.checks||[]).filter(check=>!check.name.startsWith('Profile tagging'));
  const profiles=rows.filter(o=>o.status==='create'&&o.type==='threat-profile');
  if(data.apiVersion==='v2.1'&&profiles.length) {
    const tagged=profiles.filter(o=>o.source.tags?.length);
    if(tagged.length)checks.push({name:'Profile tagging preservation',ok:false,detail:'This API release ignores Threat Prevention profile tags. Existing source profile tags cannot be preserved: '+tagged.map(o=>o.name).join(', ')});
    else if(data.options?.importTag)checks.push({name:'Profile tagging compatibility',ok:true,severity:'notice',detail:'API v2.1 ignores Threat Prevention profile tags. The optional import tag applies to other supported new objects; profiles remain untagged.'});
  }
  return {...data,checks,objects:rows,importTagUid};
}
export function plannedObjectPayload(row,plan,mapping) {
  const body=objectPayload(row.source,mapping,plan.objectSchema);
  // CSV archives omit empty values. Make common creation defaults explicit so
  // independent readback compares them instead of silently ignoring extra data.
  const writable=writableFields(row.type,plan.objectSchema,fields);
  for(const [key,value] of Object.entries({comments:'',color:'black',tags:[]}))if(body[key]===undefined&&writable.includes(key))body[key]=value;
  if(row.importName)body.name=row.importName;
  if(['simple-gateway','simple-cluster'].includes(row.type))for(const key of gatewayManagementFields)if(Array.isArray(body[key]))body[key]=body[key].map(value=>value===plan.sourceDomain.name?plan.targetDomain.name:value);
  if(row.type==='simple-cluster'&&Array.isArray(body.members)&&plan.options?.objectSuffix)body.members=body.members.map(member=>({...member,name:member.name+plan.options.objectSuffix}));
  if(plan.importTagUid&&supportsImportTag(row.type,plan))body.tags=[...new Set([...(Array.isArray(body.tags)?body.tags:body.tags?[body.tags]:[]),mapping.get(plan.importTagUid)||plan.importTagUid])];
  return body;
}
const gatewayManagementFields=['send-alerts-to-server','send-logs-to-server','send-logs-to-backup-server','fetch-policy'];
export function expectedCopyWarnings(row,plan) {
  if(row.status!=='create'||row.type!=='host'||!plan.options?.objectSuffix||row.importName!==row.name+plan.options.objectSuffix||Object.hasOwn(plan.renames||{},row.uid))return [];
  return ['ipv4-address','ipv6-address'].filter(key=>row.source[key]&&plan.inventory?.some(o=>o.type==='host'&&o[key]===row.source[key])).map(key=>`Multiple objects have the same IP address ${row.source[key]}`);
}
export function buildPlan(data) {
  data=preparePlanObjects(data);
  data.checks=data.checks.filter(check=>!check.name.startsWith('Address duplicate copy · '));
  for(const row of data.objects) {
    const warnings=expectedCopyWarnings(row,data);
    if(warnings.length)data.checks.push({name:`Address duplicate copy · ${row.importName}`,ok:true,severity:'notice',detail:`The requested suffix creates a separate host with an existing IP address. Staging may acknowledge only these specific warnings: ${warnings.join('; ')}. The existing objects are retained.`});
  }
  data.checks=data.checks.filter(check=>check.name!=='Gateway trust');
  if(data.objects.some(o=>o.status==='create'&&['simple-gateway','simple-cluster'].includes(o.type)))data.checks.push({name:'Gateway trust',ok:true,severity:'notice',detail:'New gateway and cluster definitions require SIC to be established separately in the destination before use. Existing source trust is retained. The app does not reset SIC or install policy.'});
  data.checks=data.checks.filter(check=>!check.name.startsWith('Gateway management · '));
  for(const row of data.objects.filter(o=>o.status==='create'&&['simple-gateway','simple-cluster'].includes(o.type))) {
    const values=gatewayManagementFields.flatMap(key=>row.source[key]||[]);
    const unresolved=values.filter(value=>typeof value==='string'&&value!==data.sourceDomain.name&&!data.objects.some(o=>o.uid===value));
    data.checks.push({name:`Gateway management · ${row.name}`,ok:!unresolved.length,severity:unresolved.length?'error':'notice',detail:unresolved.length?`Named management/log-server references need explicit destination mapping: ${[...new Set(unresolved)].join(', ')}.`:`References to source management ${data.sourceDomain.name} become destination management ${data.targetDomain.name}. Disabled blade settings are omitted; active settings are preserved and verified.`});
  }
  data.checks=data.checks.filter(check=>!check.name.startsWith('Cluster member · '));
  const memberNames=new Set(data.inventory.map(o=>o.name.toLowerCase()));
  for(const row of data.objects.filter(o=>o.status==='create'&&o.type==='simple-cluster'))for(const member of normalizedObject(row.source).members||[]) {
    const name=member.name+(data.options?.objectSuffix||'');
    const collision=memberNames.has(name.toLowerCase())||data.objects.some(o=>(o.importName||o.name).toLowerCase()===name.toLowerCase());
    data.checks.push({name:`Cluster member · ${name}`,ok:!collision&&name.length<=100,detail:collision?'A member name already exists. Choose a different object suffix; existing destination members will not be attached or modified.':name.length>100?'The suffixed member name exceeds 100 characters.':`Create member ${name} in ${row.importName||row.name}. Establish its SIC separately.`});memberNames.add(name.toLowerCase());
  }
  const counts={create:0,reuse:0,conflict:0,blocked:0};
  for(const o of data.objects) counts[o.status]++;
  const blockers=data.checks.filter(c=>!c.ok).length+counts.conflict+counts.blocked;
  const digest=hash(planSnapshot(data));
  return {...data,id:randomUUID(),createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+15*60_000).toISOString(),digest,counts,blockers,ready:blockers===0,state:'preview',ruleCount:data.layers.reduce((n,l)=>n+l.items.filter(r=>r.type.endsWith('-rule')).length+(l.exceptionSets||[]).reduce((count,set)=>count+set.items.filter(r=>r.type==='threat-exception').length,0),0)+data.nat.filter(r=>r.type==='nat-rule').length};
}
export function publicPlan(plan) {const {inventory,...publicData}=plan;return publicData;}

function trackEnum(value,objects) {
  const name=typeof value==='object'?(value.name||objects.get(value.uid)?.name):(objects.get(value)?.name||value);
  const normalized=typeof name==='string'?name.toLowerCase():'';
  if(!['none','log','extended log','detailed log'].includes(normalized))throw new Error(`Unresolved or unsupported logging type: ${String(name||value)}.`);
  return normalized;
}

function writableTrack(track,objects) {
  const result={...track,type:trackEnum(track.type,objects)};
  // These log-generation options are inactive for None and rejected on creation.
  if(result.type==='none')for(const key of ['per-session','per-connection','accounting','enable-firewall-session','alert'])delete result[key];
  return result;
}

function writableVpn(value,objects) {
  const name=reference=>typeof reference==='object'?reference.name||objects.get(reference.uid)?.name:objects.get(reference)?.name||reference;
  if(!Array.isArray(value)&&['Any','All_GwToGw'].includes(name(value)))return name(value);
  if(Array.isArray(value)) {
    if(value.length===1&&['Any','All_GwToGw'].includes(name(value[0])))return name(value[0]);
    if(value.every(item=>typeof item==='string'||item?.uid))return {community:value};
  }
  return value;
}

export function layerRulePayload(rule, layer, mapping, objects, schema) {
  const body=rulePayload(rule,mapping,objects,schema);
  // The outbound certificate is managed by Check Point, not writable on a rule.
  // Keep it in the expected snapshot so readback still verifies the certificate.
  if(kindOf(layer)==='https'&&(layer.slot==='outbound-https-layer'||layer['layer-type']==='outbound'))delete body.certificate;
  return body;
}
function httpsBlades(value,objects) {
  const aliases={'Anti-Virus':'Anti Virus','Anti-Bot':'Anti Bot','URL Filtering':'Url Filtering','Data Loss Prevention':'DLP','Content Awareness':'Data Awareness'};
  const name=value=>typeof value==='object'?value.name||objects.get(value.uid)?.name:objects.get(value)?.name||value;
  const convert=value=>aliases[name(value)]||name(value);
  return Array.isArray(value)?value.map(convert):convert(value);
}
export function rulePayload(rule, mapping, objects = new Map(), schema) {
  const payload=pick(rule,policyFields(rule,rule.type==='nat-rule'?natFields:ruleFields,schema));
  if(payload.vpn!==undefined)payload.vpn=writableVpn(payload.vpn,objects);
  // track.type is an enum, unlike object reference fields that accept a UID.
  if(rule.track?.type!==undefined) payload.track=writableTrack(rule.track,objects);
  // The upstream importer removes these response-only settings for Drop rules.
  const actionName=typeof rule.action==='object'?rule.action.name:objects.get(rule.action)?.name || rule.action;
  if(['Apply Layer','Inner Layer'].includes(actionName)) {
    delete payload['action-settings'];
    delete payload['user-check'];
  }
  if(actionName==='Drop') {
    delete payload['action-settings'];
    if(payload['user-check']) {
      payload['user-check']={...payload['user-check']};
      for(const key of ['frequency','custom-frequency','confirm']) delete payload['user-check'][key];
    }
  }
  const enumName=value=>typeof value==='object'?value.name||objects.get(value.uid)?.name:objects.get(value)?.name||value;
  const extraEnums={};
  if(rule.type.startsWith('https-')||rule.type.startsWith('threat-')) {
    if(payload.track!==undefined)extraEnums.track=String(enumName(payload.track)).toLowerCase();
    if(rule.type.startsWith('https-')&&payload.action!==undefined)extraEnums.action=enumName(payload.action);
    if(rule.type.startsWith('https-')&&payload.blade!==undefined) {
      payload.blade=httpsBlades(payload.blade,objects);
      if(payload.blade==='All'||Array.isArray(payload.blade)&&payload.blade.length===1&&payload.blade[0]==='All')delete payload.blade;
    }
    Object.assign(payload,extraEnums);
  }
  const translated=translate(payload,mapping);
  Object.assign(translated,extraEnums);
  if(payload.track?.type!==undefined)translated.track.type=payload.track.type;
  return translated;
}

export function verifyRulebase(expectedItems, actualItems, mapping, objects, label, dictionary=[], schema) {
  const actualObjects=new Map([...objects,...[...objects].filter(([uid])=>mapping.has(uid)).map(([uid,obj])=>[mapping.get(uid),obj]),...dictionary.map(obj=>[obj.uid,obj])]);
  if(actualItems.length!==expectedItems.length) throw new Error(`Staged rule/section count differs for ${label}: expected ${expectedItems.length}, received ${actualItems.length}.`);
  const normalize=value=>{
    if(Array.isArray(value)) return value.map(normalize);
    if(value&&typeof value==='object') {
      if(value.uid) return value.uid;
      return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,normalize(item)]));
    }
    return value;
  };
  for(let i=0;i<expectedItems.length;i++) {
    const expected=expectedItems[i], actual=actualItems[i];
    if(expected.type!==actual.type) throw new Error(`Staged rule/section order differs for ${label}, item ${i+1}: expected ${expected.type} ${expected.name||''}, received ${actual.type} ${actual.name||''}.`);
    if(expected.natPosition && expected.natPosition!==actual.natPosition)throw new Error(`Staged NAT placement differs for ${label}, item ${i+1}: expected ${expected.natPosition}, received ${actual.natPosition}.`);
    const section=expected.type.endsWith('section');
    const wanted=section?{...translate(pick(expected,['name','tags']),mapping),name:expected.name||'Section'}:rulePayload(expected,mapping,objects,schema);
    for(const [key,value] of Object.entries(wanted)) {
      let received=actual[key];
      if(expected.type==='threat-exception'&&key==='action'&&typeof value==='string'&&!objects.has(expected.action)&&!mapping.has(expected.action)) {
        const action=typeof received==='object'?received:actualObjects.get(received);
        if(builtin(action)&&action.name===value)received=action.name;
      }
      if(key==='vpn')received=writableVpn(received,actualObjects);
      if((expected.type.startsWith('https-')||expected.type.startsWith('threat-'))&&key==='track')received=String(typeof received==='object'?received.name||actualObjects.get(received.uid)?.name:actualObjects.get(received)?.name||received).toLowerCase();
      if(expected.type.startsWith('https-')&&key==='action')received=typeof received==='object'?received.name:actualObjects.get(received)?.name||received;
      if(expected.type.startsWith('https-')&&key==='blade')received=httpsBlades(received,actualObjects);
      if(expected.type==='nat-rule'&&key.startsWith('translated-')&&value==='Original') {
        const original=typeof received==='object'?received:actualObjects.get(received);
        if(original?.name==='Original'&&builtin(original))received='Original';
      }
      if(key==='track' && received?.type!==undefined) received=writableTrack(received,actualObjects);
      if(key==='user-check' && !Object.hasOwn(wanted,'action-settings')) {
        const actionName=typeof expected.action==='object'?expected.action.name:objects.get(expected.action)?.name || expected.action;
        if(actionName==='Drop' && received) {
          received={...received};
          for(const field of ['frequency','custom-frequency','confirm']) delete received[field];
        }
      }
      if(received===undefined || hash(normalize(received))!==hash(value)) throw new Error(`Staged rule verification failed: ${label}, item ${i+1}, ${key}.`);
    }
  }
}

function normalizedReferences(value) {
  if(Array.isArray(value)) return value.map(normalizedReferences);
  if(value&&typeof value==='object') {
    if(value.uid) return value.uid;
    return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,normalizedReferences(item)]));
  }
  return value;
}

function layerPayload(layer, mapping = new Map(), schema) {
  const settings=pick(layer,policyLayerFields(layer,layerFields,schema));
  if(settings['applications-and-url-filtering']===false&&settings['content-awareness']===false)delete settings['detect-using-x-forward-for'];
  const cleanup=settings['implicit-cleanup-action'];
  if(cleanup && typeof cleanup==='object') settings['implicit-cleanup-action']=cleanup.name?.toLowerCase();
  else if(typeof cleanup==='string') settings['implicit-cleanup-action']=cleanup.toLowerCase();
  return translate(settings,mapping);
}

// Compare full writable definitions, including server-added writable fields. Unknown
// defaults therefore fail closed instead of silently changing migration semantics.
export function verifyCreatedDefinition(expected, actual, {uid,type,objectSchema,policySchema,expectedName}) {
  const label=type==='access-layer'?'layer':'object';
  if(!actual || actual.uid!==uid || actual.type!==type) throw new Error(`Staged ${label} identity verification failed: ${expected.name}.`);
  if(expectedName&&actual.name!==expectedName)throw new Error(`Staged object name differs: expected ${expectedName}, received ${actual.name}.`);
  const writable=type.endsWith('-layer')?policyLayerFields({kind:type.split('-')[0]},layerFields,policySchema):writableFields(type,objectSchema,fields);
  const unknown=type.endsWith('-layer')?Object.keys(actual).filter(key=>!writable.includes(key) && !metadata.has(key) && !(type==='threat-layer'&&key==='ips-layer') && !(type==='access-layer'&&key==='parent-layer')):[];
  if(unknown.length) throw new Error(`Staged ${label} verification failed: ${expected.name}, unmapped settings ${unknown.join(', ')}.`);
  if(!type.endsWith('-layer')&&unsupported(actual,objectSchema))throw new Error(`Staged object verification failed: ${expectedName||expected.name}, unmapped settings or unsupported definition: ${unsupported(actual,objectSchema)}`);
  const normalized={...Object.fromEntries(Object.entries(type.endsWith('-layer')?actual:normalizedObject(actual)).map(([key,value])=>[key,normalizedReferences(value)])),type};
  if(type==='data-center-object')normalized['data-center-name']=actual['data-center']?.name||actual['data-center-name'];
  // Cleanup actions are enums, so retain their name before expanding UID references.
  if(type==='access-layer') normalized['implicit-cleanup-action']=actual['implicit-cleanup-action'];
  const received=type.endsWith('-layer')?layerPayload({...normalized,kind:type.split('-')[0]},new Map(),policySchema):objectPayload(normalized,new Map(),objectSchema);
  const canonical=(value,key)=>{
    const result=normalizedReferences(value);
    // Group membership and tags are sets; response ordering is not policy semantics.
    return Array.isArray(result) && ['members','tags','activate-protections-by-extended-attributes','deactivate-protections-by-extended-attributes'].includes(key)?[...result].sort((a,b)=>hash(a).localeCompare(hash(b))):result;
  };
  for(const key of new Set([...Object.keys(expected),...Object.keys(received)])) {
    if(expected[key]===undefined || received[key]===undefined || hash(canonical(expected[key],key))!==hash(canonical(received[key],key))) {
      const detail=['nat-settings','tags','logs-settings','firewall-settings'].includes(key)?` Expected ${JSON.stringify(expected[key])}; received ${JSON.stringify(received[key])}.`:'';
      throw new Error(`Staged ${label} verification failed: ${expected.name}, ${key}.${detail}`);
    }
  }
}

export function verifyInheritedGatewaySettings(source,actual,mapping=new Map(),path='') {
  if(!source||typeof source!=='object')return;
  if(source['override-profile']===false&&Object.hasOwn(source,'profile-value')) {
    const wanted=translate(normalizedReferences(source['profile-value']),mapping);
    if(!actual||!Object.hasOwn(actual,'profile-value')||hash(wanted)!==hash(normalizedReferences(actual['profile-value'])))throw new Error(`Inherited gateway setting differs in the destination: ${path}. Align the destination profile before migration.`);
  }
  for(const [key,value] of Object.entries(source))if(value&&typeof value==='object')verifyInheritedGatewaySettings(value,actual?.[key],mapping,path?`${path}.${key}`:key);
}

export async function stagePlan({sessions,targetId,plan,onProgress=()=>{}}) {
  if(!plan.ready||plan.blockers) throw new Error('This plan has unresolved blockers.');
  const state=await sessions.command(targetId,'show-session',{});
  if(typeof state.changes!=='number'||state.changes!==0) throw new Error('Destination session must be empty before staging. Discard existing changes or reconnect.');
  const mapping=new Map(plan.objects.filter(o=>o.status==='reuse').map(o=>[o.uid,o.target.uid]));
  const sourceMap=new Map(plan.objects.map(o=>[o.uid,o.source]));
  const logs=[];
  const createdDefinitions=[];
  const write=async(command,body,allowedWarnings=[])=>{
    const asynchronous=sessions.catalog?.commands.find(c=>c.name===command)?.asynchronous;
    const message=`Running ${command}${body.name?` · ${body.name}`:''}`;
    onProgress(asynchronous?{message,pendingCommand:command,taskId:undefined}:message);
    let result;
    try{result=await sessions.command(targetId,command,body);}
    catch(error){
      const warnings=error.response?.warnings;
      if(error.response?.code==='err_validation_failed'&&Array.isArray(warnings)&&warnings.length&&!error.response?.['blocking-errors']?.length&&!error.response?.errors?.length&&warnings.every(item=>allowedWarnings.includes(item?.message))) {
        onProgress(`Creating reviewed address duplicate · ${body.name}`);
        result=await sessions.command(targetId,command,{...body,'ignore-warnings':true});
        logs.push({command:'acknowledged-copy-warning',name:body.name,warnings:warnings.map(item=>item.message),time:new Date().toISOString()});
      }else {
      if(asynchronous&&!creationRejected(error)){error.batchPending=true;error.pendingCommand=command;}
      const details=['blocking-errors','errors','warnings'].flatMap(key=>Array.isArray(error.response?.[key])?error.response[key].map(item=>item?.message).filter(message=>typeof message==='string'):[]);
      error.message=`${error.message}${body.name?` (${body.name})`:''}${details.length?`: ${details.join('; ')}`:''}`;
      throw error;
      }
    }
    if(!result['task-id']&&(result.errors?.length||result.warnings?.length)) throw new Error(`${command} returned errors or warnings. Staging aborted.`);
    if(result['task-id'])onProgress({message:`Waiting for ${command}…`,pendingCommand:command,taskId:result['task-id']});
    else if(asynchronous) {
      if(result.uid)onProgress({message:`${command} completed.`,pendingCommand:undefined,taskId:undefined});
      else {const error=new Error(`${command} returned neither an object UID nor a task ID.`);error.batchPending=true;error.pendingCommand=command;throw error;}
    }
    logs.push({command,name:body.name||'',uid:result.uid||'',time:new Date().toISOString()});
    return result;
  };
  try {
    const httpsDefaults=new Map();
    const pending=plan.objects.filter(o=>o.status==='create');
    const batchSupported=['add-objects-batch','show-task','show-validations'].every(name=>sessions.catalog?.commands.some(command=>command.name===name));
    while(pending.length) {
      const ready=pending.filter(o=>(!plan.importTagUid||o.type==='tag'||mapping.has(plan.importTagUid))&&[...refs(pick(normalizedObject(o.source),writableFields(o.type,plan.objectSchema,fields)),sourceMap)].every(uid=>mapping.has(uid)));
      const batch=ready.filter(o=>batchObjectTypes.has(o.type)&&!expectedCopyWarnings(o,plan).length).slice(0,50);
      if(batchSupported&&batch.length>=10) {
        const bodies=new Map(batch.map(row=>[row.uid,plannedObjectPayload(row,plan,mapping)])),byType=new Map();
        for(const row of batch){if(!byType.has(row.type))byType.set(row.type,[]);byType.get(row.type).push(bodies.get(row.uid));}
        const result=await runNativeBatch({sessions,targetId,command:'add-objects-batch',body:{objects:[...byType].map(([type,list])=>({type,list}))},allowedWarnings:plan.objects.flatMap(row=>expectedCopyWarnings(row,plan)),onProgress});
        logs.push({command:'add-objects-batch',count:batch.length,taskId:result.taskId,time:new Date().toISOString()});
        const rows=new Map(batch.map(row=>[row.uid,row]));
        await readDependencyFrontiers(new Set(rows.keys()),async uid=>{
          const row=rows.get(uid);return sessions.command(targetId,`show-${row.type}`,{name:bodies.get(uid).name,'details-level':'full'});
        },(uid,response)=>{
          const row=rows.get(uid),actual=response.object||response,body=bodies.get(uid);
          if(!actual.uid||[...mapping.values()].includes(actual.uid)||plan.inventory.some(o=>o.uid===actual.uid))throw new Error(`Batch did not create a distinct identity for ${body.name}.`);
          verifyCreatedDefinition(body,actual,{uid:actual.uid,type:row.type,expectedName:body.name,objectSchema:plan.objectSchema});
          mapping.set(uid,actual.uid);createdDefinitions.push({uid:actual.uid,type:row.type,expected:body,expectedName:body.name,objectSchema:plan.objectSchema});
        });
        for(const row of batch)pending.splice(pending.findIndex(o=>o.uid===row.uid),1);
        continue;
      }
      const index=pending.findIndex(o=>(!plan.importTagUid||o.type==='tag'||mapping.has(plan.importTagUid))&&[...refs(pick(normalizedObject(o.source),writableFields(o.type,plan.objectSchema,fields)),sourceMap)].every(uid=>mapping.has(uid)));
      if(index<0) throw new Error('Circular or unresolved object dependencies.');
      const [o]=pending.splice(index,1);
      const body=plannedObjectPayload(o,plan,mapping);
      let created=await write(`add-${o.type}`,body,expectedCopyWarnings(o,plan));
      if(created['task-id']) {
        await runNativeBatch({sessions,targetId,command:`add-${o.type}`,initialResponse:created,allowedWarnings:plan.objects.flatMap(row=>expectedCopyWarnings(row,plan)),onProgress});
        const response=await sessions.command(targetId,`show-${o.type}`,{name:body.name||o.name,'details-level':'full'});
        created=response.object||response;
        if(created.name!==(body.name||o.name)||plan.inventory.some(object=>object.uid===created.uid))throw new Error(`Asynchronous creation did not return a new ${o.type} named ${body.name||o.name}.`);
      }
      if(!created.uid) throw new Error(`No UID returned for ${o.name}.`);
      // Gateway creation initializes some log thresholds to platform defaults
      // despite accepting the supplied fields. Apply them after creation and
      // keep the complete expected definition for independent readback.
      if(['simple-gateway','simple-cluster'].includes(o.type)&&body['logs-settings']) {
        const configured=await write(`set-${o.type}`,{uid:created.uid,'logs-settings':body['logs-settings']});
        if(configured['task-id'])await runNativeBatch({sessions,targetId,command:`set-${o.type}`,initialResponse:configured,allowedWarnings:plan.objects.flatMap(row=>expectedCopyWarnings(row,plan)),onProgress});
      }
      mapping.set(o.uid,created.uid);
      createdDefinitions.push({uid:created.uid,type:o.type,expected:body,expectedName:o.importName||o.name,objectSchema:plan.objectSchema,inheritedSource:['simple-gateway','simple-cluster'].includes(o.type)?o.source:undefined});
    }
    for(const l of plan.layers) {
      const body={...layerPayload(l,mapping,plan.policySchema),name:l.targetName};
      const kind=kindOf(l);
      const created=await write(`add-${kind}-layer`,{...body,...kind==='https'?{}:{'add-default-rule':false}});
      if(!created.uid) throw new Error('Layer creation returned no UID.');
      mapping.set(l.uid,created.uid);
      createdDefinitions.push({uid:created.uid,type:`${kind}-layer`,expected:body,policySchema:plan.policySchema,parentLayer:kind==='access'?uidOf(l['parent-layer']):undefined});
      if(kind==='https')httpsDefaults.set(created.uid,(await readRulebase(sessions,targetId,'show-https-rulebase',{uid:created.uid})).items);
    }
    const pkg=await write('add-package',packagePayload(plan));
    if(!pkg.uid) throw new Error('Package creation returned no UID.');
    const createdPackage=await sessions.command(targetId,'show-package',{uid:pkg.uid,'details-level':'full'});
    const defaults=createdPackage['access-layers']||[];
    if(!Array.isArray(defaults)||defaults.some(l=>!l.uid||!l.name))throw new Error('New package returned incomplete default layer identities.');
    // R82.10 requires separate add/remove calls and layer names for removal.
    if(plan.layers.some(l=>kindOf(l)==='access'))await write('set-package',{uid:pkg.uid,'access-layers':{add:plan.layers.filter(l=>l.ordered&&kindOf(l)==='access').map((l,i)=>({name:l.targetName,position:i+1}))}});
    if(defaults.length)await write('set-package',{uid:pkg.uid,'access-layers':{remove:defaults.map(l=>l.name)}});
    const threatLayers=plan.layers.filter(l=>kindOf(l)==='threat');
    const mandatoryThreat=createdPackage['threat-layers']||[];
    if(threatLayers.length) {
      await write('set-package',{uid:pkg.uid,'threat-layers':{add:threatLayers.map((l,i)=>({name:l.targetName,position:mandatoryThreat.length+i+1}))}});
      for(const layer of mandatoryThreat) {
        const base=await readRulebase(sessions,targetId,'show-threat-rulebase',{uid:layer.uid});
        if(layer.name==='IPS'&&base.items.length)throw new Error('Required destination IPS layer contains rules; review it before migration.');
        if(layer.name!=='IPS') {
          if(layer.name!==plan.targetName+' Threat Prevention'||plan.inventory.some(o=>o.uid===layer.uid))throw new Error('Unexpected generated Threat Prevention layer.');
          for(const rule of base.items)await write('set-threat-rule',{layer:layer.uid,uid:rule.uid,enabled:false});
          const disabled=await readRulebase(sessions,targetId,'show-threat-rulebase',{uid:layer.uid});
          if(disabled.items.some(r=>r.enabled!==false))throw new Error('Generated Threat Prevention rules remain enabled.');
        }
      }
    }
    const httpsLayers=plan.layers.filter(l=>kindOf(l)==='https');
    if(httpsLayers.length) {
      const settings=plan.package['https-inspection-layers']?{'https-inspection-layers':Object.fromEntries(httpsLayers.map(l=>[l.slot,mapping.get(l.uid)]))}:{'https-layer':mapping.get(httpsLayers[0].uid)};
      await write('set-package',{uid:pkg.uid,...settings});
    }
    const attached=await sessions.command(targetId,'show-package',{uid:pkg.uid,'details-level':'full'});
    const wantedLayers=plan.layers.filter(l=>l.ordered&&kindOf(l)==='access').map(l=>mapping.get(l.uid));
    if(wantedLayers.length&&(!Array.isArray(attached['access-layers']) || hash(attached['access-layers'].map(uidOf))!==hash(wantedLayers))) throw new Error('Staged package layer attachment or order differs from the preview.');
    if(threatLayers.length&&hash((attached['threat-layers']||[]).map(uidOf))!==hash([...mandatoryThreat.map(uidOf),...threatLayers.map(l=>mapping.get(l.uid))]))throw new Error('Staged Threat Prevention layer order differs from preview.');
    for(const layer of httpsLayers) {
      const ref=attached['https-inspection-layers']?.[layer.slot]||attached['https-inspection-layer'];
      if(uidOf(ref)!==mapping.get(layer.uid))throw new Error('Staged HTTPS layer attachment differs from preview.');
    }
    // Verify detachment before deleting any generated layer.
    for(const layer of defaults) {
      if(!plan.inventory.some(o=>o.uid===layer.uid))await write('delete-access-layer',{uid:layer.uid});
    }
    let usedRuleBatch=false;
    const ruleBatchSupported=['add-rules-batch','show-task','show-validations'].every(name=>sessions.catalog?.commands.some(command=>command.name===name));
    for(const l of plan.layers) {
      for(let index=0;index<l.items.length;index++) {
        const r=l.items[index];
        const batch=[];
        if(ruleBatchSupported&&['access-rule','https-rule'].includes(r.type))for(let i=index;i<l.items.length&&batch.length<50&&l.items[i].type===r.type&&canBatchRule(layerRulePayload(l.items[i],l,mapping,sourceMap,plan.policySchema));i++)batch.push(l.items[i]);
        if(batch.length>=10) {
          const result=await runNativeBatch({sessions,targetId,command:'add-rules-batch',body:{objects:[{type:r.type,layer:mapping.get(l.uid),'first-position':'bottom',list:batch.map(rule=>batchRulePayload(layerRulePayload(rule,l,mapping,sourceMap,plan.policySchema)))}]},validate:false,onProgress});
          usedRuleBatch=true;logs.push({command:'add-rules-batch',name:l.targetName,count:batch.length,taskId:result.taskId,time:new Date().toISOString()});
          index+=batch.length-1;continue;
        }
        if(r.type.endsWith('section')) await write(`add-${r.type}`,{...translate(pick(r,['name','tags']),mapping),layer:mapping.get(l.uid),name:r.name||'Section',position:'bottom'});
        else {const created=await write(`add-${r.type}`,{...layerRulePayload(r,l,mapping,sourceMap,plan.policySchema),layer:mapping.get(l.uid),position:'bottom'});if(created.uid)mapping.set(r.uid,created.uid);}
      }
    }
    const exceptionGroups=new Map();
    // Direct exceptions must exist before attaching groups at their source
    // positions; appending them after groups changes exception evaluation order.
    for(const layer of plan.layers)for(const set of layer.exceptionSets||[])for(const rule of set.items) {
      if(rule.type.endsWith('section')||set.groups.some(g=>g.sectionUid===rule.parentSectionUid))continue;
      await write('add-threat-exception',{...rulePayload(rule,mapping,sourceMap,plan.policySchema),layer:mapping.get(layer.uid),'rule-uid':mapping.get(set.ruleUid),position:'bottom'});
    }
    for(const layer of plan.layers)for(const set of layer.exceptionSets||[])for(const group of set.groups) {
      if(!exceptionGroups.has(group.uid))exceptionGroups.set(group.uid,{group,attachments:[]});
      exceptionGroups.get(group.uid).attachments.push({layer:mapping.get(layer.uid),uid:mapping.get(set.ruleUid),position:group.position||'bottom'});
    }
    for(const [uid,{group,attachments}] of exceptionGroups) {
      const created=await write('add-exception-group',{...exceptionGroupSettings(group,mapping,plan.objectSchema),name:group.targetName,'apply-on':'manually-select-threat-rules','applied-threat-rules':[]});
      if(!created.uid)throw new Error('Exception group creation returned no UID.');mapping.set(uid,created.uid);
      for(const layer of plan.layers)for(const set of layer.exceptionSets||[])for(const member of set.groups.filter(g=>g.uid===uid))mapping.set(member.sectionUid,created.uid);
    }
    const importedGroups=new Set();
    for(const layer of plan.layers)for(const set of layer.exceptionSets||[]) {
      for(const rule of set.items) {
        if(rule.type.endsWith('section'))continue;
        const group=set.groups.find(g=>g.sectionUid===rule.parentSectionUid);
        if(!group)continue;
        if(group&&importedGroups.has(group.uid))continue;
        const owner=group?{'exception-group-uid':mapping.get(group.uid)}:{layer:mapping.get(layer.uid),'rule-uid':mapping.get(set.ruleUid)};
        await write('add-threat-exception',{...rulePayload(rule,mapping,sourceMap,plan.policySchema),...owner,position:'bottom'});
      }
      for(const group of set.groups)importedGroups.add(group.uid);
    }
    // Attach populated groups independently for each rule. A shared group can
    // appear before another group in one rule and after it in another.
    for(const layer of plan.layers)for(const set of layer.exceptionSets||[]) {
      let position=1;
      for(const item of set.items) {
        if(item.type.endsWith('section')) {
          const group=set.groups.find(g=>g.sectionUid===item.uid);
          if(group)await write('set-exception-group',{uid:mapping.get(group.uid),'applied-threat-rules':{add:[{layer:mapping.get(layer.uid),uid:mapping.get(set.ruleUid),position}]}});
        }else position++;
      }
    }
    for(const [layer,defaults] of httpsDefaults) {
      for(const rule of defaults)await write(`delete-${rule.type}`,{layer,uid:rule.uid});
    }
    // Keep manual NAT on its original side of Check Point's automatic rules.
    // Create upper sections in reverse at top, then append each section's rules
    // by section UID. Unsectioned upper rules are prepended in reverse order.
    const upper=plan.nat.filter(r=>r.natPosition==='upper');
    const lower=plan.nat.filter(r=>r.natPosition!=='upper');
    const sectionUids=new Map();
    for(const r of upper.filter(r=>r.type==='nat-section').reverse()) {
      const created=await write('add-nat-section',{...translate(pick(r,['name','tags']),mapping),package:pkg.uid,name:r.name||'Section',position:'top'});
      if(!created.uid)throw new Error('NAT section creation returned no UID.');
      sectionUids.set(r.uid,created.uid);
    }
    let sectionUid;
    const unsectioned=[];
    for(const r of upper) {
      if(r.type==='nat-section'){sectionUid=sectionUids.get(r.uid);continue;}
      if(!sectionUid){unsectioned.push(r);continue;}
      await write('add-nat-rule',{...rulePayload(r,mapping,sourceMap),package:pkg.uid,position:{bottom:sectionUid}});
    }
    for(const r of unsectioned.reverse())await write('add-nat-rule',{...rulePayload(r,mapping,sourceMap),package:pkg.uid,position:'top'});
    for(const r of lower) {
      if(r.type==='nat-section') await write('add-nat-section',{...translate(pick(r,['name','tags']),mapping),package:pkg.uid,name:r.name||'Section',position:'bottom'});
      else await write('add-nat-rule',{...rulePayload(r,mapping,sourceMap),package:pkg.uid,position:'bottom'});
    }
    if(usedRuleBatch)await validateNativeSession(sessions,targetId,plan.objects.flatMap(row=>expectedCopyWarnings(row,plan)));
    // Verify count and order in the staging session before allowing Publish.
    for(const l of plan.layers) {
      const actual=await readRulebase(sessions,targetId,`show-${kindOf(l)}-rulebase`,{uid:mapping.get(l.uid)});
      verifyRulebase(l.items,actual.items,mapping,sourceMap,l.name,actual.dictionary,plan.policySchema);
    }
    for(const [uid,{group}] of exceptionGroups) {
      const actual=await sessions.command(targetId,'show-exception-group',{uid:mapping.get(uid),'details-level':'full'});
      if(actual.uid!==mapping.get(uid)||actual.name!==group.targetName||actual['apply-on']!=='manually-select-threat-rules')throw new Error('Staged exception group identity or application scope differs from preview.');
      const expected=exceptionGroupSettings(group,mapping,plan.objectSchema);
      for(const [key,value] of Object.entries(expected))if(hash(normalizedReferences(actual[key]))!==hash(value))throw new Error(`Staged exception group verification failed: ${group.name}, ${key}.`);
    }
    for(const layer of plan.layers)for(const set of layer.exceptionSets||[]) {
      const actual=await readRulebase(sessions,targetId,'show-threat-rule-exception-rulebase',{uid:mapping.get(layer.uid),'rule-uid':mapping.get(set.ruleUid)});
      const items=actual.items.filter(item=>!(item.type.endsWith('section')&&item.name==='Global Exceptions'));
      const expected=set.items.map(item=>{const group=set.groups.find(g=>g.sectionUid===item.uid);return group?{...item,name:group.targetName}:item;});
      verifyRulebase(expected,items,mapping,sourceMap,`${layer.name} exceptions`,actual.dictionary,plan.policySchema);
    }
    if(plan.nat.length) {
      const actual=await readRulebase(sessions,targetId,'show-nat-rulebase',{package:pkg.uid});
      verifyRulebase(plan.nat,natItemsForMigration(actual.items),mapping,sourceMap,'NAT',actual.dictionary,plan.policySchema);
    }
    for(const definition of createdDefinitions) {
      onProgress(`Verifying ${definition.type} · ${definition.expected.name}`);
      const response=await sessions.command(targetId,definition.type.endsWith('-layer')||definition.type==='threat-profile'?`show-${definition.type}`:'show-object',{uid:definition.uid,'details-level':'full'});
      if(definition.parentLayer&&(!mapping.has(definition.parentLayer)||uidOf((response.object||response)['parent-layer'])!==mapping.get(definition.parentLayer)))throw new Error(`Staged inline layer parent differs: ${definition.expected.name}.`);
      if(definition.inheritedSource)verifyInheritedGatewaySettings(definition.inheritedSource,response.object||response,mapping);
      verifyCreatedDefinition(definition.expected,response.object||response,definition);
    }
    return {state:'staged',packageUid:pkg.uid,logs,message:'Changes are staged and unpublished. Review in SmartConsole, then publish or discard.'};
  } catch(error) {
    let discarded=false;
    try {if(!error.batchPending){
      await discardChanges(sessions,targetId);
      discarded=true;
    }
    } catch { /* report uncertainty; do not imply rollback */ }
    const e=new Error(`${error.message} ${discarded?'Unpublished changes were discarded.':error.batchPending?'The creation task may still be writing. It must finish before the session can be safely discarded; use authenticated recovery.':'Automatic discard could not be verified; inspect the destination session in SmartConsole before retrying.'}`);
    if(error.batchPending){e.taskId=error.taskId;e.pendingCommand=error.pendingCommand;}
    e.logs=logs;e.state=discarded?'failed':'recovery-required';throw e;
  }
}

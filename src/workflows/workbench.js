import {endpointCredentials,managementContext,managementSessions} from './endpoints.js';
import {nativeEngine} from './engine.js';
import {normalizeMigrationOptions} from './options.js';
import {catalogsReady} from '../catalogs.js';
import {coerceUpstream} from './upstream-archive.js';
import {archiveSessions,exportArchive,importArchive,archiveDescriptor} from './archives.js';
import {exportUpstreamArchive} from './upstream-export.js';
import { discardChanges } from './discard.js';
import { randomUUID } from 'node:crypto';
import { OperationJournal } from './journal.js';
import { migrationApi } from './compatibility.js';
import { demoDomains, demoPlan } from './demo.js';
import { collection, scan, buildPlan, publicPlan, stagePlan, changedPlanSections } from './migration.js';

export class Workbench {
  constructor(sessions,{journal=new OperationJournal()}={}) {this.journal=journal;this.sessions=sessions;this.connections=new Map();this.locks=new Set();this.recoveryLocks=new Set();}
  get(id) {const c=this.connections.get(id);if(!c)throw new Error('Connection expired. Connect to the MDS again.');c.lastUsed=Date.now();return c;}
  async locked(id,action) {
    if(this.locks.has(id)) throw new Error('Another operation is in progress for this connection.');
    const c=this.get(id);
    c.activity={id:randomUUID(),state:'running',message:'Working…',startedAt:Date.now(),updatedAt:Date.now()};
    this.locks.add(id);
    try {const result=await action(c);c.activity={...c.activity,state:'completed',updatedAt:Date.now()};return result;}
    catch(e){c.activity={...c.activity,state:'failed',message:e.message,updatedAt:Date.now()};throw e;}
    finally{this.locks.delete(id);}
  }
  progress(c,update) {c.activity={...c.activity,...(typeof update==='string'?{message:update}:update),updatedAt:Date.now()};}
  describe(c) {return {demo:c.demo,mode:c.mode||'mds',host:c.host,sourceHost:c.sourceHost,domains:c.domains,sourceDomain:c.sourceDomain,targetDomain:c.targetDomain,packages:c.packages||[],archive:c.archive?.descriptor||null,recoveries:c.demo?[]:this.journal.unresolved(c.host),plan:c.plan?publicPlan(c.plan):null,job:c.job||null};}
  async connect(body) {
    if(body.demo) {
      const id=randomUUID();const c={demo:true,host:'Demo MDS · synthetic data',domains:demoDomains,lastUsed:Date.now()};
      this.connections.set(id,c);return {id,...this.describe(c)};
    }
    if(body.mode==='pair')return this.connectPair(body);
    const u=new URL(/^https:\/\//.test(body.host)?body.host:`https://${body.host}`);
    if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash) throw new Error('Use an MDS hostname or IP address over HTTPS, without a path or credentials.');
    const credentials={auxiliaryContexts:false,proxyUrl:body.proxyUrl,host:u.origin,port:body.port,username:body.username,password:body.password,authMode:body.authMode,apiKey:body.apiKey,ignoreTls:body.ignoreTls===true,mdsMode:true,largeEnvironmentMode:body.largeEnvironmentMode===true,readOnly:true};
    const root=await this.sessions.login(credentials);
    try {
      const domains=await collection(this.sessions,root.sessionId,'show-domains','objects',{},'mds');
      if(!domains.length)throw new Error('No MDS domains are available to this account.');
      const id=randomUUID();const c={host:root.baseUrl,credentials,rootId:root.sessionId,domains,lastUsed:Date.now(),demo:false};
      this.connections.set(id,c);return {id,...this.describe(c)};
    } catch(e) {await this.sessions.logout(root.sessionId).catch(()=>{});throw e;}
  }
  async connectPair(body) {
    const opened=[];
    const open=async(endpoint,role)=>{
      const credentials=endpointCredentials(endpoint);let rootId,domain;
      if(credentials.domain) {
        const root=await this.sessions.login({...credentials,domain:'',readOnly:true});rootId=root.sessionId;opened.push(rootId);
        const domains=await collection(this.sessions,rootId,'show-domains','objects',{},'mds');
        domain=domains.find(d=>d.uid===credentials.domain||d.name===credentials.domain);
        if(!domain)throw new Error(`${role} domain was not found in its management directory.`);
      }
      const session=await this.sessions.login({...credentials,mdsMode:false,domain:domain?.uid||'',readOnly:role==='Source',...(role==='Destination'?{sessionName:'Native migration destination'}:{})});opened.push(session.sessionId);
      if(!domain) {
        const state=await this.sessions.command(session.sessionId,'show-session',{});
        if(!state.domain?.uid||!state.domain?.name)throw new Error(`${role} management context could not be identified.`);
        domain=state.domain;
        if(['mds','global domain'].includes(domain['domain-type']))throw new Error(`${role} is not a standalone policy domain. Specify its MDS domain.`);
      }
      return {credentials,rootId,id:session.sessionId,host:session.baseUrl,domain:{...domain,endpoint:session.baseUrl}};
    };
    try {
      const source=await open(body.source,'Source'),target=await open(body.target,'Destination');
      if(source.host===target.host&&source.domain.uid===target.domain.uid)throw new Error('Source and destination must be different management domains.');
      const packages=await collection(this.sessions,source.id,'show-packages','packages');
      const id=randomUUID(),c={mode:'pair',demo:false,host:target.host,sourceHost:source.host,credentials:target.credentials,sourceCredentials:source.credentials,rootId:target.rootId,sourceRootId:source.rootId,sourceId:source.id,targetId:target.id,sourceDomain:source.domain,targetDomain:target.domain,domains:[source.domain,target.domain],packages,lastUsed:Date.now()};
      this.connections.set(id,c);return {id,...this.describe(c)};
    }catch(error){await Promise.allSettled(opened.map(id=>this.sessions.logout(id)));throw error;}
  }
  async select(id,body) {return this.locked(id,async c=>{
    if(c.mode==='pair')throw new Error('Reconnect to change management endpoints.');
    this.progress(c,'Opening source and destination sessions…');
    if(['staged','publishing','publish-unknown','recovery-required'].includes(c.job?.state)) throw new Error('Publish or discard the current staged changes before switching domains.');
    const sourceDomain=c.domains.find(d=>d.uid===body.source),targetDomain=c.domains.find(d=>d.uid===body.target);
    if(!sourceDomain||!targetDomain||sourceDomain.uid===targetDomain.uid) throw new Error('Select two different MDS domains.');
    for(const sid of [c.sourceId,c.targetId].filter(Boolean))await this.sessions.logout(sid).catch(()=>{});
    c.plan=null;c.job=null;c.operation=null;c.input=null;c.sourceId=null;c.targetId=null;c.sourceDomain=sourceDomain;c.targetDomain=targetDomain;
    if(c.demo)c.packages=[{uid:'pkg-corp',name:'Corporate_Access'}];
    else {
      try {
        c.sourceId=(await this.sessions.login({...c.credentials,mdsMode:false,domain:sourceDomain.uid,readOnly:true})).sessionId;
        c.targetId=(await this.sessions.login({...c.credentials,mdsMode:false,domain:targetDomain.uid,readOnly:false,sessionName:'Single Policy Move migration',sessionDescription:`Dedicated destination session for ${targetDomain.name}`})).sessionId;
        this.progress(c,'Reading source policy packages…');
        c.packages=await collection(this.sessions,c.sourceId,'show-packages','packages');
      }catch(e){for(const sid of [c.sourceId,c.targetId].filter(Boolean))await this.sessions.logout(sid).catch(()=>{});c.sourceId=null;c.targetId=null;throw e;}
    }
    return this.describe(c);
  });}
  async refreshExpiredReads(c,{source=true}={}) {
    if(c.demo||!this.sessions.keepAlive)return;
    const slots=[['rootId',c.credentials,''],['sourceRootId',c.sourceCredentials,'']];
    if(source)slots.push(['sourceId',c.sourceCredentials||c.credentials,c.mode==='pair'&&!c.sourceCredentials?.domain?'':c.sourceDomain?.uid]);
    const seen=new Set();
    for(const [slot,credentials,domain] of slots) {
      const id=c[slot];if(!id||seen.has(id))continue;seen.add(id);
      try{await this.sessions.keepAlive(id,'primary',c.operation?.apiVersion||c.plan?.apiVersion||c.input?.apiVersion||'');}catch(error){
        const expired=error.phase==='api-response'&&(/wrong.session|session.*expired/i.test(error.response?.code||'')||/wrong session id|session (?:has |may be )?expired/i.test(error.message));
        if(!expired)throw error;
        this.progress(c,'Refreshing an expired read-only management session…');
        const replacement=await this.sessions.login({...credentials,domain,mdsMode:slot!=='sourceId',auxiliaryContexts:false,readOnly:true});
        c[slot]=replacement.sessionId;await this.sessions.logout(id).catch(()=>{});
      }
    }
  }
  async preview(id,body) {return this.locked(id,async c=>{
    if(['staged','publishing','publish-unknown','recovery-required'].includes(c.job?.state))throw new Error('Resolve the staged migration before creating another preview.');
    if(!c.sourceDomain||!c.targetDomain)throw new Error('Choose source and destination domains first.');
    c.plan=null;c.job=null;c.operation=null;
    const input={sourceDomain:body.archiveToken?{...c.archive?.snapshot.sourceDomain,archive:true}:c.sourceDomain,targetDomain:c.targetDomain,packageUid:body.archiveToken?c.archive?.snapshot.package.uid:body.packageUid,archiveToken:body.archiveToken,targetName:String(body.targetName||'').trim(),scenario:body.scenario,options:normalizeMigrationOptions(body.options)};
    if(body.apiVersion!==undefined&&body.apiVersion!=='')input.apiVersion=String(body.apiVersion).trim();
    if(!input.targetName)throw new Error('A destination policy name is required.');
    if(body.archiveToken&&body.archiveToken!==c.archive?.descriptor.token)throw new Error('Archive expired. Upload it again.');
    if(!body.archiveToken&&!c.packages.some(p=>p.uid===input.packageUid))throw new Error('Select an available policy package.');
    if(c.input && ['packageUid','targetName','scenario','archiveToken','apiVersion'].every(k=>c.input[k]===input[k])&&JSON.stringify(c.input.options||{})===JSON.stringify(input.options)) input.renames=c.input.renames||{};
    c.input=input;
    await this.refreshExpiredReads(c,{source:!body.archiveToken});
    this.progress(c,'Checking policy and domain compatibility…');
    const engine=c.demo?null:await nativeEngine();
    c.plan=c.demo?demoPlan(input):await engine.scan({sessions:c.input?.archiveToken?archiveSessions(this.sessions,c.sourceId,c.archive.snapshot,c.targetId):this.sessions,...managementContext(c),sourceId:c.sourceId,targetId:c.targetId,...input,engineRevision:engine.revision,onProgress:update=>this.progress(c,update)});
    return {plan:publicPlan(c.plan)};
  });}
  async uploadArchive(id,bytes) {return this.locked(id,async c=>{
    if(['staging','staged','publishing','publish-unknown','recovery-required'].includes(c.job?.state))throw new Error('Resolve the current migration before replacing its archive.');
    const snapshot=importArchive(bytes);if(snapshot.upstream)coerceUpstream(snapshot,await (await catalogsReady).ensure(snapshot.apiVersion));c.archive={snapshot,bytes,descriptor:archiveDescriptor(bytes,snapshot)};
    return {archive:c.archive.descriptor};
  });}
  async manualIps(id,body) {return this.locked(id,async c=>{
    if(c.demo)throw new Error('Manual IPS handling requires a real destination preview.');
    const plan=c.plan;
    if(!plan||plan.id!==body.planId||plan.state!=='preview'||c.job)throw new Error('Manual IPS handling requires the current unstaged preview.');
    const choices=[...(c.input.options.manualIps||[])].filter(x=>x.uid!==body.objectUid);
    if(body.reset!==true) {
      const item=plan.checks.find(check=>!check.ok&&check.manualIps?.uid===body.objectUid)?.manualIps;
      if(!item||body.acknowledged!==true)throw new Error('Review and acknowledge the affected IPS exceptions first.');
      choices.push({uid:item.uid,fingerprint:item.fingerprint});
    }
    const input={...c.input,options:{...c.input.options,manualIps:choices}};
    const engine=await nativeEngine();
    const rebuilt=await engine.scan({sessions:input.archiveToken?archiveSessions(this.sessions,c.sourceId,c.archive.snapshot,c.targetId):this.sessions,...managementContext(c),sourceId:c.sourceId,targetId:c.targetId,...input,engineRevision:engine.revision,onProgress:update=>this.progress(c,update)});
    c.input=input;c.plan=rebuilt;
    return {plan:publicPlan(c.plan)};
  });}
  async updateIps(id,body) {return this.locked(id,async c=>{
    if(c.demo)throw new Error('IPS updates require a real destination connection.');
    if(!c.targetId||!c.plan||c.plan.id!==body.planId||c.plan.state!=='preview')throw new Error('IPS update requires the current destination preview.');
    if(c.job&&!['failed','discarded','published'].includes(c.job.state))throw new Error('Resolve the active migration before updating IPS.');
    const version=c.plan.apiVersion;
    if(c.ipsUpdate&&(c.ipsUpdate.targetId!==c.targetId||c.ipsUpdate.version!==version))throw new Error('An IPS update is unresolved in another destination session or API version. Check that destination before starting another update.');
    const api=await migrationApi(this.sessions,[{id:c.targetId,label:'Destination domain'}],{version});
    api.validate('run-ips-update',{});
    c.plan.expiresAt=new Date(0).toISOString();
    this.progress(c,'Requesting the latest IPS content on the destination…');
    if(!c.ipsUpdate) {
      c.ipsUpdate={targetId:c.targetId,version};
      try {
        const response=await api.command(c.targetId,'run-ips-update',{});
        c.ipsUpdate.taskId=response['task-id'];
      }catch(error){if(error.phase==='api-response')delete c.ipsUpdate;throw error;}
    }
    if(!c.ipsUpdate.taskId)throw new Error('IPS update outcome is unconfirmed because no task ID was received. Check the destination IPS update status in SmartConsole before retrying; another update has not been submitted.');
    this.progress(c,'Waiting for the destination IPS update task…');
    try {await this.sessions.waitForTask(c.targetId,c.ipsUpdate.taskId,'primary',version);}
    catch(error){if(error.taskOutcome==='failed')delete c.ipsUpdate;throw error;}
    delete c.ipsUpdate;
    const message='Destination IPS update completed. Rescan to check the required protections; an update may not restore every missing protection.';
    this.progress(c,message);
    return {plan:publicPlan(c.plan),message};
  });}
  async updateRepository(id,body) {return this.locked(id,async c=>{
    if(c.demo)throw new Error('Repository updates require a real destination connection.');
    if(!c.targetId||!c.plan||c.plan.id!==body.planId||c.plan.state!=='preview')throw new Error('Repository update requires the current destination preview.');
    if(c.job&&!['failed','discarded','published'].includes(c.job.state))throw new Error('Resolve the active migration before updating the repository.');
    const version=c.plan.apiVersion;
    if(c.repositoryUpdate&&(c.repositoryUpdate.targetId!==c.targetId||c.repositoryUpdate.version!==version))throw new Error('A repository update is unresolved in another destination session or API version. Check that destination before starting another update.');
    const api=await migrationApi(this.sessions,[{id:c.targetId,label:'Destination domain'}],{version});
    api.validate('update-updatable-objects-repository-content',{});
    // Repository updates change the inventory independently of policy sessions.
    // Keep the preview available for review, but require a new scan before staging.
    c.plan.expiresAt=new Date(0).toISOString();
    this.progress(c,'Updating the destination Updatable Objects repository…');
    if(!c.repositoryUpdate) {
      c.repositoryUpdate={submitted:true,targetId:c.targetId,version};
      try {
        const response=await api.command(c.targetId,'update-updatable-objects-repository-content',{});
        c.repositoryUpdate.taskId=response['task-id'];
      }catch(error){if(error.phase==='api-response')delete c.repositoryUpdate;throw error;}
    }
    if(c.repositoryUpdate.taskId) {
      this.progress(c,'Waiting for the destination repository update task…');
      try {await this.sessions.waitForTask(c.targetId,c.repositoryUpdate.taskId,'primary',version);}
      catch(error){if(error.taskOutcome==='failed')delete c.repositoryUpdate;throw error;}
    }
    this.progress(c,'Checking that the destination repository is readable…');
    const contents=await api.command(c.targetId,'show-updatable-objects-repository-content',{limit:1,'details-level':'full'});
    if(!Array.isArray(contents.objects))throw new Error('Repository update could not be verified. Check the destination repository status before retrying.');
    delete c.repositoryUpdate;
    this.progress(c,'Destination repository is available. Rescan to verify the required country objects.');
    return {plan:publicPlan(c.plan),message:'Destination repository is available. Rescan to verify the required country objects.'};
  });}
  async exportPolicy(id,body) {return this.locked(id,async c=>{
    if(body.format!==undefined&&!['native','upstream'].includes(body.format))throw new Error('Choose a supported archive format.');
    if(['staging','staged','publishing','publish-unknown','recovery-required'].includes(c.job?.state))throw new Error('Resolve the current migration before exporting another archive.');
    if(!c.sourceId||!c.targetId)throw new Error('Load source and destination domains first.');
    const engine=await nativeEngine();
    await this.refreshExpiredReads(c);
    // Archives retain complete source definitions and gateway dependencies.
    // Rebuild is a destination import decision, not destructive export filtering.
    const options=normalizeMigrationOptions({...body.options,objectSuffix:'',importTag:'',rebuildGateways:false});
    const plan=await engine.scan({sessions:this.sessions,...managementContext(c),sourceId:c.sourceId,targetId:c.targetId,sourceDomain:c.sourceDomain,targetDomain:c.targetDomain,packageUid:body.packageUid,apiVersion:body.apiVersion||undefined,options,targetName:'Archive_'+randomUUID().slice(0,8),onProgress:update=>this.progress(c,update)});
    if(plan.checks.some(check=>!check.ok&&check.name.startsWith('Global policy')))throw new Error('Global policy must be unassigned before exporting.');
    const bytes=body.format==='upstream'?exportUpstreamArchive(plan):exportArchive(plan),snapshot=importArchive(bytes);
    if(snapshot.upstream)coerceUpstream(snapshot,await (await catalogsReady).ensure(snapshot.apiVersion));
    c.archive={snapshot,bytes,descriptor:archiveDescriptor(bytes,snapshot)};
    return {archive:c.archive.descriptor};
  });}
  downloadArchive(id,token) {const c=this.get(id);if(token!==c.archive?.descriptor.token)throw new Error('Archive expired. Export or upload it again.');return c.archive.bytes;}
  async rename(id,body) {return this.locked(id,async c=>{
    const plan=c.plan;
    if(!plan || plan.id!==body.planId || plan.state!=='preview' || c.job) throw new Error('Rename requires the current, unstaged preview. Rescan first.');
    if(Date.parse(plan.expiresAt)<Date.now()) throw new Error('Preview expired. Rescan before resolving conflicts.');
    const row=plan.objects.find(o=>o.uid===body.objectUid);
    if(!row?.renameAllowed&&!row?.profileResolutionAllowed&&!row?.gatewayResolutionAllowed) throw new Error('This conflict cannot be resolved by renaming.');
    const renames={...plan.renames};
    if(body.reset===true) delete renames[row.uid];
    else if(row.gatewayResolutionAllowed) {
      if(!['reuse-gateway','create-gateway'].includes(body.gatewayAction))throw new Error('Choose a gateway resolution.');
      renames[row.uid]=body.gatewayAction==='reuse-gateway'?{action:body.gatewayAction,targetUid:body.targetUid}:{action:body.gatewayAction,name:body.newName,address:body.address};
    }else if(row.profileResolutionAllowed) {
      if(!['reuse-profile','copy-profile'].includes(body.profileAction))throw new Error('Choose a profile resolution.');
      renames[row.uid]=body.profileAction==='reuse-profile'?{action:body.profileAction,targetUid:row.target?.uid||row.profileTargetUid}:{action:body.profileAction,name:body.newName};
    }else renames[row.uid]=body.newName;
    // Rebuild from the immutable scanned definitions, not client-supplied objects.
    const {id:oldId,createdAt,expiresAt,digest,counts,blockers,ready,state,ruleCount,...snapshot}=plan;
    const engine=c.demo?null:await nativeEngine();
    if(engine&&plan.engineRevision&&engine.revision!==plan.engineRevision)throw new Error('The native engine was updated. Generate a fresh preview before renaming.');
    let rebuilt=(engine?.buildPlan||buildPlan)({...snapshot,renames});
    if(engine) {
      const api=await migrationApi(this.sessions,[{id:c.targetId,label:'Destination domain'}],{version:plan.apiVersion});
      rebuilt=engine.buildPlan({...rebuilt,checks:[...rebuilt.checks.filter(c=>!c.name.startsWith('API schema')),...engine.validatePlanCommands(api,rebuilt)]});
    }
    rebuilt.expiresAt=expiresAt;
    c.plan=rebuilt;c.input.renames=renames;
    return {plan:publicPlan(c.plan)};
  });}
  async stage(id,body) {
    const c=this.get(id);
    if(this.locks.has(id))throw new Error('An operation is already running.');
    const plan=c.plan;
    if(!plan||plan.id!==body.planId||body.confirmName!==plan.targetName)throw new Error('Confirm the exact destination package name from the current preview.');
    if(!plan.ready||plan.state!=='preview')throw new Error('This plan is blocked or already consumed. Generate a new preview.');
    if(Date.parse(plan.expiresAt)<Date.now())throw new Error('Preview expired. Run a new scan.');
    const activeStates=['staging','staged','publishing','publish-unknown','recovery-required'];
    for(const [otherId,other] of this.connections) {
      if(otherId!==id && !c.demo && !other.demo && other.host===c.host && other.targetDomain?.uid===c.targetDomain?.uid && activeStates.includes(other.job?.state)) {
        throw new Error('Another migration owns this destination domain. Resolve its staged changes before proceeding.');
      }
    }
    if(!c.demo && this.journal.unresolved(c.host).some(r=>r.targetDomain.uid===c.targetDomain.uid))throw new Error('An unfinished migration owns this destination. Recover it before staging.');
    plan.state='staging';
    c.job={state:'staging',message:'Rechecking global assignments, source policy and destination inventory…',logs:[]};
    this.locks.add(id);
    void (async()=>{
      try {
        if(c.demo) {
          c.job={state:'staged',message:'Demo only: simulated staging completed. No MDS was contacted.',logs:[{command:'demo-stage',name:plan.targetName,time:new Date().toISOString()}]};
        }else {
          await this.refreshExpiredReads(c,{source:!c.input?.archiveToken});
          const engine=await nativeEngine();
          if(plan.engineRevision&&engine.revision!==plan.engineRevision)throw new Error('The native engine was updated after preview. Generate a fresh preview; no changes were made.');
          const fresh=await engine.scan({sessions:c.input?.archiveToken?archiveSessions(this.sessions,c.sourceId,c.archive.snapshot,c.targetId):this.sessions,...managementContext(c),sourceId:c.sourceId,targetId:c.targetId,...c.input,engineRevision:plan.engineRevision,apiVersion:plan.apiVersion,onProgress:update=>{c.job.message=update.message;}});
          if(!fresh.ready||fresh.digest!==plan.digest) {
            const changed=changedPlanSections(plan,fresh);
            throw new Error(`The source or destination changed after preview${changed.length?`: ${changed.join(', ')}`:''}. Generate a fresh preview; no changes were made.`);
          }
          const api=await migrationApi(this.sessions,[{id:c.targetId,context:'primary',label:'Destination domain'}],{version:plan.apiVersion||fresh.apiVersion});
          plan.apiVersion=api.version;
          const session=await api.command(c.targetId,'show-session',{});
          if(!session.uid || session.changes!==0)throw new Error('Cannot identify a clean destination session. No migration writes were made.');
          c.operation=this.journal.begin({host:c.host,targetDomain:c.targetDomain,targetName:plan.targetName,sessionUid:session.uid,apiVersion:api.version});
          c.job=await engine.stagePlan({sessions:api,targetId:c.targetId,plan,onProgress:update=>{Object.assign(c.job,typeof update==='string'?{message:update}:update);this.persist(c);}});
          this.persist(c);
        }
        plan.state=c.job.state;
      }catch(e){c.job={state:e.state||'failed',message:e.message,logs:e.logs||[],taskId:e.taskId,pendingCommand:e.pendingCommand};try{this.persist(c);}catch(journalError){c.job={...c.job,state:'recovery-required',message:journalError.message};}plan.state=c.job.state;}
      finally{this.locks.delete(id);}
    })();
    return {job:c.job};
  }
  persist(c) {
    if(!c.operation)return;
    try{c.operation=this.journal.update(c.operation,{state:c.job.state,taskId:c.job.taskId,packageUid:c.job.packageUid,pendingCommand:c.job.pendingCommand});}
    catch(e){const error=new Error(`Recovery record could not be saved: ${e.message}. Migration outcome requires inspection.`);error.state='recovery-required';throw error;}
  }
  async finish(id,body) {
    return this.locked(id,async c=>{
      if(c.job?.engine==='python')throw new Error('Use authenticated recovery for Python imports; batches may already be published.');
      if(body.action==='publish'&&c.job?.state!=='staged')throw new Error('Only a successfully staged migration can be published.');
      if(body.action==='discard'&&!['staged','recovery-required'].includes(c.job?.state))throw new Error('There are no staged changes to discard.');
      if(!['publish','discard'].includes(body.action)||body.confirmName!==c.plan?.targetName)throw new Error('Confirm the destination policy name.');
      const api=c.demo?this.sessions:await migrationApi(this.sessions,[...managementSessions(c),{id:c.targetId,context:'primary',label:'Destination domain'}],{version:c.operation?.apiVersion||c.plan?.apiVersion});
      if(!c.demo)c.plan.apiVersion=api.version;
      if(c.demo)c.job={...c.job,state:body.action==='publish'?'published':'discarded',message:`Demo only: ${body.action} simulated. No changes to an MDS.`};
      else if(body.action==='discard') {
        const record=c.operation||c.job;
        if(record.engine!=='python'&&/^(add|set)-/.test(record.pendingCommand||'')) {
          if(!record.taskId)throw new Error('An asynchronous creation was submitted without a recorded task ID. Inspect the original session in SmartConsole before discarding; its writes may still be running.');
          this.progress(c,'Waiting for the native creation task before discarding…');
          try{await this.sessions.waitForTask(c.targetId,record.taskId,'primary',record.apiVersion);}
          catch(error){if(error.taskOutcome!=='failed'&&!error.taskTerminal)throw error;}
        }
        try{await discardChanges(api,c.targetId);c.job={...c.job,state:'discarded',message:'All unpublished changes in this migration session were discarded.'};}
        catch(e){c.job={...c.job,state:'recovery-required',message:`Discard failed: ${e.message}. Inspect the destination session in SmartConsole.`};}
      }else {
        // Global assignments can change between staging and publish. Recheck both domains.
        const {globalCheck}=await import('./migration.js');
        for(const [domain,rootId] of [[c.sourceDomain,c.mode==='pair'?c.sourceRootId:c.rootId],[c.targetDomain,c.rootId]]) {
          const assignments=rootId?await collection(api,rootId,'show-global-assignments','objects',{},'mds'):[];
          const check=globalCheck(assignments,domain,[]);if(!check.ok)throw new Error(check.detail);
        }
        c.job={...c.job,state:'publishing',message:'Waiting for Check Point publish task…'};
        this.persist(c);
        try {
          const result=await api.command(c.targetId,'publish',{});
          const taskId=result['task-id']||result.tasks?.[0]?.['task-id'];
          if(!taskId)throw new Error('Publish did not return a task ID. Its outcome is unknown.');
          c.job.taskId=taskId;c.job.raw=result;this.persist(c);
          const final=await this.sessions.waitForTask(c.targetId,taskId,'primary',api.version);
          c.job={...c.job,state:'published',message:'Policy published in the destination. Source retained. Policy was not installed on gateways.',raw:final};
        }catch(e){await this.recordPublishFailure(c,e);}
      }
      this.persist(c);c.plan.state=c.job.state;return {job:c.job};
    });
  }
  async recordPublishFailure(c,error) {
    c.job={...c.job,state:'publish-unknown',message:`Publish outcome requires review: ${error.message}. Check task/session state in SmartConsole; do not retry blindly.`};
    if(error.taskOutcome!=='failed') return;
    // A terminal failed task alone does not prove whether unpublished changes remain.
    // Inspect this dedicated session before enabling recovery or a fresh migration.
    try {
      const session=await this.sessions.command(c.targetId,'show-session',{},'primary',c.operation?.apiVersion||c.plan?.apiVersion||'');
      if(typeof session.changes!=='number'||!Number.isFinite(session.changes)||session.changes<0) return;
      if(session.changes>0) {
        try {
          await discardChanges(this.sessions,c.targetId,c.operation?.apiVersion||c.plan?.apiVersion||'');
          c.job={...c.job,raw:error.taskResult,state:'failed',message:'Publish failed. All unpublished changes in the dedicated migration session were discarded. Generate a fresh preview to retry.'};
        } catch(discardError) {
          c.job={...c.job,raw:error.taskResult,state:'recovery-required',message:`Publish failed and discard could not be verified: ${discardError.message}`};
        }
      } else c.job={...c.job,raw:error.taskResult,state:'failed',message:'Publish failed. The dedicated session has no unpublished changes. Generate a fresh preview to retry.'};
    }catch{/* Failed session inspection leaves the outcome unresolved. */}
  }
  async reconcile(id) {return this.locked(id,async c=>{
    if(c.job?.state!=='publish-unknown'||!c.job.taskId)throw new Error('No pending publish task ID is available. Inspect the session in SmartConsole.');
    const api=await migrationApi(this.sessions,[{id:c.targetId,context:'primary',label:'Destination domain'}],{version:c.operation?.apiVersion||c.plan?.apiVersion});
    if(c.job.engine==='python') {
      try {
        await this.sessions.waitForTask(c.targetId,c.job.taskId,'primary',api.version);
      }catch(error){if(error.taskOutcome!=='failed')throw error;}
      await discardChanges(this.sessions,c.targetId,api.version);
      c.job={...c.job,state:'failed',message:'Interrupted Python import resolved. Unpublished changes were discarded. Earlier published batches remain; inspect the destination package before retrying.'};
      this.persist(c);return {job:c.job};
    }
    c.plan.apiVersion=api.version;
    try {
      const result=await this.sessions.waitForTask(c.targetId,c.job.taskId,'primary',api.version);
      c.job={...c.job,state:'published',raw:result,message:'Publish task succeeded. Source retained. Policy was not installed on gateways.'};
      c.plan.state='published';
    }catch(e){await this.recordPublishFailure(c,e);c.plan.state=c.job.state;}
    this.persist(c);return {job:c.job};
  });}
  async recover(id,body) {return this.locked(id,async c=>{
    if(c.demo)throw new Error('Recovery requires an authenticated MDS connection.');
    const record=this.journal.unresolved(c.host).find(r=>r.id===body.operationId);
    if(!record || !c.domains.some(d=>d.uid===record.targetDomain.uid))throw new Error('Recovery record is unavailable in this MDS connection.');
    if(!['inspect','discard'].includes(body.action))throw new Error('Choose inspect or discard for recovery.');
    if(body.action==='discard' && body.confirmName!==record.targetName)throw new Error('Confirm the exact recorded destination policy name.');
    for(const [ownerId,owner] of this.connections) {
      if(owner.operation?.id===record.id && (this.locks.has(ownerId)&&ownerId!==id || ['staging','publishing'].includes(owner.job?.state)))throw new Error('This migration is still running. Wait for its operation to finish.');
    }
    if(this.recoveryLocks.has(record.id))throw new Error('Another recovery is in progress for this migration.');
    this.recoveryLocks.add(record.id);
    let sessionId;
    try {
      sessionId=(await this.sessions.login({...c.credentials,mdsMode:false,domain:c.mode==='pair'?(c.credentials.domain?record.targetDomain.uid:''):record.targetDomain.uid,readOnly:body.action!=='discard'})).sessionId;
      const api=await migrationApi(this.sessions,[{id:sessionId,context:'primary',label:'Recovery domain'}],{version:record.apiVersion});
      let observed=await this.sessions.inspectSession(sessionId,record.sessionUid,'primary',record.apiVersion);
      let outcome;
      if(['published','discarded'].includes(observed.state) && observed.changes===0) outcome=observed.state;
      else if(body.action==='discard') {
        if(record.engine!=='python'&&/^(add|set)-/.test(record.pendingCommand||'')) {
          if(!record.taskId)throw new Error('An asynchronous creation was submitted without a recorded task ID. Inspect the original session in SmartConsole before discarding; its writes may still be running.');
          try{await this.sessions.waitForTask(sessionId,record.taskId,'primary',record.apiVersion);}
          catch(error){if(error.taskOutcome!=='failed'&&!error.taskTerminal)throw error;}
        }
        // A crash before saving the publish task ID cannot be made safe by guessing.
        if(['publishing','publish-unknown'].includes(record.state)) {
          if(!record.taskId)throw new Error('Publish outcome is unknown and no task ID was recorded. Inspect the original session in SmartConsole; only a verified published/discarded state releases recovery.');
          try{await this.sessions.waitForTask(sessionId,record.taskId,'primary',record.apiVersion);if(record.engine!=='python')throw new Error('Publish task succeeded. Inspect the original session again before resolving recovery.');}
          catch(e){if(e.taskOutcome!=='failed')throw e;}
        }
        observed=await this.sessions.resumeSession(sessionId,record.sessionUid,'primary',record.apiVersion);
        if(observed.changes===null)throw new Error('The resumed session change count is unknown. Discard is blocked.');
        await discardChanges(api,sessionId);
        observed={uid:record.sessionUid,state:'discarded',changes:0};
        outcome='discarded';
      }
      if(outcome) {
        const resolved=this.journal.update(record,{state:outcome});
        for(const owner of this.connections.values())if(owner.operation?.id===record.id){owner.operation=resolved;owner.job={...owner.job,state:record.engine==='python'?'failed':outcome,message:`Original session verified ${outcome} during authenticated recovery.${record.engine==='python'?' Earlier published Python batches remain; inspect the policy before retrying.':''}`};if(owner.plan)owner.plan.state=outcome;}
      }
      return {recoveries:this.journal.unresolved(c.host),inspection:observed,message:outcome?`Original migration session verified ${outcome}. Destination reservation released.${record.engine==='python'?' Earlier Python import batches may already be published; session recovery does not undo them.':''}`:'Session remains unresolved. No changes made. To discard, the original API session must be disconnected and owned by this administrator.'};
    } finally {try{if(sessionId)await this.sessions.logout(sessionId).catch(()=>{});}finally{this.recoveryLocks.delete(record.id);}}
  });}
  async logout(id) {return this.locked(id,async c=>{
    if(['staging','staged','publishing','publish-unknown','recovery-required'].includes(c.job?.state))throw new Error('Resolve staged changes before disconnecting.');
    const result=await Promise.allSettled([...new Set([c.sourceId,c.targetId,c.rootId,c.sourceRootId].filter(Boolean))].map(sid=>this.sessions.logout(sid)));
    c.archive=null;
    this.connections.delete(id);return {ok:true,logoutFailures:result.filter(x=>x.status==='rejected'||x.value.failures).length};
  });}
  async expire() {
    for(const [id,c] of this.connections) {
      if(this.locks.has(id))continue;
      if(!c.demo && ['staged','publish-unknown','recovery-required'].includes(c.job?.state)) {
        this.locks.add(id);
        try {
          await this.refreshExpiredReads(c);
          for(const sid of [...new Set([c.rootId,c.sourceRootId,c.sourceId,c.targetId].filter(Boolean))])await this.sessions.keepAlive(sid,'primary',c.operation?.apiVersion||c.plan?.apiVersion||'');
        }catch(e){
          if(c.job.state==='staged')c.job={...c.job,state:'recovery-required',message:`Session keepalive failed: ${e.message}. Use authenticated recovery to inspect the original session.`};
          try{this.persist(c);}catch{/* Existing durable reservation remains unresolved. */}
          if(c.plan)c.plan.state=c.job.state;
        }finally{this.locks.delete(id);}
        continue;
      }
      if(Date.now()-c.lastUsed<60*60_000) {
        if(!c.demo&&this.sessions.keepAlive) {
          this.locks.add(id);
          try{await this.refreshExpiredReads(c);if(c.targetId)await this.sessions.keepAlive(c.targetId,'primary',c.operation?.apiVersion||c.plan?.apiVersion||c.input?.apiVersion||'');}
          catch{/* Surface endpoint failures on the next requested operation. */}
          finally{this.locks.delete(id);}
        }
        continue;
      }
      // Do not silently discard a staged migration on idle timeout.
      if(['staged','publishing','publish-unknown','recovery-required'].includes(c.job?.state))continue;
      await this.logout(id).catch(()=>{});
    }
  }
}

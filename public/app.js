const $=s=>document.querySelector(s);
const $$=s=>[...document.querySelectorAll(s)];
let connection=null, plan=null, job=null, busy=false, currentView='setup', pollTimer=null;
const el=(tag,text,className)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(className)n.className=className;return n;};
const badge=(text,state)=>el('span',text,`badge ${state}`);
const labels={create:'Create',reuse:'Reuse',conflict:'Conflict',blocked:'Unsupported'};
const activityLabels={'archive/export':['Exporting policy archive','Policy archive exported'],connect:['Connecting to MDS','Management connected'],select:['Opening domain sessions','Domains and policy list loaded'],preview:['Scanning policy','Scan complete'],rename:['Updating preview','Preview updated'],stage:['Staging migration','Staging request completed'],finish:['Updating destination session','Destination session updated'],reconcile:['Checking publish result','Publish status checked'],recover:['Checking recovery','Recovery check complete'],logout:['Disconnecting','Disconnected'],'catalog/coverage':['Checking API coverage','API coverage loaded'],'catalog/update':['Updating API catalogs','API catalogs updated']};
let activity=null,activityPoll=null,activitySequence=0;
let policyArchive=null;
const jobTitles={exported:'Policy archive exported',staging:'Staging migration',staged:'Changes staged · not published',publishing:'Publishing changes',published:'Migration published',discarded:'Changes discarded',failed:'Migration stopped','publish-unknown':'Publish outcome unconfirmed','recovery-required':'Recovery required'};
function beginActivity(path) {
  if(!activityLabels[path])return null;
  $('#workspaceStatus').hidden=true;
  clearTimeout(activityPoll);
  const token=++activitySequence;
  activity={token,path,title:activityLabels[path][0],message:path==='connect'?'Authenticating and discovering MDS domains…':'Waiting for the server…',startedAt:Date.now(),lastResponse:null,running:true,error:false,requestPending:true};
  renderActivity();watchActivity(token);return token;
}
function jobActivity(value) {
  if(!activity||!value)return;
  activity.title=jobTitles[value.state]||value.state;activity.message=value.message;
  activity.running=['staging','publishing'].includes(value.state);
  activity.error=['failed','publish-unknown','recovery-required'].includes(value.state);
  if(!activity.running)activity.finishedAt=Date.now();
  renderActivity();
}
function endActivity(token,data,error) {
  if(!token||activity?.token!==token)return;
  activity.lastResponse=Date.now();activity.requestPending=false;
  if(!error&&data?.job){jobActivity(data.job);if(activity.running)return;}
  else {
    activity.running=false;activity.error=!!error;activity.finishedAt=Date.now();
    activity.title=error?'Operation needs attention':activityLabels[activity.path][1];
    activity.message=error?error.message:data?.plan?`Rules reviewed: ${data.plan.ruleCount}. Blockers: ${data.plan.blockers}. ${data.plan.ready?'Review the preview before staging.':'Resolve the blockers before staging.'}`:'Ready for the next step.';
    activity.attention=!error&&data?.plan?.blockers>0;
    if(activity.attention)activity.title='Scan complete · review required';
  }
  clearTimeout(activityPoll);renderActivity();
}
function renderActivity() {
  const panel=$('#activityPanel');panel.hidden=!activity;if(!activity)return;
  panel.classList.toggle('is-error',activity.error);panel.classList.toggle('is-complete',!activity.running&&!activity.error&&!activity.attention);panel.classList.toggle('is-attention',!!activity.attention);
  $('#activityTitle').textContent=activity.title;
  if($('#activityMessage').textContent!==activity.message)$('#activityMessage').textContent=activity.message;
  const seconds=Math.max(0,Math.floor(((activity.finishedAt||Date.now())-activity.startedAt)/1000));
  $('#activityElapsed').textContent=`${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,'0')} ${activity.running?'elapsed':'total'}`;
  $('#activityProgress').hidden=!activity.running;
  const age=activity.lastResponse===null?null:Math.floor((Date.now()-activity.lastResponse)/1000);
  $('#activityHeartbeat').textContent=activity.running?(activity.pollError||age>=15?'Status connection interrupted or delayed. Waiting for a response; do not repeat the operation.':age===null?'Waiting for the first server response…':`Server responded ${age}s ago. ${seconds>=20?'Large inventories and throttled requests can take several minutes.':''}`):activity.error?'Review the message before trying again.':'Operation finished.';
}
function watchActivity(token) {
  clearTimeout(activityPoll);
  activityPoll=setTimeout(async()=>{
    if(activity?.token!==token||!activity.running)return;
    if(connection) {
      try {
        const data=await api('job');
        if(activity?.token!==token||!activity.running)return;
        activity.lastResponse=Date.now();activity.pollError=false;
        if(['stage','finish','reconcile'].includes(activity.path)&&data.job&&(!activity.requestPending||['staging','publishing'].includes(data.job.state)))jobActivity(data.job);
        else if(data.activity?.state==='running'&&data.activity.startedAt>=activity.startedAt-1000&&data.activity.message!=='Working…')activity.message=data.activity.message;
      }catch{if(activity?.token===token)activity.pollError=true;}
    }
    if(activity?.token!==token)return;
    renderActivity();if(activity.running)watchActivity(token);
  },1500);
}
setInterval(()=>{if(activity?.running)renderActivity();},1000);
async function api(path,body={}) {
  const activityToken=beginActivity(path);
  try {
  const response=await fetch(`/api/${path}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  const data=await response.json();
  if(response.status===404 && data.error==='Unknown API route.')throw new Error('The running backend is older than this page and does not support this feature. Resolve any active migration, then restart the app server and refresh this page.');
  if(!response.ok)throw new Error(data.error||'Request failed.');endActivity(activityToken,data);return data;
  }catch(error){endActivity(activityToken,null,error);throw error;}
}
function status(text,error=false) {const n=$('#workspaceStatus');n.hidden=!text;n.textContent=text;n.classList.toggle('error',error);}
async function run(message,fn) {
  if(busy)return;busy=true;status(message);updateControls();
  try{await fn();status('');}catch(e){status(e.message,true);}finally{busy=false;updateControls();}
}
function updateControls() {
  $$('[data-recovery], #refreshRecovery, #catalogLoad, #catalogUpdate, #catalogVersion').forEach(button=>button.disabled=busy);
  const unresolved=['staging','staged','publishing','publish-unknown','recovery-required'].includes(job?.state);
  for(const id of ['sourceDomain','targetDomain','policySelect','targetName','demoScenario'])$('#'+id).disabled=busy||unresolved;
  for(const id of ['loadPolicies','previewButton','rescanButton','logoutButton'])$("#"+id).disabled=busy||unresolved;
  $('#renameAllConflicts').disabled=busy||plan?.state!=='preview'||!!job||!plan?.objects.some(o=>o.status==='conflict'&&o.renameAllowed&&(!o.importName||(plan.options?.objectSuffix&&o.importName===o.name+plan.options.objectSuffix&&!plan.renames?.[o.uid])));
  $('#stageButton').disabled=busy||!plan?.ready||plan.state!=='preview'||$('#confirmName').value!==plan.targetName||!$('#confirmReviewed').checked;
  $('#publishButton').disabled=busy||job?.state!=='staged';
  $('#reconcileButton').disabled=busy;
  $('#discardButton').disabled=busy||!['staged','recovery-required'].includes(job?.state);
  for(const id of ['archiveExport','archiveFile','archiveDownload','archivePreview'])$('#'+id).disabled=busy||unresolved||(id!=='archiveFile'&&id!=='archiveExport'&&!policyArchive);
}
function show(view) {
  currentView=view;
  $$('.view').forEach(n=>n.hidden=n.id!==`view-${view}`);
  $('#planWorkspace').hidden=view==='setup'||!plan;
  $$('[data-view]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.view===view)));
  if(view==='objects')renderObjects();if(view==='rules')renderRules();if(view==='review')renderReview();
  const heading=$(`#view-${view} h1`);heading.tabIndex=-1;heading.focus({preventScroll:true});
}
function option(value,text){const n=el('option',text);n.value=value;return n;}
function setConnection(data) {
  connection=data;plan=data.plan||null;job=data.job||null;policyArchive=data.archive||null;renderArchive();renderRecoveries(data.recoveries||[]);
  $('#recoveryPanel').after($('#activityPanel'));
  $('#loginCard').hidden=true;$('#workspace').hidden=false;
  $('#connectionHost').textContent=data.host;$('#modeLabel').textContent=data.demo?'DEMO · synthetic data':data.mode==='pair'?'Management connected':'MDS connected';
  $('#domainForm').hidden=data.mode==='pair';
  if(data.mode==='pair')$('#connectionHost').textContent=`${data.sourceDomain.name} → ${data.targetDomain.name}`;
  $('#sourceDomain').replaceChildren(option('','Select source domain'),...data.domains.map(d=>option(d.uid,d.name)));
  $('#targetDomain').replaceChildren(option('','Select destination domain'),...data.domains.map(d=>option(d.uid,d.name)));
  $('#demoScenarioRow').hidden=!data.demo;
  if(data.sourceDomain){$('#sourceDomain').value=data.sourceDomain.uid;$('#targetDomain').value=data.targetDomain.uid;setPackages(data.packages);}
  else{$('#previewForm').hidden=true;}
  if(plan){$('#migrationApiVersion').value=plan.apiVersion||'';setMigrationOptions(plan.options);$('#targetName').value=plan.targetName;if(!plan.sourceDomain.archive)$('#policySelect').value=plan.package.uid;$('#demoScenario').value=plan.scenario|| (plan.counts.conflict?'conflict':plan.checks.some(c=>!c.ok&&c.name.startsWith('Global policy'))?'global':'clean');renderPlan();show(job?'review':'preflight');if(['staging','publishing'].includes(job?.state))poll();}
  else{lockNav();show('setup');}
  $('#archivePanel').hidden=!!data.demo||!data.sourceDomain;
  updateControls();
}
function lockNav(){if(!plan)$('#navBlockers').textContent='';$$('[data-view]').forEach(b=>b.disabled=b.dataset.view!=='setup'&&!plan);}
function setPackages(packages) {
  $('#previewForm').hidden=false;
  $('#policySelect').replaceChildren(...(packages.length?packages.map(p=>option(p.uid,p.name)):[option('','No source policies found')]));
  $('#targetName').value=packages[0]?`${packages[0].name}_Migrated`:'';
}
$('#connectionMode').addEventListener('change',()=>{
 const pair=$('#connectionMode').value==='pair';
 $('#mdsConnectionFields').hidden=pair;$('#mdsConnectionFields').disabled=pair;
 $('#pairConnectionFields').hidden=!pair;$('#pairConnectionFields').disabled=!pair;
 $('#connectButton').textContent=pair?'Connect management endpoints':'Connect to MDS →';
});
function syncAuthentication(prefix='') {
 const form=$('#loginForm'),name=field=>prefix?prefix+field[0].toUpperCase()+field.slice(1):field;
 const key=form.elements[name('authMode')].value==='api-key';
 for(const field of ['username','password','apiKey']) {
   const input=form.elements[name(field)],hidden=field==='apiKey'?!key:key;
   input.closest('label').hidden=hidden;input.disabled=hidden;input.required=!hidden;
   if(hidden)input.removeAttribute('aria-invalid');
 }
 if(prefix)form.elements[name('username')].closest('.endpoint-credentials').hidden=key;
}
for(const prefix of ['', 'source','target']) {
 const name=prefix?prefix+'AuthMode':'authMode';
 $('#loginForm').elements[name].addEventListener('change',()=>syncAuthentication(prefix));
 syncAuthentication(prefix);
}
$('#loginForm').addEventListener('input',e=>{e.target.removeAttribute('aria-invalid');$('#loginStatus').textContent='';});
$('#loginForm').addEventListener('submit',async e=>{
  e.preventDefault();if(busy)return;
  const invalid=[...e.currentTarget.elements].find(input=>input.willValidate&&!input.validity.valid);
  if(invalid){invalid.setAttribute('aria-invalid','true');invalid.setAttribute('aria-describedby','loginStatus');$('#loginStatus').textContent=`Enter ${invalid.closest('label').firstChild.textContent.trim().toLowerCase()} to continue.`;invalid.focus();return;}
  busy=true;const button=e.submitter||$('#connectButton');button.disabled=true;$('#loginStatus').classList.add('is-working');$('#loginStatus').textContent=$('#connectionMode').value==='pair'?'Connecting source and destination…':'Connecting and discovering MDS domains…';
  const f=new FormData(e.currentTarget),body=Object.fromEntries(f);
  body.ignoreTls=f.has('ignoreTls');body.largeEnvironmentMode=f.has('largeEnvironmentMode');
  if(body.mode==='pair')for(const prefix of ['source','target'])body[prefix]={proxyUrl:f.get('proxyUrl'),host:f.get(prefix+'Host'),domain:f.get(prefix+'Domain'),authMode:f.get(prefix+'AuthMode'),username:f.get(prefix+'Username'),password:f.get(prefix+'Password'),apiKey:f.get(prefix+'ApiKey'),smart1Cloud:f.has(prefix+'Smart1Cloud'),ignoreTls:f.has(prefix+'IgnoreTls'),largeEnvironmentMode:true};
  try{const data=await api('connect',body);e.target.querySelectorAll('input[type=password]').forEach(input=>input.value='');setConnection(data);$('#loginStatus').textContent='';}
  catch(error){$('#loginStatus').textContent=error.message;}
  finally{busy=false;button.disabled=false;$('#loginStatus').classList.remove('is-working');updateControls();}
});
$('#demoButton').addEventListener('click',async()=>{
  if(busy)return;busy=true;$('#demoButton').disabled=true;
  try{
    const data=await api('connect',{demo:true});setConnection(data);
    const selected=await api('select',{source:data.domains[0].uid,target:data.domains[1].uid});setConnection(selected);
    const result=await api('preview',{packageUid:selected.packages[0].uid,targetName:'Corporate_Access_Migrated',scenario:'conflict'});plan=result.plan;renderPlan();show('preflight');
  }catch(e){$('#loginStatus').textContent=e.message;status(e.message,true);}
  finally{busy=false;$('#demoButton').disabled=false;updateControls();}
});
$('#logoutButton').addEventListener('click',()=>run('Disconnecting…',async()=>{
  await api('logout');$('#loginCard').before($('#activityPanel'));clearTimeout(pollTimer);connection=null;plan=null;job=null;policyArchive=null;renderArchive();$('#workspace').hidden=true;$('#loginCard').hidden=false;$('#loginStatus').textContent='';
}));
$('#domainForm').addEventListener('submit',e=>{e.preventDefault();run('Opening source and destination sessions…',async()=>{
  const data=await api('select',{source:$('#sourceDomain').value,target:$('#targetDomain').value});setConnection(data);
});});
for(const id of ['sourceDomain','targetDomain'])$('#'+id).addEventListener('change',()=>{
  if(['staging','staged','publishing','publish-unknown','recovery-required'].includes(job?.state))return;
  // A selection change invalidates navigation until the server opens the chosen domains.
  $('#previewForm').hidden=true;$('#archivePanel').hidden=true;$$('[data-view]').filter(b=>b.dataset.view!=='setup').forEach(b=>b.disabled=true);
});
$('#policySelect').addEventListener('change',()=>{$('#targetName').value=`${$('#policySelect').selectedOptions[0]?.textContent||'Policy'}_Migrated`;});
async function preview() {
  await run('Scanning global assignments, object dependencies and destination definitions. Large domains may take several minutes…',async()=>{
    const result=await api('preview',{packageUid:$('#policySelect').value,targetName:$('#targetName').value,scenario:$('#demoScenario').value,apiVersion:$('#migrationApiVersion').value.trim(),options:migrationOptions()});
    plan=result.plan;job=null;$('#confirmName').value='';$('#confirmReviewed').checked=false;renderPlan();show('preflight');
  });
}
$('#previewForm').addEventListener('submit',e=>{e.preventDefault();void preview();});
$('#rescanButton').addEventListener('click',()=>plan?.sourceDomain.archive?previewArchive():preview());
$$('[data-view]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.view)));
$$('[data-go]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.go)));
$$('[data-action=export]').forEach(b=>b.addEventListener('click',()=>{
  if(!plan)return;const url=URL.createObjectURL(new Blob([JSON.stringify(plan,null,2)],{type:'application/json'}));const a=el('a');a.href=url;a.download='single-policy-move-plan.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}));
function notice(title,text,state) {const n=el('div',undefined,`notice ${state}`);n.append(el('b',title),el('p',text));return n;}
function renderPlan() {
  lockNav();$('#routeSource').textContent=plan.sourceDomain.name;$('#routeTarget').textContent=plan.targetDomain.name;
  $('#navBlockers').textContent=plan.blockers?String(plan.blockers):'';
  $('#planBadge').replaceWith(Object.assign(badge(plan.ready?'Ready for review':`${plan.blockers} blocker${plan.blockers===1?'':'s'}`,plan.ready?'pass':'fail'),{id:'planBadge'}));
  $('#preflightSummary').replaceChildren(notice(plan.ready?'Preflight passed. Review the proposed changes.':'Migration blocked. Resolve these issues before continuing.',plan.ready?'No changes have been made. Review every object and rule before staging.':'Resolve name conflicts in Object changes. Other blockers require correction in SmartConsole and a rescan. No changes have been made.',plan.ready?'pass':'fail'));
  const checks=[...plan.checks,{name:'Object definitions & name conflicts',ok:plan.counts.conflict+plan.counts.blocked===0,detail:plan.counts.conflict+plan.counts.blocked?`${plan.counts.conflict} conflicts and ${plan.counts.blocked} unsupported objects. Open Object changes for the exact definitions.`:`${plan.counts.create} objects to create; ${plan.counts.reuse} verified matches to reuse.`}];
  $('#checks').replaceChildren(...checks.map(c=>{const row=el('div',undefined,`check-row-result ${['warning','notice'].includes(c.severity)?'warning':c.ok?'pass':'fail'}`);const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 24 24');const circle=document.createElementNS(svg.namespaceURI,'circle');circle.setAttribute('cx','12');circle.setAttribute('cy','12');circle.setAttribute('r','9');svg.append(circle);const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d',['warning','notice'].includes(c.severity)?'M12 7v6m0 3v1':c.ok?'m8 12 3 3 5-6':'m9 9 6 6m0-6-6 6');svg.append(path);const text=el('div');text.append(el('b',c.name),el('p',c.detail));row.append(svg,text,badge(['warning','notice'].includes(c.severity)?(c.severity==='notice'?'Notice':'Review'):c.ok?'Passed':'Blocked',['warning','notice'].includes(c.severity)?'warning':c.ok?'pass':'fail'));return row;}));
  $('#planDescription').textContent=`${plan.package.name} → ${plan.targetName} · ${plan.ruleCount} rules across ${plan.layers.length} policy layers`;
  $('#changeSummary').replaceChildren(...[['create','To create'],['reuse','To reuse'],['conflict','Conflicts'],['blocked','Unsupported']].map(([k,label])=>{const d=el('div');d.append(el('strong',String(plan.counts[k])),el('span',label));return d;}));
  $('#layerSelect').replaceChildren(...plan.layers.flatMap(l=>[option(l.uid,`${l.name} · ${l.kind||'access'}${l.kind==='access'&&!l.ordered?' · Inline':''}`),...(l.exceptionSets||[]).filter(e=>e.items.length).map(e=>option(`exceptions:${l.uid}:${e.ruleUid}`,`${l.name} · Exceptions for ${l.items.find(r=>r.uid===e.ruleUid)?.name||e.ruleUid}`))]),...(plan.nat.length?[option('nat','NAT rulebase')]:[]));
  $('#ruleCount').textContent=`${plan.ruleCount} rules`;
  $('#objectDetail').hidden=true;
}
function definition(o) {
  if(!o)return 'Not present';
  if(o.type==='host')return o['ipv4-address']||o['ipv6-address']||'Host';
  if(o.type==='network')return `${o.subnet4||o.subnet6}/${o['mask-length4']??o['mask-length6']}`;
  if(o.port!==undefined)return `${o.type==='service-udp'?'UDP':'TCP'} / ${o.port}`;
  if(o.members)return `${o.members.length} members`;
  return o.name;
}
function renderObjects() {
  if(!plan)return;
  const q=$('#objectSearch').value.toLowerCase(),filter=$('#objectFilter').value;
  const rows=plan.objects.filter(o=>(filter==='all'||o.status===filter)&&`${o.name} ${o.importName||''} ${o.type} ${definition(o.source)} ${o.target?.name||''}`.toLowerCase().includes(q));
  $('#objectCount').textContent=`${rows.length} of ${plan.objects.length}`;
  $('#objectsBody').replaceChildren(...rows.map(o=>{
    const tr=el('tr');const name=el('td',o.name);if(o.importName)name.append(el('small',`Import as ${o.importName}`));if(o.target&&o.target.name!==o.name)name.append(el('small',`Maps to ${o.target.name}`));
    const dest=el('td',definition(o.target),'definition');
    const outcome=el('td');outcome.append(badge(labels[o.status],o.status));
    const detail=el('td'),button=el('button',o.renameAllowed?(o.importName?'Edit rename':'Resolve'):'↗',o.renameAllowed?'resolve-button':'detail-button');button.setAttribute('aria-label',`${o.renameAllowed?'Resolve conflict for':'Compare'} ${o.name}`);button.addEventListener('click',()=>objectDetail(o));detail.append(button);
    tr.append(name,el('td',o.type),el('td',definition(o.source),'definition'),dest,outcome,detail);return tr;
  }));
  if(!rows.length){const row=el('tr'),td=el('td',plan.objects.length?'No objects match these filters.':'Object scan is unavailable until the preflight blockers are resolved.','empty-state');td.colSpan=6;row.append(td);$('#objectsBody').append(row);}
}
function objectDetail(o) {
  const panel=$('#objectDetail');panel.hidden=false;
  const heading=el('div',undefined,'detail-heading');heading.append(el('h2',o.name),badge(labels[o.status],o.status));
  const compare=el('div',undefined,'definition-compare');
  for(const [title,data] of [['Source definition',o.source],['Destination definition',o.target]]){const side=el('div');side.append(el('h3',title),el('pre',data?JSON.stringify(data,null,2):'No matching object. A new object will be created.'));compare.append(side);}
  panel.replaceChildren(heading,el('p',o.reason),compare);
  if(o.renameAllowed && plan.state==='preview' && !job) panel.append(renameForm(o));
  else if(o.status==='conflict') panel.append(el('p','Renaming resolves name collisions. Ambiguous exact matches still require review before migration.')); heading.tabIndex=-1;heading.focus({preventScroll:true});panel.scrollIntoView({behavior:'instant',block:'nearest'});
}
function renameForm(o) {
  const form=el('form',undefined,'rename-form');
  const label=el('label','New name for imported object');
  const input=el('input');input.value=o.importName||`${o.name}_MIGRATED`;input.required=true;input.maxLength=100;input.autocomplete='off';label.append(input);
  const help=el('p','Only the incoming object is renamed. Group members and rule references follow the new object. Exact definition matching and name uniqueness checks still apply.','field-help');
  const error=el('p',undefined,'status-message');error.setAttribute('role','alert');
  const actions=el('div',undefined,'bottom-actions'),save=el('button','Apply rename','primary');save.type='submit';actions.append(save);
  const apply=async reset=>{
    if(busy)return;busy=true;save.disabled=true;input.disabled=true;error.textContent='';updateControls();
    try {
      const result=await api('rename',{planId:plan.id,objectUid:o.uid,newName:input.value,reset});
      plan=result.plan;$('#confirmName').value='';$('#confirmReviewed').checked=false;
      renderPlan();renderObjects();objectDetail(plan.objects.find(row=>row.uid===o.uid));
      status(reset?'Rename removed. Review the conflict.':'Rename applied to the preview. Review the updated objects and rulebase.');
    } catch(e){error.textContent=e.message;}
    finally{busy=false;save.disabled=false;input.disabled=false;updateControls();}
  };
  if(o.importName){const undo=el('button','Undo rename');undo.type='button';undo.addEventListener('click',()=>void apply(true));actions.append(undo);}
  form.append(label,help,error,actions);form.addEventListener('submit',e=>{e.preventDefault();void apply(false);});return form;
}
async function renameAllConflicts() {
  if(busy||!plan||plan.state!=='preview'||job)return;
  const candidates=plan.objects.filter(o=>o.status==='conflict'&&o.renameAllowed&&(!o.importName||(plan.options?.objectSuffix&&o.importName===o.name+plan.options.objectSuffix&&!plan.renames?.[o.uid])));
  if(!candidates.length)return;
  busy=true;updateControls();
  const message=$('#bulkRenameStatus');
  let completed=0;
  try {
    for(const object of candidates) {
      message.textContent=`Renaming ${completed+1} of ${candidates.length}: ${object.name}`;
      const result=await api('rename',{planId:plan.id,objectUid:object.uid,newName:`${object.importName||object.name}_MIGRATED`});
      plan=result.plan;completed++;
      $('#confirmName').value='';$('#confirmReviewed').checked=false;
      renderPlan();
    }
    message.textContent=`Renamed ${completed} incoming object${completed===1?'':'s'} with _MIGRATED. ${plan.counts.conflict} conflicts remain; review the updated preview.`;
  } catch(error) {
    message.textContent=`Renamed ${completed} of ${candidates.length} objects. Stopped: ${error.message} Resolve this object individually, then retry for the remaining conflicts.`;
    status(message.textContent,true);
  } finally {busy=false;updateControls();}
}
$('#renameAllConflicts').addEventListener('click',renameAllConflicts);
$('#objectSearch').addEventListener('input',renderObjects);$('#objectFilter').addEventListener('change',renderObjects);$('#layerSelect').addEventListener('change',renderRules);
function chips(value) {
  const div=el('div');for(const v of (Array.isArray(value)?value:[value]).filter(v=>v!==undefined&&v!==null)){
    const uid=typeof v==='object'?v.uid:v, obj=plan.objects.find(o=>o.uid===uid),layer=plan.layers.find(l=>l.uid===uid);
    const name=obj?.importName||obj?.target?.name||obj?.name||layer?.targetName||(typeof v==='object'?v.name||JSON.stringify(v):String(v));
    const chip=el('span',name,`object-chip ${obj?.status||'default'}`);if(obj)chip.title=obj.reason;
    div.append(chip);
  }return div;
}
function renderRules() {
  if(!plan)return;
  const selected=$('#layerSelect').value,exception=selected.startsWith('exceptions:')?selected.split(':'):null;
  const nat=selected==='nat',layer=plan.layers.find(l=>l.uid===(exception?exception[1]:selected)),items=nat?plan.nat:exception?layer?.exceptionSets.find(e=>e.ruleUid===exception[2])?.items||[]:layer?.items||[];
  const headers=nat?['#','Rule','Original source','Original destination','Original service','Translated source','Translated destination','Translated service']:['#','Rule','Source','Destination','Services','Action','Track'];
  const hr=el('tr');headers.forEach(h=>hr.append(el('th',h)));$('#rulesHead').replaceChildren(hr);
  let n=0;$('#rulesBody').replaceChildren(...items.map(r=>{
    const tr=el('tr');if(r.type.endsWith('section')){tr.className='rule-section';const td=el('td',r.name);td.colSpan=headers.length;tr.append(td);return tr;}
    if(r.enabled===false)tr.classList.add('disabled-rule');
    const name=el('td',r.name||'Unnamed rule','rule-name');if(nat&&r.natPosition)name.append(el('small',r.natPosition==='upper'?' · Before automatic NAT':' · After automatic NAT'));if(r.enabled===false)name.append(el('small',' · Disabled'));
    tr.append(el('td',String(++n)),name);
    const keys=nat?['original-source','original-destination','original-service','translated-source','translated-destination','translated-service']:['source','destination','service'];
    for(const k of keys){const td=el('td');if(r[k.replace(/source|destination|service/,'$&')+'-negate'])td.append(el('small','NOT '));td.append(chips(r[k]));tr.append(td);}
    if(!nat){const action=el('td');action.append(chips(r.action));if(r['inline-layer'])action.append(chips(r['inline-layer']));const track=r.track?.type??r.track;tr.append(action,el('td',typeof track==='object'?track.name:track||'None'));}
    return tr;
  }));
  if(!items.length){const tr=el('tr'),td=el('td','No rulebase available. Resolve the preflight blockers and rescan.','empty-state');td.colSpan=headers.length;tr.append(td);$('#rulesBody').append(tr);}
  $('#ruleWarning').replaceChildren(...(!plan.ready?[notice('This is a proposed rulebase, not an executable plan.','Unresolved object references and other preflight blockers must be corrected before staging.','fail')]:[]));
  $('#rawRules').textContent=JSON.stringify(nat?plan.nat:layer||{},null,2);
}
function renderReview() {
  if(!plan)return;
  const facts=el('dl',undefined,'review-facts');for(const [key,value] of [['Source',`${plan.sourceDomain.name} / ${plan.package.name}`],['Destination',`${plan.targetDomain.name} / ${plan.targetName}`],['Objects',`${plan.counts.create} create · ${plan.counts.reuse} reuse · ${plan.counts.conflict+plan.counts.blocked} blocked`],['Rules',`${plan.ruleCount} rules in ${plan.layers.length} policy layers`],['Preview expires',new Date(plan.expiresAt).toLocaleString()],['Migration API',plan.apiVersion||'Demo · no API calls'],['Source policy','Retained; no policy is installed on gateways']])facts.append(el('dt',key),el('dd',value));
  for(const check of plan.checks.filter(c=>['warning','notice'].includes(c.severity)))facts.append(el('dt',check.name),el('dd',check.detail));
  $('#reviewSummary').replaceChildren(facts);
  $('#reviewGate').replaceChildren(notice(plan.ready?'Ready to stage after your review.':'Staging is blocked.',plan.ready?'Global assignments and both domain snapshots will be checked again before creating anything. A changed snapshot requires a new preview.':`${plan.blockers} blocker${plan.blockers===1?'':'s'} remain. Resolve them in the domains and rescan.`,plan.ready?'neutral':'fail'));
  $('#stageForm').hidden=!!job;
  renderJob();updateControls();
}
$('#confirmName').addEventListener('input',updateControls);$('#confirmReviewed').addEventListener('change',updateControls);
$('#stageForm').addEventListener('submit',e=>{e.preventDefault();run('Starting migration…',async()=>{
  const data=await api('stage',{planId:plan.id,confirmName:$('#confirmName').value});job=data.job;plan.state=job.state;renderReview();poll();
});});
function renderJob() {
  $('#jobPanel').hidden=!job;if(!job)return;
  if(!activity&&['staging','publishing'].includes(job.state))beginActivity(job.state==='staging'?'stage':'finish');
  if(activity&&['stage','finish','reconcile'].includes(activity.path))jobActivity(job);
  $('#reviewGate').replaceChildren(notice('Migration status',job.message,['failed','recovery-required','publish-unknown'].includes(job.state)?'fail':'neutral'));

  const titles={staging:'Staging migration…',staged:'Changes staged · not published',publishing:'Publishing…',published:'Migration published',discarded:'Staged changes discarded',failed:'Migration stopped','publish-unknown':'Publish outcome not confirmed','recovery-required':'Manual recovery required'};
  $('#preflightSummary').replaceChildren(notice('Preview record · migration has been started',`Current state: ${titles[job.state]||job.state}. Open Review & migrate for the latest outcome. This is the pre-migration snapshot.`,'neutral'));
  $('#jobTitle').textContent=titles[job.state]||job.state;$('#jobMessage').textContent=job.message;
  $('#jobLog').textContent=JSON.stringify({operations:job.logs,taskId:job.taskId,raw:job.raw},null,2);
  $('#reconcileButton').hidden=job.state!=='publish-unknown'||!job.taskId;
  $('#finishActions').hidden=!['staged','recovery-required'].includes(job.state);updateControls();
}
function poll(){clearTimeout(pollTimer);pollTimer=setTimeout(async()=>{
  try{job=(await api('job')).job;if(plan&&job)plan.state=job.state;renderJob();if(['staging','publishing'].includes(job?.state))poll();}
  catch(e){status(`Unable to retrieve migration status: ${e.message}. Reconnect or refresh to check the server job; do not repeat staging.`,true);}
},1000);}
async function finish(action){
  const dialog=$('#confirmDialog');$('#dialogTitle').textContent=action==='publish'?'Publish destination changes?':'Discard staged changes?';
  $('#dialogMessage').textContent=action==='publish'?`Commit ${plan.targetName} in ${plan.targetDomain.name}. The source is retained and this action does not install policy.`:'Remove all unpublished changes in this dedicated migration session.';
  $('#finishName').value='';$('#dialogConfirm').disabled=true;dialog.showModal();
  dialog.addEventListener('close',()=>{if(dialog.returnValue!=='confirm')return;run(`${action==='publish'?'Publishing':'Discarding'} changes…`,async()=>{job=(await api('finish',{action,confirmName:$('#finishName').value})).job;plan.state=job.state;renderReview();});},{once:true});
}
$('#reconcileButton').addEventListener('click',()=>run('Checking publish task…',async()=>{job=(await api('reconcile')).job;plan.state=job.state;renderReview();}));
$('#finishName').addEventListener('input',()=>$('#dialogConfirm').disabled=$('#finishName').value!==plan?.targetName);
$('#publishButton').addEventListener('click',()=>finish('publish'));$('#discardButton').addEventListener('click',()=>finish('discard'));
try{const data=await api('session');setConnection(data);}catch{/* No cookie is the expected initial state. */}

function renderRecoveries(records) {
  $('#recoveryPanel').hidden=!!connection?.demo;
  const container=$('#recoveryRecords');container.replaceChildren();
  if(!records.length){container.append(el('p','No unfinished migrations recorded for this MDS.','muted'));return;}
  for(const record of records) {
    const item=el('article',null,'recovery-record');
    item.append(el('h3',`${record.targetName} · ${record.targetDomain.name}`));
    item.append(el('p',`Recorded state: ${record.state}. Started ${new Date(record.createdAt).toLocaleString()}.`));
    item.append(el('p',`Session object UID: ${record.sessionUid}`,'recovery-session'));
    const inspect=el('button','Inspect original session');inspect.type='button';inspect.dataset.recovery='true';
    const action=async(action,confirmName)=>{
      const result=await api('recover',{operationId:record.id,action,confirmName});
      connection.recoveries=result.recoveries;renderRecoveries(result.recoveries);
      $('#recoveryStatus').textContent=`${result.message} Observed state: ${result.inspection.state}; unpublished changes: ${result.inspection.changes??'unknown'}.`;
      const latest=await api('session');job=latest.job;if(plan&&job){plan.state=job.state;renderJob();}
    };
    inspect.addEventListener('click',()=>run('Inspecting original migration session…',()=>action('inspect')));
    const form=el('form');const label=el('label','To discard, type the recorded destination policy name');
    const input=el('input');input.required=true;input.autocomplete='off';input.spellcheck=false;label.append(input);
    const discard=el('button','Recover session & discard');discard.type='submit';discard.dataset.recovery='true';
    form.append(label,discard);
    form.addEventListener('submit',e=>{e.preventDefault();run('Verifying the original session before discard…',()=>action('discard',input.value));});
    item.append(inspect,form);container.append(item);
  }
}
$('#refreshRecovery').addEventListener('click',()=>run('Checking recovery records…',async()=>{
  const latest=await api('session');connection.recoveries=latest.recoveries;renderRecoveries(latest.recoveries||[]);
}));

async function loadCatalogCoverage() {
  const data=await api('catalog/coverage',{version:$('#catalogVersion').value});
  const wasAutomatic=!$('#catalogVersion').value;$('#catalogVersion').replaceChildren(option('','Automatic · highest common supported'),...data.installed.map(v=>option(v,v)));$('#catalogVersion').value=wasAutomatic?'':data.version;
  const advertised=data.advertised===null?'Server availability has not been checked.':data.advertised?'All checked management contexts advertise this API version.':'This version is not verified across all checked management contexts.';
  $('#catalogStatus').textContent=`${data.candidates.length} documented creation commands. ${advertised} ${data.executionVersion?`Migration API: ${data.executionVersion}.`:'Connect both domains to determine the migration API version.'} Viewing ${data.version}. Catalog updates extend ordinary object fields; policy structures use dedicated native adapters.`;
  const states={'adapter-needed':'Adapter needed','version-validation-needed':'Version validation needed','adapter-implemented':'Native policy handler · preflight required','catalog-candidate':'Catalog-derived object handler · not proof of tested support',deprecated:'Deprecated · review required'};
  $('#catalogRows').replaceChildren(...data.candidates.map(c=>{const row=el('tr');row.append(el('td',c.command),el('td',states[c.status]),el('td',c.newSinceBaseline?`Added since ${data.baselineVersion}`:`Present in ${data.baselineVersion}`));return row;}));
}
$('#catalogLoad').addEventListener('click',()=>run('Checking version and migration coverage…',loadCatalogCoverage));
$('#catalogUpdate').addEventListener('click',()=>run('Downloading official Check Point API catalogs…',async()=>{await api('catalog/update');await loadCatalogCoverage();}));

function renderArchive() {
  $('#archiveStatus').textContent=policyArchive?`Archive ready · ${(policyArchive.size/1024/1024).toFixed(2)} MiB · SHA-256 ${policyArchive.sha256}`:'No archive loaded.';
  $('#archiveDownload').hidden=!policyArchive;
  $('#archiveContents').textContent=policyArchive?.manifest?`API: ${policyArchive.manifest.versions.join(', ')}. ${Object.entries(policyArchive.manifest.counts).map(([type,count])=>`${count} ${type}`).join(' · ')}.`:'';
  updateControls();
}
$('#archiveExport').addEventListener('click',()=>run('Exporting policy definitions…',async()=>{policyArchive=(await api('archive/export',{packageUid:$('#policySelect').value,apiVersion:$('#migrationApiVersion').value.trim(),options:migrationOptions(),format:$('#archiveFormat').value})).archive;renderArchive();}));
function migrationOptions(){return {access:$('#scopeAccess').checked,threat:$('#scopeThreat').checked,https:$('#scopeHttps').checked,nat:$('#scopeNat').checked,includeSections:$('#includeSections').checked,objectSuffix:$('#objectSuffix').value,importTag:$('#importTag').value};}
function setMigrationOptions(options={}){for(const [key,id] of Object.entries({access:'scopeAccess',threat:'scopeThreat',https:'scopeHttps',nat:'scopeNat',includeSections:'includeSections'}))$('#'+id).checked=options[key]!==false;$('#objectSuffix').value=options.objectSuffix||'';$('#importTag').value=options.importTag||'';}
function previewArchive(){return run('Reviewing archive against the destination…',async()=>{
  plan=(await api('preview',{archiveToken:policyArchive.token,targetName:$('#targetName').value,apiVersion:$('#migrationApiVersion').value.trim(),options:migrationOptions()})).plan;job=null;$('#confirmName').value='';$('#confirmReviewed').checked=false;renderPlan();show('preflight');
});}
$('#archivePreview').addEventListener('click',previewArchive);
$('#archiveFile').addEventListener('change',()=>run('Validating policy archive…',async()=>{
  const file=$('#archiveFile').files[0];if(!file)return;
  if(file.size>128*1024*1024)throw new Error('Archive limit is 128 MiB.');
  const response=await fetch('/api/archive/upload',{method:'POST',headers:{'content-type':'application/gzip'},body:file});
  const result=await response.json();if(!response.ok)throw new Error(result.error||'Archive upload failed.');
  policyArchive=result.archive;$('#archiveFile').value='';renderArchive();
}));
$('#archiveDownload').addEventListener('click',()=>run('Downloading archive…',async()=>{
  const response=await fetch('/api/archive/download',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:policyArchive.token})});
  if(!response.ok){const result=await response.json();throw new Error(result.error||'Archive download failed.');}
  const url=URL.createObjectURL(await response.blob()),link=el('a');link.href=url;link.download=policyArchive.fileName||'policy-package.cma.gz';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}));

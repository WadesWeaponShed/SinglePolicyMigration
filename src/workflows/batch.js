// Batch creation is unpublished. Check Point ignores item warnings/errors in
// batch commands, so a successful task alone is never sufficient verification.
export const batchObjectTypes=new Set(['access-role','address-range','application-site-category','application-site-group','dns-domain','dynamic-object','group','group-with-exclusion','host','multicast-address-range','network','security-zone','service-dce-rpc','service-group','service-icmp','service-other','service-sctp','service-tcp','service-udp','tag','time','time-group','wildcard']);
export const taskNotVisible=error=>error.command==='show-task'&&error.phase==='api-response'&&(/not_found/.test(error.response?.code||'')||/Requested object .* not found/i.test(error.message));
export const creationRejected=error=>error.phase==='api-response'&&/^(err_validation_failed|generic_err_(invalid_parameter(?:_name)?|missing_required_parameters|object_not_found))$/.test(error.response?.code||'');
export async function validateNativeSession(sessions,targetId,allowedWarnings=[]) {
  const validation=await sessions.command(targetId,'show-validations',{});
  for(const key of ['warnings','errors','blocking-errors']) {
    const entries=validation[key],total=validation[key+'-total'];
    if(!Array.isArray(entries)||!Number.isInteger(total)||total<0)throw new Error('Batch validation response is incomplete.');
    if(total!==entries.length)throw new Error('Batch validation results are truncated or inconsistent; current-session validations cannot be established.');
    const current=entries.filter(item=>item['current-session']!==false&&!(key==='warnings'&&allowedWarnings.includes(item.message)));
    if(current.length)throw new Error(`${current.length} current-session ${key} reported. ${current.map(item=>item.message).filter(Boolean).join('; ')}`);
  }
}
export async function runNativeBatch({sessions,targetId,command,body,initialResponse,allowedWarnings=[],validate=true,onProgress=()=>{},pollAttempts=240,pollIntervalMs=250}) {
  let taskId,terminal=false,dispatched=false;
  const progress=message=>onProgress({message,pendingCommand:command,taskId});
  try {
    progress(`Submitting ${command}…`);dispatched=true;
    const response=initialResponse||await sessions.command(targetId,command,body);
    taskId=response['task-id'];
    if(typeof taskId!=='string'||!taskId)throw new Error(`${command} did not return a task ID.`);
    progress(`Waiting for ${command} task…`);
    for(let attempt=0;attempt<pollAttempts;attempt++) {
      let reply;
      try{reply=await sessions.command(targetId,'show-task',{'task-id':taskId,'details-level':'full'});}
      catch(error){if(!taskNotVisible(error)||attempt+1===pollAttempts)throw error;progress(`Waiting for ${command} task registration…`);await new Promise(resolve=>setTimeout(resolve,pollIntervalMs));continue;}
      const tasks=reply.tasks?.filter(task=>task['task-id']===taskId);
      if(!Array.isArray(tasks)||tasks.length!==1)throw new Error('Batch task identity could not be verified.');
      const task=tasks[0];
      if(['succeeded','failed','partially succeeded'].includes(task.status)) {
        terminal=true;
        onProgress({message:`${command} task ${task.status}. Checking validations…`,pendingCommand:undefined,taskId:undefined});
        if(task.status!=='succeeded') {
          const messages=[];
          const collect=value=>{if(Array.isArray(value))value.forEach(collect);else if(value&&typeof value==='object')for(const [key,item] of Object.entries(value)){if(['message','statusDescription','status-description','error-message','error','description'].includes(key)&&typeof item==='string')messages.push(item);else if(!['request','payload','body'].includes(key))collect(item);}};
          collect(task['task-details']);
          if(task['progress-description'])messages.push(task['progress-description']);
          const error=new Error(`${command} task ${task.status}${messages.length?': '+[...new Set(messages)].join('; ').slice(0,6000):'. '+JSON.stringify(task['task-details']||[]).slice(0,6000)}`);
          error.taskId=taskId;error.taskTerminal=true;throw error;
        }
        break;
      }
      if(!['in progress','pending'].includes(task.status))throw new Error(`Unrecognized batch task status: ${task.status}.`);
      progress(`${command} · ${Number(task['progress-percentage'])||0}% complete`);
      if(attempt+1<pollAttempts)await new Promise(resolve=>setTimeout(resolve,pollIntervalMs));
    }
    if(!terminal)throw new Error(`${command} task has not reached a terminal state.`);
    if(validate)await validateNativeSession(sessions,targetId,allowedWarnings);
    return {taskId};
  }catch(error){
    // An API validation rejection is terminal before task dispatch. A socket
    // failure, missing ID or unreadable task can still have active writes.
    const rejected=creationRejected(error)&&!taskId;
    if(dispatched&&!terminal&&!rejected){error.batchPending=true;error.taskId=taskId;error.pendingCommand=command;}
    throw error;
  }
}

// The batch handler rejects these tracking keys (including string booleans).
// Only batch rules whose requested values match the API's ordinary Log defaults;
// omit those keys on this transport, then verify ALL source flags independently.
const batchTrackDefaults={'enable-firewall-session':false,'per-connection':true,'per-session':false};
export function canBatchRule(body) {
  const track=body.track;
  if(!track||typeof track!=='object')return true;
  return Object.entries(batchTrackDefaults).every(([key,value])=>track[key]===undefined||track.type==='log'&&track[key]===value);
}
export function batchRulePayload(body) {
  if(!canBatchRule(body))throw new Error('This rule requires individual creation to preserve its logging flags.');
  if(!body.track||typeof body.track!=='object')return body;
  const track={...body.track};for(const key of Object.keys(batchTrackDefaults))delete track[key];
  return {...body,track};
}

import {mkdirSync,readFileSync,readdirSync,openSync,writeFileSync,fsyncSync,closeSync,renameSync,unlinkSync} from 'node:fs';
import {join} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';

const terminal=new Set(['published','discarded','failed']);
const states=new Set(['staging','staged','publishing','publish-unknown','recovery-required',...terminal]);
const string=value=>typeof value==='string' && value.length>0;
const key=record=>createHash('sha256').update(`${record.host}\n${record.targetDomain.uid}`).digest('hex');
// Deliberately whitelist persisted metadata. Never serialize connection, credentials,
// policy definitions, raw API replies or login SIDs into the recovery journal.
function clean(record) {
  const out={version:1,id:record.id,host:record.host,targetDomain:{uid:record.targetDomain?.uid,name:record.targetDomain?.name},targetName:record.targetName,sessionUid:record.sessionUid,apiVersion:record.apiVersion??'v2.1',state:record.state,createdAt:record.createdAt,updatedAt:record.updatedAt||record.createdAt};
  for(const field of ['taskId','packageUid','engine','pendingCommand']) if(string(record[field]))out[field]=record[field];
  // Journals written before dynamic selection used v2.1; preserve that legacy operation schema only.
  if(!/^v\d+(?:\.\d+){0,2}$/.test(out.apiVersion))throw new Error('Invalid recovery journal API version. Migration blocked.');
  if(![out.id,out.host,out.targetDomain.uid,out.targetDomain.name,out.targetName,out.sessionUid,out.createdAt].every(string)||!states.has(out.state)||!/^[a-f0-9-]{36}$/.test(out.id))throw new Error('Invalid recovery journal record. Migration blocked.');
  return out;
}
export class OperationJournal {
  constructor(directory=null) {this.directory=directory;this.memory=new Map();if(directory)mkdirSync(directory,{recursive:true,mode:0o700});}
  list() {
    if(!this.directory)return [...this.memory.values()].map(r=>structuredClone(r));
    return readdirSync(this.directory).filter(f=>f.endsWith('.json')).map(f=>{
      try {const record=JSON.parse(readFileSync(join(this.directory,f),'utf8'));if(record.version!==1||`${record.id}.json`!==f)throw new Error();return clean(record);}
      catch {throw new Error(`Recovery journal ${f} cannot be read. Repair it before migrating; do not remove unresolved records.`);}
    });
  }
  unresolved(host) {return this.list().filter(r=>!terminal.has(r.state)&&(!host||r.host===host));}
  save(input) {
    const record=clean({...input,updatedAt:new Date().toISOString()});
    if(!this.directory){this.memory.set(record.id,record);return record;}
    const temporary=join(this.directory,`${record.id}.${randomUUID()}.tmp`);
    const fd=openSync(temporary,'wx',0o600);
    try{writeFileSync(fd,JSON.stringify(record)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
    renameSync(temporary,join(this.directory,`${record.id}.json`));
    const dir=openSync(this.directory,'r');try{fsyncSync(dir);}finally{closeSync(dir);}
    return record;
  }
  begin(input) {
    if(this.unresolved().some(r=>r.host===input.host && r.targetDomain.uid===input.targetDomain.uid))throw new Error('An unfinished migration owns this destination. Recover it before staging.');
    const record=clean({...input,id:randomUUID(),state:'staging',createdAt:new Date().toISOString()});
    if(this.directory) {
      // Exclusive creation also serializes processes using this journal directory.
      const lock=join(this.directory,`${key(record)}.lock`);
      let fd;try{fd=openSync(lock,'wx',0o600);}catch(e){if(e.code==='EEXIST')throw new Error('Destination recovery lock exists. Inspect the journal before staging.');throw e;}
      try{writeFileSync(fd,record.id);fsyncSync(fd);}finally{closeSync(fd);}
    }
    return this.save(record);
  }
  update(record,patch) {
    const saved=this.save({...record,...patch});
    if(this.directory && terminal.has(saved.state)) {
      const lock=join(this.directory,`${key(saved)}.lock`);
      // Never release another operation's reservation.
      try{if(readFileSync(lock,'utf8')===saved.id)unlinkSync(lock);}catch(e){if(e.code!=='ENOENT')throw e;}
    }
    return saved;
  }
}

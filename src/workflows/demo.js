import { buildPlan } from './migration.js';
import { compareObjects } from './objects.js';
export const demoDomains=[{uid:'domain-hq',name:'Corporate · Chicago'},{uid:'domain-dr',name:'Recovery · Dallas'},{uid:'domain-lab',name:'Lab · Austin'}];
const domain={uid:'domain-hq',name:'Corporate · Chicago','domain-type':'domain'};
const targetDomain={uid:'domain-dr',name:'Recovery · Dallas','domain-type':'domain'};
const dataDomain={name:'Check Point Data','domain-type':'data domain'};
const host=(uid,name,ip)=>({uid,name,type:'host','ipv4-address':ip,domain});
const network=(uid,name,subnet,mask)=>({uid,name,type:'network',subnet4:subnet,'mask-length4':mask,domain});
const service=(uid,name,port)=>({uid,name,type:'service-tcp',port,domain});
export const demoObjects=[
  host('web-01','web-prod-01','10.20.10.21'),host('web-02','web-prod-02','10.20.10.22'),
  host('db','database-primary','10.20.20.10'),host('bastion','admin-bastion','10.20.30.5'),
  network('users','corporate-users','10.40.0.0',16),network('monitor','monitoring-net','10.50.12.0',24),
  service('https','HTTPS',443),service('ssh','SSH',22),service('pg','PostgreSQL',5432),
  {uid:'web-group',name:'production-web',type:'group',members:['web-01','web-02'],domain},
  {uid:'any',name:'Any',type:'CpmiAnyObject',domain:dataDomain},
  {uid:'accept',name:'Accept',type:'RulebaseAction',domain:dataDomain},
  {uid:'drop',name:'Drop',type:'RulebaseAction',domain:dataDomain},
];
const ref=uid=>{const o=demoObjects.find(o=>o.uid===uid);return {uid:o.uid,name:o.name,type:o.type};};
function rule(uid,name,src,dst,svc,action='accept') {return {uid,type:'access-rule',name,source:src.map(ref),destination:dst.map(ref),service:svc.map(ref),action:ref(action),enabled:true,track:{type:'Log'},'install-on':[ref('any')],vpn:[ref('any')],time:[ref('any')]};}
const items=[
  {uid:'sec-1',type:'access-section',name:'Application access'},
  rule('r1','Corporate access to production',['users'],['web-group'],['https']),
  rule('r2','Application database connection',['web-group'],['db'],['pg']),
  {uid:'sec-2',type:'access-section',name:'Operations & administration'},
  rule('r3','Secure administration',['bastion'],['web-group','db'],['ssh']),
  rule('r4','Health checks',['monitor'],['web-group'],['https']),
  {uid:'sec-3',type:'access-section',name:'Default policy'},
  rule('r5','Cleanup rule',['any'],['any'],['any'],'drop'),
];
export function demoPlan({sourceDomain=demoDomains[0],targetDomain:target=demoDomains[1],targetName='Corporate_Access_Migrated',scenario='conflict',renames={}}={}) {
  const destination=demoObjects.filter(o=>['https','ssh','any','accept','drop','monitor'].includes(o.uid)).map(o=>({...o,domain:o.domain===dataDomain?dataDomain:targetDomain}));
  if(scenario==='conflict') destination.push({...host('target-db','database-primary','10.20.20.99'),domain:targetDomain});
  const checks=[
    {name:`Global policy · ${sourceDomain.name}`,ok:scenario!=='global',detail:scenario==='global'?'Global policy is assigned. Uninstall/remove the global policy assignment in SmartConsole, then scan again.':'No global policy assignment or inherited global layers.'},
    {name:`Global policy · ${target.name}`,ok:true,detail:'No global policy assignment or inherited global layers.'},
    {name:'Destination inventory',ok:true,detail:`${destination.length} synthetic objects scanned. Full definitions compared.`},
    {name:'Destination package',ok:true,detail:'Package name is available. Source policy is retained.'},
    {name:'Package coverage',ok:true,detail:'One Access Control layer. No NAT or unsupported blades.'},
  ];
  return buildPlan({sourceDomain,targetDomain:target,targetName,checks,objects:compareObjects(demoObjects,destination),layers:[{uid:'layer-network',name:'Network',targetName:`${targetName} / Network`,type:'access-layer',firewall:true,ordered:true,items}],nat:[],package:{uid:'pkg-corp',name:'Corporate_Access',access:true},inventory:destination,demo:true,scenario,renames});
}

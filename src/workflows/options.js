export const defaultMigrationOptions=Object.freeze({access:true,threat:true,https:true,nat:true,includeSections:true,objectSuffix:'',importTag:'',rebuildGateways:false,manualIps:[]});
export function normalizeMigrationOptions(value={}) {
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('Invalid migration options.');
  for(const key of Object.keys(value))if(!Object.hasOwn(defaultMigrationOptions,key))throw new Error(`Unknown migration option: ${key}.`);
  const result={...defaultMigrationOptions,...value};
  if(!Array.isArray(result.manualIps)||result.manualIps.length>500||result.manualIps.some(x=>!x||typeof x.uid!=='string'||typeof x.fingerprint!=='string'||!/^[a-f0-9]{64}$/.test(x.fingerprint)))throw new Error('Invalid manual IPS acknowledgments.');
  for(const key of ['access','threat','https','nat','includeSections','rebuildGateways'])if(typeof result[key]!=='boolean')throw new Error(`${key} must be true or false.`);
  if(!['access','threat','https','nat'].some(key=>result[key]))throw new Error('Select at least one policy component.');
  for(const key of ['objectSuffix','importTag'])if(typeof result[key]!=='string'||result[key].length>100||/[\x00-\x1f\x7f]/.test(result[key]))throw new Error(`${key} must contain at most 100 characters without control characters.`);
  result.importTag=result.importTag.trim();
  return result;
}

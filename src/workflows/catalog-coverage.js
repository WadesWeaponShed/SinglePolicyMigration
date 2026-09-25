import {objectAdapters,policyTypes} from './adapters.js';
import {compareVersions} from '../catalog-manager.js';

// Catalog entries describe API commands, not proof of migration semantics.
export function catalogCoverage(manager, version, serverVersions=null, pinnedVersion=null) {
  const catalog=manager.get(version);
  const adapters=objectAdapters(catalog);
  const versions=manager.status().installed;
  const baselineVersion=versions.filter(v=>compareVersions(v,version)<0).at(-1)||version;
  const baseline=new Set(manager.get(baselineVersion).commands.map(c=>c.name));
  const executionVersion=pinnedVersion||(serverVersions?.slice().sort(compareVersions).at(-1))||null;
  const normalize=v=>`v${String(v).replace(/^v/,'')}`;
  const advertised=serverVersions===null?null:serverVersions.map(normalize).includes(version);
  const candidates=catalog.commands.filter(c=>c.name.startsWith('add-')).map(command=>{
    const type=command.name.slice(4);
    const hasAdapter=Object.hasOwn(adapters,type)||policyTypes.has(type);
    return {type,command:command.name,category:command.category,deprecated:command.deprecated,
      newSinceBaseline:!baseline.has(command.name),hasAdapter,
      status:command.deprecated?'deprecated':!hasAdapter?'adapter-needed':policyTypes.has(type)?'adapter-implemented':'catalog-candidate',
      requiredFields:command.requiredFields.map(f=>f.name),
      description:command.description};
  });
  return {version,installed:versions,executionVersion,baselineVersion,advertised,candidates,
    note:'Named CRUD objects inherit writable fields from the selected API version. Policy structures use native adapters. Complete dependencies, required inputs and staged readback must pass before publication.'};
}

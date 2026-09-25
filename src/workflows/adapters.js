// Native migration adapters are compiled from the negotiated API catalog.
// Catalog growth adds writable fields to ordinary CRUD objects; policy structures
// use explicit handlers because ordering and attachment semantics differ.
const structural = new Set(['package','access-layer','access-rule','access-section','nat-rule','nat-section','threat-layer','threat-rule','threat-exception','threat-exception-section','https-layer','https-rule','https-section']);
const controls = new Set(['details-level','ignore-warnings','ignore-errors','set-if-exists','uid','groups','new-name','new-position']);
export function objectAdapters(catalog) {
  const commands=new Map(catalog.commands.map(c=>[c.name,c]));
  const result={};
  for(const command of catalog.commands) {
    if(!command.name.startsWith('add-')||command.deprecated)continue;
    const type=command.name.slice(4);
    if(structural.has(type)||!commands.has(`show-${type}`)||!commands.has(`delete-${type}`))continue;
    const fields=[...command.requiredFields,...command.optionalFields].flatMap(f=>[f.name,...(f.alternatives||[])]).filter(name=>!controls.has(name));
    // Ordinary named object creation is the extensible adapter contract.
    // Actions, server settings and bulk operations do not satisfy it.
    if(!fields.includes('name')&&!['updatable-object','custom-trusted-ca-certificate'].includes(type))continue;
    result[type]=fields;
  }
  return result;
}
export function writableFields(type,schema,fallback) {return schema?.[type]||fallback[type]||[];}
export const policyTypes=structural;

export const threatFields=['name','action','destination','destination-negate','enabled','install-on','protected-scope','protected-scope-negate','service','service-negate','source','source-negate','tags','track','track-settings','comments'];
export const httpsFields=['name','source','source-negate','destination','destination-negate','service','service-negate','action','track','install-on','enabled','site-category','site-category-negate','certificate','blade','comments','tags'];
export const threatLayerFields=['name','color','comments','tags'];
export const httpsLayerFields=['name','layer-type','shared','color','comments','tags'];
export const kindOf=layer=>layer.kind||'access';
export const ruleKind=rule=>rule.type==='nat-rule'?'nat':rule.type.startsWith('threat-')?'threat':rule.type.startsWith('https-')?'https':'access';
export function schemaPolicyFields(catalog) {
  const result={};
  for(const command of catalog.commands)if(/^add-(access|nat|https|threat)-(rule|layer|section|exception)$/.test(command.name))result[command.name.slice(4)]=[...command.requiredFields,...command.optionalFields].map(f=>f.name).filter(f=>!['layer','package','position','details-level','ignore-errors','ignore-warnings','add-default-rule','exception-group-uid','exception-group-name','rule-uid','rule-name','rule-number'].includes(f));
  return result;
}
export function policyFields(item, fallback, schema) {return schema?.[item.type]|| (ruleKind(item)==='https'?httpsFields:ruleKind(item)==='threat'?[...threatFields,...item.type==='threat-exception'?['protection-or-site']:[]]:fallback);}
export function policyLayerFields(layer,accessFields,schema) {if(schema?.[`${kindOf(layer)}-layer`])return schema[`${kindOf(layer)}-layer`];return kindOf(layer)==='https'?httpsLayerFields:kindOf(layer)==='threat'?threatLayerFields:accessFields;}
export function packagePayload(plan) {return {name:plan.targetName,access:plan.layers.some(l=>kindOf(l)==='access'),'threat-prevention':plan.layers.some(l=>kindOf(l)==='threat'),'installation-targets':[]};}

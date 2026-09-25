// Discard is executed on the same dedicated API session that made the writes.
// Check Point may remove its old session object when discard succeeds, so inspect
// the current authenticated session rather than requiring that old object to exist.
export async function discardChanges(sessions,id,apiVersion='') {
  const result=await sessions.command(id,'discard',{},'primary',apiVersion);
  if(result?.errors?.length||result?.warnings?.length)throw new Error('Discard returned errors or warnings.');
  const current=await sessions.command(id,'show-session',{},'primary',apiVersion);
  if(current.changes!==0)throw new Error('Discard acknowledgement could not be verified: the current session is not confirmed empty.');
  return current;
}

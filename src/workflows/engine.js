import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {dirname,resolve} from 'node:path';
const directory=dirname(fileURLToPath(import.meta.url));
const files=['migration.js','objects.js','adapters.js','policy-types.js','compatibility.js','discard.js','options.js','batch.js'];
let cached;
// Reload only trusted application modules. No uploaded archive or browser input
// can select code. Existing management sessions remain in the Workbench process.
export async function nativeEngine() {
  const contents=await Promise.all(files.map(async name=>[resolve(directory,name),await readFile(resolve(directory,name),'utf8')]));
  const sources=new Map(contents),revision=createHash('sha256').update(JSON.stringify(contents)).digest('hex');
  if(cached?.revision===revision)return cached;
  const urls=new Map(),visiting=new Set();
  function moduleUrl(path) {
    if(urls.has(path))return urls.get(path);
    if(visiting.has(path))throw new Error('Native engine module dependency cycle.');
    visiting.add(path);
    const source=sources.get(path).replace(/(from\s*['"])(\.[^'"]+)(['"])/g,(_,start,relative,end)=>{
      const dependency=resolve(dirname(path),relative);
      return start+(sources.has(dependency)?moduleUrl(dependency):pathToFileURL(dependency).href)+end;
    });
    const url='data:text/javascript;base64,'+Buffer.from(source+'\n//# sourceURL='+pathToFileURL(path).href).toString('base64');urls.set(path,url);visiting.delete(path);return url;
  }
  const engine=await import(moduleUrl(resolve(directory,'migration.js')));
  cached={revision,...engine};return cached;
}

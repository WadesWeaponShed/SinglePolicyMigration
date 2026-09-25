import { CatalogManager } from '../src/catalog-manager.js';
const manager = await new CatalogManager().init();
console.log(JSON.stringify(await manager.update(), null, 2));

import {CatalogManager} from './catalog-manager.js';
// Share the active framework catalogs between discovery and migration execution.
export const catalogsReady=new CatalogManager().init();

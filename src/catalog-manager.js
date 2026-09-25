import { readFile, writeFile, mkdir, rename, readdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { buildCatalog, parseReleaseMapping } from "../scripts/generate-command-catalog.mjs";

const BASE = "https://sc1.checkpoint.com/documents/latest/APIs";
export function validVersion(value) { return typeof value === "string" && /^v\d+(?:\.\d+){0,2}$/.test(value); }
export function compareVersions(a, b) {
  const x = a.replace(/^v/, "").split(".").map(Number), y = b.replace(/^v/, "").split(".").map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const difference = (x[i] || 0) - (y[i] || 0);
    if (difference) return difference;
  }
  return 0;
}
export function parseVersions(text) {
  const versions = [...new Set([...text.matchAll(/"key"\s*:\s*"(v\d+(?:\.\d+){0,2})"/g)].map(m => m[1]))].sort(compareVersions);
  if (!versions.length || versions.length > 100) throw new Error("Unrecognized official API version list.");
  return versions;
}
export function validateCatalog(catalog, version) {
  if (!validVersion(version) || catalog?.apiVersion !== version || !Array.isArray(catalog.commands) || !catalog.commands.length ||
      catalog.commandCount !== catalog.commands.length || !Array.isArray(catalog.categories)) throw new Error("Invalid catalog.");
  const names = new Set();
  for (const command of catalog.commands) {
    if (!/^[a-z0-9][a-z0-9-]*$/i.test(command.name) || names.has(command.name) ||
        !Array.isArray(command.requiredFields) || !Array.isArray(command.optionalFields) || typeof command.readOnly !== "boolean") throw new Error("Invalid command metadata.");
    names.add(command.name);
  }
  return catalog;
}
export function catalogDiff(before, after) {
  const old = new Map((before?.commands || []).map(c => [c.name, c]));
  const next = new Map(after.commands.map(c => [c.name, c]));
  return {
    added: [...next.keys()].filter(n => !old.has(n)),
    removed: [...old.keys()].filter(n => !next.has(n)),
    changed: [...next.keys()].filter(n => old.has(n) && JSON.stringify(old.get(n)) !== JSON.stringify(next.get(n))),
    deprecated: after.commands.filter(c => c.deprecated && !old.get(c.name)?.deprecated).map(c => c.name)
  };
}
export class CatalogManager {
  constructor({ directory = fileURLToPath(new URL("../.catalog-cache/", import.meta.url)),
    bundled = fileURLToPath(new URL("../public/data/", import.meta.url)), fetcher = fetch } = {}) {
    this.directory = directory; this.bundled = bundled; this.fetcher = fetcher;
    this.catalogs = new Map(); this.published = []; this.lastCheck = ""; this.lastError = ""; this.changes = []; this.pending = null;
    this.installing = new Map();
  }
  async init() {
    for (const directory of [this.bundled, this.directory]) {
      for (const file of await readdir(directory).catch(() => [])) {
        const match = /^check-point-api-(v\d+(?:\.\d+){0,2})\.json$/.exec(file);
        if (!match) continue;
        try { this.catalogs.set(match[1], validateCatalog(JSON.parse(await readFile(join(directory, file), "utf8")), match[1])); }
        catch {
          try { this.catalogs.set(match[1], validateCatalog(JSON.parse(await readFile(join(directory, file + ".previous"), "utf8")), match[1])); }
          catch { /* A corrupt cache cannot displace a working bundled catalog. */ }
        }
      }
    }
    if (!this.catalogs.size) throw new Error("No valid bundled command catalogs.");
    return this;
  }
  status() {
    const versions = [...this.catalogs.keys()].sort(compareVersions);
    const versionChanges = versions.slice(1).map((version, index) => ({
      version,
      comparedTo: versions[index],
      ...catalogDiff(this.catalogs.get(versions[index]), this.catalogs.get(version))
    }));
    return { installed: [...this.catalogs.keys()].sort(compareVersions), published: this.published,
      lastCheck: this.lastCheck, lastError: this.lastError, changes: this.changes, versionChanges };
  }
  get(version) {
    if (!validVersion(version) || !this.catalogs.has(version)) throw new Error("Catalog version is not installed.");
    const catalog = this.catalogs.get(version);
    return { ...catalog, commands: catalog.commands.map(command => ({
      ...command,
      documentedVersions: [...this.catalogs].filter(([, c]) => c.commands.some(x => x.name === command.name)).map(([v]) => v).sort(compareVersions),
      releaseCompatibility: catalog.release ? `API ${version} maps to ${catalog.release} in Check Point's release table. This is not a guarantee of gateway, permission or platform compatibility.` : "Release and hotfix requirements are not verified; API availability is not gateway compatibility."
    })) };
  }
  async download(path, json = true) {
    const response = await this.fetcher(BASE + path, { signal: AbortSignal.timeout(30000), redirect: "error" });
    if (!response.ok) throw new Error("Official documentation download failed: HTTP " + response.status);
    const text = await response.text();
    if (text.length > 50000000) throw new Error("Documentation exceeds size limit.");
    return json ? JSON.parse(text) : text;
  }
  async ensure(version) {
    if (!validVersion(version)) throw new Error("Invalid catalog version.");
    if (this.catalogs.has(version)) return this.get(version);
    if (!this.installing.has(version)) {
      const installation = this.installVersion(version).finally(() => this.installing.delete(version));
      this.installing.set(version, installation);
    }
    await this.installing.get(version);
    return this.get(version);
  }
  async installVersion(version) {
    // Version is validated before it can become a URL or cache path component.
    if (!validVersion(version)) throw new Error("Invalid catalog version.");
    const [apis, content] = await Promise.all([
      this.download(`/data/${version}/dynamic/apis.json`),
      this.download(`/data/${version}/dynamic/content.json`)
    ]);
    if (!Array.isArray(apis?.commands) || !Array.isArray(apis?.objects) || !Array.isArray(content?.chapters)) throw new Error("Documentation schema changed.");
    const catalog = validateCatalog(buildCatalog(apis, content, version), version);
    await mkdir(this.directory, { recursive: true });
    const path = join(this.directory, `check-point-api-${version}.json`);
    const temporary = `${path}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, JSON.stringify(catalog), { flag: "wx" });
      await rename(temporary, path);
    } catch (error) {
      await unlink(temporary).catch(() => {});
      throw error;
    }
    // A failed fetch, validation or cache write must never activate a fallback.
    this.catalogs.set(version, catalog);
  }
  update() {
    if (this.pending) return this.pending;
    this.pending = this.performUpdate().finally(() => { this.pending = null; });
    return this.pending;
  }
  async performUpdate() {
    this.changes = [];
    try {
      this.published = parseVersions(await this.download("/js/versions.js", false));
      const releaseSource = "/data/" + this.published.at(-1) + "/api_versions.html";
      const releases = parseReleaseMapping(await this.download(releaseSource, false));
      // Stage every download before activation. Network/schema failure leaves the in-memory catalog set untouched.
      const staged = [];
      for (const version of this.published) {
        const apis = await this.download("/data/" + version + "/dynamic/apis.json");
        const content = await this.download("/data/" + version + "/dynamic/content.json");
        if (!Array.isArray(apis.commands) || !Array.isArray(apis.objects) || !Array.isArray(content.chapters)) throw new Error("Documentation schema changed.");
        const catalog = buildCatalog(apis, content, version);
        catalog.release = releases[version] || "";
        catalog.releaseSource = BASE + releaseSource;
        staged.push(validateCatalog(catalog, version));
      }
      await mkdir(this.directory, { recursive: true });
      for (const catalog of staged) {
        const version = catalog.apiVersion, previous = this.catalogs.get(version);
        const path = join(this.directory, "check-point-api-" + version + ".json");
        if (previous) await writeFile(path + ".previous", JSON.stringify(previous));
        const temporary = path + "." + randomUUID() + ".tmp";
        await writeFile(temporary, JSON.stringify(catalog));
        await rename(temporary, path);
      }
      for (const catalog of staged) {
        const previous = this.catalogs.get(catalog.apiVersion) || staged.filter(c => compareVersions(c.apiVersion, catalog.apiVersion) < 0).at(-1);
        this.changes.push({ version: catalog.apiVersion, comparedTo: previous?.apiVersion || null, ...catalogDiff(previous, catalog) });
        this.catalogs.set(catalog.apiVersion, catalog);
      }
      this.lastCheck = new Date().toISOString(); this.lastError = "";
    } catch (error) { this.lastError = error.message; throw error; }
    return this.status();
  }
}

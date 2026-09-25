import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const API_VERSION = argument("--version") || "v2.1";
if (!/^v\d+(?:\.\d+){0,2}$/.test(API_VERSION)) throw new Error("Invalid API version");
const DOCS_BASE = `https://sc1.checkpoint.com/documents/latest/APIs/data/${API_VERSION}/dynamic`;
const DEFAULT_OUTPUT = fileURLToPath(new URL(`../public/data/check-point-api-${API_VERSION}.json`, import.meta.url));

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : "";
}

async function loadJson(localPath, remoteName) {
  if (localPath) return JSON.parse(await readFile(resolve(localPath), "utf8"));
  const response = await fetch(`${DOCS_BASE}/${remoteName}`);
  if (!response.ok) throw new Error(`Unable to download ${remoteName}: HTTP ${response.status}`);
  return response.json();
}

function categoryMap(chapters) {
  const result = new Map();
  const visit = (items, parents = []) => {
    for (const chapter of items || []) {
      const path = [...parents, chapter.name].filter((name) => name && !name.endsWith(":"));
      for (const item of chapter["commands-data"] || []) {
        const name = item?.name?.web;
        if (name && !result.has(name)) result.set(name, path.join(" / ") || "Other");
      }
      visit(chapter["sub-chapters"], path);
    }
  };
  visit(chapters);
  return result;
}

function stripHtml(value) {
  return String(value || "")
    .replace(/<br\s*\/?>/gi, " ")
    .replace(/<[^>]+>/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function parseReleaseMapping(html) {
  const table = /<table[^>]*id="versions-releases"[^>]*>([\s\S]*?)<\/table>/i.exec(html)?.[1];
  if (!table) throw new Error("Official release mapping table is missing.");
  const releases = {};
  for (const row of table.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const cells = [...row[1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map(m => stripHtml(m[1]));
    if (/^v\d+(?:\.\d+){0,2}$/.test(cells[0]) && /^R\d/.test(cells[1])) releases[cells[0]] = cells[1];
  }
  if (!Object.keys(releases).length) throw new Error("No official release mappings found.");
  return releases;
}

function typeLabel(type) {
  if (!type) return "value";
  if (type.name === "list") return `list<${typeLabel(type["element-type"])}>`;
  if (type.name === "object") return "object";
  return type.name || "value";
}

function sampleValue(field) {
  const type = field.types?.[0] || {};
  const validValues = type["valid-values"];
  if (field["default-value"] !== undefined && field["default-value"] !== "") {
    const value = field["default-value"];
    if (type.name === "boolean") return String(value).toLowerCase() === "true";
    if (["integer", "number"].includes(type.name) && Number.isFinite(Number(value))) return Number(value);
    return value;
  }
  if (Array.isArray(validValues) && validValues.length) return validValues[0];
  if (type.name === "boolean") return false;
  if (["integer", "number"].includes(type.name)) return 0;
  if (type.name === "list") return [];
  if (type.name === "object") return {};
  return "";
}

function nestedTypes(field, objects, depth=0, seen=new Set()) {
  if(depth>6)return undefined;
  return (field.types||[]).map(type=>{
    const result={name:type.name};
    if(type['valid-values'])result.validValues=type['valid-values'];
    if(type.name==='list')result.items=nestedTypes({types:[type['element-type']]},objects,depth+1,seen);
    const name=type['object-name'];
    if(name&&objects.has(name)&&!seen.has(name)) {
      const object=objects.get(name),next=new Set(seen).add(name);
      result.fields=[...(object['required-fields']||[]),...(object.fields||[]),...(object['under-more-fields']||[])].map(f=>({name:f.name,alternatives:(f['field-alternatives']||[]).map(a=>a.name),types:nestedTypes(f,objects,depth+1,next)}));
    }
    return result;
  });
}

function fieldRecord(field, required = false, objects = new Map()) {
  return {
    name: field.name,
    types: nestedTypes(field,objects),
    required: required || Boolean(field.required),
    type: (field.types || []).map(typeLabel).join(" | ") || "value",
    description: stripHtml(field.description),
    default: field["default-value"] ?? "",
    validValues: field.types?.flatMap((type) => type["valid-values"] || []).slice(0, 50) || [],
    alternatives: (field["field-alternatives"] || []).map((alternative) => alternative.name)
  };
}

function isReadOnly(name, type) {
  return type === "show" ||
    /^(show|get|where-used|verify|keepalive|show-task|show-api-versions)(-|$)/.test(name);
}

export function buildCatalog(apis, content, version = API_VERSION) {
  const objects = new Map(apis.objects.map((object) => [object.name, object]));
  const categories = categoryMap(content.chapters);
  const commands = apis.commands
    .filter((command) => command.documented !== false && command.internal !== true && command?.name?.web)
    .map((command) => {
      const name = command.name.web;
      const request = objects.get(command.request) || {};
      const requiredFields = request["required-fields"] || [];
      const optionalFields = [...(request.fields || []), ...(request["under-more-fields"] || [])];
      const response=objects.get(command.response?.['on-success']?.web?.object?.['object-name']);
      const template = {};
      for (const field of requiredFields) template[field.name] = sampleValue(field);
      return {
        name,
        category: categories.get(name) || "Other",
        description: stripHtml(command.description),
        type: command.type || "other",
        readOnly: isReadOnly(name, command.type),
        asynchronous: [...(response?.fields||[]),...(response?.['under-more-fields']||[])].some(field=>field.name==='task-id'),
        deprecated: Boolean(command.deprecated),
        deprecatedDescription: stripHtml(command["deprecated-description"]),
        allowedDomains: command["allowed-domains"] || [],
        requestTemplate: template,
        requiredFields: requiredFields.map((field) => fieldRecord(field, true, objects)),
        optionalFields: optionalFields.map((field) => fieldRecord(field, false, objects))
      };
    })
    .sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));

  return {
    apiVersion: version,
    generatedAt: new Date().toISOString(),
    source: "https://sc1.checkpoint.com/documents/latest/APIs/index.html",
    commandCount: commands.length,
    categories: [...new Set(commands.map((command) => command.category))].sort(),
    commands
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
const apis = await loadJson(argument("--apis"), "apis.json");
const content = await loadJson(argument("--content"), "content.json");
const output = resolve(argument("--output") || DEFAULT_OUTPUT);
const catalog = buildCatalog(apis, content);
if (argument("--release-html")) {
  catalog.release = parseReleaseMapping(await readFile(resolve(argument("--release-html")), "utf8"))[API_VERSION] || "";
  catalog.releaseSource = `https://sc1.checkpoint.com/documents/latest/APIs/data/${API_VERSION}/api_versions.html`;
}
await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(catalog)}\n`, "utf8");
console.log(`Generated ${catalog.commandCount} ${catalog.apiVersion} commands at ${output}`);
}

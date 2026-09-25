import {ManagementProxyAgent,normalizeProxy} from './proxy-agent.js';
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

const DEFAULT_TIMEOUT_MS = 45_000;

export class CheckPointApiError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "CheckPointApiError";
    Object.assign(this, details);
  }
}

export function normalizeApiBasePath(pathname, smart1Cloud = false) {
  let path = String(pathname || "").trim();
  if (!path || path === "/") return smart1Cloud ? "/web_api" : "";
  path = path.replace(/\/+/g, "/").replace(/\/$/, "").replace(/\/web-api$/i, "/web_api");
  if (smart1Cloud && !/\/web_api$/i.test(path)) path = `${path}/web_api`;
  return path;
}

export function normalizeBaseUrl(host, port, { smart1Cloud = false } = {}) {
  const value = String(host || "").trim();
  if (!value) throw new Error("Management server host is required.");
  const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
  if (port) url.port = String(port);
  url.pathname = normalizeApiBasePath(url.pathname, smart1Cloud);
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

export function apiUrl(connection, command, apiVersion = "") {
  if (apiVersion && !/^v\d+(?:\.\d+){0,2}$/.test(apiVersion)) throw new Error("Invalid API version.");
  const url = new URL(connection.baseUrl);
  const basePath = normalizeApiBasePath(url.pathname, connection.smart1Cloud);
  url.pathname = `${basePath || "/web_api"}/${apiVersion ? `${apiVersion}/` : ""}${String(command).replace(/^\/+/, "")}`.replace(/\/+/g, "/");
  url.search = "";
  url.hash = "";
  return url;
}

export function redactSecrets(value) {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key,
    ["password", "api-key", "apikey", "sid", "proxyurl", "one-time-password", "base64-password", "base64-certificate", "private-key", "client-secret", "passphrase"].includes(key.toLowerCase()) ? "[redacted]" : redactSecrets(item)
  ]));
}

export class CheckPointClient {
  constructor({
    baseUrl,
    sid = "",
    smart1Cloud = false,
    rejectUnauthorized = true,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    logger = null,
    proxyUrl = "",
    proxyAgent = null
  }) {
    this.proxyUrl=normalizeProxy(proxyUrl);
    this.proxyAgent=proxyAgent||(this.proxyUrl?new ManagementProxyAgent(this.proxyUrl,{timeoutMs}):null);
    this.baseUrl = baseUrl;
    this.sid = sid;
    this.smart1Cloud = smart1Cloud;
    this.rejectUnauthorized = rejectUnauthorized;
    this.timeoutMs = timeoutMs;
    this.logger = logger;
  }

  withSid(sid) {
    return new CheckPointClient({ ...this, sid });
  }

  async command(command, body = {}, apiVersion = "") {
    for(let attempt=0;;attempt++) {
      try{return await this.requestCommand(command,body,apiVersion);}
      catch(error){
        const transient=['socket','response-interrupted','timeout'].includes(error.phase)||error.phase==='api-response'&&[429,502,503,504].includes(error.statusCode);
        if(!(command.startsWith('show-')||command==='keepalive')||!transient||attempt>=2)throw error;
        await new Promise(resolve=>setTimeout(resolve,150*(attempt+1)));
      }
    }
  }

  async requestCommand(command, body = {}, apiVersion = "") {
    const url = apiUrl(this, command, apiVersion);
    const payload = JSON.stringify(body);
    const startedAt = Date.now();
    this.logger?.({ event: "request", command, target: `${url.origin}${url.pathname}`, body: redactSecrets(body) });

    return new Promise((resolve, reject) => {
      const transport = url.protocol === "http:" ? httpRequest : httpsRequest;
      const headers = {
        accept: "application/json",
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload)
      };
      if (this.sid) headers["X-chkp-sid"] = this.sid;
      const options = { method: "POST", headers };
      if(this.proxyAgent) {
        if(url.protocol!=="https:"){reject(new Error("Proxied management connections require HTTPS."));return;}
        options.agent=this.proxyAgent;
      }
      if (url.protocol === "https:") options.rejectUnauthorized = this.rejectUnauthorized;

      const req = transport(url, options, (res) => {
        let raw = "";
        const responseFailure = () => reject(new CheckPointApiError(`${command} response was interrupted; its outcome may be unknown.`, {
          command, phase: "response-interrupted", statusCode: res.statusCode
        }));
        res.on("aborted", responseFailure);
        res.on("error", responseFailure);
        res.on("close", () => { if (!res.complete) responseFailure(); });
        res.setEncoding("utf8");
        res.on("data", (chunk) => { raw += chunk; });
        res.on("end", () => {
          let parsed = {};
          try {
            parsed = raw ? JSON.parse(raw) : {};
          } catch {
            reject(new CheckPointApiError(`${command} returned a non-JSON response.`, {
              command, phase: "response-parse", statusCode: res.statusCode, responsePreview: raw.slice(0, 500)
            }));
            return;
          }
          if (res.statusCode < 200 || res.statusCode >= 300) {
            if(this.sid) {
              const scrub=value=>typeof value==='string'?value.split(this.sid).join('[redacted]'):Array.isArray(value)?value.map(scrub):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,item])=>[key,scrub(item)])):value;
              parsed=scrub(parsed);
            }
            reject(new CheckPointApiError(
              `${command}: ${parsed.message || parsed.errors?.[0]?.message || `HTTP ${res.statusCode}`}`,
              { command, phase: "api-response", statusCode: res.statusCode, response: parsed }
            ));
            return;
          }
          this.logger?.({ event: "response", command, statusCode: res.statusCode, durationMs: Date.now() - startedAt });
          resolve(parsed);
        });
      });
      req.setTimeout(this.timeoutMs, () => req.destroy(new CheckPointApiError(`${command} timed out.`, {
        command, phase: "timeout"
      })));
      req.on("error", (error) => reject(
        error instanceof CheckPointApiError
          ? error
          : new CheckPointApiError(error.message, { command, phase: "socket", cause: error })
      ));
      req.write(payload);
      req.end();
    });
  }

  async list(command, body = {}, { pageSize = 500, itemKeys = ["objects", "packages"] } = {}) {
    const items = [];
    let offset = 0;
    let total = 0;
    do {
      const page = await this.command(command, {
        limit: pageSize,
        offset,
        "details-level": "full",
        ...body
      });
      const pageItems = itemKeys.map((key) => page[key]).find(Array.isArray) || [];
      items.push(...pageItems);
      total = Number(page.total ?? items.length);
      offset += pageSize;
    } while (offset < total);
    return items;
  }
}

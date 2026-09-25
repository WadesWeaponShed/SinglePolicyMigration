import { randomUUID } from "node:crypto";
import { CheckPointClient, normalizeBaseUrl } from "./check-point-client.js";
import {taskNotVisible} from './workflows/batch.js';

const CONTEXTS = new Set(["primary", "mds", "global", "system-data"]);

function enabled(value) {
  return value === true || value === "true" || value === "on";
}

function loginBody(payload, domain) {
  const authMode = payload.authMode === "api-key" ? "api-key" : "password";
  const body = {};
  if (authMode === "api-key") {
    if (!payload.apiKey) throw new Error("API key is required.");
    body["api-key"] = String(payload.apiKey);
  } else {
    if (!payload.username) throw new Error("Username is required.");
    if (!payload.password) throw new Error("Password is required.");
    body.user = String(payload.username);
    body.password = String(payload.password);
  }
  if (domain) body.domain = String(domain);
  if (payload.readOnly === true) body["read-only"] = true;
  if (payload.sessionName) body["session-name"] = String(payload.sessionName);
  if (payload.sessionDescription) body["session-description"] = String(payload.sessionDescription);
  return body;
}

function taskIds(result) {
  return [...new Set((result?.tasks || [])
    .map((task) => task?.["task-id"] || task?.taskId || task?.uid)
    .filter(Boolean))];
}

function decodeResponseMessage(value) {
  if (!value) return "";
  try { return Buffer.from(String(value), "base64").toString("utf8").trim(); } catch { return ""; }
}

function taskSummary(result) {
  return (result?.tasks || []).map((task) => {
    const details = task?.["task-details"] || task?.taskDetails || [];
    const executions = details.map((detail) => ({
      target: detail?.gatewayName || detail?.["gateway-name"] || "",
      status: detail?.status || detail?.statusCode || detail?.["status-code"] || "",
      message: String(detail?.statusDescription || detail?.["status-description"] || ""),
      output: decodeResponseMessage(detail?.responseMessage || detail?.["response-message"]),
      error: String(detail?.responseError || detail?.["response-error"] || "")
    }));
    const output = executions
      .map((execution) => execution.output)
      .filter(Boolean)
      .join("\n");
    return {
      id: task?.["task-id"] || task?.taskId || task?.uid || "",
      name: task?.["task-name"] || task?.taskName || task?.name || "run-script",
      status: task?.status || "unknown",
      progress: task?.["progress-percentage"] ?? task?.progressPercentage ?? null,
      startedAt: task?.["start-time"] || task?.startTime || "",
      lastUpdatedAt: task?.["last-update-time"] || task?.lastUpdateTime || "",
      targets: executions.map((execution) => execution.target).filter(Boolean),
      output,
      statusDescription: executions
        .map((execution) => execution.message)
        .filter(Boolean)
        .join("\n"),
      errors: executions
        .map((execution) => execution.error)
        .filter(Boolean),
      executions
    };
  });
}

function taskOutput(result) {
  const tasks = taskSummary(result);
  const messages = tasks.map((task) => task.output).filter(Boolean);
  if (messages.length) return messages.join("\n");
  return tasks.map((task) => task.statusDescription).filter(Boolean).join("\n");
}

function scriptResult(result) {
  return { result, output: taskOutput(result), taskSummary: taskSummary(result) };
}

function createLimiter(limit) {
  let active = 0;
  const queue = [];
  const next = () => {
    if (active >= limit || queue.length === 0) return;
    const { work, resolve, reject } = queue.shift();
    active += 1;
    Promise.resolve().then(work).then(resolve, reject).finally(() => {
      active -= 1;
      next();
    });
  };
  return (work) => new Promise((resolve, reject) => {
    queue.push({ work, resolve, reject });
    next();
  });
}

export class SessionManager {
  constructor({
    logger = null,
    runScriptConcurrency = 8,
    largeEnvironmentRunScriptConcurrency = 3,
    largeEnvironmentApiConcurrency = 10,
    taskPollAttempts = 120,
    taskPollIntervalMs = 1000,
    largeEnvironmentTaskPollIntervalMs = 1250,
    clientFactory = (options) => new CheckPointClient(options)
  } = {}) {
    this.sessions = new Map();
    this.logger = logger;
    this.taskPollAttempts = taskPollAttempts;
    this.taskPollIntervalMs = taskPollIntervalMs;
    this.largeEnvironmentTaskPollIntervalMs = largeEnvironmentTaskPollIntervalMs;
    this.clientFactory = clientFactory;
    this.runQueued = createLimiter(runScriptConcurrency);
    this.largeEnvironmentRunQueued = createLimiter(largeEnvironmentRunScriptConcurrency);
    this.largeEnvironmentApiQueued = createLimiter(largeEnvironmentApiConcurrency);
  }

  async login(payload) {
    const smart1Cloud = enabled(payload.smart1Cloud);
    const mdsMode = enabled(payload.mdsMode) || enabled(payload.mdsScan);
    const largeEnvironmentMode = enabled(payload.largeEnvironmentMode);
    const baseUrl = normalizeBaseUrl(payload.host, payload.port, { smart1Cloud });
    const baseClient = this.clientFactory({
      baseUrl,
      smart1Cloud,
      proxyUrl:payload.proxyUrl,
      rejectUnauthorized: !enabled(payload.ignoreTls),
      logger: this.logger
    });
    const primaryLogin = await baseClient.command("login", loginBody(payload, payload.domain));
    if (!primaryLogin.sid) throw new Error(primaryLogin.message || "Login did not return a session ID.");

    const sids = { primary: primaryLogin.sid, mds: "", global: "", "system-data": "" };
    const contextErrors = {};
    const optionalLogin = async (context, domain) => {
      try {
        const result = await baseClient.command("login", loginBody(payload, domain));
        if (!result.sid) throw new Error(`${domain} login did not return a session ID.`);
        sids[context] = result.sid;
      } catch (error) {
        contextErrors[context] = error.message;
      }
    };

    if (mdsMode) {
      if (payload.domain) await optionalLogin("mds", "");
      else sids.mds = primaryLogin.sid;
      if(payload.auxiliaryContexts!==false)await optionalLogin("global", "Global");
    }
    if(payload.auxiliaryContexts!==false)await optionalLogin("system-data", "System Data");

    const id = randomUUID();
    const session = {
      id,
      baseClient,
      sids,
      contextErrors,
      smart1Cloud,
      mdsMode,
      largeEnvironmentMode,
      domain: String(payload.domain || ""),
      managementObjectName: String(payload.managementObjectName || ""),
      user: payload.authMode === "api-key" ? "API Key" : String(payload.username),
      createdAt: new Date().toISOString()
    };
    this.sessions.set(id, session);
    return this.describe(session);
  }

  get(id) {
    const session = this.sessions.get(id);
    if (!session) throw new Error("Session not found. Log in again.");
    return session;
  }

  async capabilities(id, context = "primary") {
    const session = this.get(id);
    session.capabilities ||= {};
    if (session.capabilities[context]) return session.capabilities[context];
    try {
      const result = await this.command(id, "show-api-versions", {}, context);
      const normalize = (value) => {
        const version = `v${String(value).replace(/^v/, "")}`;
        return /^v\d+(?:\.\d+){0,2}$/.test(version) ? version : "";
      };
      const supported = (Array.isArray(result["supported-versions"]) ? result["supported-versions"] : []).map(normalize).filter(Boolean);
      if (!supported.length) throw new Error("Server did not advertise supported API versions.");
      return session.capabilities[context] = { supported, current: normalize(result["current-version"]), error: "" };
    } catch (error) { return { supported: [], current: "", error: error.message }; }
  }

  async validateVersion(id, context, version) {
    if (!version) return;
    const capability = await this.capabilities(id, context);
    if (!capability.supported.includes(version)) throw new Error(`API ${version} is not verified as supported in this context.`);
  }

  client(id, context = "primary") {
    if (!CONTEXTS.has(context)) throw new Error(`Unknown session context: ${context}.`);
    const session = this.get(id);
    if (session.unverifiedContexts?.has(context)) throw new Error("Session recovery could not verify its identity. Authenticate again before using this connection.");
    const sid = session.sids[context];
    if (!sid) throw new Error(session.contextErrors[context] || `${context} session is not available.`);
    return session.baseClient.withSid(sid);
  }

  describe(sessionOrId) {
    const session = typeof sessionOrId === "string" ? this.get(sessionOrId) : sessionOrId;
    return {
      sessionId: session.id,
      user: session.user,
      baseUrl: session.baseClient.baseUrl,
      smart1Cloud: session.smart1Cloud,
      mdsMode: session.mdsMode,
      largeEnvironmentMode: session.largeEnvironmentMode,
      domain: session.domain,
      managementObjectName: session.managementObjectName,
      contexts: Object.fromEntries(Object.entries(session.sids).map(([name, sid]) => [name, {
        available: Boolean(sid),
        error: session.contextErrors[name] || ""
      }]))
    };
  }

  command(id, command, body = {}, context = "primary", apiVersion = "") {
    if (!command || !/^[a-z0-9][a-z0-9-]*$/i.test(command)) throw new Error("A valid API command is required.");
    const session = this.get(id);
    const work = () => this.client(id, context).command(command, body, apiVersion);
    const dispatch = () => session.largeEnvironmentMode ? this.largeEnvironmentApiQueued(work) : work();
    return apiVersion ? this.validateVersion(id, context, apiVersion).then(dispatch) : dispatch();
  }

  list(id, command, body = {}, context = "primary") {
    const session = this.get(id);
    const work = () => this.client(id, context).list(command, body);
    return session.largeEnvironmentMode ? this.largeEnvironmentApiQueued(work) : work();
  }

  runScript(id, body, context = "primary", apiVersion = "") {
    const session = this.get(id);
    const queue = session.largeEnvironmentMode ? this.largeEnvironmentRunQueued : this.runQueued;
    return queue(async () => {
      await this.validateVersion(id, context, apiVersion);
      const client = this.client(id, context);
      const initial = await client.command("run-script", body, apiVersion);
      if (taskOutput(initial)) return scriptResult(initial);
      const ids = taskIds(initial);
      if (ids.length === 0) return scriptResult(initial);

      let lastResult = initial;
      for (let attempt = 0; attempt < this.taskPollAttempts; attempt += 1) {
        const results = await Promise.all(ids.map((taskId) => client.command("show-task", {
          "task-id": taskId,
          "details-level": "full"
        }, apiVersion)));
        lastResult = results[0] || lastResult;
        const completed = results.find((result) => taskOutput(result));
        if (completed) return scriptResult(completed);
        if (attempt < this.taskPollAttempts - 1) {
          const interval = session.largeEnvironmentMode
            ? this.largeEnvironmentTaskPollIntervalMs
            : this.taskPollIntervalMs;
          await new Promise((resolve) => setTimeout(resolve, interval));
        }
      }
      return scriptResult(lastResult);
    });
  }

  async logout(id) {
    const session = this.get(id);
    const uniqueSids = [...new Set(Object.values(session.sids).filter(Boolean))];
    const results = await Promise.allSettled(uniqueSids.map((sid) => session.baseClient.withSid(sid).command("logout")));
    this.sessions.delete(id);
    return { ok: true, closedContexts: uniqueSids.length, failures: results.filter((item) => item.status === "rejected").length };
  }

  async inspectSession(id, uid = "", context = "primary", apiVersion = "") {
    if (uid && (typeof uid !== "string" || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(uid))) throw new Error("A valid session object UID is required.");
    const result = await this.command(id, "show-session", uid ? { uid } : {}, context, apiVersion);
    if (typeof result.uid !== "string" || !result.uid || (uid && result.uid !== uid)) throw new Error("Session inspection returned a different or missing session UID.");
    const domainUid = result.domain?.uid || "";
    const expectedDomain = this.get(id).domain;
    if (domainUid && expectedDomain && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(expectedDomain) && domainUid !== expectedDomain) throw new Error("Session belongs to a different destination domain.");
    return {
      uid: result.uid,
      state: typeof result.state === "string" ? result.state : "unknown",
      changes: Number.isInteger(result.changes) && result.changes >= 0 ? result.changes : null,
      domainUid,
      inWork: typeof result["in-work"] === "boolean" ? result["in-work"] : null,
      expired: typeof result["expired-session"] === "boolean" ? result["expired-session"] : null,
      connectionMode: result["connection-mode"] || "",
      user: result["user-name"] || ""
    };
  }

  async resumeSession(id, uid, context = "primary", apiVersion = "") {
    if (!uid) throw new Error("The recorded migration session UID is required.");
    const target = await this.inspectSession(id, uid, context, apiVersion);
    if (target.state !== "open") throw new Error("Only an open migration session can be resumed. Inspect its terminal state or workflow in SmartConsole.");
    const current = await this.inspectSession(id, "", context, apiVersion);
    if (current.uid === uid) return current;
    if (current.changes !== 0) throw new Error("Recovery requires an empty authenticated session.");
    try {
      // switch-session is restricted by Check Point to this administrator's disconnected API sessions.
      // Never substitute take-over-session or continue-last-session.
      await this.command(id, "switch-session", { uid }, context, apiVersion);
      const resumed = await this.inspectSession(id, "", context, apiVersion);
      if (resumed.uid !== uid || resumed.state !== "open") throw new Error("Resumed migration session identity or state could not be verified.");
      return resumed;
    } catch (error) {
      const session = this.get(id);
      session.unverifiedContexts ||= new Set();
      session.unverifiedContexts.add(context);
      throw error;
    }
  }

  keepAlive(id, context = "primary", apiVersion = "") {
    return this.command(id, "keepalive", {}, context, apiVersion);
  }

  async waitForTask(id, taskId, context = "primary", apiVersion = "") {
    for (let attempt = 0; attempt < this.taskPollAttempts; attempt += 1) {
      let result;
      try{result=await this.command(id, "show-task", { "task-id": taskId, "details-level": "full" }, context, apiVersion);}
      catch(error){if(!taskNotVisible(error)||attempt+1===this.taskPollAttempts)throw error;await new Promise(resolve=>setTimeout(resolve,this.taskPollIntervalMs));continue;}
      const tasks = result.tasks;
      if (!Array.isArray(tasks) || tasks.length!==1 || tasks[0]['task-id']!==taskId) {const error=new Error('Task status identity is unavailable or does not match the requested task.');error.taskOutcome='uncertain';throw error;}
      if (tasks.some(task => ["failed", "partially succeeded"].includes(task.status))) {
        const error = new Error("Check Point task failed or partially succeeded.");
        error.taskOutcome = tasks.every(task => task.status === "failed") ? "failed" : "uncertain";
        error.taskResult = result;
        error.taskTerminal=tasks.every(task=>['failed','succeeded','partially succeeded'].includes(task.status));
        throw error;
      }
      if (tasks.every(task => task.status === "succeeded")) return result;
      if (attempt < this.taskPollAttempts - 1) await new Promise(resolve => setTimeout(resolve, this.taskPollIntervalMs));
    }
    throw new Error("Task polling timed out; the task may still be running.");
  }
}

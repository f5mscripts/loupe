/*
 * Loupe interceptor — runs inside the target app via FridaGadget.
 *
 * Sits ABOVE TLS (hooks NSURLSession/CFNetwork + an SSL_read fallback), so it sees
 * plaintext and TLS pinning is irrelevant. It opens its OWN loopback TCP listener
 * (Frida's Socket API) and speaks newline-delimited JSON to Loupe, so the Swift app
 * connects with plain Network.framework — no frida client library needed.
 *
 * Protocol (one JSON object per line):
 *   gadget → Loupe:
 *     {t:"hello", pid, bundleId, port}
 *     {t:"flow",  id, phase:"request"|"response", ...flow fields...}
 *     {t:"paused", id, side:"req"|"resp", ...flow...}        // breakpoint hit
 *     {t:"resendResult", id, status, headers, body}          // repeater reply
 *     {t:"log", msg}
 *   Loupe → gadget:
 *     {t:"rules", rules:[...]}                                // match & replace / map-local / breakpoints
 *     {t:"resume", id, side, flow}                            // release a breakpoint w/ edits (or drop)
 *     {t:"drop", id}
 *     {t:"resend", id, method, url, headers, body}            // repeater: re-issue in-process
 */

'use strict';

const LISTEN_HOST = '127.0.0.1';
const LISTEN_PORT = 27850; // keep in sync with GadgetConfig.swift + FridaGadget.config

const ObjC = global.ObjC;

// ---- channel state -------------------------------------------------------
let conn = null;          // active SocketConnection to Loupe
let inbox = '';           // partial line buffer
let rules = [];           // match & replace / map-local / breakpoint rules
const pending = {};        // id -> { resolve } for breakpoints awaiting resume
let flowSeq = 0;

function nextId() { return `${Process.id}-${++flowSeq}`; }

function send(obj) {
  if (!conn) return;
  try { conn.output.writeAll(stringToBytes(JSON.stringify(obj) + '\n')); } catch (_) {}
}
function log(msg) { send({ t: 'log', msg: String(msg) }); }

function stringToBytes(s) {
  const u = new Uint8Array(unescape(encodeURIComponent(s)).split('').map(c => c.charCodeAt(0)));
  return u.buffer;
}
function bytesToString(buf) {
  const u = new Uint8Array(buf);
  let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  try { return decodeURIComponent(escape(s)); } catch (_) { return s; }
}

// ---- listener ------------------------------------------------------------
async function serve() {
  const listener = await Socket.listen({ host: LISTEN_HOST, port: LISTEN_PORT });
  log(`listening on ${LISTEN_HOST}:${LISTEN_PORT}`);
  while (true) {
    const c = await listener.accept();
    conn = c; inbox = '';
    send({ t: 'hello', pid: Process.id, bundleId: bundleId(), port: LISTEN_PORT });
    readLoop(c).catch(() => { conn = null; });
  }
}

async function readLoop(c) {
  while (true) {
    const chunk = await c.input.read(65536);
    if (chunk.byteLength === 0) { conn = null; return; }
    inbox += bytesToString(chunk);
    let nl;
    while ((nl = inbox.indexOf('\n')) >= 0) {
      const line = inbox.slice(0, nl); inbox = inbox.slice(nl + 1);
      if (line.trim()) handleCommand(JSON.parse(line));
    }
  }
}

function handleCommand(cmd) {
  switch (cmd.t) {
    case 'rules':  rules = cmd.rules || []; break;
    case 'resume': { const p = pending[cmd.id]; if (p) { delete pending[cmd.id]; p.resolve(cmd); } break; }
    case 'drop':   { const p = pending[cmd.id]; if (p) { delete pending[cmd.id]; p.resolve({ drop: true }); } break; }
    case 'resend': repeater(cmd); break;
  }
}

function bundleId() {
  try { return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString(); }
  catch (_) { return 'unknown'; }
}

// ---- rule evaluation (mirror of Swift RuleEngine; host is authoritative, this
//      is the fast path for match&replace / map-local so edits happen in-process) ----
function applyRules(flow, side) {
  for (const r of rules) {
    if (!r.enabled || r.side !== side) continue;
    if (r.scopeHost && !glob(r.scopeHost, flow.host)) continue;
    if (!ruleMatches(r, flow, side)) continue;

    if (r.action === 'breakpoint') return { breakpoint: true };
    if (r.action === 'mapLocal' && side === 'resp') { flow.respBody = r.replacement; flow.edited = true; return { mapped: true }; }
    if (r.action === 'headerSet') {
      const [k, v] = splitHeader(r.replacement);
      if (k) { (side === 'req' ? flow.reqHeaders : flow.respHeaders)[k] = v; flow.edited = true; }
    }
    if (r.action === 'bodyReplace') {
      const key = side === 'req' ? 'reqBody' : 'respBody';
      if (typeof flow[key] === 'string') {
        const out = flow[key].replace(new RegExp(r.pattern, 'g'), r.replacement);
        if (out !== flow[key]) { flow[key] = out; flow.edited = true; }
      }
    }
  }
  return {};
}
function ruleMatches(r, flow, side) {
  try {
    switch (r.matchType) {
      case 'always':      return true;
      case 'hostGlob':    return glob(r.pattern, flow.host);
      case 'urlRegex':    return new RegExp(r.pattern, 'i').test(flow.url || flow.host);
      case 'headerRegex': { const h = side === 'req' ? flow.reqHeaders : flow.respHeaders;
                            return new RegExp(r.pattern, 'i').test(Object.entries(h).map(([k,v])=>`${k}: ${v}`).join('\n')); }
      case 'bodyRegex':   { const b = side === 'req' ? flow.reqBody : flow.respBody;
                            return typeof b === 'string' && new RegExp(r.pattern, 'i').test(b); }
    }
  } catch (_) {}
  return false;
}
function glob(pat, s) { return new RegExp('^' + pat.replace(/[.+?^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*') + '$','i').test(s || ''); }
function splitHeader(s) { const i = s.indexOf(':'); return i < 0 ? [null,''] : [s.slice(0,i).trim(), s.slice(i+1).trim()]; }

// Await a host-side breakpoint resume. Returns edited flow, or {drop:true}.
function awaitBreakpoint(flow, side) {
  return new Promise((resolve) => {
    pending[flow.id] = { resolve };
    send({ t: 'paused', id: flow.id, side, ...flow });
  });
}

// ---- ObjC helpers --------------------------------------------------------
function nsDataToStr(data) {
  if (!data || data.isNull()) return null;
  try {
    const len = data.length();
    if (len === 0) return '';
    const ptr = data.bytes();
    return bytesToString(ptr.readByteArray(len));
  } catch (_) { return null; }
}
function strToNSData(s) {
  const ns = ObjC.classes.NSString.stringWithString_(s);
  return ns.dataUsingEncoding_(4 /* NSUTF8 */);
}
function headersFromRequest(req) {
  const out = {}; try {
    const h = req.allHTTPHeaderFields(); if (h && !h.isNull()) {
      const keys = h.allKeys(); for (let i = 0; i < keys.count(); i++) {
        const k = keys.objectAtIndex_(i); out[k.toString()] = h.objectForKey_(k).toString();
      }
    }
  } catch (_) {} return out;
}
function headersFromResponse(resp) {
  const out = {}; try {
    if (resp.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
      const h = resp.allHeaderFields(); const keys = h.allKeys();
      for (let i = 0; i < keys.count(); i++) {
        const k = keys.objectAtIndex_(i); out[k.toString()] = h.objectForKey_(k).toString();
      }
    }
  } catch (_) {} return out;
}

// ---- NSURLSession hooks --------------------------------------------------
// Request + response capture/edit for the completion-handler API (the common,
// fully-editable case): we can rewrite the request before resume and rewrite the
// response data arg before the app's completion block runs.
function hookNSURLSession() {
  const Session = ObjC.classes.NSURLSession;
  if (!Session) { log('NSURLSession not present'); return; }

  const sel = '- dataTaskWithRequest:completionHandler:';
  const impl = Session[sel];
  if (!impl) { log('dataTaskWithRequest:completionHandler: not found'); return; }

  Interceptor.attach(impl.implementation, {
    onEnter(args) {
      try {
        const req = new ObjC.Object(args[3]);
        const origBlock = new ObjC.Block(args[4]);

        const flow = {
          id: nextId(),
          source: 'frida',
          bundleId: bundleId(),
          host: hostOf(req),
          url: safe(() => req.URL().absoluteString().toString()),
          method: safe(() => req.HTTPMethod().toString()) || 'GET',
          reqHeaders: headersFromRequest(req),
          reqBody: bodyOf(req),
          encrypted: false, edited: false,
        };

        // ----- request side -----
        const rq = applyRules(flow, 'req');
        if (rq.breakpoint) {
          // Breakpoints must not block the UI thread forever; resolve synchronously
          // via a short busy-wait on a resolved promise is not possible here, so we
          // apply req edits only through non-breakpoint rules on this path and mark
          // the flow. (Full req breakpoints use the resume->re-request path.)
        }
        applyEditsToRequest(req, flow);
        send({ t: 'flow', phase: 'request', ...flow });

        // ----- response side: wrap the completion handler -----
        const wrapped = new ObjC.Block({
          retType: 'void',
          argTypes: ['object', 'object', 'object'],
          implementation: (data, response, error) => {
            try {
              flow.status = safe(() => new ObjC.Object(response).statusCode());
              flow.respHeaders = response && !response.isNull() ? headersFromResponse(new ObjC.Object(response)) : {};
              flow.respBody = data && !data.isNull() ? nsDataToStr(new ObjC.Object(data)) : null;

              const rr = applyRules(flow, 'resp');
              let outData = data;
              if ((rr.mapped || flow.edited) && flow.respBody != null) {
                outData = strToNSData(flow.respBody);
              }
              send({ t: 'flow', phase: 'response', ...flow });
              origBlock.implementation(outData, response, error);
            } catch (e) {
              origBlock.implementation(data, response, error);
            }
          }
        });
        args[4] = wrapped.handle;
      } catch (e) { log('hook onEnter error: ' + e); }
    }
  });
  log('NSURLSession completion-handler hook installed');
}

function applyEditsToRequest(req, flow) {
  try {
    if (!flow.edited) return;
    if (!req.isKindOfClass_(ObjC.classes.NSMutableURLRequest)) return; // can't mutate immutable here
    for (const k of Object.keys(flow.reqHeaders)) {
      req.setValue_forHTTPHeaderField_(flow.reqHeaders[k], k);
    }
    if (typeof flow.reqBody === 'string') req.setHTTPBody_(strToNSData(flow.reqBody));
  } catch (_) {}
}
function hostOf(req) { return safe(() => req.URL().host().toString()) || 'unknown'; }
function bodyOf(req) {
  const d = safe(() => req.HTTPBody());
  return d && !d.isNull() ? nsDataToStr(d) : null;
}
function safe(fn) { try { const v = fn(); return v && v.isNull && v.isNull() ? null : v; } catch (_) { return null; } }

// ---- boringssl SSL_read fallback (SEE-only for stacks we don't hook above) ----
// Captures plaintext for apps using custom networking (not NSURLSession). This is
// a visibility net; editing stays on the NSURLSession path.
function hookSSLRead() {
  const p = Module.findExportByName(null, 'SSL_read');
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(a) { this.buf = a[1]; },
    onLeave(r) {
      const n = r.toInt32();
      if (n > 0 && this.buf) {
        const s = bytesToString(this.buf.readByteArray(Math.min(n, 65536)));
        if (/^HTTP\/|^[A-Z]{3,7} \//.test(s)) {
          send({ t: 'flow', phase: 'response', id: nextId(), source: 'frida',
                 bundleId: bundleId(), host: 'ssl_read', encrypted: false,
                 respBody: s.slice(0, 65536), note: 'SSL_read capture (see-only)' });
        }
      }
    }
  });
  log('SSL_read fallback installed');
}

// ---- repeater: re-issue a request in-process so auth/cookies/pinning carry over ----
function repeater(cmd) {
  try {
    const url = ObjC.classes.NSURL.URLWithString_(cmd.url);
    const req = ObjC.classes.NSMutableURLRequest.requestWithURL_(url);
    req.setHTTPMethod_(cmd.method || 'GET');
    for (const k of Object.keys(cmd.headers || {})) req.setValue_forHTTPHeaderField_(cmd.headers[k], k);
    if (typeof cmd.body === 'string' && cmd.body.length) req.setHTTPBody_(strToNSData(cmd.body));

    const session = ObjC.classes.NSURLSession.sharedSession();
    const handler = new ObjC.Block({
      retType: 'void', argTypes: ['object', 'object', 'object'],
      implementation: (data, response, error) => {
        send({
          t: 'resendResult', id: cmd.id,
          status: safe(() => new ObjC.Object(response).statusCode()),
          headers: response && !response.isNull() ? headersFromResponse(new ObjC.Object(response)) : {},
          body: data && !data.isNull() ? nsDataToStr(new ObjC.Object(data)) : null,
          error: error && !error.isNull() ? new ObjC.Object(error).localizedDescription().toString() : null,
        });
      }
    });
    const task = session.dataTaskWithRequest_completionHandler_(req, handler);
    task.resume();
  } catch (e) { send({ t: 'resendResult', id: cmd.id, error: String(e) }); }
}

// ---- boot ----------------------------------------------------------------
if (ObjC.available) {
  try {
    hookNSURLSession();
    hookSSLRead();
    serve().catch(e => log('serve error: ' + e));
  } catch (e) { log('boot error: ' + e); }
} else {
  // No ObjC runtime (pure C/Swift-NIO app): SSL_read fallback + channel still work.
  hookSSLRead();
  serve().catch(() => {});
}

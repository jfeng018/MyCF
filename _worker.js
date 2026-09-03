/**
 * Cloudflare Worker: MyCF
 * 1. Cloudflare多账号管理系统，本版本为修改版，原作者： https://t.me/yifang_chat
 * 2. 推荐workers部署。
 * 3. 推荐添加变量名称为大写的ACCESS_PASSWORD，建立访问密码。不设则不启用密码保护。
 * 4. 推荐建立任意名称KV空间。 绑定建立的KV空间，变量名为大写的CF_ACCOUNTS_KV，用来存储账号信息，不绑定则存储在本地浏览器。
 * 5. 绑定域名，访问域名，批量导入格式为：每行一个账号，格式：邮箱|GlobalApiKey。
 */


// 支持批量创建workers,批量添加环境变量、kv、d1,是否开启workers分配的域名

export default {
  async fetch(request, env, ctx) {
    return await handleRequest(request, env, ctx);
  },
  async scheduled(event, env, ctx) {
    try {
      const utcHour = new Date().getUTCHours();
      await heartbeat(env);
      // 时段偏好：日报推送小时可配置（UTC，默认 23=北京 07:23）；探活 4h 一次避开该小时
      let reportHours = [23];
      try { const c = await getTGConfig(env); if (c && Array.isArray(c.reportHours) && c.reportHours.length) reportHours = c.reportHours; } catch(e){}
      if (utcHour === 23) {
        await runDailyMonitoring(env);
      }
      if (reportHours.indexOf(utcHour) !== -1) {
        await pushDailyReport(env);
      }
      if (utcHour % 4 === 3 && reportHours.indexOf(utcHour) === -1) {
        await runProbeMonitoring(env);
      }
    } catch (e) {
      console.error('scheduled error', e);
    }
  }
};

// 兼容旧版 Worker 环境
addEventListener('fetch', (event) => {
  event.respondWith(handleRequest(event.request, null, event));
});

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';
// ---- OAuth 2.0（自服务 client：dash → Manage Account → OAuth clients）----
const CF_OAUTH_AUTH = 'https://dash.cloudflare.com/oauth2/auth';
const CF_OAUTH_TOKEN = 'https://dash.cloudflare.com/oauth2/token';
const OAUTH_CLIENT_KV = 'oauth_client';
function randHex(n){ const b = crypto.getRandomValues(new Uint8Array(n)); let s=''; for(let i=0;i<b.length;i++) s += b[i].toString(16).padStart(2,'0'); return s; }
// OAuth token 注入密钥前缀：cfHeaders 识别后改用 Authorization: Bearer
const OAUTH_KEY_PREFIX = '__oa_';
// 账号凭据二选一/回退：OAuth token 新鲜用 Bearer；失效/撤销且存有 Global Key 则回退 key；否则仍按 oauth 尝试
function oauthOrKey(a){
  if (!a) return '';
  if (!a.oauth) return a.key || '';
  const fresh = a.accessToken && (!a.expiresAt || a.expiresAt > Date.now() + 60000);
  if (fresh) return OAUTH_KEY_PREFIX + a.accessToken;
  if (a.key) return a.key;
  return a.accessToken ? OAUTH_KEY_PREFIX + a.accessToken : '';
}

// ---------------- 边缘缓存（降低 Cloudflare API 调用频率，规避限流） ----------------
// 用 Cache API 在边缘缓存只读 GET 响应：跨 isolate / 区域命中，且不消耗 KV 写入额度（免费版仅 1000 写/日）。
let _ctxWaitUntil = null;     // 由 fetch 入口注入，用于缓存写入不阻塞主响应
let _apiCacheBypass = false;  // 由 API 请求的 payload.forceRefresh 控制，跳过缓存拿实时数据
const _apiCache = caches.default;
const API_CACHE_TTL = 30;     // 秒；与个人面板刷新频率匹配，写操作后最多 30s 可见新数据
async function _apiCacheGet(url, email, key) {
  try {
    const req = new Request(url, { method: 'GET', headers: cfHeaders(email, key) });
    const res = await _apiCache.match(req);
    if (!res) return null;
    return await res.json();
  } catch (e) { return null; }
}
async function _apiCachePut(url, email, key, data) {
  try {
    const req = new Request(url, { method: 'GET', headers: cfHeaders(email, key) });
    const res = new Response(JSON.stringify(data), { status: 200, headers: { 'content-type': 'application/json', 'Cache-Control': 'max-age=' + API_CACHE_TTL } });
    const p = _apiCache.put(req, res);
    if (_ctxWaitUntil) _ctxWaitUntil(p); else await p;
  } catch (e) {}
}

// ---------------- Router ----------------
// -------- 密码保护辅助 --------
function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) { h = (Math.imul(31, h) + str.charCodeAt(i)) | 0; }
  return 'sess_' + Math.abs(h).toString(36) + str.length.toString(36);
}
function getSessionToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)cf_session=([^;]+)/);
  return m ? m[1] : null;
}

async function handleRequest(request, env, ctx) {
  _ctxWaitUntil = (ctx && typeof ctx.waitUntil === 'function') ? ctx.waitUntil.bind(ctx) : null;
  const url = new URL(request.url);
  const p = url.pathname;
  const hasPassword = !!(env && env.ACCESS_PASSWORD);

  // 密码验证接口（无需 session）
  if (p === '/auth' && request.method === 'POST') {
    try {
      const body = await request.json();
      if (!hasPassword || body.password === env.ACCESS_PASSWORD) {
        const token = simpleHash(hasPassword ? env.ACCESS_PASSWORD : 'nopwd');
        return new Response(JSON.stringify({ success: true }), {
          headers: {
            'content-type': 'application/json',
            'Set-Cookie': 'cf_session=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400'
          }
        });
      }
      return new Response(JSON.stringify({ success: false, error: '密码错误' }), {
        status: 401, headers: { 'content-type': 'application/json' }
      });
    } catch(e) {
      return new Response(JSON.stringify({ success: false }), { status: 400, headers: { 'content-type': 'application/json' } });
    }
  }

  // Telegram 机器人 webhook（无需 session，依靠 webhook URL 保密 + token 校验）
  if (p === '/telegram' && request.method === 'POST') {
    return handleTelegramWebhook(request, env);
  }

  // OAuth 2.0 授权流程（start 302 到 dash；callback 由 CF 跳回，二者均公开、依赖 state 校验）
  if (request.method === 'GET' && p === '/oauth/start') return handleOAuthStart(env, url);
  if (request.method === 'GET' && p === '/oauth/callback') return handleOAuthCallback(env, url);

  // session 校验（仅在设置了 ACCESS_PASSWORD 时生效）
  if (hasPassword) {
    const token = getSessionToken(request);
    const valid = !!(token && token === simpleHash(env.ACCESS_PASSWORD));
    const isPublic = p === '/login' || p === '/login/' || p === '/static.js' || p === '/auth';
    if (!valid && !isPublic) {
      if (request.method === 'GET') {
        return Response.redirect(url.origin + '/login', 302);
      }
      return new Response(JSON.stringify({ success: false, error: '未授权，请先输入访问密码' }), {
        status: 401, headers: { 'content-type': 'application/json' }
      });
    }
  }

  // 增加 no-store 防止缓存
  if (p === '/static.js' && request.method === 'GET') {
    return new Response(renderStaticJS(env), {
      headers: {
        'content-type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
  }

  if (request.method === 'GET' && (p === '/' || p === '/index.html')) {
    return Response.redirect(url.origin + '/login', 302);
  }
  // 退出（清除密码会话 cookie）
  if (p === '/logout') {
    return new Response('ok', {
      headers: { 'Set-Cookie': 'cf_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0' }
    });
  }
  if (request.method === 'GET' && (p === '/login' || p === '/login/')) {
    // 两级结构：未设 ACCESS_PASSWORD 时无需任何登录，直接进入主工作台
    if (!hasPassword) return Response.redirect(url.origin + '/workers', 302);
    return new Response(renderLoginHTML(env), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  if (request.method === 'GET' && p.startsWith('/workers')) {
    return new Response(renderAppHTML(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  if (p === '/api' && request.method === 'POST') {
    return handleAPI(request, env);
  }
  return new Response('Not Found', { status: 404 });
}

// ---------------- API handler ----------------
async function handleAPI(req, env) {
  const payload = await safeJSON(req);
  const action = payload.action;
  _apiCacheBypass = !!payload.forceRefresh; // 强制刷新时跳过边缘缓存
  if (!action) return json({ success:false, error:'action required' }, 400);

  if (action === 'fetch-external-script') {
    const { url } = payload;
    if (!url) return json({ success: false, error: 'url required' });
    try {
      const resp = await fetch(url, { headers: { 'User-Agent': 'CF-Worker-Manager' } });
      if (!resp.ok) return json({ success: false, error: 'Fetch failed: ' + resp.status });
      const text = await resp.text();
      return json({ success: true, content: text });
    } catch (e) {
      return json({ success: false, error: e.message });
    }
  }

  const needsCreds = new Set([
    'validate-credentials','list-accounts','list-workers','get-worker-script','deploy-worker',
    'list-kv-namespaces','list-d1','put-worker-variables','get-worker-variables',
    'get-workers-subdomain','put-workers-subdomain','list-dns','delete-worker',
    'create-kv-namespace','delete-kv-namespace','put-kv-value','get-kv-value','delete-kv-value',
    'list-kv-keys','create-d1-database','delete-d1-database','execute-d1-query',
    'list-zones','create-zone','delete-zone','list-dns-records','create-dns-record','delete-dns-record',
    'update-dns-record','toggle-worker-domain','get-worker-analytics','get-usage-today',
    'get-worker-domains','toggle-worker-subdomain','add-worker-domain', 'delete-worker-domain', 'get-worker-bindings','list-pages-projects','delete-pages-project','deploy-pages-direct','list-snippets','get-snippet','deploy-snippet','delete-snippet','list-snippet-rules','add-snippet-rule','delete-snippet-rule',
    // WAF 自定义规则 / 隧道 / 批量重定向
    'list-waf-rules','create-waf-entrypoint','create-waf-rule','update-waf-rule','delete-waf-rule',
    'list-tunnels','create-tunnel','get-tunnel-token','get-tunnel-connections','delete-tunnel',
    'list-redirect-lists','create-redirect-list','delete-redirect-list','list-redirect-items','add-redirect-items','delete-redirect-item','get-redirect-rules','save-redirect-rules',
    // 站点优化 / 邮箱转发 / DNS IO / R2 / 流量
    'get-zone-settings','set-zone-setting','list-cache-rules','save-cache-rules',
    'get-email-routing','set-email-routing','add-email-rule','update-email-rule','delete-email-rule',
    'export-dns','import-dns','list-r2-buckets','get-zone-analytics'
  ]);

  // 资源类 action 的 OAuth 会话解析：前端仅提交 oauthId，后端解密 token 注入为 Bearer（key=__oa_+token）
  if (needsCreds.has(action)) {
    if (payload.oauthId && !(payload.key && payload.key.startsWith(OAUTH_KEY_PREFIX))) {
      try {
        const oaAccs = await loadKVAccounts(env);
        const oaAcc = oaAccs.find(a => a && a.oauth && a.oauthId === payload.oauthId);
        if (!oaAcc) return json({ success: false, error: 'OAuth 连接不存在或已断开，请在账号库重新授权' }, 401);
        if (oaAcc.expiresAt && Date.now() > oaAcc.expiresAt - 60000 && oaAcc.refreshToken) {
          await refreshOAuthToken(env, oaAcc);
          const fresh = (await loadKVAccounts(env)).find(a => a && a.oauth && a.oauthId === payload.oauthId);
          if (fresh && fresh.accessToken) { oaAcc.accessToken = fresh.accessToken; oaAcc.refreshToken = fresh.refreshToken; oaAcc.expiresAt = fresh.expiresAt; }
        }
        payload.email = oaAcc.email || oaAcc.name || '';
        // 双通道回退：OAuth token 新鲜走 Bearer；失效/撤销且存有 Global Key 时回退 key 通道
        const credK = oauthOrKey(oaAcc);
        if (!credK) return json({ success: false, error: 'OAuth 凭据不可用，请重新授权' }, 401);
        payload.key = credK;
      } catch(e){ return json({ success: false, error: 'OAuth 会话解析失败：' + e.message }, 500); }
    }
    const isOa = typeof payload.key === 'string' && payload.key.startsWith(OAUTH_KEY_PREFIX);
    if (!payload.key || (!isOa && !payload.email)) return json({ success:false, error:'email & key required' }, 400);
  }

  try {
    switch(action) {
      case 'validate-credentials': {
        const r = await cfAny('GET','/accounts', payload.email, payload.key);
        if (!r.success && !r.result) {
            return json({ success: false, error: r.errors?.[0]?.message || '验证失败，请检查 Email 和 Global API Key' });
        }
        return json(r);
      }

      case 'list-accounts':
        return json(await cfGet('/accounts', payload.email, payload.key));

      case 'list-workers': {
        if (!payload.accountId) return json({ success: false, error: 'accountId required' }, 400);
        const result = await cfGet(`/accounts/${payload.accountId}/workers/scripts`, payload.email, payload.key);
        
        let workersSubdomain = null;
        try {
          const subdomainResult = await cfGet(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key);
          if (subdomainResult.success) workersSubdomain = subdomainResult.result.subdomain;
        } catch (e) {}
        
        if (result.success && result.result) {
          for (let worker of result.result) {
            try {
              const domainsResult = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${worker.id}/domains`, payload.email, payload.key);
              worker.domains = domainsResult.success ? (domainsResult.result || []) : [];
              
              try {
                const bindingsResult = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${worker.id}/bindings`, payload.email, payload.key);
                worker.bindings = (bindingsResult.success && bindingsResult.result) ? bindingsResult.result : [];
              } catch (e) { worker.bindings = []; }

              try {
                const subdomainStatus = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${worker.id}/subdomain`, payload.email, payload.key);
                worker.subdomainEnabled = subdomainStatus.success ? subdomainStatus.result.enabled : true;
              } catch (e) { worker.subdomainEnabled = true; }
              
              if (workersSubdomain) {
                worker.defaultDomain = {
                  hostname: `${worker.id}.${workersSubdomain}.workers.dev`,
                  type: 'workers_dev',
                  enabled: worker.subdomainEnabled !== false
                };
              }
            } catch (e) {
              worker.domains = [];
              worker.bindings = [];
              worker.subdomainEnabled = true;
            }
          }
        }
        return json(result);
      }

      case 'get-worker-bindings': {
        const { scriptName } = payload;
        if (!scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        if (!payload.accountId) return json({ success: false, error: 'accountId required' }, 400);
        try {
          const result = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
          return json({ success: true, bindings: result.success ? result.result : [] });
        } catch (e) {
          return json({ success: false, error: '获取绑定信息失败: ' + e.message });
        }
      }

      case 'get-worker-script': {
        return await getWorkerScriptInternal(payload.email, payload.key, payload.accountId, payload.scriptName);
      }

      case 'deploy-worker': {
        const { scriptName, scriptSource, metadataBindings, usage_model } = payload;
        if (!scriptName) return json({ success:false, error:'scriptName required' },400);
        
        let accountId = payload.accountId;
        if (!accountId) {
             accountId = await getAccountId(payload.email, payload.key);
        }

        let currentBindings = [];
        try {
          const bindingsRes = await cfGet(`/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
          if (bindingsRes && bindingsRes.success) {
            currentBindings = bindingsRes.result;
          }
        } catch (e) {}

        const normalizedNewBindings = (metadataBindings || []).map((b) => {
          const copy = JSON.parse(JSON.stringify(b));
          if (copy.type === 'kv_namespace') {
            if (copy.namespace) { copy.namespace_id = copy.namespace; delete copy.namespace; }
            if (!copy.namespace_id && copy.id) copy.namespace_id = copy.id;
            delete copy.id; 
          }
          if (copy.type === 'd1_database' || copy.type === 'd1') {
             copy.type = 'd1'; 
             if (copy.database_id) { copy.id = copy.database_id; delete copy.database_id; }
             if (!copy.id && copy.namespace_id) { copy.id = copy.namespace_id; delete copy.namespace_id; }
             delete copy.database_name; 
             delete copy.preview_database_id;
          }
          return copy;
        });

        const finalBindings = [...currentBindings];
        normalizedNewBindings.forEach(newB => {
            const idx = finalBindings.findIndex(oldB => oldB.name === newB.name);
            if (idx !== -1) finalBindings[idx] = newB;
            else finalBindings.push(newB);
        });

        const cleanedBindings = finalBindings.map(b => {
            if(b.type === 'd1' || b.type === 'd1_database') return { type: 'd1', id: b.id || b.database_id, name: b.name };
            if(b.type === 'kv_namespace') return { type: 'kv_namespace', namespace_id: b.namespace_id || b.id, name: b.name };
            delete b.last_deployed_from;
            return b;
        });

        let finalScript = scriptSource;
        if (typeof finalScript !== 'string' || finalScript.trim().length === 0) {
             finalScript = "export default { async fetch() { return new Response('Deployed via Manager'); } };";
        }

        const isModule = finalScript.includes('export default') || finalScript.includes('export {');
        
        const form = new FormData();
        const metadata = { 
          bindings: cleanedBindings,
          usage_model: usage_model || 'standard',
          placement: { mode: 'smart' },
          compatibility_date: new Date().toISOString().slice(0,10)
        };
        if (payload.enableCpuLimit === true) {
          metadata.limits = { cpu_ms: 300000 };
        }
        let autoDowngraded = false;

        if (isModule) {
            metadata.main_module = 'worker.js';
            form.append('metadata', JSON.stringify(metadata));
            form.append('worker.js', new Blob([finalScript], { type:'application/javascript+module' }), 'worker.js');
        } else {
            metadata.body_part = 'script';
            form.append('metadata', JSON.stringify(metadata));
            form.append('script', new Blob([finalScript], { type:'application/javascript' }), 'worker.js');
        }

        const uploadUrl = `${CF_API_BASE}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}`;
        let resp = await fetch(uploadUrl, { method:'PUT', headers:cfHeaders(payload.email, payload.key), body: form });
        
        let text = "";
        try { text = await resp.text(); } catch(e) { text = "{}"; }
        
        let uploadRes;
        try { uploadRes = JSON.parse(text); } catch { uploadRes = { errors: [{ message: text }] }; }

        // 智能降级：如果设置了 CPU 限制但账号为免费版导致报错，则自动去掉限制重试
        if (!resp.ok && metadata.limits && uploadRes.errors?.[0]?.message?.includes('CPU limits')) {
          delete metadata.limits;
          const retryForm = new FormData();
          retryForm.append('metadata', JSON.stringify(metadata));
          if (isModule) {
            retryForm.append('worker.js', new Blob([finalScript], { type:'application/javascript+module' }), 'worker.js');
          } else {
            retryForm.append('script', new Blob([finalScript], { type:'application/javascript' }), 'worker.js');
          }
          resp = await fetch(uploadUrl, { method:'PUT', headers:cfHeaders(payload.email, payload.key), body: retryForm });
          try { text = await resp.text(); } catch(e) { text = "{}"; }
          try { uploadRes = JSON.parse(text); } catch { uploadRes = { errors: [{ message: text }] }; }
          autoDowngraded = true;
        }

        if (!resp.ok) return json({ success: false, error: '部署失败: ' + (uploadRes.errors?.[0]?.message || 'Unknown'), upload: uploadRes, uploadStatus: resp.status }, 200); 
        return json({ success: true, message: 'Worker 部署成功', upload: uploadRes, autoDowngraded: autoDowngraded });
      }

      case 'put-worker-variables': {
        const { scriptName, variables } = payload;
        if (!scriptName || !Array.isArray(variables) || !payload.accountId) return json({ success:false },400);
        
        let currentScript = null;
        let currentBindings = [];
        
        try {
          const bRes = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
          if (bRes.success) currentBindings = bRes.result;
        } catch (e) {}
        
        try {
             const scriptRes = await getWorkerScriptInternal(payload.email, payload.key, payload.accountId, scriptName);
             const scriptData = await scriptRes.json();
             if (scriptData.ok && scriptData.rawScript) {
                 currentScript = scriptData.rawScript;
             }
        } catch (e) {}

        if (!currentScript || currentScript.trim() === '') {
             currentScript = "export default { async fetch() { return new Response('Worker updated successfully.'); } };";
        }
        
        const envBindings = variables.map(v => ({ type: v.type==='secret_text'?'secret_text':'plain_text', name: v.name, text: String(v.value) }));
        const otherBindings = currentBindings.filter(b => b.type !== 'plain_text' && b.type !== 'secret_text');
        const existingNames = new Set(otherBindings.map(b => b.name));
        const safeEnvBindings = envBindings.filter(b => !existingNames.has(b.name));

        const allBindings = [...otherBindings, ...safeEnvBindings].map(b => {
             if(b.type === 'd1' || b.type === 'd1_database') return { type: 'd1', id: b.id || b.database_id, name: b.name };
             if(b.type === 'kv_namespace') return { type: 'kv_namespace', namespace_id: b.namespace_id || b.id, name: b.name };
             delete b.last_deployed_from;
             return b;
        });
        
        const isModule = currentScript.includes('export default') || currentScript.includes('export {');
        const form = new FormData();
        const metadata = { bindings: allBindings };

        if (isModule) {
            metadata.main_module = 'worker.js';
            form.append('metadata', JSON.stringify(metadata));
            form.append('worker.js', new Blob([currentScript], { type:'application/javascript+module' }), 'worker.js');
        } else {
            metadata.body_part = 'script';
            form.append('metadata', JSON.stringify(metadata));
            form.append('script', new Blob([currentScript], { type:'application/javascript' }), 'worker.js');
        }
        
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}`, { method: 'PUT', headers: cfHeaders(payload.email, payload.key), body: form });
        return json({ success: r.ok, message: r.ok?'Saved':'Failed', details: await r.text() });
      }

      case 'get-worker-variables': {
        const { scriptName } = payload;
        if (!scriptName || !payload.accountId) return json({ success:false },400);
        const r = await cfGet(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, payload.email, payload.key);
        const vars = [];
        if (r.success && r.result) r.result.forEach(b => { if(b.type==='plain_text'||b.type==='secret_text') vars.push({ name:b.name, type:b.type, value:b.text||'' }); });
        return json({ success: true, result: { vars } });
      }
      
      case 'get-worker-analytics': { const { scriptName } = payload; if (!scriptName || !payload.accountId) return json({ success:false },400); const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(scriptName)}/analytics/summary`, { headers: cfHeaders(payload.email, payload.key) }); if (r.ok) return json({ success: true, data: (await r.json()).result || {} }); return json({ success: false, error: 'Error' }); }
      
      case 'get-usage-today': { 
        if (!payload.accountId) return json({ success:false },400); 
        const { accountId, email, key: apikey } = payload; 
        const now=new Date(); 
        const end=now.toISOString(); 
        now.setUTCHours(0,0,0,0); 
        const start=now.toISOString(); 
        try { 
          const r=await fetch("https://api.cloudflare.com/client/v4/graphql",{method:"POST",headers:Object.assign({ "Content-Type":"application/json" }, cfHeaders(email, apikey)),body:JSON.stringify({query:`query getBillingMetrics($accountId:String!,$filter:AccountWorkersInvocationsAdaptiveFilter_InputObject){viewer{accounts(filter:{accountTag:$accountId}){pagesFunctionsInvocationsAdaptiveGroups(limit:1000,filter:$filter){sum{requests}}workersInvocationsAdaptive(limit:10000,filter:$filter){sum{requests}}}}}`,variables:{accountId,filter:{datetime_geq:start,datetime_leq:end}}})}); 
          if(!r.ok) return json({success:true,data:{total:0,workers:0,pages:0,percentage:0}}); 
          const res=await r.json(); 
          const ac=res?.data?.viewer?.accounts?.[0]; 
          const p=(ac?.pagesFunctionsInvocationsAdaptiveGroups||[]).reduce((t,i)=>t+(i?.sum?.requests||0),0); 
          const w=(ac?.workersInvocationsAdaptive||[]).reduce((t,i)=>t+(i?.sum?.requests||0),0); 
          return json({success:true,data:{total:p+w,workers:w,pages:p,percentage:Math.min(100,((p+w)/100000)*100)}}); 
        } catch(e){ 
          return json({success:true,data:{total:0,workers:0,pages:0,percentage:0}}); 
        } 
      }
      
      
case 'list-pages-projects': {
  const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
  return json(await cfGet('/accounts/' + accountId + '/pages/projects', payload.email, payload.key));
}

case 'delete-pages-project': {
  const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
  const projectName = String(payload.projectName || '').trim();
  if (!projectName) return json({ success:false, error:'projectName required' },400);
  return json(await cfDelete('/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName), payload.email, payload.key));
}

case 'deploy-pages-direct': {
  const projectName = String(payload.projectName || '').trim().toLowerCase();
  const branch = String(payload.branch || 'main').trim() || 'main';
  const inputFiles = Array.isArray(payload.files) ? payload.files : [];
  const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,56}[a-z0-9])?$/.test(projectName)) return json({ success:false, error:'Pages 项目名仅支持小写字母、数字、连字符，长度 2-58' }, 400);
  if (!inputFiles.length) return json({ success:false, error:'没有可部署的文件' }, 400);
  if (inputFiles.length > 1000) return json({ success:false, error:'单次最多 1000 个文件' }, 400);

  const paths = new Set();
  const files = [];
  let workerFile = null; // 提取 _worker.js 单独处理，不作为 asset 上传
  
  for (const item of inputFiles) {
    const path = String(item && item.path || '');
    const hash = String(item && item.hash || '').toLowerCase();
    const base64 = String(item && item.base64 || '');
    const isWorker = (path === '/_worker.js' || path === '_worker.js');
    
    // _worker.js 不需要作为 asset 上传，放宽对其 hash 的校验
    if (!path.startsWith('/') || path.includes('..') || path.includes('\\\\') || (!isWorker && !/^[a-f0-9]{32}$/.test(hash))) return json({ success:false, error:'非法文件路径或 hash：' + path }, 400);
    if (paths.has(path)) return json({ success:false, error:'重复文件路径：' + path }, 400);
    if (!base64 || base64.length > 34952536) return json({ success:false, error:'文件为空或超过 25 MiB：' + path }, 400);
    paths.add(path);
    
    if (isWorker) {
      workerFile = { path: path, base64: base64, contentType: String(item.contentType || 'application/javascript+module') };
    } else {
      files.push({ path:path, hash:hash, base64:base64, contentType:String(item.contentType || 'application/octet-stream') });
    }
  }

  let project = await cfGet('/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName), payload.email, payload.key);
  if (!project || !project.success) {
    const created = await cfPost('/accounts/' + accountId + '/pages/projects', payload.email, payload.key, { name:projectName, production_branch:branch });
    if (!created || !created.success) return json({ success:false, step:'create-project', error:(created && created.errors && created.errors[0] && created.errors[0].message) || '创建 Pages 项目失败' }, 200);
  }

  // 先读取完整项目配置再合并，不能用片段 deployment_configs 覆盖已有 Functions 设置。
  const currentProjectRes = await cfGet('/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName), payload.email, payload.key);
  const oldConfigs = currentProjectRes && currentProjectRes.result && currentProjectRes.result.deployment_configs ? currentProjectRes.result.deployment_configs : {};
  function mergeRuntimeConfig(environment) {
    const old = oldConfigs[environment] || {};
    const merged = Object.assign({}, old);
    merged.placement = Object.assign({}, old.placement || {}, { mode: 'smart' });
    if (payload.enableCpuLimit) {
      const cpuMs = Math.max(1, Math.min(300000, Number(payload.cpuMs) || 300000));
      merged.limits = Object.assign({}, old.limits || {}, { cpu_ms: cpuMs });
    }
    return merged;
  }
  const projectConfig = {
    deployment_configs: Object.assign({}, oldConfigs, {
      production: mergeRuntimeConfig('production'),
      preview: mergeRuntimeConfig('preview')
    })
  };
  let projectConfigRes = await cfAny('PATCH', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName), payload.email, payload.key, projectConfig);
  let pagesAutoDowngraded = false;
  if (!projectConfigRes || projectConfigRes.success === false) {
    const errMsg = (projectConfigRes && projectConfigRes.errors && projectConfigRes.errors[0] && projectConfigRes.errors[0].message) || '';
    if (errMsg.includes('CPU limits') && projectConfig.deployment_configs.production.limits) {
      delete projectConfig.deployment_configs.production.limits;
      delete projectConfig.deployment_configs.preview.limits;
      projectConfigRes = await cfAny('PATCH', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName), payload.email, payload.key, projectConfig);
      if (!projectConfigRes || projectConfigRes.success === false) {
        return json({ success:false, step:'pages-project-config', error:(projectConfigRes && projectConfigRes.errors && projectConfigRes.errors[0] && projectConfigRes.errors[0].message) || '保存 Pages 运行时配置失败' }, 200);
      }
      pagesAutoDowngraded = true;
    } else {
      return json({ success:false, step:'pages-project-config', error: errMsg || '保存 Pages 运行时配置失败' }, 200);
    }
  }

  const tokenRes = await cfGet('/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName) + '/upload-token', payload.email, payload.key);
  const jwt = tokenRes && tokenRes.result && (tokenRes.result.jwt || tokenRes.result.token);
  if (!jwt) return json({ success:false, step:'upload-token', error:(tokenRes && tokenRes.errors && tokenRes.errors[0] && tokenRes.errors[0].message) || '获取 Pages 上传令牌失败' }, 200);

  const headers = { Authorization:'Bearer ' + jwt, 'Content-Type':'application/json' };
  let bucket = [], bucketSize = 0;
  async function flush() {
    if (!bucket.length) return;
    const r = await fetch(CF_API_BASE + '/pages/assets/upload', { method:'POST', headers:headers, body:JSON.stringify(bucket) });
    let data; try { data = await r.json(); } catch(e) { data = { success:r.ok }; }
    if (!r.ok || data.success === false) throw new Error((data.errors && data.errors[0] && data.errors[0].message) || '资产上传失败 HTTP ' + r.status);
    bucket = []; bucketSize = 0;
  }
  try {
    for (const f of files) {
      const size = f.base64.length + 512;
      if (bucket.length && (bucket.length >= 100 || bucketSize + size > 40 * 1024 * 1024)) await flush();
      bucket.push({ key:f.hash, value:f.base64, base64:true, metadata:{ contentType:f.contentType } });
      bucketSize += size;
    }
    await flush();
  } catch(e) { return json({ success:false, step:'assets-upload', error:String(e.message || e) }, 200); }

  const hashesRes = await fetch(CF_API_BASE + '/pages/assets/upsert-hashes', { method:'POST', headers:headers, body:JSON.stringify({ hashes:files.map(function(f){ return f.hash; }) }) });
  let hashesData; try { hashesData = await hashesRes.json(); } catch(e) { hashesData = { success:hashesRes.ok }; }
  if (!hashesRes.ok || hashesData.success === false) return json({ success:false, step:'upsert-hashes', error:(hashesData.errors && hashesData.errors[0] && hashesData.errors[0].message) || '资产 hash 注册失败' }, 200);

  const manifest = {};
  files.forEach(function (f) {
    let manifestPath = String(f.path || '');
    if (!manifestPath.startsWith('/')) manifestPath = '/' + manifestPath;
    manifest[manifestPath] = f.hash;
  });
  const form = new FormData();
  form.append('manifest', JSON.stringify(manifest));
  form.append('branch', branch);
  form.append('commit_dirty', 'false');
  form.append('commit_hash', crypto.randomUUID().replace(/-/g, '').slice(0, 40));
  form.append('commit_message', 'Batch Pages deploy via MyCF');

  // 如果存在 _worker.js，将其作为 Pages Function 单独附加到部署表单中
  if (workerFile) {
    try {
      // 在 Worker 环境中使用 fetch data URI 高效且安全地解码 base64
      const workerBlob = await fetch(`data:${workerFile.contentType};base64,${workerFile.base64}`).then(r => r.blob());
      form.append('_worker.js', workerBlob, '_worker.js');
    } catch(e) {
      return json({ success:false, step:'worker-parse', error:'_worker.js 解码失败: ' + e.message }, 200);
    }
  }

  const deployRes = await fetch(CF_API_BASE + '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName) + '/deployments', { method:'POST', headers:cfHeaders(payload.email, payload.key), body:form });
  let deploy; try { deploy = await deployRes.json(); } catch(e) { deploy = { success:deployRes.ok }; }
  if (!deployRes.ok || deploy.success === false) return json({ success:false, step:'create-deployment', error:(deploy.errors && deploy.errors[0] && deploy.errors[0].message) || '创建部署失败' }, 200);
  const result = deploy.result || {};
  return json({ success:true, deployment:result, url:result.url || ('https://' + projectName + '.pages.dev'), pagesDomain:projectName + '.pages.dev', fileCount:files.length, autoDowngraded: pagesAutoDowngraded });
}

case 'list-kv-namespaces': return json(await cfGet(`/accounts/${payload.accountId || await getAccountId(payload.email, payload.key)}/storage/kv/namespaces`, payload.email, payload.key));
      case 'create-kv-namespace': return json(await cfPost(`/accounts/${payload.accountId}/storage/kv/namespaces`, payload.email, payload.key, { title: payload.title }));
      case 'delete-kv-namespace': return json(await cfDelete(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}`, payload.email, payload.key));
      case 'list-kv-keys': return json(await cfGet(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/keys`, payload.email, payload.key));
      case 'get-kv-value': { const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/values/${encodeURIComponent(payload.key)}`, { headers:cfHeaders(payload.email, payload.key)}); return json({ success: r.ok, value: await r.text() }); }
      case 'put-kv-value': { const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/values/${encodeURIComponent(payload.key)}`, { method: 'PUT', headers:cfHeaders(payload.email, payload.key), body: payload.value }); return json({ success: r.ok }); }
      case 'delete-kv-value': return json(await cfDelete(`/accounts/${payload.accountId}/storage/kv/namespaces/${payload.namespaceId}/values/${encodeURIComponent(payload.key)}`, payload.email, payload.key));

      case 'list-d1': return json(await cfGet(`/accounts/${payload.accountId || await getAccountId(payload.email, payload.key)}/d1/database`, payload.email, payload.key));
      case 'create-d1-database': return json(await cfPost(`/accounts/${payload.accountId}/d1/database`, payload.email, payload.key, { name: payload.name }));
      case 'delete-d1-database': return json(await cfDelete(`/accounts/${payload.accountId}/d1/database/${payload.databaseId}`, payload.email, payload.key));
      case 'execute-d1-query': return json(await cfPost(`/accounts/${payload.accountId}/d1/database/${payload.databaseId}/query`, payload.email, payload.key, { sql: payload.query }));

      case 'get-workers-subdomain': return json(await cfGet(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key));
      case 'put-workers-subdomain': return json({ success: true, data: await cfPutRaw(`/accounts/${payload.accountId}/workers/subdomain`, payload.email, payload.key, { subdomain: payload.subdomain }) });
      case 'toggle-worker-subdomain': return json(await cfPost(`/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}/subdomain`, payload.email, payload.key, { enabled: payload.enabled }));

      case 'list-zones': return json(await cfGet('/zones', payload.email, payload.key));
      case 'create-zone': return json(await cfPost('/zones', payload.email, payload.key, { name: payload.name }));
      case 'delete-zone': return json(await cfDelete(`/zones/${payload.zoneId}`, payload.email, payload.key));
      case 'list-dns-records': return json(await cfGet(`/zones/${payload.zoneId}/dns_records`, payload.email, payload.key));
      case 'create-dns-record': return json(await cfPost(`/zones/${payload.zoneId}/dns_records`, payload.email, payload.key, { type: payload.type, name: payload.name, content: payload.content, ttl: payload.ttl||1, proxied: payload.proxied||false }));
      case 'update-dns-record': return json(await cfPut(`/zones/${payload.zoneId}/dns_records/${payload.recordId}`, payload.email, payload.key, { type: payload.type, name: payload.name, content: payload.content, ttl: payload.ttl||1, proxied: payload.proxied||false }));
      case 'delete-dns-record': return json(await cfDelete(`/zones/${payload.zoneId}/dns_records/${payload.recordId}`, payload.email, payload.key));
      
      case 'add-worker-domain': {
        const { scriptName, hostname } = payload;
        const cleanHost = hostname.replace(/^https?:\/\//, '').replace(/\/$/, '').trim();
        const zonesRes = await cfGet('/zones', payload.email, payload.key);
        const zone = zonesRes.success ? zonesRes.result.find(z => cleanHost === z.name || cleanHost.endsWith('.' + z.name)) : null;
        if (!zone) return json({ success: false, error: '未找到匹配的 Zone' });
        const res = await cfPutRaw(`/zones/${zone.id}/workers/domains`, payload.email, payload.key, { environment: "production", hostname: cleanHost, service: scriptName, zone_id: zone.id });
        return json({ success: res.success || !!res.result, error: res.errors?.[0]?.message });
      }
      case 'delete-worker-domain': {
        const url = `${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}/domains/${payload.domainId}`;
        const r = await fetch(url, { method: 'DELETE', headers: cfHeaders(payload.email, payload.key) });
        return json({ success: r.ok });
      }
      

      // ===== Snippets API =====
      case 'list-snippets': {
        const { zoneId } = payload;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        return json(await cfGet(`/zones/${zoneId}/snippets`, payload.email, payload.key));
      }

      case 'get-snippet': {
        const { zoneId, snippetName } = payload;
        if (!zoneId || !snippetName) return json({ success: false, error: 'zoneId & snippetName required' }, 400);
        const metaRes = await cfGet(`/zones/${zoneId}/snippets/${encodeURIComponent(snippetName)}`, payload.email, payload.key);
        const contentResp = await fetch(`${CF_API_BASE}/zones/${zoneId}/snippets/${encodeURIComponent(snippetName)}/content`, { headers: cfHeaders(payload.email, payload.key) });
        let snippetCode = '';
        if (contentResp.ok) { try { snippetCode = await contentResp.text(); } catch(e) {} }
        return json({ success: true, metadata: metaRes.result || {}, code: snippetCode });
      }

      case 'deploy-snippet': {
        const { zoneId, snippetName, snippetCode } = payload;
        if (!zoneId || !snippetName) return json({ success: false, error: 'zoneId & snippetName required' }, 400);
        
        const finalCode = snippetCode || "export default { async fetch(request, env, ctx) { return new Response('Hello from snippet'); } };";
        const form = new FormData();
        const metadata = { main_module: 'main.js' };
        form.append('metadata', JSON.stringify(metadata));
        form.append('main.js', new Blob([finalCode], { type:'application/javascript+module' }), 'main.js');
        
        const uploadUrl = `${CF_API_BASE}/zones/${zoneId}/snippets/${encodeURIComponent(snippetName)}`;
        const resp = await fetch(uploadUrl, { method:'PUT', headers:cfHeaders(payload.email, payload.key), body: form });
        
        let text = ""; try { text = await resp.text(); } catch(e) { text = "{}"; }
        let uploadRes; try { uploadRes = JSON.parse(text); } catch { uploadRes = { errors: [{ message: text }] }; }
        
        if (!resp.ok) return json({ success: false, error: '部署失败: ' + (uploadRes.errors?.[0]?.message || 'Unknown'), upload: uploadRes }, 200); 
        return json({ success: true, message: 'Snippet 部署成功', upload: uploadRes });
      }

      case 'delete-snippet': {
        const { zoneId, snippetName } = payload;
        if (!zoneId || !snippetName) return json({ success: false, error: 'zoneId & snippetName required' }, 400);
        return json(await cfDelete(`/zones/${zoneId}/snippets/${encodeURIComponent(snippetName)}`, payload.email, payload.key));
      }

      case 'list-snippet-rules': {
        const { zoneId } = payload;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const res = await cfGet(`/zones/${zoneId}/snippets/ruleset`, payload.email, payload.key);
        if (!res.success) { return json({ success: true, result: { rules: [] } }); }
        return json(res);
      }

      case 'add-snippet-rule': {
        const { zoneId, snippetName, expression, description } = payload;
        if (!zoneId || !snippetName || !expression) return json({ success: false, error: 'zoneId, snippetName & expression required' }, 400);
        
        // 自动检查并创建 DNS 记录
        try {
          const hostMatches = [...expression.matchAll(/http\.host\s+eq\s+"([^"]+)"/g)];
          for (const m of hostMatches) {
            const hostname = m[1];
            const dnsRes = await cfGet(`/zones/${zoneId}/dns_records?name=${encodeURIComponent(hostname)}`, payload.email, payload.key);
            const records = dnsRes.result || [];
            const hasProxied = records.some(r => r.proxied === true);
            if (!hasProxied) {
              await cfPost(`/zones/${zoneId}/dns_records`, payload.email, payload.key, {
                type: 'AAAA', name: hostname, content: '100::', ttl: 1, proxied: true
              });
            }
          }
        } catch(e) {}

        const rulesetRes = await cfGet(`/zones/${zoneId}/snippets/ruleset`, payload.email, payload.key);
        let rules = [];
        if (rulesetRes.success && rulesetRes.result && rulesetRes.result.rules) { rules = rulesetRes.result.rules; }
        rules.push({ action: 'run_snippet', action_parameters: { snippet: snippetName }, expression: expression, description: description || 'Route to ' + snippetName });
        return json(await cfAny('PUT', `/zones/${zoneId}/snippets/ruleset`, payload.email, payload.key, { rules: rules }));
      }

      case 'delete-snippet-rule': {
        const { zoneId, ruleId } = payload;
        if (!zoneId || !ruleId) return json({ success: false, error: 'zoneId & ruleId required' }, 400);
        const rulesetRes = await cfGet(`/zones/${zoneId}/snippets/ruleset`, payload.email, payload.key);
        if (!rulesetRes.success || !rulesetRes.result || !rulesetRes.result.rules) return json({ success: false, error: '获取规则集失败' });
        const rules = rulesetRes.result.rules.filter(function(r) { return r.id !== ruleId; });
        return json(await cfAny('PUT', `/zones/${zoneId}/snippets/ruleset`, payload.email, payload.key, { rules: rules }));
      }

      case 'delete-worker': {
        const r = await fetch(`${CF_API_BASE}/accounts/${payload.accountId}/workers/scripts/${encodeURIComponent(payload.scriptName)}`, { method:'DELETE', headers:cfHeaders(payload.email, payload.key) });
        return json({ success: r.ok });
      }

      case 'check-features': {
        return json({ success: true, hasPassword: !!(env && env.ACCESS_PASSWORD), hasKV: !!(env && env.CF_ACCOUNTS_KV) });
      }

      case 'save-accounts-kv': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success: false, error: 'CF_ACCOUNTS_KV 未绑定，请在 Worker 绑定设置中添加 KV 命名空间并变量名设为 CF_ACCOUNTS_KV' });
        const { accounts } = payload;
        if (!Array.isArray(accounts)) return json({ success: false, error: 'accounts 必须是数组' });
        // oauth 账号仅合并非 token 字段（token 只经授权回调写入 KV，前端不可见、不可覆盖）
        const prev = await loadKVAccounts(env).catch(() => []);
        const merged = [];
        for (const sub of accounts) {
          if (sub && sub.oauth) {
            const old = prev.find(p => p && p.oauth && p.oauthId === sub.oauthId);
            if (!old) continue; // 新 oauth 记录只能由 /oauth/callback 创建
            merged.push(Object.assign({}, old, sub, { accessToken: old.accessToken, refreshToken: old.refreshToken, expiresAt: old.expiresAt, accountId: old.accountId, accountIds: old.accountIds, key: old.key || '' }));
          } else merged.push(sub);
        }
        await persistAccountsEnc(env, merged);
        return json({ success: true, encrypted: !!(await getCryptoKey(env)) });
      }

      case 'load-accounts-kv': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success: false, error: 'CF_ACCOUNTS_KV 未绑定' });
        const accounts = await loadKVAccounts(env);
        // oauth token 绝不回传前端；双通道账号(含 Global Key)保留 key，供执行账号按 key 通道使用
        const sanitized = accounts.map(a => (a && a.oauth) ? Object.assign({}, a, { accessToken: '', refreshToken: '' }) : a);
        return json({ success: true, accounts: sanitized });
      }

      case 'save-oauth-client': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success: false, error: 'CF_ACCOUNTS_KV 未绑定' });
        const clientId = String(payload.clientId || '').trim();
        if (!clientId) return json({ success: false, error: 'Client ID 必填' });
        const cur = await getOAuthClient(env) || {};
        const next = { clientId, authMethod: payload.authMethod || cur.authMethod || 'post' };
        if (payload.clientSecret) next.clientSecret = String(payload.clientSecret).trim();
        else if (cur.clientSecret) next.clientSecret = cur.clientSecret;
        if (payload.scopes) next.scopes = String(payload.scopes);
        else if (cur.scopes) next.scopes = cur.scopes;
        await saveOAuthClient(env, next);
        return json({ success: true });
      }

      case 'load-oauth-client': {
        const cl = await getOAuthClient(env);
        if (!cl) return json({ success: true, configured: false, connections: [] });
        const accs = await loadKVAccounts(env).catch(() => []);
        const connections = accs.filter(a => a && a.oauth).map(a => ({
          oauthId: a.oauthId, name: a.name || a.email || a.oauthId, email: a.email || '',
          scope: a.scope || '', added: a.added || '', accountId: a.accountId || '',
          group: a.group || '', status: a.status || 'ok', statusReason: a.statusReason || ''
        }));
        return json({ success: true, configured: true, clientId: cl.clientId, hasSecret: !!cl.clientSecret, authMethod: cl.authMethod || 'post', connections });
      }

      case 'oauth-begin': {
        const cl = await getOAuthClient(env);
        if (!cl || !cl.clientId) return json({ success: false, error: '请先在「OAuth 免密钥接入」保存 Client ID / Secret' });
        const origin = new URL(req.url).origin;
        const state = randHex(16);
        if (env && env.CF_ACCOUNTS_KV) await env.CF_ACCOUNTS_KV.put('oauth_state_' + state, cl.clientId, { expirationTtl: 600 });
        const q = new URLSearchParams({ client_id: cl.clientId, response_type: 'code', redirect_uri: origin + '/oauth/callback', state });
        return json({ success: true, url: CF_OAUTH_AUTH + '?' + q.toString() });
      }

      case 'oauth-revoke-account': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success: false, error: 'CF_ACCOUNTS_KV 未绑定' });
        const oauthId = payload.oauthId;
        if (!oauthId) return json({ success: false, error: 'oauthId required' }, 400);
        const arr = await loadKVAccounts(env);
        const next = [];
        for (const a of arr) {
          if (a && a.oauth && a.oauthId === oauthId) {
            // 双通道：仅剥离 oauth，保留 Global Key
            if (a.key) next.push({ email: a.email || '', key: a.key, group: a.group || '', added: a.added || '', status: 'ok' });
            continue; // 纯 oauth：整条移除
          }
          next.push(a);
        }
        await persistAccountsEnc(env, next);
        return json({ success: true });
      }

      // ===== WAF 自定义规则（zone ruleset phase: http_request_firewall_custom）=====
      case 'list-waf-rules': {
        const zoneId = payload.zoneId;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const r = await cfGet(`/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`, payload.email, payload.key);
        if (!r.success || !r.result) {
          if (r.status === 404) return json({ success: true, exists: false, rules: [] });
          return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取 WAF 规则失败' });
        }
        return json({ success: true, exists: true, rulesetId: r.result.id, rules: r.result.rules || [] });
      }
      case 'create-waf-entrypoint': {
        const zoneId = payload.zoneId; const rules = payload.rules || [];
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const r = await cfPost(`/zones/${zoneId}/rulesets`, payload.email, payload.key, { name: 'Custom Rules', kind: 'zone', phase: 'http_request_firewall_custom', description: 'MyCF WAF custom rules', rules });
        return json(r.success ? { success: true, rulesetId: r.result && r.result.id, rules: (r.result && r.result.rules) || rules } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '创建 ruleset 失败' });
      }
      case 'create-waf-rule': {
        const { zoneId, rulesetId, rule } = payload;
        if (!zoneId || !rulesetId || !rule) return json({ success: false, error: 'zoneId/rulesetId/rule required' }, 400);
        const r = await cfPost(`/zones/${zoneId}/rulesets/${rulesetId}/rules`, payload.email, payload.key, rule);
        return json(r.success ? { success: true, rule: r.result } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '创建规则失败' });
      }
      case 'update-waf-rule': {
        const { zoneId, rulesetId, ruleId, rule } = payload;
        if (!zoneId || !rulesetId || !ruleId || !rule) return json({ success: false, error: 'zoneId/rulesetId/ruleId/rule required' }, 400);
        const r = await cfAny('PATCH', `/zones/${zoneId}/rulesets/${rulesetId}/rules/${ruleId}`, payload.email, payload.key, rule);
        return json(r.success ? { success: true, rule: r.result } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '更新规则失败' });
      }
      case 'delete-waf-rule': {
        const { zoneId, rulesetId, ruleId } = payload;
        if (!zoneId || !rulesetId || !ruleId) return json({ success: false, error: 'zoneId/rulesetId/ruleId required' }, 400);
        const r = await cfAny('DELETE', `/zones/${zoneId}/rulesets/${rulesetId}/rules/${ruleId}`, payload.email, payload.key);
        return json({ success: r.success, error: r.success ? undefined : ((r.errors && r.errors[0] && r.errors[0].message) || '删除失败') });
      }

      // ===== Cloudflare Tunnel（cfd_tunnel）=====
      case 'list-tunnels': {
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfGet(`/accounts/${accountId}/cfd_tunnel?is_deleted=false`, payload.email, payload.key);
        if (!r.success) return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取隧道列表失败' });
        return json({ success: true, tunnels: r.result || [], accountId });
      }
      case 'create-tunnel': {
        const name = String(payload.name || '').trim();
        if (!name) return json({ success: false, error: '隧道名称必填' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfPost(`/accounts/${accountId}/cfd_tunnel`, payload.email, payload.key, { name, config_src: 'cloudflare' });
        if (!r.success) return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '创建隧道失败' });
        return json({ success: true, tunnel: r.result });
      }
      case 'get-tunnel-token': {
        const { tunnelId } = payload;
        if (!tunnelId) return json({ success: false, error: 'tunnelId required' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfGet(`/accounts/${accountId}/cfd_tunnel/${tunnelId}/token`, payload.email, payload.key);
        if (!r.success) return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取 token 失败' });
        return json({ success: true, token: r.result });
      }
      case 'get-tunnel-connections': {
        const { tunnelId } = payload;
        if (!tunnelId) return json({ success: false, error: 'tunnelId required' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfGet(`/accounts/${accountId}/cfd_tunnel/${tunnelId}/connections`, payload.email, payload.key);
        return json({ success: r.success, connections: (r.success && r.result) ? r.result : [], error: r.success ? undefined : ((r.errors && r.errors[0] && r.errors[0].message) || '获取连接失败') });
      }
      case 'delete-tunnel': {
        const { tunnelId } = payload;
        if (!tunnelId) return json({ success: false, error: 'tunnelId required' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfAny('DELETE', `/accounts/${accountId}/cfd_tunnel/${tunnelId}`, payload.email, payload.key);
        return json({ success: r.success, error: r.success ? undefined : ((r.errors && r.errors[0] && r.errors[0].message) || '删除隧道失败') });
      }

      // ===== 批量重定向 Bulk Redirects（redirect lists + http_request_redirect ruleset）=====
      case 'list-redirect-lists': {
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfGet(`/accounts/${accountId}/rules/lists?per_page=1000`, payload.email, payload.key);
        if (!r.success) return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取列表失败' });
        const lists = (r.result || []).filter(l => l && l.kind === 'redirect');
        return json({ success: true, lists, accountId });
      }
      case 'create-redirect-list': {
        const name = String(payload.name || '').trim();
        if (!name) return json({ success: false, error: '列表名称必填' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfPost(`/accounts/${accountId}/rules/lists`, payload.email, payload.key, { name, kind: 'redirect', description: payload.description || '' });
        return json(r.success ? { success: true, list: r.result } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '创建列表失败' });
      }
      case 'delete-redirect-list': {
        const { listId } = payload;
        if (!listId) return json({ success: false, error: 'listId required' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfAny('DELETE', `/accounts/${accountId}/rules/lists/${listId}`, payload.email, payload.key);
        return json({ success: r.success, error: r.success ? undefined : ((r.errors && r.errors[0] && r.errors[0].message) || '删除列表失败') });
      }
      case 'list-redirect-items': {
        const { listId } = payload;
        if (!listId) return json({ success: false, error: 'listId required' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfGet(`/accounts/${accountId}/rules/lists/${listId}/items?per_page=1000`, payload.email, payload.key);
        if (!r.success) return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取条目失败' });
        return json({ success: true, items: r.result || [] });
      }
      case 'add-redirect-items': {
        const { listId, items } = payload;
        if (!listId || !Array.isArray(items) || !items.length) return json({ success: false, error: 'listId + items[] required' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfPost(`/accounts/${accountId}/rules/lists/${listId}/items`, payload.email, payload.key, items);
        if (!r.success) return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '添加条目失败' });
        const opId = r.result && r.result.operation_id;
        if (opId) {
          for (let i = 0; i < 12; i++) {
            await new Promise(res => setTimeout(res, 500));
            try {
              const s = await cfGet(`/accounts/${accountId}/rules/lists/bulk_operations/${opId}`, payload.email, payload.key);
              if (s && s.result && s.result.status === 'completed') break;
              if (s && s.result && s.result.status === 'failed') return json({ success: false, error: '批量添加失败：' + ((s.result.error && s.result.error.message) || s.result.status) });
            } catch(e){ break; }
          }
        }
        return json({ success: true });
      }
      case 'delete-redirect-item': {
        const { listId, itemId } = payload;
        if (!listId || !itemId) return json({ success: false, error: 'listId & itemId required' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfAny('DELETE', `/accounts/${accountId}/rules/lists/${listId}/items/${itemId}`, payload.email, payload.key);
        return json({ success: r.success, error: r.success ? undefined : ((r.errors && r.errors[0] && r.errors[0].message) || '删除条目失败') });
      }
      case 'get-redirect-rules': {
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfGet(`/accounts/${accountId}/rulesets/phases/http_request_redirect/entrypoint`, payload.email, payload.key);
        if (!r.success || !r.result) {
          if (r.status === 404) return json({ success: true, exists: false, rules: [] });
          return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取重定向规则失败' });
        }
        return json({ success: true, exists: true, rulesetId: r.result.id, rules: r.result.rules || [] });
      }
      case 'save-redirect-rules': {
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const rules = payload.rules || [];
        // 先探测 entrypoint 是否存在；不存在则用 POST 创建 root ruleset
        const probe = await cfGet(`/accounts/${accountId}/rulesets/phases/http_request_redirect/entrypoint`, payload.email, payload.key);
        let r;
        if (probe && probe.success && probe.result) {
          r = await cfAny('PUT', `/accounts/${accountId}/rulesets/phases/http_request_redirect/entrypoint`, payload.email, payload.key, { rules });
        } else {
          r = await cfPost(`/accounts/${accountId}/rulesets`, payload.email, payload.key, { name: 'Bulk Redirects', kind: 'root', phase: 'http_request_redirect', description: 'MyCF bulk redirects', rules });
        }
        return json(r.success ? { success: true, rules: (r.result && r.result.rules) || rules } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '保存重定向规则失败' });
      }

      // ===== Zone 安全设置 =====
      case 'get-zone-settings': {
        const zoneId = payload.zoneId;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const r = await cfGet(`/zones/${zoneId}/settings`, payload.email, payload.key);
        if (!r.success || !r.result) return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取设置失败' });
        const pick = ['always_use_https','min_tls_version','ssl','tls_1_3','0rtt','http2','http3','brotli','websockets','opportunistic_encryption','automatic_https_rewrites','ipv6','image_resizing','hotlink_protection','security_level','challenge_ttl','browser_check','email_obfuscation','server_side_exclude'];
        const map = {};
        (r.result || []).forEach(s => { if (s && s.id && pick.indexOf(s.id) !== -1) map[s.id] = { value: s.value, editable: s.editable !== false }; });
        return json({ success: true, settings: map });
      }
      case 'set-zone-setting': {
        const { zoneId, name, value } = payload;
        if (!zoneId || !name) return json({ success: false, error: 'zoneId & name required' }, 400);
        const r = await cfAny('PATCH', `/zones/${zoneId}/settings/${encodeURIComponent(name)}`, payload.email, payload.key, { value });
        return json(r.success ? { success: true } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '设置失败' });
      }
      case 'list-cache-rules': {
        const zoneId = payload.zoneId;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const r = await cfGet(`/zones/${zoneId}/rulesets/phases/http_request_cache_settings/entrypoint`, payload.email, payload.key);
        if (!r.success || !r.result) {
          if (r.status === 404) return json({ success: true, exists: false, rules: [] });
          return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取缓存规则失败' });
        }
        return json({ success: true, exists: true, rules: r.result.rules || [] });
      }
      case 'save-cache-rules': {
        const zoneId = payload.zoneId; const rules = payload.rules || [];
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const probe = await cfGet(`/zones/${zoneId}/rulesets/phases/http_request_cache_settings/entrypoint`, payload.email, payload.key);
        let r;
        if (probe && probe.success && probe.result) {
          r = await cfAny('PUT', `/zones/${zoneId}/rulesets/phases/http_request_cache_settings/entrypoint`, payload.email, payload.key, { rules });
        } else {
          r = await cfPost(`/zones/${zoneId}/rulesets`, payload.email, payload.key, { name: 'Cache Rules', kind: 'zone', phase: 'http_request_cache_settings', description: 'MyCF cache rules', rules });
        }
        return json(r.success ? { success: true, rules: (r.result && r.result.rules) || rules } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '保存缓存规则失败' });
      }

      // ===== Email Routing =====
      case 'get-email-routing': {
        const zoneId = payload.zoneId;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const out = { enabled: false, zoneName: '', rules: [], addresses: [] };
        try { const s = await cfGet(`/zones/${zoneId}/email/routing`, payload.email, payload.key); if (s && s.success && s.result) { out.enabled = !!s.result.enabled; out.zoneName = s.result.name || ''; } } catch(e){}
        try { const rr = await cfGet(`/zones/${zoneId}/email/routing/rules`, payload.email, payload.key); if (rr && rr.success && Array.isArray(rr.result)) out.rules = rr.result; } catch(e){}
        try { const ad = await cfGet(`/accounts/${accountId}/email/routing/addresses?per_page=1000`, payload.email, payload.key); if (ad && ad.success && Array.isArray(ad.result)) out.addresses = ad.result; } catch(e){}
        return json({ success: true, email: out });
      }
      case 'set-email-routing': {
        const zoneId = payload.zoneId; const enabled = !!payload.enabled;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const r = await cfPost(`/zones/${zoneId}/email/routing/${enabled ? 'enable' : 'disable'}`, payload.email, payload.key, {});
        return json(r.success ? { success: true, enabled } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '切换失败' });
      }
      case 'add-email-rule': {
        const { zoneId, rule } = payload;
        if (!zoneId || !rule) return json({ success: false, error: 'zoneId & rule required' }, 400);
        const r = await cfPost(`/zones/${zoneId}/email/routing/rules`, payload.email, payload.key, rule);
        return json(r.success ? { success: true, rule: r.result } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '添加规则失败' });
      }
      case 'update-email-rule': {
        const { zoneId, ruleId, rule } = payload;
        if (!zoneId || !ruleId || !rule) return json({ success: false, error: 'zoneId/ruleId/rule required' }, 400);
        const r = await cfAny('PUT', `/zones/${zoneId}/email/routing/rules/${ruleId}`, payload.email, payload.key, rule);
        return json(r.success ? { success: true } : { success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '更新规则失败' });
      }
      case 'delete-email-rule': {
        const { zoneId, ruleId } = payload;
        if (!zoneId || !ruleId) return json({ success: false, error: 'zoneId & ruleId required' }, 400);
        const r = await cfAny('DELETE', `/zones/${zoneId}/email/routing/rules/${ruleId}`, payload.email, payload.key);
        return json({ success: r.success, error: r.success ? undefined : ((r.errors && r.errors[0] && r.errors[0].message) || '删除规则失败') });
      }

      // ===== DNS 导入导出 / R2 / Zone 流量 =====
      case 'export-dns': {
        const zoneId = payload.zoneId;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        const r = await fetch(`${CF_API_BASE}/zones/${zoneId}/dns_records/export`, { method: 'GET', headers: cfHeaders(payload.email, payload.key) });
        if (!r.ok) return json({ success: false, error: '导出失败 HTTP ' + r.status });
        return json({ success: true, text: await r.text() });
      }
      case 'import-dns': {
        const { zoneId, bindText, proxied } = payload;
        if (!zoneId || !bindText) return json({ success: false, error: 'zoneId & bindText required' }, 400);
        const fd = new FormData();
        fd.append('file', new Blob([bindText], { type: 'text/bind' }), 'import.txt');
        if (proxied) fd.append('proxied', 'true');
        const r = await fetch(`${CF_API_BASE}/zones/${zoneId}/dns_records/import`, { method: 'POST', headers: cfHeaders(payload.email, payload.key), body: fd });
        const data = await r.json().catch(() => ({}));
        return json({ success: r.ok && data.success !== false, result: data.result || null, error: r.ok ? undefined : ((data.errors && data.errors[0] && data.errors[0].message) || '导入失败 HTTP ' + r.status) });
      }
      case 'list-r2-buckets': {
        const accountId = payload.accountId || await getAccountId(payload.email, payload.key);
        const r = await cfGet(`/accounts/${accountId}/r2/buckets?per_page=1000`, payload.email, payload.key);
        if (!r.success) return json({ success: false, error: (r.errors && r.errors[0] && r.errors[0].message) || '获取 R2 桶失败' });
        return json({ success: true, buckets: r.result || [] });
      }
      case 'get-zone-analytics': {
        const { zoneId } = payload;
        if (!zoneId) return json({ success: false, error: 'zoneId required' }, 400);
        try {
          const end = new Date(); const start = new Date(Date.now() - 24 * 3600 * 1000);
          const q = `query Z($tag:String!,$st:Time!,$et:Time!){viewer{zones(filter:{zoneTag:$tag}){httpRequests1hGroups(limit:24,filter:{datetime_geq:$st,datetime_leq:$et}){dimensions{datetimeHour}sum{requests bytes}uniq{uniques}}}}}`
          const g = await fetch('https://api.cloudflare.com/client/v4/graphql', { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, cfHeaders(payload.email, payload.key)), body: JSON.stringify({ query: q, variables: { tag: zoneId, st: start.toISOString(), et: end.toISOString() } }) });
          const res = await g.json();
          const zone = res && res.data && res.data.viewer && res.data.viewer.zones && res.data.viewer.zones[0];
          const groups = (zone && zone.httpRequests1hGroups) || [];
          return json({ success: true, groups });
        } catch(e){ return json({ success: false, error: '流量查询失败：' + e.message }); }
      }

      case 'save-tg-config': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success: false, error: 'CF_ACCOUNTS_KV 未绑定' });
        const cfg = payload.config || {};
        const cur = await env.CF_ACCOUNTS_KV.get('tg_config');
        let merged = { enabled:true, dailyReport:true, alerts:true };
        if (cur) { try { merged = Object.assign(merged, JSON.parse(cur)); } catch(e){} }
        if (typeof cfg.botToken === 'string') merged.botToken = cfg.botToken;
        if (typeof cfg.chatId === 'string') merged.chatId = cfg.chatId;
        if (typeof cfg.enabled === 'boolean') merged.enabled = cfg.enabled;
        if (typeof cfg.dailyReport === 'boolean') merged.dailyReport = cfg.dailyReport;
        if (typeof cfg.alerts === 'boolean') merged.alerts = cfg.alerts;
        if (typeof cfg.alertsTraffic === 'boolean') merged.alertsTraffic = cfg.alertsTraffic;
        if (Array.isArray(cfg.reportHours)) merged.reportHours = cfg.reportHours.map(Number).filter(h => h >= 0 && h <= 23);
        if (cfg.segments && typeof cfg.segments === 'object' && !Array.isArray(cfg.segments)) merged.segments = { quota: cfg.segments.quota !== false, traffic: cfg.segments.traffic !== false, health: cfg.segments.health !== false };
        await env.CF_ACCOUNTS_KV.put('tg_config', JSON.stringify(merged));
        return json({ success: true });
      }

      case 'load-tg-config': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success:false, error:'CF_ACCOUNTS_KV 未绑定' });
        const raw = await env.CF_ACCOUNTS_KV.get('tg_config');
        const cfg = raw ? JSON.parse(raw) : { enabled:true, dailyReport:true, alerts:true };
        const masked = cfg.botToken ? (cfg.botToken.slice(0,4) + '****' + cfg.botToken.slice(-4)) : '';
        return json({ success:true, config: Object.assign({}, cfg, { botToken: masked, botTokenSet: !!cfg.botToken }) });
      }

      // P0-B 多通道通知配置
      case 'save-notify-config': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success:false, error:'CF_ACCOUNTS_KV 未绑定' });
        const nc = payload.config || {};
        const clean = { discord:{enabled:false}, bark:{enabled:false}, wecom:{enabled:false} };
        if(nc.discord){ clean.discord = { enabled: !!nc.discord.enabled, webhook: String(nc.discord.webhook||'').trim() }; }
        if(nc.bark){ clean.bark = { enabled: !!nc.bark.enabled, deviceKey: String(nc.bark.deviceKey||'').trim(), server: String(nc.bark.server||'').trim() }; }
        if(nc.wecom){ clean.wecom = { enabled: !!nc.wecom.enabled, key: String(nc.wecom.key||'').trim() }; }
        await env.CF_ACCOUNTS_KV.put('notify_config', JSON.stringify(clean));
        return json({ success:true });
      }
      case 'load-notify-config': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success:false, error:'CF_ACCOUNTS_KV 未绑定' });
        let nc = {}; try { const r = await env.CF_ACCOUNTS_KV.get('notify_config'); if(r) nc = JSON.parse(r)||{}; } catch(e){}
        return json({ success:true, config: nc });
      }

      case 'push-tg-test': {
        const r = await sendTelegram(env, '✅ MyCF TG 推送测试成功\n时间: ' + new Date().toISOString());
        return json(r.ok ? { success:true } : { success:false, error:r.error });
      }

      case 'push-tg-now': {
        const r = await pushDailyReport(env, true);
        return json(r.ok ? { success:true } : { success:false, error:r.error });
      }

      case 'set-tg-webhook': {
        let origin = '';
        try { const u = new URL(req.url); origin = u.origin; } catch(e){}
        const wh = (payload.webhookUrl && String(payload.webhookUrl).trim()) || (origin ? origin.replace(/\/$/,'') + '/telegram' : '');
        if(!wh) return json({ success:false, error:'无法确定 webhook URL' });
        const r = await setTGWebhook(env, wh);
        return json(r.ok ? { success:true, webhook: wh } : { success:false, error: (r.error || (r.raw && r.raw.description) || JSON.stringify(r.raw||{})) });
      }

      case 'get-tg-webhook': {
        const r = await getTGWebhook(env);
        return json(r.ok ? { success:true, info: r.info } : { success:false, error: r.error });
      }

      case 'set-tg-commands': {
        const r = await registerTGCommands(env);
        return json(r.ok ? { success:true } : { success:false, error: r.error || JSON.stringify(r.raw||{}) });
      }

      case 'get-all-usage': {
        const creds = await loadKVAccounts(env);
        if (!creds.length) return json({ success:false, error:'KV 中无账号' });
        const results = [];
        for (const c of creds) {
          try { const list = await queryAllUsageForCred(env, c); results.push(...list); }
          catch(e){ results.push({ email:c.email, error:String(e) }); }
        }
        return json({ success:true, date: new Date().toISOString().slice(0,10), results });
      }

      // ================= 监控中心 actions（走 KV 凭据，免登录校验） =================
      case 'get-dashboard': {
        const out = { snap: null, daily: {}, usage: {}, accounts: [], officialDaily: {}, officialFetchedAt: '', officialUsage: {}, officialUsageFetchedAt: '' };
        try { const r = await kvGet(env, 'an_snap'); if (r) out.snap = JSON.parse(r); } catch(e){}
        try { const r = await kvGet(env, 'an_daily'); if (r) out.daily = JSON.parse(r) || {}; } catch(e){}
        try { const r = await kvGet(env, 'official_daily'); if (r) { const od = JSON.parse(r) || {}; out.officialDaily = od.data || {}; out.officialFetchedAt = od.fetchedAt || ''; } } catch(e){}
        try { const r = await kvGet(env, 'official_usage'); if (r) { const ou = JSON.parse(r) || {}; out.officialUsage = ou.data || {}; out.officialUsageFetchedAt = ou.fetchedAt || ''; } } catch(e){}
        try { const r = await kvGet(env, 'usage_history'); if (r) out.usage = JSON.parse(r) || {}; } catch(e){}
        try {
          const accs = await loadKVAccounts(env);
          out.accounts = accs.map(a => ({ email: a.email || '', name: a.name || '', oauth: !!a.oauth, oauthId: a.oauthId || '', status: a.status || 'ok', group: a.group || '' }));
        } catch(e){}
        return json({ success: true, dash: out });
      }
      case 'collect-analytics-now': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success: false, error: 'CF_ACCOUNTS_KV 未绑定' });
        const h = await storeAnalytics(env);        // 24h 快照（官方 1hGroups 直读）
        const d = await storeOfficialAnalytics(env); // 官方按日 92 天直读
        return json({ success: true, ok: h.ok + d.ok, fail: h.fail + d.fail });
      }

      case 'backfill-usage-history': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success: false, error: 'CF_ACCOUNTS_KV 未绑定' });
        const daysN = Math.min(Math.max(parseInt(payload.days, 10) || 14, 1), 30);   // 上限 30 天，逐日官方现查
        const creds = await loadKVAccounts(env);
        if(!creds.length) return json({ success: false, error: 'KV 中无账号' });
        let merged = null;
        try { const r = await kvGet(env, 'official_usage'); if (r) merged = JSON.parse(r) || null; } catch(e){ merged = null; }
        if(!merged) merged = { data:{} };
        let ok = 0, fail = 0;
        const iso = (d) => { const x = new Date(d); x.setUTCHours(0,0,0,0); return x.toISOString(); };
        const dates = [];
        for (let i = 1; i <= daysN; i++) dates.push(iso(Date.now() - i * 86400000));   // 昨天起往前 N 天
        for (const c of creds){
          const email = c.email || c.name || ('acc-' + String(c.accountId || '').slice(0,6));
          const key = c.oauth ? OAUTH_KEY_PREFIX + c.accessToken : c.key;
          if(!key){ fail++; continue; }
          try {
            const ar = await cfGet('/accounts', c.email, oauthOrKey(c));
            if(!ar || !ar.success){ fail++; continue; }
            for(const a of (ar.result||[])){
              for(const s of dates){
                const e = new Date(new Date(s).getTime() + 86400000 - 1).toISOString();
                const u = await queryUsageByAccountId(c.email, oauthOrKey(c), a.id, s, e);
                if(u.error) continue;
                const date = s.slice(0,10);
                const arr = merged.data[date] = merged.data[date] || [];
                const idx = arr.findIndex(x => x.email === email && x.accountId === a.id);
                const rec = { email, accountId: a.id, name: a.name || '', total: u.total, workers: u.workers, pages: u.pages };
                if (idx > -1) arr[idx] = rec; else arr.push(rec);
              }
            }
            ok++;
          } catch(e){ fail++; }
        }
        const ds = Object.keys(merged.data).sort(); while (ds.length > 70) delete merged.data[ds.shift()];
        merged.fetchedAt = new Date().toISOString();
        await kvPut(env, 'official_usage', merged);
        return json({ success: true, ok, fail, days: dates.length });
      }

      case 'get-usage-trend': {
        let history = {}; try { const r = await kvGet(env,'usage_history'); if(r) history = JSON.parse(r)||{}; } catch(e){}
        const credsN = (await loadKVAccounts(env)).length;
        return json({ success:true, trend: computeUsageTrend(history, 30), accounts: computeAccountTrends(history, 30), prediction: predictExhaustion(history, credsN) });
      }
      case 'run-monitor-now': {
        await runDailyMonitoring(env);
        await runProbeMonitoring(env);
        return json({ success:true, message:'监控巡检已执行，数据已刷新' });
      }
      case 'get-asset-audit': {
        let snap = null; try { const r = await kvGet(env,'asset_snapshot'); if(r) snap = JSON.parse(r); } catch(e){}
        return json({ success:true, snapshot: snap });
      }
      case 'get-storage-usage': {
        let data = []; try { const r = await kvGet(env,'storage_usage'); if(r) data = JSON.parse(r)||[]; } catch(e){}
        return json({ success:true, data });
      }
      case 'get-health-probe': {
        let results = []; try { const r = await kvGet(env,'health_probe'); if(r) results = JSON.parse(r)||[]; } catch(e){}
        return json({ success:true, results });
      }
      case 'get-cert-expiry': {
        let certs = []; try { const r = await kvGet(env,'cert_expiry'); if(r) certs = JSON.parse(r)||[]; } catch(e){}
        return json({ success:true, certs });
      }
      case 'get-waf-status': {
        let waf = []; try { const r = await kvGet(env,'waf_status'); if(r) waf = JSON.parse(r)||[]; } catch(e){}
        return json({ success:true, waf });
      }
      case 'get-audit-log': {
        let log = []; try { const r = await kvGet(env,'audit_log'); if(r) log = JSON.parse(r)||[]; } catch(e){}
        return json({ success:true, log });
      }
      // ================= 批量操作（需当前登录凭据） =================
      case 'bulk-deploy': {
        const { scriptName, scriptSource, targets } = payload;
        if (!scriptName || !Array.isArray(targets) || !targets.length) return json({ success:false, error:'scriptName 与 targets 必填' }, 400);
        const results = [];
        for(const t of targets){
          try { const r = await deployWorkerTo(t.email, t.key, t.accountId, scriptName, scriptSource, payload.metadataBindings, payload.usage_model); results.push({ accountId:t.accountId, ok:r.success, message:r.message }); }
          catch(e){ results.push({ accountId:t.accountId, ok:false, message:String(e) }); }
        }
        await writeAudit(env, { action:'bulk-deploy', scriptName, count:targets.length, results });
        return json({ success:true, results });
      }
      case 'bulk-purge': {
        const { zoneIds, email, key, files, everything } = payload;
        if (!Array.isArray(zoneIds) || !zoneIds.length) return json({ success:false, error:'zoneIds 必填' }, 400);
        if (!email || !key) return json({ success:false, error:'email/key 必填' }, 400);
        const results = [];
        for(const zid of zoneIds){
          try { const r = await cfPost('/zones/'+zid+'/purge_cache', email, key, everything ? { purge_everything:true } : { files: files||[] }); results.push({ zoneId:zid, ok:r.success, message:r.errors?.[0]?.message }); }
          catch(e){ results.push({ zoneId:zid, ok:false, message:String(e) }); }
        }
        await writeAudit(env, { action:'bulk-purge', count:zoneIds.length, results });
        return json({ success:true, results });
      }
      case 'bulk-dns': {
        const { zoneIds, email, key, paused } = payload;
        if (!Array.isArray(zoneIds) || !zoneIds.length) return json({ success:false, error:'zoneIds 必填' }, 400);
        if (!email || !key) return json({ success:false, error:'email/key 必填' }, 400);
        const results = [];
        for(const zid of zoneIds){
          try { const zr = await cfGet('/zones/'+zid, email, key); const zone = zr.success ? zr.result : null; if(zone){ const up = await cfPut('/zones/'+zid, email, key, { paused: !!paused }); results.push({ zoneId:zid, ok:up.success }); } else results.push({ zoneId:zid, ok:false, message:'zone 不存在' }); }
          catch(e){ results.push({ zoneId:zid, ok:false, message:String(e) }); }
        }
        await writeAudit(env, { action:'bulk-dns', paused:!!paused, count:zoneIds.length, results });
        return json({ success:true, results });
      }

      default:
        return json({ success:false, error:'unknown action' },400);
    }
  } catch(e) {
    return json({ success:false, error: String(e) },500);
  }
}

// ---------------- Telegram 推送 ----------------
function fmtNum(n){ return (n||0).toLocaleString('en-US'); }
function maskEmail(e){
  e = String(e||'').replace(/^[\s\u200B-\u200D\uFEFF]+|[\s\u200B-\u200D\uFEFF]+$/g,'');
  if(!e) return '未知';
  const i = e.indexOf('@');
  if(i <= 0) return '未知';
  const u = e.slice(0,i), d = e.slice(i+1);
  if(u.length <= 1) return '*@' + d;
  return u.slice(0,1) + '***@' + d;
}
function relBar(val, max, width){
  const w = width || 16;
  if(!max || !val) return '░'.repeat(w);
  const n = Math.min(w, Math.max(1, Math.round(val/max*w)));
  return '█'.repeat(n) + '░'.repeat(w-n);
}
function computeExhaustion(total){
  if(!total || total <= 0) return null;
  const now = new Date();
  const sod = new Date(now); sod.setUTCHours(0,0,0,0);
  const elapsed = (now - sod)/1000;
  if(elapsed <= 0) return null;
  const rate = total/elapsed;
  const remain = 100000 - total;
  if(remain <= 0) return '已耗尽';
  const eta = new Date(now.getTime() + (remain/rate)*1000);
  return eta.toISOString().slice(11,16) + ' UTC';
}
// ---- P1-D 凭据 AES-GCM 加密存储（依赖 Worker secret: SECRET_KEY）----
async function getCryptoKey(env){
  const sk = env && env.SECRET_KEY;
  if(!sk) return null;
  try {
    const enc = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', enc.encode(sk), { name:'PBKDF2' }, false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name:'PBKDF2', salt: enc.encode('mycf-v1-salt'), iterations: 100000, hash:'SHA-256' },
      km, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
    );
  } catch(e){ return null; }
}
function _b64enc(bytes){ let s=''; for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]); return btoa(s); }
function _b64dec(b64){ const s=atob(b64); const out=new Uint8Array(s.length); for(let i=0;i<s.length;i++) out[i]=s.charCodeAt(i); return out; }
async function encJSON(obj, key){
  if(!key) return obj;
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const buf = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  const combined = new Uint8Array(iv.length + buf.byteLength);
  combined.set(iv, 0); combined.set(new Uint8Array(buf), iv.length);
  return { __enc:true, data:_b64enc(combined) };
}
async function decJSON(wrapped, key){
  if(!wrapped || !wrapped.__enc) return wrapped;
  if(!key) return null;
  try {
    const combined = _b64dec(wrapped.data);
    const iv = combined.slice(0,12); const ct = combined.slice(12);
    const buf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(buf));
  } catch(e){ return null; }
}
async function loadKVAccounts(env){
  if(!env || !env.CF_ACCOUNTS_KV) return [];
  const raw = await env.CF_ACCOUNTS_KV.get('accounts');
  if(!raw) return [];
  let arr; try { arr = JSON.parse(raw); } catch(e){ return []; }
  if(!Array.isArray(arr)) return [];
  const key = await getCryptoKey(env);
  if(!key) return arr; // 未配置 SECRET_KEY：明文兼容
  const out = [];
  for(const a of arr){ if(a && a.__enc){ const d = await decJSON(a, key); if(d) out.push(d); } else out.push(a); }
  return out;
}
// ============ OAuth 2.0 免密钥接入（Authorization Code + client_secret）============
// 前置：dash → Manage Account → OAuth clients 自建 client（redirect: <本面板>/oauth/callback）
async function getOAuthClient(env){
  if (!env || !env.CF_ACCOUNTS_KV) return null;
  const raw = await env.CF_ACCOUNTS_KV.get(OAUTH_CLIENT_KV);
  if (!raw) return null;
  let cl; try { cl = JSON.parse(raw); } catch(e){ return null; }
  const key = await getCryptoKey(env);
  if (key && cl && cl.__enc) { const d = await decJSON(cl, key); if (d) cl = d; }
  return (cl && cl.clientId) ? cl : null;
}
async function saveOAuthClient(env, client){
  if (!env || !env.CF_ACCOUNTS_KV) return;
  const key = await getCryptoKey(env);
  await env.CF_ACCOUNTS_KV.put(OAUTH_CLIENT_KV, JSON.stringify(key ? await encJSON(client, key) : client));
}
// token 端点调用：authMethod = post(默认,secret 放 body) | basic(Authorization Basic) | none(PKCE)
async function oauthTokenFetch(cl, params){
  const body = new URLSearchParams(Object.assign({ client_id: cl.clientId }, params));
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  const am = cl.authMethod || 'post';
  if (am === 'basic') headers['Authorization'] = 'Basic ' + btoa(cl.clientId + ':' + (cl.clientSecret || ''));
  else if (am !== 'none' && cl.clientSecret) body.set('client_secret', cl.clientSecret);
  const r = await fetch(CF_OAUTH_TOKEN, { method:'POST', headers, body: body.toString() });
  if (!r.ok) { const t = await r.text().catch(()=>''); const e = new Error('token HTTP ' + r.status + ' ' + t.slice(0,160)); e.status = r.status; throw e; }
  return r.json();
}
async function persistAccountsEnc(env, arr){
  if (!env || !env.CF_ACCOUNTS_KV) return;
  const key = await getCryptoKey(env);
  const toStore = [];
  for (const a of arr) toStore.push(key ? await encJSON(a, key) : a);
  await env.CF_ACCOUNTS_KV.put('accounts', JSON.stringify(toStore));
}
// 同账号合并策略：① 已有 oauth 连接同 accountId → 更新；② 否则 email 命中已有 Global Key 账号 → 升级为双通道(保留 key)；③ 否则新增 oauth 连接
async function upsertOAuthAccount(env, acc){
  const arr = await loadKVAccounts(env);
  let i = arr.findIndex(a => a && a.oauth && acc.accountId && a.accountId === acc.accountId);
  if (i === -1 && acc.email) i = arr.findIndex(a => a && !a.oauth && a.email === acc.email);
  let out;
  if (i !== -1) {
    const old = arr[i];
    const merged = Object.assign({}, old, acc, {
      oauth: true,
      oauthId: old.oauthId || acc.oauthId,
      accountId: old.accountId || acc.accountId,
      key: old.key || (old.oauth ? '' : (old.key || '')),   // 保留已存的 Global Key(双通道并存)
      accessToken: acc.accessToken || old.accessToken,
      refreshToken: acc.refreshToken || old.refreshToken,
      expiresAt: acc.expiresAt || old.expiresAt
    });
    if (!merged.email && old.email) merged.email = old.email;
    if (!merged.name && old.name) merged.name = old.name;
    out = merged; arr[i] = merged;
  } else { out = acc; arr.unshift(acc); }
  await persistAccountsEnc(env, arr);
  return out;
}
async function refreshOAuthToken(env, acc){
  try {
    const cl = await getOAuthClient(env);
    if (!cl || !cl.clientId || !acc || !acc.refreshToken) return null;
    const j = await oauthTokenFetch(cl, { grant_type: 'refresh_token', refresh_token: acc.refreshToken });
    if (!j || !j.access_token) return null;
    const exp = (j.expires_in && Number(j.expires_in)) || 3600;
    acc.accessToken = j.access_token;
    if (j.refresh_token) acc.refreshToken = j.refresh_token;
    acc.expiresAt = Date.now() + exp * 1000;
    await upsertOAuthAccount(env, acc);
    return acc;
  } catch(e){ return null; }
}
async function handleOAuthStart(env, url){
  const html = (msg, ok) => new Response('<!doctype html><html><head><meta charset="utf-8"><title>OAuth</title></head><body style="font-family:system-ui,sans-serif;background:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0"><div style="background:#fff;border-radius:16px;padding:32px 40px;max-width:520px;box-shadow:0 10px 30px rgba(2,6,23,.08);text-align:center"><div style="font-size:44px;margin-bottom:12px">' + (ok ? '🔐' : '⚠️') + '</div><h2 style="margin:0 0 10px;color:#0f172a">' + (ok ? '正在前往 Cloudflare 授权…' : 'OAuth 无法启动') + '</h2><p style="color:#64748b;line-height:1.7">' + msg + '</p><p style="margin-top:18px"><a href="/settings" style="color:#1d4ed8">← 返回设置</a></p></div></body></html>', { headers: { 'content-type': 'text/html; charset=utf-8' } });
  const cl = await getOAuthClient(env);
  if (!cl || !cl.clientId) return html('请先在面板「设置 → OAuth 免密钥接入」保存 <b>Client ID</b> 与 <b>Client Secret</b>。', false);
  const state = randHex(16);
  if (env && env.CF_ACCOUNTS_KV) await env.CF_ACCOUNTS_KV.put('oauth_state_' + state, cl.clientId, { expirationTtl: 600 });
  const q = new URLSearchParams({ client_id: cl.clientId, response_type: 'code', redirect_uri: url.origin + '/oauth/callback', state });
  return Response.redirect(CF_OAUTH_AUTH + '?' + q.toString(), 302);
}
async function handleOAuthCallback(env, url){
  const errRedirect = (msg) => Response.redirect(url.origin + '/login?oauth_error=' + encodeURIComponent(msg), 302);
  const code = url.searchParams.get('code'), state = url.searchParams.get('state');
  if (!code || !state) return errRedirect('回调缺少 code 或 state');
  if (!env || !env.CF_ACCOUNTS_KV) return errRedirect('CF_ACCOUNTS_KV 未绑定');
  const cl = await getOAuthClient(env);
  if (!cl || !cl.clientId) return errRedirect('OAuth client 未配置');
  const stKey = 'oauth_state_' + state;
  const stored = await env.CF_ACCOUNTS_KV.get(stKey);
  if (!stored || stored !== cl.clientId) return errRedirect('state 校验失败，请重新发起授权');
  await env.CF_ACCOUNTS_KV.delete(stKey);
  try {
    const j = await oauthTokenFetch(cl, { grant_type: 'authorization_code', code, redirect_uri: url.origin + '/oauth/callback' });
    if (!j || !j.access_token) return errRedirect('换取 token 失败' + (j && j.error ? '：' + j.error : ''));
    const hdr = { Authorization: 'Bearer ' + j.access_token };
    let email = '', accounts = [];
    try { const u = await (await fetch(CF_API_BASE + '/user', { headers: hdr })).json(); if (u && u.result && u.result.email) email = u.result.email; } catch(e){}
    try { const a = await (await fetch(CF_API_BASE + '/accounts', { headers: hdr })).json(); if (a && Array.isArray(a.result)) accounts = a.result; } catch(e){}
    const acc0 = accounts[0] || {};
    const expiresIn = (j.expires_in && Number(j.expires_in)) || 3600;
    const acc = {
      oauth: true,
      oauthId: 'oau_' + randHex(6),
      name: acc0.name || email || 'Cloudflare OAuth',
      email: email || '',
      key: '',                       // oauth 账号不使用 Global Key
      accountId: acc0.id || '',
      accountIds: (accounts || []).map(x => x.id),
      scope: String(j.scope || '').slice(0, 300),
      accessToken: j.access_token,
      refreshToken: j.refresh_token || '',
      expiresAt: Date.now() + expiresIn * 1000,
      added: new Date().toISOString().slice(0, 10),
      status: 'ok'
    };
    const mergedAcc = await upsertOAuthAccount(env, acc);
    try { await sendTelegram(env, '✅ OAuth 授权完成\n账号：' + (acc.name || acc.email || acc.oauthId) + (acc.scope ? '\nScope：' + String(acc.scope).slice(0, 120) : '') + ((mergedAcc && mergedAcc.key) ? '\n（该账号已并存 Global Key，OAuth 失效时自动回退）' : ''), 'OAuth'); } catch(e){}
    return Response.redirect(url.origin + '/workers?oauth=ok', 302);
  } catch(e){ return errRedirect('OAuth 完成失败：' + e.message); }
}

async function getTGConfig(env){
  let botToken = env && env.TG_BOT_TOKEN;
  let chatId = env && env.TG_CHAT_ID;
  const cfg = { enabled:true, dailyReport:true, alerts:true };
  if(env && env.CF_ACCOUNTS_KV){
    const raw = await env.CF_ACCOUNTS_KV.get('tg_config');
    if(raw){ try { Object.assign(cfg, JSON.parse(raw)); } catch(e){} }
  }
  if(!botToken && cfg.botToken) botToken = cfg.botToken;
  if(!chatId && cfg.chatId) chatId = cfg.chatId;
  return { botToken, chatId, enabled: cfg.enabled !== false, dailyReport: cfg.dailyReport !== false, alerts: cfg.alerts !== false };
}
async function sendTelegramTo(env, chatId, text){
  const cfg = await getTGConfig(env);
  if(!cfg.botToken) return { ok:false, error:'TG 未配置：请在「设置」填写 Bot Token 与 Chat ID' };
  if(!chatId) return { ok:false, error:'TG 未配置 Chat ID' };
  const chunks = splitTGMessage(text);
  for(const c of chunks){
    const r = await fetch('https://api.telegram.org/bot' + cfg.botToken + '/sendMessage', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ chat_id: chatId, text:c, disable_web_page_preview:true })
    });
    if(!r.ok){ const t = await r.text(); return { ok:false, error:'TG 发送失败: ' + r.status + ' ' + t.slice(0,200) }; }
  }
  return { ok:true };
}
async function sendTelegram(env, text, title){
  return await notify(env, text, title);
}
// ---- P0-B 多通道通知层（Telegram + Discord + Bark + 企业微信）----
function chunkText(text, max){
  const out=[]; let cur='';
  const lines = String(text).split('\n');
  for(let ln of lines){
    // 超长单行按字符硬切（无换行的超长内容也能分片）
    while(ln.length > max){ if(cur){ out.push(cur); cur=''; } out.push(ln.slice(0,max)); ln = ln.slice(max); }
    if((cur + '\n' + ln).length > max){ if(cur) out.push(cur); cur = ln; }
    else cur = cur ? cur + '\n' + ln : ln;
  }
  if(cur) out.push(cur);
  return out.length?out:[''];
}
async function sendDiscord(webhook, text){
  for(const p of chunkText(text, 1900)){
    const r = await fetch(webhook, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ content: p }) });
    if(!r.ok) return { ok:false, error:'Discord '+r.status };
  }
  return { ok:true };
}
async function sendBark(cfg, text, title){
  const server = (cfg.server || 'https://api.day.app').replace(/\/$/,'');
  const url = server + '/' + encodeURIComponent(cfg.deviceKey) + '/' + encodeURIComponent(title||'MyCF') + '/' + encodeURIComponent(String(text).slice(0,4000));
  try { const r = await fetch(url, { method:'GET' }); const j = await r.json().catch(()=>({})); return { ok: j.code===200 }; } catch(e){ return { ok:false, error:String(e) }; }
}
async function sendWeCom(key, text){
  const url = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=' + encodeURIComponent(key);
  const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ msgtype:'text', text:{ content: text } }) });
  const j = await r.json().catch(()=>({})); return { ok: j.errcode===0 };
}
async function getNotifyConfig(env){
  let nc = {}; try { const r = await kvGet(env,'notify_config'); if(r) nc = JSON.parse(r)||{}; } catch(e){}
  return nc;
}
async function notify(env, text, title){
  const cfg = await getTGConfig(env);
  const results = [];
  if(cfg.botToken && cfg.chatId) results.push(await sendTelegramTo(env, cfg.chatId, text));
  const nc = await getNotifyConfig(env);
  if(nc.discord && nc.discord.enabled && nc.discord.webhook) results.push(await sendDiscord(nc.discord.webhook, text));
  if(nc.bark && nc.bark.enabled && nc.bark.deviceKey) results.push(await sendBark(nc.bark, text, title));
  if(nc.wecom && nc.wecom.enabled && nc.wecom.key) results.push(await sendWeCom(nc.wecom.key, text));
  // 任一通道送达即视为成功（多通道保活：单通道故障不影响整体）
  const ok = results.length>0 && results.some(r=>r&&r.ok);
  return { ok, results };
}
// 是否有任一可用通知通道（告警守卫不再仅认 Telegram）
async function notifReady(env){
  const cfg = await getTGConfig(env);
  if(cfg.enabled && cfg.botToken && cfg.chatId) return true;
  const nc = await getNotifyConfig(env);
  return !!((nc.discord && nc.discord.enabled && nc.discord.webhook) || (nc.bark && nc.bark.enabled && nc.bark.deviceKey) || (nc.wecom && nc.wecom.enabled && nc.wecom.key));
}
function buildAbnormalMsg(list){
  const L = ['🚫 异常/封号账号（' + list.length + '）'];
  for(const x of list) L.push('• ' + maskEmail(x.email) + ' → ' + (x.reason||x.status));
  return L.join('\n');
}
function splitTGMessage(text){
  const MAX = 3900; const lines = String(text).split('\n'); const out=[]; let cur='';
  for(const ln of lines){
    if((cur + '\n' + ln).length > MAX){ if(cur) out.push(cur); cur = ln; }
    else cur = cur ? cur + '\n' + ln : ln;
  }
  if(cur) out.push(cur);
  return out.length ? out : [''];
}
// ---- Telegram 机器人指令 ----
const TG_COMMANDS = [
  { command:'report', description:'立即推送每日用量/流量报告' },
  { command:'dash', description:'推送今日账号池摘要' },
  { command:'status', description:'账号池健康(异常/证书/探活/WAF)' },
  { command:'top', description:'账号 24h 请求排行' },
  { command:'zone', description:'查询某账号 Zones Top(带账号关键字)' },
  { command:'oauth', description:'OAuth 连接状态' },
  { command:'probe', description:'立即执行端点探活并推送状态' },
  { command:'help', description:'显示可用指令' }
];
async function registerTGCommands(env){
  const cfg = await getTGConfig(env);
  if(!cfg.botToken) return { ok:false, error:'TG 未配置' };
  const r = await fetch('https://api.telegram.org/bot' + cfg.botToken + '/setMyCommands', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ commands: TG_COMMANDS })
  });
  const j = await r.json().catch(()=>({}));
  return { ok: !!j.ok, raw: j };
}
// ---- P0-A webhook secret_token 鉴权（社区标准做法）----
const TG_WEBHOOK_SECRET_KEY = 'tg_webhook_secret';
async function getTGWebhookSecret(env){
  if(!env || !env.CF_ACCOUNTS_KV) return null;
  let s = null; try { s = await env.CF_ACCOUNTS_KV.get(TG_WEBHOOK_SECRET_KEY); } catch(e){}
  if(!s){
    // 生成 32 字节随机十六进制密钥并持久化
    const bytes = new Uint8Array(32);
    if(typeof crypto !== 'undefined' && crypto.getRandomValues){ crypto.getRandomValues(bytes); }
    else { for(let i=0;i<32;i++) bytes[i] = Math.floor(Math.random()*256); }
    s = Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
    try { await env.CF_ACCOUNTS_KV.put(TG_WEBHOOK_SECRET_KEY, s); } catch(e){}
  }
  return s;
}
async function setTGWebhook(env, webhookUrl){
  const cfg = await getTGConfig(env);
  if(!cfg.botToken) return { ok:false, error:'TG 未配置' };
  const secret = await getTGWebhookSecret(env);
  const body = { url: webhookUrl, secret_token: secret, allowed_updates: ['message'] };
  const r = await fetch('https://api.telegram.org/bot' + cfg.botToken + '/setWebhook', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  });
  const j = await r.json().catch(()=>({}));
  return { ok: !!j.ok, raw: j };
}
async function getTGWebhook(env){
  const cfg = await getTGConfig(env);
  if(!cfg.botToken) return { ok:false, error:'TG 未配置' };
  const r = await fetch('https://api.telegram.org/bot' + cfg.botToken + '/getWebhookInfo', { method:'GET' });
  const j = await r.json().catch(()=>({}));
  const info = j.result || {};
  return { ok: !!j.ok, info: {
    url: info.url || '',
    pending_update_count: info.pending_update_count || 0,
    last_error: info.last_error_message || '',
    last_error_date: info.last_error_date || ''
  } };
}
function tgHelpText(){
  return '🤖 MyCF 机器人指令：\n/report - 立即推送每日用量+流量报告\n/dash - 今日账号池摘要\n/status - 账号池健康(异常/证书/探活/WAF)\n/top - 账号 24h 请求排行\n/zone <关键字> - 该账号 Zones Top10\n/oauth - OAuth 连接状态\n/probe - 立即执行端点探活\n/help - 显示本帮助';
}
async function saveTGConfigRaw(env, cfg){
  if(!env || !env.CF_ACCOUNTS_KV) return;
  await env.CF_ACCOUNTS_KV.put('tg_config', JSON.stringify(cfg));
}
async function handleTelegramWebhook(request, env){
  // P0-A: 校验 Telegram 传来的 secret_token 头，杜绝任何人可 POST /telegram
  const secret = await getTGWebhookSecret(env);
  if(secret){
    const h = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
    if(h !== secret) return new Response('Unauthorized', { status: 401 });
  }
  let update;
  try { update = await request.json(); } catch(e){ return new Response('bad json', { status: 400 }); }
  const cfg = await getTGConfig(env);
  const msg = update.message; const cb = update.callback_query;
  let chatId = null, text = null;
  if(msg){ chatId = msg.chat && msg.chat.id; text = msg.text || ''; }
  else if(cb){ chatId = cb.message && cb.message.chat && cb.message.chat.id; text = cb.data || ''; }
  if(!chatId) return new Response('ok', { status: 200 });
  const t = (text||'').trim();
  // 配对/绑定：/start 或 /bind 始终把当前聊天绑定为接收者（自愈填错的 Chat ID）
  if(t === '/start' || t === '/bind' || t === 'bind'){
    if(String(cfg.chatId||'') !== String(chatId)){
      try { cfg.chatId = String(chatId); await saveTGConfigRaw(env, cfg); } catch(e){}
    }
    await sendTelegramTo(env, chatId, tgHelpText());
    return new Response('ok', { status: 200 });
  }
  // 其余指令：未绑定 Chat ID 时自动绑定首次来讯；已绑定则仅响应本聊天（陌生人不会触发）
  if(!cfg.chatId){
    try { cfg.chatId = String(chatId); await saveTGConfigRaw(env, cfg); } catch(e){}
  } else if(String(cfg.chatId) !== String(chatId)){
    return new Response('ok', { status: 200 });
  }
  try {
    const cmd = t.split(/\s+/)[0].toLowerCase().replace(/^\/+/, '');
    const arg = t.slice(t.indexOf(' ') + 1).trim();
    const say = (msg) => sendTelegramTo(env, chatId, msg);
    if(cmd === 'help' || cmd === '菜单'){
      await say(tgHelpText());
    } else if(cmd === 'report'){
      const r = await pushDailyReport(env, true);
      if(!r.ok) await say('❌ 日报推送失败：' + (r.error||''));
    } else if(cmd === 'dash'){
      await say(await tgDashDigest(env));
    } else if(cmd === 'status'){
      await say(await tgStatusDigest(env));
    } else if(cmd === 'top'){
      await say(await tgTopAccounts(env));
    } else if(cmd === 'zone'){
      await say(await tgZoneTop(env, arg));
    } else if(cmd === 'oauth'){
      await say(await tgOauthStatus(env));
    } else if(cmd === 'probe'){
      await say('⏳ 正在执行端点探活...');
      await runProbeMonitoring(env);
      await say('✅ 探活完成（异常会单独告警）');
    } else if(t){
      await say('未知指令，发送 /help 查看可用指令');
    }
  } catch(e){
    try { await sendTelegramTo(env, chatId, '⚠️ 处理指令出错：' + String(e).slice(0,200)); } catch(_){}
  }
  return new Response('ok', { status: 200 });
}
const TG_USAGE_QUERY = `query Usage($accountId:String!,$filter:AccountWorkersInvocationsAdaptiveFilter_InputObject){viewer{accounts(filter:{accountTag:$accountId}){pagesFunctionsInvocationsAdaptiveGroups(limit:1000,filter:$filter){sum{requests}}workersInvocationsAdaptive(limit:10000,filter:$filter){dimensions{scriptName}sum{requests}}}}}`;
async function queryUsageByAccountId(email, key, accountId, startISO, endISO){
  let start, end;
  if (startISO && endISO) { start = startISO; end = endISO; }
  else {
    const now = new Date();
    end = now.toISOString();
    now.setUTCHours(0,0,0,0);
    start = now.toISOString();
  }
  const r = await fetch('https://api.cloudflare.com/client/v4/graphql', {
    method:'POST', headers:Object.assign({ 'Content-Type':'application/json' }, cfHeaders(email, key)),
    body: JSON.stringify({ query: TG_USAGE_QUERY, variables:{ accountId, filter:{ datetime_geq:start, datetime_leq:end } } })
  });
  if(!r.ok) return { total:0, workers:0, pages:0, percent:0, byScript:[], error:true };
  const res = await r.json();
  const ac = res && res.data && res.data.viewer && res.data.viewer.accounts && res.data.viewer.accounts[0];
  const pages = (ac && ac.pagesFunctionsInvocationsAdaptiveGroups || []).reduce((t,i)=>t+((i&&i.sum&&i.sum.requests)||0),0);
  const groups = (ac && ac.workersInvocationsAdaptive) || [];
  const workers = groups.reduce((t,i)=>t+((i&&i.sum&&i.sum.requests)||0),0);
  const byScript = groups.filter(g=>g&&g.dimensions&&g.dimensions.scriptName).map(g=>({ script:g.dimensions.scriptName, requests:(g.sum&&g.sum.requests)||0 })).sort((a,b)=>b.requests-a.requests);
  return { total: pages+workers, workers, pages, percent: Math.min(100, ((pages+workers)/100000)*100), byScript, error:false };
}
async function queryAllUsageForCred(env, cred){
  const ar = await cfGet('/accounts', cred.email, oauthOrKey(cred));
  if(!ar || !ar.success || !Array.isArray(ar.result)) return [{ email:cred.email, error:'无法获取账号列表' }];
  const out = [];
  for(const a of ar.result){
    const u = await queryUsageByAccountId(cred.email, oauthOrKey(cred), a.id);
    out.push({ email:cred.email, accountId:a.id, name:a.name, ...u });
  }
  return out;
}
function fmtBytesB(b){
  if (!b) return '0B';
  const u = ['B','KB','MB','GB','TB']; let i = 0, v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 ? 0 : 1) + u[i];
}
function buildDailyReport(results, dateStr, ctx){
  ctx = ctx || {};
  const ok = results.filter(r=>!r.error).sort((a,b)=>(b.total||0)-(a.total||0));
  const fail = results.filter(r=>r.error);
  const ranks = ['①','②','③','④','⑤','⑥','⑦','⑧','⑨','⑩'];
  const L = [];
  L.push('📊 MyCF 每日报告');
  L.push('🗓 ' + dateStr + ' (UTC)');
  const sd = ctx.snapData || {};
  const allRecs = Object.keys(sd).map(k => sd[k]);
  if(allRecs.length && !(ctx.segments && ctx.segments.traffic === false)){
    const tReq = allRecs.reduce((s,r)=>s+(r.req||0),0);
    const tB = allRecs.reduce((s,r)=>s+(r.bytes||0),0);
    const tU = allRecs.reduce((s,r)=>s+(r.uniq||0),0);
    L.push('🌐 账号池 24h：请求 ' + fmtNum(tReq) + ' · 流量 ' + fmtBytesB(tB) + ' · 访问 ' + fmtNum(tU));
  }
  const acctLabel = fail.length ? (ok.length + ' 个有效（共 ' + results.length + ' 个）') : (results.length + ' 个账号');
  L.push('👥 ' + acctLabel);
  L.push('════════════════════════');
  ok.forEach((r,idx)=>{
    const masked = maskEmail(r.email);
    const name = r.name ? ' · ' + r.name : '';
    const pct = r.percent || 0;
    const rank = ranks[idx] || ((idx+1) + '.');
    L.push('');
    L.push(rank + ' ' + masked + name);
    if(!(ctx.segments && ctx.segments.quota === false)){
      L.push('   配额 ' + fmtNum(r.total) + ' / 100,000  (' + pct.toFixed(1) + '%)  ' + relBar(r.total, 100000, 12));
      L.push('   Workers ' + fmtNum(r.workers) + ' · Pages ' + fmtNum(r.pages));
      if(r.byScript && r.byScript.length){
        const top = r.byScript.slice(0,5).map(s=> s.script + ' ' + fmtNum(s.requests)).join(' · ');
        L.push('   Top: ' + top);
      }
    }
    if(!(ctx.segments && ctx.segments.traffic === false)){
      const s = sd[r.email];
      if(s){
        L.push('   🚦 请求 ' + fmtNum(s.req) + ' · 流量 ' + fmtBytesB(s.bytes) + ' · 访问 ' + fmtNum(s.uniq));
        const zt = (s.zones||[]).slice(0,3);
        if(zt.length) L.push('   Zones: ' + zt.map(z => z.name + ' ' + fmtNum(z.req)).join(' · '));
      }
    }
  });
  fail.forEach(r=>{
    const masked = maskEmail(r.email);
    L.push('');
    L.push('⚠ ' + masked + ' ' + (r.name||''));
    L.push('   查询失败: ' + (r.error||'未知错误'));
  });
  if(!(ctx.segments && ctx.segments.health === false)){
    const hs = [];
    const abn = ctx.abnormal || [];
    if(abn.length) hs.push('🚫 异常账号 ' + abn.length + '：' + abn.map(a => maskEmail(a.email)).join('、'));
    const certDue = (ctx.certs || []).filter(c => c.days !== null && c.days <= 7).length;
    if(certDue) hs.push('🛡 证书 ' + certDue + ' 张 7 天内到期');
    const down = (ctx.probes || []).filter(p => !p.ok).length;
    if(down) hs.push('📡 探活下线 ' + down + ' 个端点');
    const wafN = (ctx.waf || []).filter(w => w.blocked >= 50000).length;
    if(wafN) hs.push('🔥 WAF 拦截突增 ' + wafN + ' 个 zone');
    if(hs.length){ L.push(''); L.push('───── 健康 ─────'); hs.forEach(h => L.push(h)); }
  }
  L.push('');
  L.push('────────────────────────');
  L.push('由 MyCF 自动推送 · 配额 UTC 重置 · 流量为最近 24h 采集快照');
  return L.join('\n');
}
async function tgDashDigest(env){
  const L = ['📊 MyCF 今日摘要'];
  let snap = null; try { const r = await kvGet(env,'an_snap'); if(r) snap = JSON.parse(r); } catch(e){}
  let daily = {}; try { const r = await kvGet(env,'an_daily'); if(r) daily = JSON.parse(r)||{}; } catch(e){}
  const accounts = await loadKVAccounts(env).catch(()=>[]);
  const abnormal = accounts.filter(a => a.status && a.status !== 'ok');
  const sd = (snap && snap.data) || {};
  const recs = Object.keys(sd).map(k => sd[k]);
  if(recs.length){
    L.push('🌐 账号池 24h：请求 ' + fmtNum(recs.reduce((s,r)=>s+(r.req||0),0)) +
      ' · 流量 ' + fmtBytesB(recs.reduce((s,r)=>s+(r.bytes||0),0)) +
      ' · 访问 ' + fmtNum(recs.reduce((s,r)=>s+(r.uniq||0),0)));
    const top = recs.slice().sort((a,b)=>(b.req||0)-(a.req||0)).slice(0,5);
    top.forEach((r,i) => L.push((i+1) + '. ' + maskEmail(r.email) + ' ' + fmtNum(r.req) + ' req'));
  } else {
    L.push('暂无 24h 流量数据（请先在面板总览「立即采集」）');
  }
  if(abnormal.length) L.push('🚫 异常账号 ' + abnormal.length);
  L.push('👥 共 ' + accounts.length + ' 个账号' + (snap && snap.ts ? ' · 采集于 ' + new Date(snap.ts).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}).slice(5,16) : ''));
  return L.join('\n');
}
async function tgStatusDigest(env){
  const L = ['🩺 MyCF 账号池健康'];
  const accounts = await loadKVAccounts(env).catch(()=>[]);
  const abn = accounts.filter(a => a.status && a.status !== 'ok');
  L.push('👥 账号 ' + accounts.length + '（OAuth ' + accounts.filter(a=>a.oauth).length + '）');
  L.push(abn.length ? '🚫 异常 ' + abn.length + '：' + abn.map(a => maskEmail(a.email)).join('、') : '✅ 无异常账号');
  let certs = []; try { const r = await kvGet(env,'cert_expiry'); if(r) certs = JSON.parse(r)||[]; } catch(e){}
  const cd = certs.filter(c=>c.days!==null && c.days<=7);
  L.push('🛡 证书 7 天内到期：' + (cd.length ? cd.map(c=>c.zone).slice(0,5).join('、') : '无'));
  let probes = []; try { const r = await kvGet(env,'health_probe'); if(r) probes = JSON.parse(r)||[]; } catch(e){}
  const dwn = probes.filter(p=>!p.ok);
  L.push('📡 探活下线：' + (dwn.length ? dwn.slice(0,5).map(p=>p.worker).join('、') : '无'));
  let waf = []; try { const r = await kvGet(env,'waf_status'); if(r) waf = JSON.parse(r)||[]; } catch(e){}
  const ws = waf.filter(w=>w.blocked>=50000);
  L.push('🔥 WAF 拦截突增：' + (ws.length ? ws.length + ' 个 zone' : '无'));
  return L.join('\n');
}
async function tgTopAccounts(env){
  let snap = null; try { const r = await kvGet(env,'an_snap'); if(r) snap = JSON.parse(r); } catch(e){}
  const sd = (snap && snap.data) || {};
  const recs = Object.keys(sd).map(k => sd[k]).sort((a,b)=>(b.req||0)-(a.req||0));
  const L = ['🏆 账号 24h 请求排行'];
  if(!recs.length){ L.push('暂无流量数据（请先「立即采集」）'); return L.join('\n'); }
  recs.slice(0,10).forEach((r,i) => {
    const pct = recs[0].req ? Math.round((r.req / recs[0].req) * 100) : 0;
    L.push((i+1) + '. ' + maskEmail(r.email) + '  ' + fmtNum(r.req) + ' (' + pct + '%)' + relBar(r.req, recs[0].req || 1, 10));
  });
  return L.join('\n');
}
async function tgZoneTop(env, arg){
  let snap = null; try { const r = await kvGet(env,'an_snap'); if(r) snap = JSON.parse(r); } catch(e){}
  const sd = (snap && snap.data) || {};
  if(!arg){ return '用法：/zone <账号关键字>，例如 /zone @gmail 或 /zone a@x.com'; }
  const key = Object.keys(sd).find(k => k.toLowerCase().indexOf(arg.toLowerCase()) !== -1);
  if(!key) return '未找到匹配账号（已采集的数据：' + (Object.keys(sd).join('、') || '无') + '）';
  const rec = sd[key]; const zs = (rec.zones||[]).slice(0,10);
  const L = ['🌐 ' + maskEmail(key) + ' Zones Top'];
  if(!zs.length){ L.push('该账号无 zones 数据'); return L.join('\n'); }
  zs.forEach((z,i) => L.push((i+1) + '. ' + z.name + '  ' + fmtNum(z.req) + ' req · ' + fmtBytesB(z.bytes)));
  return L.join('\n');
}
async function tgOauthStatus(env){
  const cl = await getOAuthClient(env);
  if(!cl) return 'OAuth 未配置：请到面板「设置 → OAuth 免密钥接入」保存 Client 后授权。\n当前账号仍可用 Global Key 管理。';
  const accs = await loadKVAccounts(env).catch(()=>[]);
  const conns = accs.filter(a => a && a.oauth);
  const L = ['🔐 OAuth 连接状态'];
  L.push('Client ID: ' + cl.clientId.slice(0, 8) + '…（' + (cl.authMethod || 'post') + '）');
  if(!conns.length) L.push('已配置但未授权任何账号：去面板设置页点「前往 Cloudflare 授权」');
  conns.forEach(a => L.push('· ' + (a.name || a.email || a.oauthId) + (a.key ? '（Key+OAuth）' : '') + (a.scope ? ' [' + String(a.scope).slice(0,40) + ']' : '')));
  return L.join('\n');
}
// ---- 流量突增/归零检测（运行于 4h 探活周期；与自积累的 an_daily 前 7 天对比）----
async function checkTrafficAlerts(env){
  const cfg = await getTGConfig(env);
  if(!cfg.enabled || !cfg.alerts || cfg.alertsTraffic === false) return;
  if(!(await notifReady(env))) return;
  let snap = null; try { const r = await kvGet(env,'an_snap'); if(r) snap = JSON.parse(r); } catch(e){}
  if(!snap || !snap.data) return;
  let daily = {}; try { const r = await kvGet(env,'an_daily'); if(r) daily = JSON.parse(r)||{}; } catch(e){}
  // 基线优先官方按日直读(httpRequests1dGroups 免费 365 天)，自采 an_daily 仅兜底
  try { const r = await kvGet(env,'official_daily'); if(r){ const o = JSON.parse(r)||{}; if(o && o.data && Object.keys(o.data).length) daily = o.data; } } catch(e){}
  let sent = {}; try { const r = await kvGet(env,'al_traffic'); if(r) sent = JSON.parse(r)||{}; } catch(e){}
  const today = new Date().toISOString().slice(0,10);
  const dates = Object.keys(daily).sort().slice(-8, -1); // 不含今天的既往日
  const avgOf = (email) => {
    let sum = 0, n = 0;
    for(const d of dates){ const row = daily[d] && daily[d][email]; if(row && row.req){ sum += row.req; n++; } }
    return n ? sum / n : 0;
  };
  const spikes = [];
  for(const k of Object.keys(snap.data)){
    const r = snap.data[k];
    const req = r.req || 0;
    const avg = avgOf(k);
    if(sent[k] === today) continue;
    if(avg >= 10000 && req >= avg * 2 && req >= 20000){
      spikes.push({ email:k, type:'spike', req, avg, bytes:r.bytes||0 });
      sent[k] = today;
    } else if(avg >= 10000 && req === 0){
      spikes.push({ email:k, type:'zero', req, avg });
      sent[k] = today;
    }
  }
  if(spikes.length){
    const L = [];
    for(const s of spikes){
      if(s.type === 'spike') L.push('📈 流量突增：' + maskEmail(s.email) + '\n   24h 请求 ' + fmtNum(s.req) + '（近 7 日日均 ' + fmtNum(s.avg) + '，' + Math.round((s.req/s.avg)*100) + '%）\n   流量 ' + fmtBytesB(s.bytes));
      else L.push('🛑 流量归零：' + maskEmail(s.email) + '\n   近 7 日日均 ' + fmtNum(s.avg) + '，最新采集为 0 —— 请检查域名/限流/账号状态');
    }
    await kvPut(env, 'al_traffic', sent);
    const msg = L.join('\n\n');
    await sendTelegram(env, msg, '流量告警');
  } else if(Object.keys(sent).length || Object.keys(snap.data).length){
    await kvPut(env, 'al_traffic', sent);
  }
}
function buildQuotaAlert(u, tier){
  const masked = maskEmail(u.email);
  const eta = computeExhaustion(u.total);
  const etaStr = eta ? ('\n预计打满(UTC): ' + eta) : '';
  return '⚠️ 配额告警 [' + tier + '%]\n' + masked + ' 已用 ' + fmtNum(u.total) + ' / 100,000 (' + u.percent.toFixed(1) + '%)' + etaStr;
}
// 健康数据官方直读：证书/证书包与 WAF 拦截计数均来自官方 API，仅在 KV 缓存超过阈值时按官方现查刷新
const HEALTH_REFRESH_MS = 6 * 3600 * 1000;
async function ensureFreshCert(env){
  try {
    const r = await kvGet(env, 'cert_ts'); if (r && Date.now() - Number(r) < HEALTH_REFRESH_MS) return;
    const certs = await checkCertExpiry(env); await kvPut(env, 'cert_expiry', certs); await kvPut(env, 'cert_ts', String(Date.now()));
  } catch(e){}
}
async function ensureFreshWaf(env){
  try {
    const r = await kvGet(env, 'waf_ts'); if (r && Date.now() - Number(r) < HEALTH_REFRESH_MS) return;
    const waf = await checkWaf(env); await kvPut(env, 'waf_status', waf); await kvPut(env, 'waf_ts', String(Date.now()));
  } catch(e){}
}
async function pushDailyReport(env, force = false){
  const cfg = await getTGConfig(env);
  if(!cfg.enabled) return { ok:false, error:'推送未启用' };
  if(!force && !cfg.dailyReport) return { ok:false, error:'日报未启用（定时开关关闭）' };
  if(!(await notifReady(env))) return { ok:false, error:'未配置任何通知通道（TG/多通道其一即可）' };
  let creds = await loadKVAccounts(env);
  if(!creds.length) return { ok:false, error:'KV 中无账号' };
  try { await updateAccountStatuses(env); creds = await loadKVAccounts(env); } catch(e){}
  const results = [];
  for(const c of creds){
    const label = c.email || c.name || '';
    try { const list = await queryAllUsageForCred(env, c); for(const u of list){ u.email = u.email || label; results.push(u); } }
    catch(e){ results.push({ email: label, error:String(e) }); }
  }
  const dateStr = new Date().toISOString().slice(0,10);
  // 健康数据官方直读：证书/WAF 缓存超 6h 时按官方现查刷新后再进日报（状态已在上方 live 刷新）
  await ensureFreshCert(env).catch(()=>{});
  await ensureFreshWaf(env).catch(()=>{});
  // 收集健康/流量上下文（读 KV，不外发请求）
  const ctx = { snapData: {}, abnormal: [], certs: [], probes: [], waf: [], segments: (cfg && cfg.segments) || undefined };
  try { const r = await kvGet(env,'an_snap'); if(r){ const s = JSON.parse(r); ctx.snapData = (s && s.data) || {}; } } catch(e){}
  try { const r = await kvGet(env,'cert_expiry'); if(r) ctx.certs = JSON.parse(r)||[]; } catch(e){}
  try { const r = await kvGet(env,'health_probe'); if(r) ctx.probes = JSON.parse(r)||[]; } catch(e){}
  try { const r = await kvGet(env,'waf_status'); if(r) ctx.waf = JSON.parse(r)||[]; } catch(e){}
  ctx.abnormal = creds.filter(a=>a.status && a.status!=='ok').map(a=>({ email: a.email || a.name || '', status:a.status, reason:a.statusReason||a.status }));
  let msg = buildDailyReport(results, dateStr, ctx);
  return await sendTelegram(env, msg);
}
async function checkQuotaAlerts(env){
  const cfg = await getTGConfig(env);
  if(!cfg.enabled || !cfg.alerts) return;
  if(!(await notifReady(env))) return;
  const creds = await loadKVAccounts(env);
  let state = {};
  if(env && env.CF_ACCOUNTS_KV){ const raw = await env.CF_ACCOUNTS_KV.get('tg_quota_alert'); if(raw){ try{ state = JSON.parse(raw); }catch(e){} } }
  const today = new Date().toISOString().slice(0,10);
  const tiers = [50,80,95];
  const toSend = [];
  for(const c of creds){
    let list = []; try{ list = await queryAllUsageForCred(env, c); }catch(e){}
    for(const u of list){
      const pct = u.percent || 0;
      let tier = 0; for(const t of tiers){ if(pct >= t) tier = t; }
      const prev = state[c.email];
      if(tier > 0 && (!prev || prev.date !== today || (prev.tier||0) < tier)){
        toSend.push(buildQuotaAlert(u, tier));
        state[c.email] = { date: today, tier };
      }
    }
  }
  if(toSend.length) await sendTelegram(env, toSend.join('\n\n'));
  if(env && env.CF_ACCOUNTS_KV) await env.CF_ACCOUNTS_KV.put('tg_quota_alert', JSON.stringify(state));
}

// ==================== 监控模块（P0+P1） ====================
async function kvGet(env, key){ if(!env || !env.CF_ACCOUNTS_KV) return null; const r = await env.CF_ACCOUNTS_KV.get(key); return r; }
async function kvPut(env, key, val){ if(!env || !env.CF_ACCOUNTS_KV) return; await env.CF_ACCOUNTS_KV.put(key, typeof val==='string'?val:JSON.stringify(val)); }

// ---- P0-1 用量历史趋势 + 耗尽预测 ----
async function storeDailySnapshots(env){
  const creds = await loadKVAccounts(env);
  if(!creds.length) return;
  const date = new Date().toISOString().slice(0,10);
  let history = {}; try { const raw = await kvGet(env,'usage_history'); if(raw) history = JSON.parse(raw)||{}; } catch(e){}
  const dayMap = history[date] || [];
  for(const c of creds){
    try { const list = await queryAllUsageForCred(env, c); for(const u of list){ if(u.error) continue; dayMap.push({ email:c.email, accountId:u.accountId, name:u.name||'', total:u.total, workers:u.workers, pages:u.pages }); } }
    catch(e){}
  }
  history[date] = dayMap;
  const keys = Object.keys(history).sort(); while(keys.length > 60) delete history[keys.shift()];
  await kvPut(env,'usage_history', history);
}

// ---- 账号 HTTP 分析采集（请求/带宽/访问者，GraphQL zones 24h；写入 an_snap + an_daily）----
async function storeAnalytics(env){
  const creds = await loadKVAccounts(env);
  if(!creds.length) return { ok:0, fail:0 };
  const now = new Date();
  const st = new Date(now.getTime() - 24*3600*1000).toISOString();
  const et = now.toISOString();
  const date = et.slice(0,10);
  const out = {}; let ok = 0, fail = 0;
  for(const c of creds){
    try {
      const email = c.email || c.name || ('acc-' + String(c.accountId || '').slice(0,6));
      const key = c.oauth ? OAUTH_KEY_PREFIX + c.accessToken : c.key;
      if(!key){ fail++; continue; }
      const accountId = c.accountId || await getAccountId(email, key).catch(()=>null);
      if(!accountId){ fail++; continue; }
      const q = 'query($tag:String!,$st:Time!,$et:Time!){viewer{accounts(filter:{accountTag:$tag}){zones{name zoneTag httpRequests1hGroups(limit:24,filter:{datetime_geq:$st,datetime_leq:$et}){dimensions{datetimeHour}sum{requests bytes}uniq{uniques}}}}}}';
      const g = await fetch('https://api.cloudflare.com/client/v4/graphql', { method:'POST', headers: Object.assign({ 'Content-Type':'application/json' }, cfHeaders(email, key)), body: JSON.stringify({ query:q, variables:{ tag:accountId, st, et } }) });
      const res = await g.json();
      const acc = res && res.data && res.data.viewer && res.data.viewer.accounts && res.data.viewer.accounts[0];
      const zones = (acc && acc.zones) || [];
      const hourMap = {}; let req = 0, bytes = 0, uniq = 0;
      const zonesAgg = [];
      for(const z of zones){
        const groups = z.httpRequests1hGroups || [];
        let zr = 0, zb = 0, zu = 0;
        for(const h of groups){
          zr += (h.sum && h.sum.requests) || 0; zb += (h.sum && h.sum.bytes) || 0; zu += (h.uniq && h.uniq.uniques) || 0;
          const t = String(h.dimensions && h.dimensions.datetimeHour || '').slice(11, 13);
          if(t) hourMap[t] = (hourMap[t] || 0) + ((h.sum && h.sum.requests) || 0);
        }
        req += zr; bytes += zb; uniq += zu;
        zonesAgg.push({ name: z.name || z.zoneTag || '', zoneTag: z.zoneTag || '', req: zr, bytes: zb, uniq: zu });
      }
      zonesAgg.sort((a, b) => b.req - a.req);
      const points = Object.keys(hourMap).sort().map(h => ({ t: h + ':00', req: hourMap[h] }));
      out[email] = { email, accountId, name: c.name || '', zones: zonesAgg, req, bytes, uniq, points };
      ok++;
    } catch(e){ fail++; }
  }
  await kvPut(env, 'an_snap', { ts: et, data: out });
  let daily = {}; try { const r = await kvGet(env, 'an_daily'); if(r) daily = JSON.parse(r) || {}; } catch(e){}
  const day = daily[date] || {};
  for(const k of Object.keys(out)) day[k] = { email: out[k].email, accountId: out[k].accountId, name: out[k].name, req: out[k].req, bytes: out[k].bytes, uniq: out[k].uniq };
  daily[date] = day;
  const dkeys = Object.keys(daily).sort(); while(dkeys.length > 60) delete daily[dkeys.shift()];
  await kvPut(env, 'an_daily', daily);
  return { ok, fail };
}

// 官方按日直读：httpRequests1dGroups 免费计划可查 365 天，每账号一次 GraphQL 拉全部 zones
// 按日期聚合为账号级日数据，合并写入 KV official_daily（{ fetchedAt, data:{ date:{ email:{req,bytes,uniq,pageViews} } } }）
async function storeOfficialAnalytics(env, days = 92){
  const creds = await loadKVAccounts(env);
  if(!creds.length) return { ok:0, fail:0 };
  const now = new Date();
  const le = now.toISOString().slice(0,10);
  const ge = new Date(now.getTime() - (days - 1) * 86400000).toISOString().slice(0,10);
  let merged = null; let ok = 0, fail = 0;
  for(const c of creds){
    try {
      const email = c.email || c.name || ('acc-' + String(c.accountId || '').slice(0,6));
      const key = c.oauth ? OAUTH_KEY_PREFIX + c.accessToken : c.key;
      if(!key){ fail++; continue; }
      const accountId = c.accountId || await getAccountId(email, key).catch(()=>null);
      if(!accountId){ fail++; continue; }
      const q = 'query($tag:String!){viewer{accounts(filter:{accountTag:$tag}){zones{name zoneTag httpRequests1dGroups(limit:30000,filter:{date_geq:"' + ge + '",date_leq:"' + le + '"}){dimensions{date}sum{requests bytes pageViews cachedRequests threats}uniq{uniques}}}}}}';
      const g = await fetch('https://api.cloudflare.com/client/v4/graphql', { method:'POST', headers: Object.assign({ 'Content-Type':'application/json' }, cfHeaders(email, key)), body: JSON.stringify({ query:q, variables:{ tag:accountId } }) });
      const res = await g.json();
      const acc = res && res.data && res.data.viewer && res.data.viewer.accounts && res.data.viewer.accounts[0];
      const zones = (acc && acc.zones) || [];
      const dayMap = {};
      for(const z of zones){
        for(const d of (z.httpRequests1dGroups || [])){
          const dt = d.dimensions && d.dimensions.date; if(!dt) continue;
          const s = d.sum || {}, u = d.uniq || {};
          const rec = dayMap[dt] = dayMap[dt] || { req:0, bytes:0, uniq:0, pageViews:0, cachedRequests:0, threats:0 };
          rec.req += (s.requests || 0); rec.bytes += (s.bytes || 0); rec.pageViews += (s.pageViews || 0); rec.uniq += (u.uniques || 0);
          rec.cachedRequests += (s.cachedRequests || 0); rec.threats += (s.threats || 0);
        }
      }
      if(!merged){
        try { const r0 = await kvGet(env, 'official_daily'); if(r0) merged = JSON.parse(r0) || null; } catch(e){ merged = null; }
        if(!merged) merged = { data:{} };
      }
      for(const dt of Object.keys(dayMap)){
        const dayRec = merged.data[dt] = merged.data[dt] || {};
        dayRec[email] = Object.assign({ email }, dayMap[dt]);
      }
      ok++;
    } catch(e){ fail++; }
  }
  if(ok && merged){
    // 保留期裁剪：仅保留最近 days+15 天的日期，防 KV 无限膨胀
    const ds = Object.keys(merged.data).sort(); const keep = ds.slice(-(days + 15));
    if (keep.length < ds.length) { const drop = new Set(ds.slice(0, ds.length - keep.length)); for (const d of drop) delete merged.data[d]; }
    merged.fetchedAt = new Date().toISOString(); await kvPut(env, 'official_daily', merged);
  }
  return { ok, fail };
}

// 配额/用量官方历史：workersInvocationsAdaptive 免费计划单次查询窗口 ≤1 天（date_geq/date_leq 同日）
// 官方历史只能逐日累积：cron 每日现查"今天+昨天"合并写入 KV official_usage（结构同 usage_history：date->[{email,workers,pages,total}]）
async function storeOfficialUsage(env){
  const creds = await loadKVAccounts(env);
  if(!creds.length) return { ok:0, fail:0 };
  let merged = null;
  try { const r = await kvGet(env,'official_usage'); if(r) merged = JSON.parse(r) || null; } catch(e){ merged = null; }
  if(!merged) merged = { data:{} };
  let ok = 0, fail = 0;
  const iso = (d) => { const x = new Date(d); x.setUTCHours(0,0,0,0); return x.toISOString(); };
  const today = iso(Date.now());
  const days = [ today, iso(Date.now() - 86400000) ];
  for(const c of creds){
    const email = c.email || c.name || ('acc-' + String(c.accountId || '').slice(0,6));
    const key = c.oauth ? OAUTH_KEY_PREFIX + c.accessToken : c.key;
    if(!key){ fail++; continue; }
    try {
      const ar = await cfGet('/accounts', c.email, oauthOrKey(c));
      if(!ar || !ar.success) { fail++; continue; }
      for(const a of (ar.result||[])){
        for(const s of days){
          const e = new Date(new Date(s).getTime() + 86400000 - 1).toISOString();
          const u = await queryUsageByAccountId(c.email, oauthOrKey(c), a.id, s, e);
          if(u.error) continue;
          const date = s.slice(0,10);
          const arr = merged.data[date] = merged.data[date] || [];
          const idx = arr.findIndex(x => x.email === email && x.accountId === a.id);
          const rec = { email, accountId: a.id, name: a.name || '', total: u.total, workers: u.workers, pages: u.pages };
          if (idx > -1) arr[idx] = rec; else arr.push(rec);
        }
      }
      ok++;
    } catch(e){ fail++; }
  }
  const ds = Object.keys(merged.data).sort(); while (ds.length > 70) delete merged.data[ds.shift()];
  merged.fetchedAt = new Date().toISOString();
  await kvPut(env, 'official_usage', merged);
  return { ok, fail };
}

function computeUsageTrend(history, days){
  const dates = Object.keys(history||{}).sort().slice(-days);
  return dates.map(d => ({ date:d, total:(history[d]||[]).reduce((t,r)=>t+(r.total||0),0) }));
}
function computeAccountTrends(history, days){
  const dates = Object.keys(history||{}).sort().slice(-days);
  const map = {};
  for (const d of dates) {
    for (const r of (history[d]||[])) {
      const key = r.email || r.accountId || 'unknown';
      if (!map[key]) map[key] = { email:key, name:r.name||maskEmail(key), byDate:{} };
      map[key].byDate[d] = (map[key].byDate[d]||0) + (r.total||0);
    }
  }
  return Object.values(map).map(a => ({
    email:a.email, name:a.name,
    series: dates.map(d => ({ date:d, total: a.byDate[d]||0 }))
  }));
}
function predictExhaustion(history, numAccounts){
  const series = computeUsageTrend(history, 14);
  if(series.length < 3) return null;
  const n = series.length, xs = series.map((_,i)=>i), ys = series.map(s=>s.total);
  const mx = xs.reduce((a,b)=>a+b,0)/n, my = ys.reduce((a,b)=>a+b,0)/n;
  let num=0, den=0; for(let i=0;i<n;i++){ num += (xs[i]-mx)*(ys[i]-my); den += (xs[i]-mx)**2; }
  const slope = den ? num/den : 0;
  if(slope <= 0) return { trend:'稳定/下降', dailyGrowth:0, daysToLimit:null };
  const cap = Math.max(100000, (numAccounts||1)*100000);
  const remaining = cap - ys[n-1];
  if(remaining <= 0) return { trend:'已达上限', dailyGrowth:Math.round(slope), daysToLimit:0, eta:new Date().toISOString().slice(0,10) };
  const days = Math.floor(remaining/slope);
  return { trend:'上升', dailyGrowth:Math.round(slope), daysToLimit:days, eta:new Date(Date.now()+days*86400000).toISOString().slice(0,10) };
}

// ---- P0-2 账号存活 + 资产变更审计 ----
async function snapshotAssets(env){
  const creds = await loadKVAccounts(env);
  const snap = { ts: Date.now(), accounts: {} };
  for(const c of creds){
    try {
      const ar = await cfGet('/accounts', c.email, oauthOrKey(c));
      if(!ar.success){ snap.accounts[c.email] = { error:'凭据失效/403', alive:false }; continue; }
      const entry = { alive:true, accounts: [] };
      for(const a of (ar.result||[])){
        let workers=[]; try { const wr = await cfGet('/accounts/'+a.id+'/workers/scripts', c.email, oauthOrKey(c)); workers = (wr.success&&wr.result)?wr.result.map(w=>w.id):[]; } catch(e){}
        let zones=[]; try { const zr = await cfGet('/zones?account.id='+a.id, c.email, oauthOrKey(c)); zones = (zr.success&&zr.result)?zr.result.map(z=>({id:z.id,name:z.name,status:z.status})):[]; } catch(e){}
        entry.accounts.push({ id:a.id, name:a.name, workers, zones });
      }
      snap.accounts[c.email] = entry;
    } catch(e){ snap.accounts[c.email] = { error:String(e), alive:false }; }
  }
  return snap;
}
function diffAssets(prev, cur){
  const changes = [];
  const emails = new Set([...Object.keys(prev.accounts||{}), ...Object.keys(cur.accounts||{})]);
  for(const e of emails){
    const p = prev.accounts?.[e], c = cur.accounts?.[e];
    if(!p && c){ changes.push({ type:'cred_added', email:e }); continue; }
    if(p && !c){ changes.push({ type:'cred_removed', email:e }); continue; }
    if(p && c){
      if(p.alive && !c.alive) changes.push({ type:'cred_dead', email:e, detail:c.error||'' });
      else if(!p.alive && c.alive) changes.push({ type:'cred_recovered', email:e });
      else if(p.alive && c.alive){
        const pmap = Object.fromEntries((p.accounts||[]).map(a=>[a.id,a]));
        const cmap = Object.fromEntries((c.accounts||[]).map(a=>[a.id,a]));
        for(const aid of new Set([...Object.keys(pmap),...Object.keys(cmap)])){
          const pa = pmap[aid], ca = cmap[aid];
          if(!pa){ changes.push({type:'account_added',email:e,name:ca.name}); continue; }
          if(!ca){ changes.push({type:'account_removed',email:e,name:pa.name}); continue; }
          const pw = new Set(pa.workers||[]), cw = new Set(ca.workers||[]);
          for(const w of cw) if(!pw.has(w)) changes.push({type:'worker_added',email:e,account:ca.name,worker:w});
          for(const w of pw) if(!cw.has(w)) changes.push({type:'worker_removed',email:e,account:pa.name,worker:w});
          if(pa.workers?.length && ca.workers?.length && ca.workers.length <= pa.workers.length*0.5) changes.push({type:'worker_drop',email:e,account:ca.name,from:pa.workers.length,to:ca.workers.length});
          const pzm = Object.fromEntries((pa.zones||[]).map(z=>[z.id,z])), czm = Object.fromEntries((ca.zones||[]).map(z=>[z.id,z]));
          for(const zid of Object.keys(czm)){ if(pzm[zid] && pzm[zid].status!==czm[zid].status) changes.push({type:'zone_status',email:e,name:czm[zid].name,from:pzm[zid].status,to:czm[zid].status}); }
        }
      }
    }
  }
  return changes;
}
function auditLabel(c){
  switch(c.type){
    case 'cred_dead': return '凭据失效: '+maskEmail(c.email)+(c.detail?' ('+c.detail+')':'');
    case 'cred_recovered': return '凭据恢复: '+maskEmail(c.email);
    case 'cred_removed': return '凭据移除: '+maskEmail(c.email);
    case 'cred_added': return '凭据新增: '+maskEmail(c.email);
    case 'account_added': return '账号新增['+maskEmail(c.email)+'] '+c.name;
    case 'account_removed': return '账号移除['+maskEmail(c.email)+'] '+c.name;
    case 'worker_added': return '新增Worker['+c.account+'] '+c.worker;
    case 'worker_removed': return '删除Worker['+c.account+'] '+c.worker;
    case 'worker_drop': return 'Worker数量骤降['+c.account+'] '+c.from+'→'+c.to;
    case 'zone_status': return 'Zone状态['+c.name+'] '+c.from+'→'+c.to;
    default: return c.type;
  }
}
function buildAssetAuditMsg(changes){
  const L = ['🔍 资产变更审计 (' + changes.length + ' 项)'];
  for(const c of changes.slice(0,30)) L.push('• ' + auditLabel(c));
  if(changes.length>30) L.push('…共 '+changes.length+' 项');
  return L.join('\n');
}

// ---- P0-3 存储限额监控（D1 库数 / R2 操作 / KV 操作） ----
const STORAGE_QUERY = `query S($accountId:String!){viewer{accounts(filter:{accountTag:$accountId}){r2AggregateAnalytics(limit:1,filter:{}){sum{requests}}kvOperationsAdaptive(limit:1,filter:{}){sum{requests}}}}}`;
async function queryStorageUsage(env){
  const creds = await loadKVAccounts(env); const out = [];
  for(const c of creds){
    try {
      const ar = await cfGet('/accounts', c.email, oauthOrKey(c)); if(!ar.success){ out.push({email:c.email, error:true}); continue; }
      for(const a of (ar.result||[])){
        let d1Count=0; try { const r = await cfGet('/accounts/'+a.id+'/d1/database', c.email, oauthOrKey(c)); d1Count = (r.success&&r.result)?r.result.length:0; } catch(e){}
        let r2Ops=0, kvOps=0;
        try { const g = await fetch('https://api.cloudflare.com/client/v4/graphql', { method:'POST', headers:Object.assign({ 'Content-Type':'application/json' }, cfHeaders(c.email, oauthOrKey(c))), body: JSON.stringify({ query: STORAGE_QUERY, variables:{ accountId:a.id } }) }); const res = await g.json(); const vr = res?.data?.viewer?.accounts?.[0]; r2Ops = vr?.r2AggregateAnalytics?.[0]?.sum?.requests||0; kvOps = vr?.kvOperationsAdaptive?.[0]?.sum?.requests||0; } catch(e){}
        out.push({ email:c.email, accountId:a.id, name:a.name, d1Count, r2Ops, kvOps });
      }
    } catch(e){ out.push({ email:c.email, error:String(e) }); }
  }
  return out;
}
async function storeStorageUsage(env){ await kvPut(env,'storage_usage', await queryStorageUsage(env)); }

// ---- P0-4 外部 HTTP 探活 ----
async function probeEndpoints(env){
  const creds = await loadKVAccounts(env); const results = [];
  for(const c of creds){
    try {
      const ar = await cfGet('/accounts', c.email, oauthOrKey(c)); if(!ar.success) continue;
      for(const a of (ar.result||[])){
        try {
          const wr = await cfGet('/accounts/'+a.id+'/workers/scripts', c.email, oauthOrKey(c));
          const workers = (wr.success&&wr.result)?wr.result:[];
          for(const w of workers.slice(0,3)){
            const sd = (w.defaultDomain&&w.defaultDomain.hostname) || (w.domains&&w.domains[0]&&w.domains[0].hostname);
            if(!sd) continue;
            const url = 'https://'+sd; const t0 = Date.now();
            let status=-1, ok=false, ms=0;
            try { const ctrl = new AbortController(); const to = setTimeout(()=>ctrl.abort(), 8000); const pr = await fetch(url, { method:'GET', redirect:'manual', signal:ctrl.signal }); clearTimeout(to); ms = Date.now()-t0; status = pr.status; ok = pr.status>=200 && pr.status<400; }
            catch(e){ status=-1; ok=false; ms = Date.now()-t0; }
            results.push({ email:c.email, account:a.name, worker:w.id, url, status, ok, ms });
          }
        } catch(e){}
      }
    } catch(e){}
  }
  return results;
}
function buildProbeMsg(down){
  const L = ['🌐 端点探活异常 (' + down.length + ' 项)'];
  for(const d of down) L.push('• ' + (d.worker||'') + ' [' + d.account + '] ' + d.url + ' => ' + (d.status<0?'超时':d.status) + (d.ms?(' '+d.ms+'ms'):''));
  return L.join('\n');
}

// ---- P1-6 证书到期监控 ----
async function checkCertExpiry(env){
  const creds = await loadKVAccounts(env); const out = [];
  for(const c of creds){
    try {
      const zr = await cfGet('/zones', c.email, oauthOrKey(c)); if(!zr.success) continue;
      for(const z of (zr.result||[])){
        try {
          const cr = await cfGet('/zones/'+z.id+'/ssl/certificate_packs', c.email, oauthOrKey(c));
          const packs = (cr.success&&cr.result)?cr.result:[];
          let minDays=null;
          for(const p of packs){ for(const crt of (p.certificates||[])){ if(crt.expires_on){ const d = Math.ceil((new Date(crt.expires_on)-Date.now())/86400000); if(minDays===null||d<minDays) minDays=d; } } }
          out.push({ email:c.email, zone:z.name, zoneId:z.id, days:minDays });
        } catch(e){}
      }
    } catch(e){}
  }
  return out;
}
function buildCertMsg(due){
  const L = ['🔐 SSL 证书即将到期'];
  for(const c of due) L.push('• ' + c.zone + ' (' + maskEmail(c.email) + '): ' + (c.days!=null?c.days+' 天':'未知'));
  return L.join('\n');
}

// ---- P1-7 WAF 异常流量告警 ----
async function checkWaf(env){
  const creds = await loadKVAccounts(env); const out = [];
  for(const c of creds){
    try {
      const zr = await cfGet('/zones', c.email, oauthOrKey(c));
      for(const z of (zr.result||[])){
        try {
          const end = new Date().toISOString(); const start = new Date(Date.now()-86400000).toISOString();
          const q = `query W($zone:String!,$f:ZoneFirewallEventsFilter_InputObject){viewer{zones(filter:{zoneTag:$zone}){firewallEventsAdaptiveGroups(limit:1,filter:$f){sum{requests}}}}}`;
          const g = await fetch('https://api.cloudflare.com/client/v4/graphql', { method:'POST', headers:Object.assign({ 'Content-Type':'application/json' }, cfHeaders(c.email, oauthOrKey(c))), body: JSON.stringify({ query:q, variables:{ zone:z.id, f:{ datetime_geq:start, datetime_leq:end } } }) });
          const res = await g.json(); const cnt = res?.data?.viewer?.zones?.[0]?.firewallEventsAdaptiveGroups?.[0]?.sum?.requests || 0;
          out.push({ email:c.email, zone:z.name, blocked:cnt });
        } catch(e){}
      }
    } catch(e){}
  }
  return out;
}
function buildWafMsg(sp){
  const L = ['🛡️ WAF 拦截突增 (' + sp.length + ' 项)'];
  for(const w of sp) L.push('• ' + w.zone + ' (' + maskEmail(w.email) + '): 24h 拦截 ' + fmtNum(w.blocked));
  return L.join('\n');
}

// ---- P1-8 Cron 心跳 ----
async function heartbeat(env){ await kvPut(env,'tg_cron_heartbeat', { last: Date.now(), iso: new Date().toISOString() }); }

// ---- P1-9 审计日志 ----
async function writeAudit(env, entry){
  let arr = []; try { const r = await kvGet(env,'audit_log'); if(r) arr = JSON.parse(r)||[]; } catch(e){}
  arr.unshift(Object.assign({ ts: new Date().toISOString() }, entry));
  if(arr.length > 200) arr.length = 200;
  await kvPut(env,'audit_log', arr);
}

// ---- 批量部署工具 ----
async function deployWorkerTo(email, key, accountId, scriptName, scriptSource, metadataBindings, usage_model) {
  if (!accountId) accountId = await getAccountId(email, key);
  const finalScript = (typeof scriptSource === 'string' && scriptSource.trim()) ? scriptSource : "export default { async fetch() { return new Response('Deployed via MyCF'); } };";
  const bindings = (metadataBindings||[]).map(b => { const c = JSON.parse(JSON.stringify(b)); if(c.type==='kv_namespace'){ if(c.namespace){ c.namespace_id=c.namespace; delete c.namespace; } if(!c.namespace_id&&c.id) c.namespace_id=c.id; delete c.id; } if(c.type==='d1_database'||c.type==='d1'){ c.type='d1'; if(c.database_id){ c.id=c.database_id; delete c.database_id; } } return c; });
  const isModule = finalScript.includes('export default') || finalScript.includes('export {');
  const metadata = { bindings, usage_model: usage_model||'standard', placement:{mode:'smart'}, compatibility_date: new Date().toISOString().slice(0,10) };
  const form = new FormData();
  if(isModule){ metadata.main_module='worker.js'; form.append('metadata', JSON.stringify(metadata)); form.append('worker.js', new Blob([finalScript],{type:'application/javascript+module'}),'worker.js'); }
  else { metadata.body_part='script'; form.append('metadata', JSON.stringify(metadata)); form.append('script', new Blob([finalScript],{type:'application/javascript'}),'worker.js'); }
  const resp = await fetch(`${CF_API_BASE}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}`, { method:'PUT', headers:cfHeaders(email, key), body: form });
  const text = await resp.text().catch(()=>'{}');
  let res; try { res = JSON.parse(text); } catch { res = { errors:[{message:text}] }; }
  return { success: resp.ok, message: resp.ok?'OK':(res.errors?.[0]?.message||'fail') };
}

// ---- P1-C 封号/异常账号自动检测（运行于监控周期，异常立即告警并落库标记） ----
async function updateAccountStatuses(env){
  const accounts = await loadKVAccounts(env);
  if(!accounts.length) return [];
  const newly = [];
  for(const a of accounts){
    let status='ok', reason='';
    // OAuth 会话过期时先静默刷新，避免把临时失效误标为封号
    if(a && a.oauth && a.refreshToken && (!a.expiresAt || Date.now() > a.expiresAt - 60000)){
      try { await refreshOAuthToken(env, a); } catch(e){}
    }
    try {
      const ar = await cfAny('GET','/accounts', a.email, oauthOrKey(a));
      if(!ar || !ar.success){
        const code = ar ? ar.status : 0;
        if(code===401 || code===403 || (ar && ar.errors && ar.errors[0] && ar.errors[0].code===10000)){
          status='abnormal'; reason='认证失败/封号（HTTP ' + code + '）';
        } else if(code!==429){ status='error'; reason='API 错误（HTTP ' + (code||'?') + '）'; }
      }
    } catch(e){ status='error'; reason=String(e).slice(0,80); }
    const prev = a.status || 'ok';
    if(status!=='ok' && (prev==='ok' || !prev)) newly.push({ email:a.email, status, reason });
    if(a.status !== status || (a.statusReason||'') !== reason){ a.status = status; if(reason) a.statusReason = reason; else delete a.statusReason; }
  }
  const key = await getCryptoKey(env);
  const toStore = [];
  for(const a of accounts){ toStore.push(key ? await encJSON(a, key) : a); }
  if(env && env.CF_ACCOUNTS_KV) await env.CF_ACCOUNTS_KV.put('accounts', JSON.stringify(toStore));
  return newly;
}
// ---- P1-E KV retention 清理（滚动裁剪，防 KV 膨胀） ----
async function cleanupKV(env){
  if(!env || !env.CF_ACCOUNTS_KV) return;
  try {
    let history = {}; const r = await kvGet(env,'usage_history'); if(r) history = JSON.parse(r)||{};
    const hk = Object.keys(history).sort(); while(hk.length>60) delete history[hk.shift()];
    await kvPut(env,'usage_history', history);
  } catch(e){}
  try {
    const r = await kvGet(env,'health_probe'); if(r){ const arr = JSON.parse(r)||[]; if(Array.isArray(arr) && arr.length>200){ await kvPut(env,'health_probe', arr.slice(-200)); } }
  } catch(e){}
}

// ---- 编排 ----
async function runDailyMonitoring(env){
  const newly = await updateAccountStatuses(env);
  if(newly.length && await notifReady(env)) await sendTelegram(env, buildAbnormalMsg(newly));
  const cfg = await getTGConfig(env);
  await storeDailySnapshots(env);
  await storeAnalytics(env).catch(()=>{});
  await storeOfficialAnalytics(env).catch(()=>{});
  await storeOfficialUsage(env).catch(()=>{});
  await storeStorageUsage(env);
  const cur = await snapshotAssets(env);
  let prev = null; try { const r = await kvGet(env,'asset_snapshot'); if(r) prev = JSON.parse(r); } catch(e){}
  if(prev && prev.accounts){ const changes = diffAssets(prev, cur); if(changes.length && cfg.enabled && cfg.alerts && await notifReady(env)) await sendTelegram(env, buildAssetAuditMsg(changes)); }
  await kvPut(env,'asset_snapshot', cur);
  const certs = await checkCertExpiry(env); await kvPut(env,'cert_expiry', certs); await kvPut(env, 'cert_ts', String(Date.now()));
  if(cfg.enabled && cfg.alerts && await notifReady(env)){ const due = certs.filter(c=>c.days!==null && c.days<=7); if(due.length) await sendTelegram(env, buildCertMsg(due)); }
  await heartbeat(env);
}
async function runProbeMonitoring(env){
  const newly = await updateAccountStatuses(env);
  if(newly.length && await notifReady(env)) await sendTelegram(env, buildAbnormalMsg(newly));
  const cfg = await getTGConfig(env);
  const cur = await probeEndpoints(env);
  let prev = []; try { const r = await kvGet(env,'health_probe'); if(r) prev = JSON.parse(r)||[]; } catch(e){}
  const pmap = Object.fromEntries(prev.map(p=>[p.email+'|'+p.worker, p]));
  const down = cur.filter(p=>!p.ok && pmap[p.email+'|'+p.worker] && pmap[p.email+'|'+p.worker].ok);
  if(down.length && cfg.enabled && cfg.alerts && await notifReady(env)) await sendTelegram(env, buildProbeMsg(down));
  await kvPut(env,'health_probe', cur);
  const waf = await checkWaf(env); await kvPut(env,'waf_status', waf); await kvPut(env, 'waf_ts', String(Date.now()));
  if(cfg.enabled && cfg.alerts && await notifReady(env)){ const sp = waf.filter(w=>w.blocked>=50000); if(sp.length) await sendTelegram(env, buildWafMsg(sp)); }
  await checkQuotaAlerts(env);
  await storeAnalytics(env).catch(()=>{});
  await checkTrafficAlerts(env).catch(()=>{});
  try { const r = await kvGet(env,'tg_cron_heartbeat'); if(r){ const h = JSON.parse(r); if(!h.warned && Date.now()-h.last > 26*3600*1000){ await sendTelegram(env, '⏰ Cron 心跳异常：日报 cron 已超过 26 小时未运行，可能已被 CF 静默停止，请检查触发器配置。'); await kvPut(env,'tg_cron_heartbeat', Object.assign(h,{warned:true})); } } } catch(e){}
  await cleanupKV(env);
}

async function getWorkerScriptInternal(email, key, accountId, scriptName) {
    if (!scriptName) return json({ success:false, error:'scriptName required' },400);
    const accId = accountId || await getAccountId(email, key);
    const url = `${CF_API_BASE}/accounts/${accId}/workers/scripts/${encodeURIComponent(scriptName)}`;
    const resp = await fetch(url, { method:'GET', headers:cfHeaders(email, key)});
    
    if (resp.status === 404) {
         return json({ ok: false, status: 404, rawScript: "export default { async fetch() { return new Response('New Worker'); } };" });
    }

    const text = await resp.text();
    const contentType = resp.headers.get('content-type') || '';
    let scriptContent = null;

    if (contentType.includes('multipart/form-data')) {
        const boundaryMatch = contentType.match(/boundary=(.*)/);
        const boundary = boundaryMatch ? boundaryMatch[1].split(';')[0].trim() : null;
        if (boundary) {
            const parts = text.split(new RegExp(`--${boundary}(?:--)?`));
            for (const part of parts) {
                if (part.includes('Content-Type: application/javascript') || 
                    part.includes('Content-Type: application/x-javascript') ||
                    part.includes('filename="worker.js"') || 
                    part.includes('name="script"')) {
                    const bodyMatch = part.match(/\r?\n\r?\n([\s\S]*)/);
                    if (bodyMatch && bodyMatch[1]) {
                        scriptContent = bodyMatch[1].trim();
                        break;
                    }
                }
            }
        }
        if (!scriptContent) {
            const jsMatch = text.match(/Content-Type:\s*application\/javascript(?:[\+a-z]*)?[\s\S]*?\r?\n\r?\n([\s\S]*?)(?=\r?\n--)/i);
            if (jsMatch) scriptContent = jsMatch[1].trim();
        }
    } 
    else if (!text.trim().startsWith('{')) {
        scriptContent = text;
    } 
    else {
        try {
            const j = JSON.parse(text);
            if (j.result && j.result.script) scriptContent = j.result.script;
        } catch(e) {}
    }

    if (!scriptContent) {
        if (text.includes('export default') || text.includes('addEventListener')) {
             const rawMatch = text.match(/(export\s+default[\s\S]+|addEventListener[\s\S]+)/);
             if (rawMatch) {
                 scriptContent = rawMatch[0].split(/\r?\n--/)[0].trim();
             } else {
                 scriptContent = text;
             }
        }
    }

    if (scriptContent) {
        return json({ ok: true, status: 200, rawScript: scriptContent });
    }
    return json({ ok: true, status: 200, rawScript: text }); 
}

async function getAccountId(email, key) {
  const r = await cfGet('/accounts', email, key);
  const arr = r.result || (r.data && r.data.result) || r;
  if (Array.isArray(arr) && arr.length) return arr[0].id;
  throw new Error('Cannot find accountId');
}

// 统一鉴权头：OAuth（key=__oa_+token）走 Authorization Bearer；Global Key 走 X-Auth-Email/Key
function cfHeaders(email, key){
  if (key && typeof key === 'string' && key.startsWith(OAUTH_KEY_PREFIX)) return { Authorization: 'Bearer ' + key.slice(OAUTH_KEY_PREFIX.length) };
  return { 'X-Auth-Email': email, 'X-Auth-Key': key };
}

async function cfGet(path, email, key) { return cfAny('GET', path, email, key); }
async function cfPost(path, email, key, body) { return cfAny('POST', path, email, key, body); }
async function cfPut(path, email, key, body) { return cfAny('PUT', path, email, key, body); }
async function cfDelete(path, email, key) { return cfAny('DELETE', path, email, key); }

async function cfPutRaw(path, email, key, body) {
  const url = path.startsWith('http') ? path : CF_API_BASE + path;
  const res = await fetch(url, { method:'PUT', headers: Object.assign(cfHeaders(email, key), { 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
  try { return await res.json(); } catch { return { success: res.ok }; }
}

async function cfAny(method, path, email, key, body = null) {
  const url = path.startsWith('http') ? path : CF_API_BASE + path;
  const headers = cfHeaders(email, key);
  const opts = { method, headers };
  if (body !== null) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  // 只读 GET 走边缘缓存，降低 Cloudflare API 频率、规避限流
  if (method === 'GET' && !_apiCacheBypass) {
    const cached = await _apiCacheGet(url, email, key);
    if (cached !== null) return cached;
  }
  const res = await fetch(url, opts);
  let data;
  try { data = await res.json(); } catch { data = { success: res.ok }; }
  // 附上 HTTP 状态码，便于识别封号/凭据失效(401/403)
  if (typeof data === 'object' && data !== null) { data.status = res.status; }
  else data = { success: res.ok, status: res.status };
  if (method === 'GET' && !_apiCacheBypass && res.ok) {
    _apiCachePut(url, email, key, data);
  }
  return data;
}

function json(obj, status=200) {
  return new Response(JSON.stringify(obj, null, 2), { status, headers: { 'content-type': 'application/json' }});
}

async function safeJSON(req) { try { return await req.json(); } catch { return {}; } }

function renderLoginHTML(env) {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>连接您的 Cloudflare 账号</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root { --accent: #0070f3; --accent2: #00d4ff; }
body { font-family: Inter, system-ui, sans-serif; margin:0; min-height: 100vh; background: linear-gradient(135deg, #f0f4f8 0%, #d9e2ec 100%); display:flex; align-items:flex-start; justify-content:center; color: #1e293b; overflow-y: auto; position: relative; padding: 32px 0; }
body::before { content: ''; position: absolute; width: 600px; height: 600px; background: radial-gradient(circle, rgba(0,112,243,0.15), transparent 70%); top: -200px; left: -100px; z-index: 0; }
body::after { content: ''; position: absolute; width: 500px; height: 500px; background: radial-gradient(circle, rgba(0,212,255,0.15), transparent 70%); bottom: -150px; right: -100px; z-index: 0; }
.container { max-width: 920px; margin: 32px auto; padding: 24px; position: relative; z-index: 1; width: 100%; }
.card { background: rgba(255, 255, 255, 0.65); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.8); padding: 40px; border-radius: 24px; box-shadow: 0 20px 40px rgba(0, 50, 100, 0.08); }
.h1 { font-size: 28px; font-weight: 700; margin-bottom: 6px; background: linear-gradient(90deg, #0070f3, #00d4ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.small { color: #64748b; margin-bottom: 12px; }
.account-row { padding: 16px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.6); background: rgba(255,255,255,0.5); margin-bottom: 12px; display:flex; justify-content:space-between; align-items:center; transition: all 0.3s; }
.account-row:hover { background: rgba(255,255,255,0.8); transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.05); }
.form-row { display: flex; gap: 8px; margin-top: 8px; }
.input { padding: 12px; border-radius: 12px; border: 1px solid rgba(0,0,0,0.05); background: rgba(255,255,255,0.6); color: #0f172a; width: 100%; box-sizing:border-box; outline: none; transition: all 0.2s; }
.input:focus { border-color: var(--accent); box-shadow: 0 0 0 4px rgba(0, 112, 243, 0.15); background: #fff; }
textarea.input { overflow-y:auto; white-space:pre; word-wrap:normal; max-height:70vh; line-height:1.5; }
.btn { padding: 12px 16px; border-radius: 12px; border: 0; background: linear-gradient(135deg, #0070f3, #0096ff); color: #fff; cursor: pointer; font-weight: 600; transition: all 0.2s; box-shadow: 0 4px 12px rgba(0, 112, 243, 0.3); }
.btn:hover { box-shadow: 0 8px 20px rgba(0, 112, 243, 0.4); transform: translateY(-2px); }
.link { color: var(--accent); cursor:pointer; }
.note { font-size: 13px; color: #94a3b8; margin-top: 8px; }
.modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(15, 23, 42, 0.4); backdrop-filter: blur(8px); justify-content:center; align-items:center; z-index:9999; }
.modal-content { background: rgba(255,255,255,0.85); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.9); border-radius: 20px; width:90%; max-width:500px; padding:24px; position:relative; box-shadow: 0 20px 50px rgba(0,0,0,0.1); }
.modal-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; color: #0f172a; }
</style>
</head>
<body data-page="login">
<div class="container">
  <div class="card">
    <div class="h1">连接您的 Cloudflare 账号</div>
    <div class="small">选择已保存的账号或添加新账号</div>

    <div style="margin-top:12px">
      <div style="font-weight:600;margin-bottom:6px">已保存的账号</div>
      <div id="savedAccounts">未找到已保存账号</div>
    </div>

    <hr style="margin:18px 0">

    <div style="font-weight:600">添加新账号</div>
    <div class="note">如果不绑定KV空间，您的凭据将存储在本地浏览器中</div>

    <div style="margin-top:8px">
      <label class="small">Cloudflare 账号邮箱</label>
      <input id="newEmail" class="input" placeholder="your@email.com">
    </div>
    <div style="margin-top:8px">
      <label class="small">Cloudflare API 密钥</label>
      <input id="newKey" class="input" placeholder="您的 API 密钥">
    </div>

    <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
      <button class="btn" id="verifyBtn">验证并进入管理后台</button>
      <button class="btn" id="openBatchModalBtn" style="background:#4b5563;color:#fff">批量导入账号</button>
      <button class="btn" id="clearBtn" style="background:#e5e7eb;color:#111">清除本地账号</button>
    </div>

    <div class="note" style="margin-top:12px">
      点击右上角头像 → 配置文件 → API 令牌 → 下拉到 API 密钥 → 查看或创建 Global API Key
    </div>
  </div>
</div>

<div id="batchLoginModal" class="modal">
  <div class="modal-content">
    <div class="modal-title">批量添加账号</div>
    <div class="small">每行一个账号，格式：邮箱|GlobalApiKey</div>
    <textarea id="batchLoginInput" class="input" placeholder="user1@example.com|key1&#10;user2@example.com|key2"></textarea>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
      <button class="btn" style="background:#e5e7eb;color:#111" onclick="document.getElementById('batchLoginModal').style.display='none'">取消</button>
      <button class="btn" id="confirmBatchLogin">确认导入</button>
    </div>
  </div>
</div>

<div id="pwOverlay" style="display:none;position:fixed;inset:0;background:rgba(15,23,36,0.88);z-index:99999;justify-content:center;align-items:center">
  <div style="background:#fff;border-radius:16px;padding:36px 32px;width:90%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,0.35)">
    <div style="font-size:22px;font-weight:700;margin-bottom:6px">&#128274; 访问验证</div>
    <div style="color:#6b7280;font-size:14px;margin-bottom:20px">请输入访问密码以继续使用管理面板</div>
    <input id="pwInput" type="password" class="input" placeholder="请输入访问密码" style="margin-bottom:12px" onkeydown="if(event.key==='Enter')submitPw()">
    <div id="pwError" style="color:#ef4444;font-size:13px;min-height:20px;margin-bottom:10px"></div>
    <button class="btn" style="width:100%;padding:12px" onclick="submitPw()">确认进入</button>
  </div>
</div>
<script src="/static.js"></script>
</body>
</html>`;
}

function renderAppHTML() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>cloudflare 第三方管理平台</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root { --bg: #f0f4f8; --card: rgba(255, 255, 255, 0.65); --muted: #64748b; --accent: #0070f3; --accent2: #00d4ff; --danger: #f43f5e; --text: #1e293b; --border: rgba(255, 255, 255, 0.8); --shadow: 0 8px 32px rgba(0, 50, 100, 0.08); }
*{box-sizing:border-box}
body{font-family:Inter,Arial;margin:0;background:linear-gradient(135deg, #f0f4f8 0%, #e6ebf2 100%);color:var(--text)}
.app{display:flex;min-height:100vh}
.sidebar{width:260px;background:rgba(255,255,255,0.5);backdrop-filter:blur(20px);border-right:1px solid var(--border);padding:22px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;box-shadow:4px 0 24px rgba(0,0,0,0.03)}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;background:linear-gradient(90deg, #0070f3, #00d4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.nav{margin-top:22px}
.nav .item{display:flex;align-items:center;gap:10px;padding:12px;border-radius:10px;color:var(--muted);margin-bottom:6px;cursor:pointer;border-left:3px solid transparent;transition:all 0.2s}
.nav .item.active{background:rgba(0, 112, 243, 0.08);font-weight:600;color:var(--accent);border-left-color:var(--accent);box-shadow:inset 0 0 15px rgba(0, 112, 243, 0.05)}
.nav .item:hover{color:var(--text);background:rgba(255,255,255,0.6)}
.main{flex:1;padding:26px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.metric{background:var(--card);backdrop-filter:blur(20px);padding:24px;border-radius:16px;border:1px solid var(--border);display:flex;flex-direction:column;gap:8px;box-shadow:var(--shadow)}
.metric .bar{height:8px;background:rgba(0,0,0,0.05);border-radius:999px;overflow:hidden}
.metric .bar > i{display:block;height:100%;background:linear-gradient(90deg, #0070f3, #00d4ff);width:35%;box-shadow:0 0 10px rgba(0, 112, 243, 0.5)}
.grid{display:grid;grid-template-columns:1fr;gap:18px}
.card{background:var(--card);backdrop-filter:blur(20px);padding:20px;border-radius:16px;border:1px solid var(--border);box-shadow:var(--shadow)}
.workers-list{padding:6px}
.worker-row{display:flex;justify-content:space-between;align-items:flex-start;padding:18px;border-radius:14px;border:1px solid var(--border);background:rgba(255,255,255,0.4);margin-bottom:12px;transition:all 0.3s}
.worker-row:hover{border-color:rgba(0, 112, 243, 0.2);background:rgba(255,255,255,0.7);transform:translateY(-3px);box-shadow:0 10px 25px rgba(0,0,0,0.05)}
.worker-info{flex:1;padding-right:16px}
.worker-right{display:flex;flex-direction:column;align-items:flex-end;gap:10px;min-width:300px}
.worker-tags{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:6px;margin-bottom:4px}
.worker-meta{color:var(--muted);font-size:13px}
.btns{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.btn{padding:8px 12px;border-radius:8px;border:1px solid rgba(0,0,0,0.05);background:rgba(255,255,255,0.7);color:var(--text);cursor:pointer;font-size:12px;transition:all 0.2s}
.btn:hover{background:#fff;border-color:rgba(0,0,0,0.1);box-shadow:0 4px 12px rgba(0,0,0,0.05)}
.btn.primary{background:linear-gradient(135deg, #0070f3, #0096ff);color:#fff;border:0;box-shadow:0 4px 14px rgba(0, 112, 243, 0.3)}
.btn.primary:hover{box-shadow:0 8px 20px rgba(0, 112, 243, 0.4);transform:translateY(-1px)}
.btn.danger{background:rgba(244, 63, 94, 0.1);color:#e11d48;border:1px solid rgba(244, 63, 94, 0.2)}
.btn.danger:hover{background:rgba(244, 63, 94, 0.2)}
.btn.success{background:linear-gradient(135deg, #10b981, #059669);color:#fff;border:0}
.btn.small{font-size:11px;padding:4px 8px}
.small{font-size:13px;color:var(--muted)}
.modal{display:none;position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(15, 23, 42, 0.4);backdrop-filter:blur(8px);align-items:center;justify-content:center;z-index:1000}
.modal-box{width:720px;background:rgba(255,255,255,0.85);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:24px;max-height:90vh;overflow:auto;box-shadow:0 20px 50px rgba(0,0,0,0.1)}
.modal-box.fullscreen{width:100vw;height:100vh;max-width:100vw;max-height:100vh;border-radius:0;display:flex;flex-direction:column;padding:20px 32px}
.modal-box.fullscreen textarea#createScript{flex:1;min-height:0!important;max-height:none!important;width:100%;box-sizing:border-box}
.modal.fullscreen-overlay{align-items:stretch;justify-content:stretch}
.modal-box.small{width:480px}
.input{width:100%;padding:12px;border-radius:10px;border:1px solid rgba(0,0,0,0.05);background:rgba(255,255,255,0.6);color:var(--text);box-sizing:border-box;outline:none;transition:all 0.2s}
.input:focus{border-color:var(--accent);box-shadow:0 0 0 4px rgba(0, 112, 243, 0.15);background:#fff}
textarea.input{overflow-y:auto;white-space:pre;word-wrap:normal;max-height:70vh;line-height:1.5}
.kv-item{padding:12px;border-radius:10px;border:1px solid var(--border);background:rgba(255,255,255,0.4);margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}
pre{background:#f8fafc;color:#1e293b;padding:12px;border-radius:8px;overflow:auto;border:1px solid var(--border)}
.label{font-size:12px;color:var(--muted);margin-bottom:6px;font-weight:600}
.domain-toggle{display:flex;align-items:center;gap:8px;margin-top:8px}
.switch{position:relative;display:inline-block;width:34px;height:18px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:rgba(0,0,0,0.1);transition:.4s;border-radius:24px}
.slider:before{position:absolute;content:"";height:14px;width:14px;left:2px;bottom:2px;background-color:white;transition:.4s;border-radius:50%}
input:checked + .slider{background-color:var(--accent);box-shadow:0 0 10px rgba(0, 112, 243, 0.3)}
input:checked + .slider:before{transform:translateX(16px)}
.resource-section{margin-bottom:16px}
.resource-section h4{margin:0 0 8px 0}
.page-content{display:none}
.page-content.active{display:block}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th,.table td{padding:12px;text-align:left;border-bottom:1px solid rgba(0,0,0,0.05)}
.table th{background:rgba(0,0,0,0.02);color:var(--muted);font-weight:600}
.sql-console{background:#f8fafc;color:#1e293b;padding:16px;border-radius:12px;margin-top:12px;border:1px solid var(--border)}
.sql-console textarea{width:100%;background:#fff;color:#1e293b;border:1px solid rgba(0,0,0,0.05);border-radius:8px;padding:12px;font-family:monospace;min-height:120px}
.sql-results{margin-top:12px;background:#f8fafc;padding:12px;border-radius:8px;max-height:300px;overflow:auto;border:1px solid var(--border)}
.zone-row{padding:14px;border:1px solid var(--border);border-radius:12px;margin-bottom:8px;background:rgba(255,255,255,0.4);cursor:pointer;transition:all 0.2s}
.zone-row:hover{background:rgba(255,255,255,0.7);border-color:rgba(0, 112, 243, 0.2);transform:translateY(-2px)}
.dns-record-row{display:flex;justify-content:space-between;align-items:center;padding:8px;border-bottom:1px solid rgba(0,0,0,0.05)}
.ns-records{background:rgba(0, 112, 243, 0.05);padding:12px;border-radius:8px;margin-top:8px;font-size:12px;border:1px solid rgba(0, 112, 243, 0.1)}
.zone-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.zone-actions{display:flex;gap:8px}
.dns-table{width:100%;border-collapse:collapse;margin-top:12px}
.dns-table th,.dns-table td{padding:12px;text-align:left;border-bottom:1px solid rgba(0,0,0,0.05)}
.dns-table th{background:rgba(0,0,0,0.02);color:var(--muted);font-weight:600}
.copy-btn{background:rgba(0,0,0,0.05);border:1px solid rgba(0,0,0,0.05);padding:4px 8px;border-radius:6px;font-size:11px;cursor:pointer;margin-left:4px;color:var(--text)}
.copy-btn:hover{background:rgba(0,0,0,0.1)}
.domain-control{display:flex;align-items:center;gap:6px}
.domain-status{font-size:11px;padding:2px 6px;border-radius:4px}
.domain-status.active{background:rgba(16, 185, 129, 0.1);color:#059669}
.domain-status.inactive{background:rgba(244, 63, 94, 0.1);color:#e11d48}
.domain-status.pending{background:rgba(245, 158, 11, 0.1);color:#d97706}
.usage-section{margin-bottom:20px}
.usage-breakdown{display:flex;justify-content:space-between;margin-top:12px}
.usage-item{flex:1;text-align:center;padding:16px;background:rgba(255,255,255,0.4);border-radius:12px;border:1px solid var(--border)}
.usage-item .label{font-size:12px;color:var(--muted);margin-bottom:4px}
.usage-item .value{font-size:18px;font-weight:600}
.usage-item.workers .value{color:var(--accent)}
.usage-item.pages .value{color:#10b981}
.usage-item.total .value{color:#8b5cf6}
.worker-domains{margin-top:8px}
.domain-tag{display:inline-block;padding:6px 10px;background:rgba(255,255,255,0.6);border:1px solid var(--border);border-radius:8px;font-size:12px;margin-right:6px;margin-bottom:4px;text-decoration:none;color:var(--text)}
.domain-tag:hover{background:#fff;box-shadow:0 4px 10px rgba(0,0,0,0.05)}
.domain-tag .domain-status{margin-left:6px}
.domain-tag.workers-dev{background:rgba(0, 112, 243, 0.05);border-color:rgba(0, 112, 243, 0.2);color:var(--accent)}
.del-domain-btn{display:inline-block;margin-left:4px;width:16px;height:16px;line-height:16px;text-align:center;border-radius:50%;background:rgba(244, 63, 94, 0.1);color:#e11d48;font-size:10px;cursor:pointer}
.del-domain-btn:hover{background:rgba(244, 63, 94, 0.2)}
.domain-list-table { width: 100%; border-collapse: collapse; margin-top: 8px; background: transparent; border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }
.domain-list-table th, .domain-list-table td { padding: 12px; text-align: left; border-bottom: 1px solid rgba(0,0,0,0.05); font-size: 13px; }
.domain-list-table th { background: rgba(0,0,0,0.02); color: var(--muted); font-weight: 600; }
.domain-list-table tr:last-child td { border-bottom: none; }
.domain-list-table tr:hover td { background: rgba(255,255,255,0.5); }
.domain-row-actions { display: flex; gap: 8px; justify-content: flex-end; }
.trash-btn { background: rgba(255,255,255,0.6); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; color: var(--muted); padding: 6px 12px; font-size: 11px; display: flex; align-items: center; gap: 4px; transition: all 0.2s; }
.trash-btn:hover { color: var(--accent); border-color: var(--accent); background: #fff; }
.ns-pill { display: inline-flex; align-items: center; background: rgba(0,0,0,0.03); border: 1px solid var(--border); border-radius: 6px; padding: 4px 8px; font-family: monospace; font-size: 11px; color: var(--text); margin-right: 6px; margin-bottom: 4px; }
.ns-copy-icon { margin-left: 4px; cursor: pointer; color: var(--muted); display: flex; align-items: center; }
.ns-copy-icon:hover { color: var(--accent); }
.res-tag { font-size: 11px; padding: 4px 10px; border-radius: 6px; border: 1px solid transparent; display: inline-flex; align-items: center; font-weight: 600; }
.res-tag.kv { background: rgba(59, 130, 246, 0.1); color: #2563eb; border-color: rgba(59, 130, 246, 0.2); }
.res-tag.d1 { background: rgba(249, 115, 22, 0.1); color: #ea580c; border-color: rgba(249, 115, 22, 0.2); }
.res-tag.env { background: rgba(16, 185, 129, 0.1); color: #059669; border-color: rgba(16, 185, 129, 0.2); }

/* Batch Page CSS */
.batch-layout { display: flex; gap: 20px; height: calc(100vh - 100px); }
.batch-sidebar { width: 300px; border-right: 1px solid var(--border); overflow-y: auto; padding-right: 16px; }
.batch-main { flex: 1; display: flex; flex-direction: column; overflow-y: auto; }
.account-check-item { display: flex; align-items: center; padding: 12px; border-bottom: 1px solid rgba(0,0,0,0.05); border-radius: 8px; }
.account-check-item:hover { background: rgba(255,255,255,0.6); }
.log-area { background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 12px; font-family: monospace; font-size: 12px; margin-top: 16px; min-height: 150px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; border: 1px solid rgba(0,0,0,0.1); box-shadow: inset 0 2px 4px rgba(0,0,0,0.1); }
.env-row-batch { display: flex; gap: 8px; margin-top: 8px; }
.acct-row { padding: 12px; border-bottom: 1px solid rgba(0,0,0,0.05); display: flex; justify-content: space-between; align-items: center; border-radius: 8px; }
.acct-row:last-child { border-bottom: 0; }
.acct-active { background: rgba(0, 112, 243, 0.05); }
.badge { background: rgba(0, 112, 243, 0.1); color: var(--accent); font-size: 10px; padding: 4px 8px; border-radius: 6px; margin-left: 6px; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(0, 0, 0, 0.1); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(0, 0, 0, 0.2); }

/* ===== UI 增强：暗色 / 响应式 / 加载态 / 确认弹窗 / 搜索 ===== */
.spinner{width:14px;height:14px;border:2px solid var(--muted);border-top-color:var(--accent);border-radius:50%;display:inline-block;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.last-updated{font-size:11px;color:var(--muted)}
.list-search{width:200px;max-width:50vw}
.sort-ind:hover{color:var(--accent);cursor:pointer}
.sort-ind::after{content:' \\2195';opacity:.45;font-size:11px}
.confirm-box{width:460px}
.hamburger{display:none}
body.dark{--bg:#0f172a;--card:rgba(30,41,59,0.7);--muted:#94a3b8;--text:#e2e8f0;--border:rgba(255,255,255,0.12);--accent:#38bdf8;--accent2:#22d3ee;--shadow:0 8px 32px rgba(0,0,0,0.45)}
body.dark{background:linear-gradient(135deg,#0f172a,#1e293b)}
body.dark .sidebar{background:rgba(15,23,42,0.72)}
body.dark .metric,body.dark .card,body.dark .kv-item,body.dark .worker-row,body.dark .zone-row,body.dark .acct-row,body.dark .ns-pill,body.dark .domain-tag{background:rgba(30,41,59,0.55)}
body.dark pre,body.dark .sql-console,body.dark .sql-results{background:#0b1220;color:#cbd5e1}
body.dark .input{background:rgba(15,23,42,0.6);color:var(--text)}
body.dark .input:focus{background:#0b1220}
body.dark .modal-box{background:rgba(30,41,59,0.96)}
body.dark .log-area{background:#020617}
body.dark .res-tag{filter:brightness(1.1)}
body.dark .domain-status.active{background:rgba(16,185,129,0.18)}
body.dark .domain-status.pending{background:rgba(245,158,11,0.18)}
@media (max-width: 860px){
  .hamburger{display:block;position:fixed;top:12px;left:12px;z-index:60;width:40px;height:40px;border-radius:10px;background:var(--card);border:1px solid var(--border);color:var(--text);font-size:18px;cursor:pointer;box-shadow:var(--shadow)}
  .sidebar{position:fixed;left:0;top:0;bottom:0;z-index:55;transform:translateX(-100%);transition:transform .25s ease;box-shadow:0 0 40px rgba(0,0,0,.35)}
  .sidebar.open{transform:none}
  .main{padding:64px 16px 16px}
  .nav .item{font-size:14px}
  .list-search{width:130px}
  .header{flex-direction:column;align-items:flex-start;gap:10px}
}
</style>
</head>
<body data-page="app">
    <button class="hamburger" id="hamburgerBtn" onclick="toggleSidebar()" aria-label="菜单">&#9776;</button>
<div class="app">
  <aside class="sidebar">
    <div class="logo"><span style="font-size:18px">cloudflare</span>管理平台</div>
    
    <nav class="nav">
      <div style="font-size:11px;color:var(--muted);padding:10px 16px 2px;letter-spacing:.5px">全局 · 无需 CF 账户</div>
      <div class="item active" data-page="overview" onclick="navTo('overview')">总览</div>
      <div class="item" data-page="accounts" onclick="navTo('accounts')">账号库</div>
      <div class="item" data-page="monitor" onclick="navTo('monitor')">监控中心</div>
      <div class="item" data-page="settings" onclick="navTo('settings')">设置</div>
      <div style="font-size:11px;color:var(--muted);padding:14px 16px 2px;letter-spacing:.5px">资源 · 按需选择执行账号</div>
      <div class="item" data-page="workers" onclick="navTo('workers')">Workers管理</div>
      <div class="item" data-page="pages-manager" onclick="navTo('pages-manager')">Pages管理</div>
      <div class="item" data-page="snippets" onclick="navTo('snippets')">Snippets管理</div>
      <div class="item" data-page="kv" onclick="navTo('kv')">Workers KV</div>
      <div class="item" data-page="d1" onclick="navTo('d1')">D1 数据库</div>
      <div class="item" data-page="dns" onclick="navTo('dns')">域名管理</div>
      <div class="item" data-page="waf" onclick="navTo('waf')">WAF 规则</div>
      <div class="item" data-page="tunnels" onclick="navTo('tunnels')">隧道 Tunnel</div>
      <div class="item" data-page="redirects" onclick="navTo('redirects')">批量重定向</div>
      <div class="item" data-page="optimize" onclick="navTo('optimize')">站点优化</div>
      <div class="item" data-page="email" onclick="navTo('email')">邮箱转发</div>
      <div class="item" data-page="r2" onclick="navTo('r2')">R2 存储</div>
      <div class="item" data-page="batch" onclick="navTo('batch')">批量创建 Worker</div>
      <div class="item" data-page="pages" onclick="navTo('pages')">批量部署 Pages</div>
      <div class="item" data-page="bulk" onclick="navTo('bulk')">批量操作</div>
    </nav>
    
    <div style="margin-top:auto;padding-top:20px;border-top:1px solid #eef2f6">
       <div class="small" style="margin-bottom:4px">当前账号</div>
       <div style="font-weight:600;font-size:13px;word-break:break-all;cursor:pointer" id="acctInfo" onclick="openAccountSwitcher()" title="切换账号">未登录</div>
       <div style="margin-top:8px;font-size:11px;color:var(--muted);display:flex;justify-content:space-between">
         <span onclick="openAccountSwitcher()" style="cursor:pointer;text-decoration:underline">切换</span>
         <span onclick="logout()" style="cursor:pointer;color:#ef4444">退出</span>
       </div>
       <div style="margin-top:10px;display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted)">
         <span id="globalBusy" class="spinner" style="display:none"></span>
         <span id="lastUpdated" class="last-updated"></span>
       </div>
       <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
         <button class="btn small" id="darkToggle" onclick="toggleDark()">暗色</button>
         <button class="btn small" onclick="restoreFromKV()">从 KV 同步</button>
       </div>
    </div>
  </aside>

  <main class="main">
    <!-- Overview Page（全局 · 无需 CF 账户） -->
    <div id="overview-page" class="page-content active">
      <div class="header">
        <div style="font-size:20px;font-weight:700">总览</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <select id="dashScope" class="input" style="width:auto;max-width:260px" onchange="dashScopeChanged()"></select>
          <button class="btn primary" id="dashCollectBtn" onclick="collectAnalyticsNow()">立即采集</button>
          <button class="btn" onclick="openAccountSwitcher()">切换执行账号</button>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:14px">
        <div class="metric"><div class="small">24h 请求量</div><div style="font-size:26px;font-weight:700" id="dashReq">-</div></div>
        <div class="metric"><div class="small">24h 带宽</div><div style="font-size:26px;font-weight:700" id="dashBytes">-</div></div>
        <div class="metric"><div class="small">24h 访问者</div><div style="font-size:26px;font-weight:700" id="dashUniq">-</div></div>
        <div class="metric"><div class="small">缓存命中率(官方日)</div><div style="font-size:26px;font-weight:700;color:#0f6e56" id="dashCache">-</div></div>
        <div class="metric"><div class="small">威胁拦截(官方日)</div><div style="font-size:26px;font-weight:700;color:#b45309" id="dashThreats">-</div></div>
        <div class="metric"><div class="small">今日配额 (100k)</div><div style="font-size:26px;font-weight:700;color:#d97706" id="dashQuota">-</div></div>
        <div class="metric"><div class="small">异常 / 封号</div><div style="font-size:26px;font-weight:700;color:#a32d2d" id="dashBad">-</div></div>
        <div class="metric"><div class="small">最近采集</div><div style="font-size:15px;font-weight:700" id="dashTs">-</div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px">
        <div class="card" style="margin-top:0"><div style="font-weight:700">24h 请求走势 <span style="font-weight:400;font-size:11px;color:#94a3b8">(官方小时直读 · 采集中)</span></div>
          <div id="dashTrend" class="small" style="font-family:monospace">-</div>
        </div>
        <div class="card" style="margin-top:0">
          <div style="font-weight:700;margin-bottom:4px" id="dashShareTitle">各账号请求占比</div>
          <div id="dashShare" class="small" style="font-family:monospace">-</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px">
        <div class="card" style="margin-top:0"><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><span style="font-weight:700">请求趋势</span>
          <select id="dashTrendDays" class="input" style="width:auto" onchange="trendDaysChanged()"><option value="7">近 7 天</option><option value="14" selected>近 14 天</option><option value="30">近 30 天</option><option value="90">近 90 天</option></select>
          <span id="dashDailySrc" style="font-weight:400;font-size:11px;color:#94a3b8"></span></div>
          <div id="dashDaily" class="small" style="font-family:monospace;margin-top:6px">-</div>
        </div>
        <div class="card" style="margin-top:0"><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><span style="font-weight:700">配额消耗 14 天</span><span style="font-weight:400;font-size:11px;color:#94a3b8" id="dashQuotaSrc">官方直读</span><button class="btn small" onclick="backfillUsageHistory()">回填官方历史(≤30 天)</button></div><div id="dashQuotaChart" class="small" style="font-family:monospace;margin-top:6px">-</div></div>
      </div>
      <div class="card" style="margin-top:12px">
        <h3 style="margin:0 0 8px">账号明细 <span class="small">点「Zones」下钻 · 点「设为执行」切换</span></h3>
        <div id="dashTable" class="small" style="font-family:monospace"></div>
      </div>
      <div class="small" id="dashSrcNote" style="margin-top:10px;color:#94a3b8;line-height:1.7"></div>
    </div>

    <!-- Accounts Page（账号库 · 全局） -->
    <div id="accounts-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">账号库</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <input id="accSearch" class="input list-search" placeholder="搜索账号" oninput="filterRows('accountsBox', this.value)">
          <button class="btn primary" onclick="openAddAccount()">添加账号</button>
          <button class="btn" onclick="openBatchImport()">批量导入</button>
        </div>
      </div>
      <div class="card" style="margin-top:8px">
        <h3 style="margin:0 0 8px">账号列表</h3>
        <div class="small" style="margin-bottom:12px">绿色=有效，红色=异常/封号（由监控周期自动检测）。点击「设为执行账号」后即可在资源页操作该账号。</div>
        <div id="accountsBox"></div>
      </div>
    </div>

    <!-- Workers Page -->
    <div id="workers-page" class="page-content">

    <div id="addAccountModal" class="modal"><div class="modal-box">
      <h3>添加 Cloudflare 账号</h3>
      <div class="label">账号邮箱</div><input id="addAccEmail" class="input" placeholder="your@email.com">
      <div class="label" style="margin-top:8px">Global API Key</div><input id="addAccKey" class="input" placeholder="全局 API 密钥">
      <div class="label" style="margin-top:8px">分组（可选，如 main / 备用）</div><input id="addAccGroup" class="input" placeholder="main">
      <div class="small" style="margin-top:6px">保存前会联网校验凭据有效性</div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:14px">
        <button class="btn" onclick="closeAddAccount()">取消</button>
        <button class="btn primary" onclick="confirmAddAccount()">校验并添加</button>
      </div>
    </div></div>

    <div id="importAccountsModal" class="modal"><div class="modal-box">
      <h3>批量导入账号</h3>
      <div class="small">每行一个账号，格式：邮箱|GlobalApiKey（可带第三段分组）</div>
      <textarea id="importAccInput" class="input" style="min-height:180px;font-family:monospace;white-space:pre" placeholder="user1@example.com|key1|main&#10;user2@example.com|key2|备用"></textarea>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:12px">
        <button class="btn" onclick="closeBatchImport()">取消</button>
        <button class="btn primary" onclick="confirmBatchImport()">确认导入</button>
      </div>
    </div></div>

      <div class="header">
        <div style="font-size:20px;font-weight:700">Workers 管理</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <input id="workerSearch" class="input list-search" placeholder="搜索 Worker / 域名" oninput="filterRows('workersList', this.value)">
          <button class="btn primary" onclick="openCreateWorker()">新建 Worker</button>
        </div>
      </div>

      <div class="metric">
        <div class="small">今天的请求</div>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div style="font-size:28px;font-weight:700" id="metricCount">0 / 100,000</div>
        </div>
        <div class="bar"><i id="metricBar" style="width:0%"></i></div>
        
        <div class="usage-section">
          <div class="usage-breakdown">
            <div class="usage-item workers">
              <div class="label">WORKERS 请求</div>
              <div class="value" id="workersRequests">0</div>
            </div>
            <div class="usage-item pages">
              <div class="label">PAGES 请求</div>
              <div class="value" id="pagesRequests">0</div>
            </div>
            <div class="usage-item total">
              <div class="label">日配额</div>
              <div class="value">100,000</div>
            </div>
          </div>
        </div>
      </div>

      <div class="grid" style="margin-top:16px">
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div><h2 style="margin:0">Workers 列表</h2><div class="small">查看和管理您的 Cloudflare Workers</div></div>
            <div style="display:flex; gap:8px; align-items:center;">
              <label style="font-size:12px; cursor:pointer;"><input type="checkbox" id="selectAllWorkers" onchange="toggleSelectAllWorkers(this)"> 全选</label>
              <button class="btn danger" onclick="batchDeleteWorkers()">批量删除</button>
            </div>
          </div>
          <div class="workers-list" id="workersList"></div>
        </div>
      </div>
    </div>
    
    <!-- Batch Page -->
    <div id="batch-page" class="page-content">
        <div class="header"><div style="font-size:20px;font-weight:700">批量创建 Workers</div></div>
        <div class="batch-layout">
            <div class="batch-sidebar">
                <div style="padding-bottom:10px;border-bottom:1px solid #eef2f6;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;">
                    <span style="font-weight:600">选择账号</span>
                    <label style="font-size:12px;cursor:pointer"><input type="checkbox" id="selectAllAccounts" onchange="toggleSelectAllAccounts(this)"> 全选</label>
                </div>
                <div id="batchAccountList"></div>
            </div>
            <div class="batch-main">
                <div class="card">
                    <div style="font-weight:600;margin-bottom:12px">基本配置</div>
                    <label class="small">Worker 名称</label>
                    <input id="batchWorkerName" class="input" placeholder="例如: my-proxy-worker">
                    <div style="margin-top:12px">
                       <label class="small" style="display:flex;align-items:center;cursor:pointer">
                          <input type="checkbox" id="batchEnableSubdomain" checked style="margin-right:8px"> 开启默认域名 (*.workers.dev)
                       </label>
                    </div>
                    <div style="margin-top:8px">
                       <span class="small">💡 系统将自动尝试开启 CPU 限制 (付费版生效，免费版自动忽略)</span>
                    </div>
                    <label class="small" style="display:block;margin-top:12px">代码来源</label>
                    <select id="batchScriptSourceType" class="input" onchange="toggleBatchSourceInput()">
                        <option value="builtin">内置模板 (环境变量配置)</option>
                        <option value="url">远程链接 (URL)</option>
                        <option value="custom">自定义脚本 (本地编辑)</option>
                    </select>
                    <div id="batchSourceBuiltinDiv" style="margin-top:8px">
                        <select id="batchBuiltinSelect" class="input">
                            <option value="">未配置 BATCH_NAMES / BATCH_URLS 环境变量</option>
                        </select>
                    </div>
                    <div id="batchSourceUrlDiv" style="margin-top:8px;display:none">
                        <div style="display:flex;gap:8px;align-items:center">
                            <input id="batchScriptUrl" class="input" placeholder="https://github.com/user/repo 或 raw链接" oninput="normalizeGithubUrl(this)">
                            <button class="btn" style="white-space:nowrap;background:#0ea5e9;color:#fff;flex-shrink:0" onclick="autoFillFromRemoteScript()">&#128269; 自动解析</button>
                        </div>
                        <div class="note" style="font-size:12px;color:#666;margin-top:4px">支持直接粘贴 GitHub 项目地址，自动查找 <code>_worker.js</code> 并转换为 raw 链接；也可直接填写 raw 链接后点击「自动解析」</div><div id="urlConvertHint" style="font-size:12px;color:#10b981;margin-top:4px;display:none"></div>
                    </div>
                    <div id="batchSourceCustomDiv" style="margin-top:8px;display:none">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                            <span style="font-size:13px;font-weight:600;color:#374151">自定义脚本编辑器</span>
                            <div style="display:flex;gap:6px">
                                <button class="btn small" style="background:#0ea5e9;color:#fff" onclick="autoFillFromCustomScript()">&#128269; 解析依赖</button>
                                <button class="btn small" style="background:#10b981;color:#fff" onclick="saveCustomScriptFile()">&#128190; 下载 _worker.js</button>
                            </div>
                        </div>
                        <textarea id="batchCustomScript" class="input" rows="14" style="font-family:monospace;font-size:12px;min-height:280px;resize:vertical" placeholder="// 在此编写或粘贴你的 Worker 脚本&#10;export default {&#10;  async fetch(request, env, ctx) {&#10;    return new Response('Hello World');&#10;  }&#10;};"></textarea>
                        <div id="scriptDepPreview" style="margin-top:8px;display:none;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:12px;line-height:1.8"></div>
                        <div style="font-size:11px;color:#9ca3af;margin-top:4px">脚本自动保存到 localStorage；停止输入 0.8 秒后自动解析依赖并展示预览</div>
                    </div>
                </div>
                <div class="card" style="margin-top:16px">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                        <div style="font-weight:600">高级绑定配置</div>
                        <span id="autoParseStatus" style="font-size:12px;color:#10b981;font-weight:600"></span>
                    </div>
                    <div style="margin-bottom:16px">
                        <div style="font-size:13px;font-weight:600;margin-bottom:4px;color:#374151">环境变量 (ENV)</div>
                        <div id="batchEnvList"></div>
                        <button class="btn small" style="margin-top:6px" onclick="addBatchEnvRow()">+ 添加变量</button>
                    </div>
                    <div style="margin-bottom:16px;border-top:1px solid #eee;padding-top:10px">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                            <div style="font-size:13px;font-weight:600;color:#374151">KV 命名空间 (自动查找或创建)</div>
                            <button class="btn small" onclick="addBatchKvRow()">+ 添加</button>
                        </div>
                        <div style="font-size:11px;color:#9ca3af;margin-bottom:6px">KV空间名留空则自动使用「Worker名-绑定名」</div>
                        <div id="batchKvList"></div>
                    </div>
                    <div style="margin-bottom:16px;border-top:1px solid #eee;padding-top:10px">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                            <div style="font-size:13px;font-weight:600;color:#374151">D1 数据库 (自动查找或创建)</div>
                            <button class="btn small" onclick="addBatchD1Row()">+ 添加</button>
                        </div>
                        <div style="font-size:11px;color:#9ca3af;margin-bottom:6px">数据库名留空则自动使用「Worker名-绑定名」</div>
                        <div id="batchD1List"></div>
                    </div>
                    <button class="btn primary" style="margin-top:10px;width:100%" onclick="startBatchCreate()">开始批量创建</button>
                </div>
                <div style="font-weight:600;margin-top:16px">执行日志</div>
                <div id="batchLog" class="log-area">等待开始...</div>
            </div>
        </div>
    </div>

    
<!-- Pages Batch Page -->
<div id="pages-page" class="page-content">
  <div class="header"><div style="font-size:20px;font-weight:700">批量部署 Pages</div></div>
  <div class="batch-layout">
    <div class="batch-sidebar">
      <div style="padding-bottom:10px;border-bottom:1px solid #eef2f6;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center"><span style="font-weight:600">选择账号</span><label style="font-size:12px;cursor:pointer"><input type="checkbox" id="pagesSelectAllAccounts" onchange="toggleSelectAllPagesAccounts(this)"> 全选</label></div>
      <div id="pagesAccountList"></div>
    </div>
    <div class="batch-main">
      <div class="card">
        <div style="font-weight:600;margin-bottom:12px">Pages Direct Upload</div>
        <label class="small">项目名称</label><input id="pagesProjectName" class="input" placeholder="my-static-site" autocomplete="off">
        <div style="margin-top:10px"><label class="small">部署分支</label><input id="pagesBranch" class="input" value="main" placeholder="main"></div><div style="margin-top:10px"><span class="small">💡 系统将自动尝试开启 CPU 限制 (付费版生效，免费版自动忽略)</span></div>
        <div style="margin-top:10px"><label class="small">上传来源</label><select id="pagesUploadMode" class="input"><option value="folder">构建输出文件夹</option><option value="zip">ZIP 压缩包</option></select></div>
        <div id="pagesUploadDrop" style="margin-top:12px;padding:26px 18px;border:2px dashed #cbd5e1;border-radius:10px;text-align:center;color:#64748b;cursor:pointer">点击选择，或拖入构建输出文件夹 / ZIP 文件<br><span style="font-size:11px">文件夹支持递归目录；ZIP 在浏览器本地解压</span></div>
        <input id="pagesFolderInput" type="file" webkitdirectory directory multiple style="display:none"><input id="pagesZipInput" type="file" accept=".zip,application/zip" style="display:none">
        <div id="pagesFileSummary" class="small" style="margin-top:10px">尚未选择文件</div>
      </div>
      <div class="card" style="margin-top:16px"><div style="font-weight:600;margin-bottom:8px">执行</div><div class="small" style="margin-bottom:10px">每个账号中创建或更新同名 Pages 项目；不绑定 GitHub。</div><button class="btn primary" style="width:100%" onclick="startPagesBatchDeploy()">开始批量部署 Pages</button></div>
      <div style="font-weight:600;margin-top:16px">执行日志</div><div id="pagesBatchLog" class="log-area">等待开始...</div>
    </div>
  </div>
</div>

<!-- Pages Manager Page -->
<div id="pages-manager-page" class="page-content"><div class="header"><div style="font-size:20px;font-weight:700">Pages 管理</div><button class="btn primary" onclick="refreshPagesManager()">刷新列表</button></div><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px"><div class="small">列出当前账号全部 Pages 项目。删除项目会一并删除全部部署记录，且不可恢复。</div><div style="display:flex; gap:8px; align-items:center;"><label style="font-size:12px; cursor:pointer;"><input type="checkbox" id="selectAllPages" onchange="toggleSelectAllPages(this)"> 全选</label><button class="btn danger" onclick="batchDeletePages()">批量删除</button></div></div><div id="pagesManagerList"></div></div></div>

<!-- KV Page -->
    <div id="kv-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">Workers KV 管理</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <input id="kvSearch" class="input list-search" placeholder="搜索命名空间" oninput="filterRows('kvNamespacesList', this.value)">
          <button class="btn primary" onclick="openCreateKVNamespace()">创建 KV 命名空间</button>
        </div>
      </div>

      <div class="card">
        <h3 style="margin:0">KV 命名空间列表</h3>
        <div class="small" style="margin-top:8px">管理您的 Workers KV 命名空间</div>
        <div id="kvNamespacesList" style="margin-top:16px"></div>
      </div>
    </div>

    <!-- D1 Page -->
    <div id="d1-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">D1 数据库管理</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <input id="d1Search" class="input list-search" placeholder="搜索数据库" oninput="filterRows('d1DatabasesList', this.value)">
          <button class="btn primary" onclick="openCreateD1Database()">创建 D1 数据库</button>
        </div>
      </div>

      <div class="card">
        <h3 style="margin:0">D1 SQL 数据库</h3>
        <div class="small" style="margin-top:8px">管理您的 Cloudflare D1 数据库实例</div>
        <div id="d1DatabasesList" style="margin-top:16px"></div>
      </div>

      <div class="card" style="margin-top:16px">
        <h4 style="margin:0">SQL 控制台</h4>
        <div class="small" style="margin-top:8px">在选定的数据库中执行 SQL 查询</div>
        <div style="margin-top:12px">
          <select id="d1DatabaseSelect" class="input" onchange="refreshD1Tables()">
            <option value="">- 选择数据库 -</option>
          </select>
        </div>
        <div class="sql-console">
          <textarea id="d1Query" placeholder="SELECT * FROM table_name LIMIT 10;"></textarea>
          <button class="btn primary" style="margin-top:8px" onclick="executeD1Query()">执行查询</button>
        </div>
        <div id="d1QueryResults" class="sql-results"></div>
      </div>
    </div>

    <!-- DNS Page -->
    <div id="dns-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">域名管理</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <input id="zoneSearch" class="input list-search" placeholder="搜索域名" oninput="filterRows('zonesList', this.value)">
          <button class="btn" onclick="openDnsExportImport()">导出/导入 BIND</button>
          <button class="btn primary" onclick="openAddZone()">添加新域名</button>
        </div>
      </div>

      <div class="card">
        <h3 style="margin:0">域名列表</h3>
        <div class="small" style="margin-top:8px">管理您的 Cloudflare 域名</div>
        <div id="zonesList" style="margin-top:16px"></div>
      </div>

      <div id="dnsRecordsSection" class="card" style="margin-top:16px;display:none">
        <div class="zone-header">
          <div>
            <h3 style="margin:0" id="selectedZoneName">域名 DNS 记录</h3>
            <div class="small" id="selectedZoneInfo">管理选定域名的 DNS 记录</div>
          </div>
          <div class="zone-actions">
            <input id="dnsSearch" class="input list-search" placeholder="搜索记录" oninput="filterRows('dnsRecordsList', this.value)">
            <button class="btn primary" onclick="openAddDNSRecord()">添加 DNS 记录</button>
            <button class="btn" onclick="backToZones()">返回域名列表</button>
          </div>
        </div>
        <div id="dnsRecordsList"></div>
      </div>
    </div>


    <!-- Snippets Page -->
    <div id="snippets-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">Snippets 管理</div>
        <div>
          <button class="btn primary" onclick="openAddZone()">添加新域名</button>
        </div>
      </div>

      <div class="card">
        <h3 style="margin:0">域名列表</h3>
        <div class="small" style="margin-top:8px">选择域名以管理其 Snippets 和路由规则</div>
        <div id="snippetsZonesList" style="margin-top:16px"></div>
      </div>

      <div id="snippetsSection" class="card" style="margin-top:16px;display:none">
        <div class="zone-header">
          <div>
            <h3 style="margin:0" id="selectedSnippetZoneName">Snippets</h3>
            <div class="small" id="selectedSnippetZoneInfo">管理选定域名的 Snippets</div>
          </div>
          <div class="zone-actions">
            <button class="btn primary" onclick="openCreateSnippet()">创建 Snippet</button>
            <button class="btn" onclick="openAddSnippetRule()">添加路由规则</button>
            <button class="btn" onclick="backToSnippetZones()">返回域名列表</button>
          </div>
        </div>
        <h4 style="margin:0 0 8px 0">Snippets 列表</h4>
        <div id="snippetsList"></div>
        <div style="margin-top:20px;border-top:1px solid #eef2f6;padding-top:16px">
          <h4 style="margin:0 0 8px 0">路由规则</h4>
          <div class="small" style="margin-bottom:8px">路由规则决定哪些请求会触发对应的 Snippet</div>
          <div id="snippetRulesList"></div>
        </div>
      </div>
    </div>

        <!-- Settings Page -->
    <div id="settings-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">设置</div>
      </div>
      <div class="card">
        <h3 style="margin:0">Workers 域名设置</h3>
        <div class="small" style="margin-top:8px">设置您的 workers.dev 子域名</div>
        <div style="margin-top:12px">
          <input id="subdomainInput" class="input" placeholder="输入子域名">
          <button class="btn primary" style="margin-top:8px" onclick="saveSubdomain()">保存设置</button>
        </div>
        <div class="small" style="margin-top:8px">
          设置后，您的 Workers 将通过 https://worker-name.your-subdomain.workers.dev 访问
        </div>
        <div class="small" style="margin-top:8px;color:#b45309">注意：此为账户级设置，作用于当前「执行账号」的 workers.dev 子域名，需先在账号库选择执行账号。</div>
      </div>

      <div class="card" style="margin-top:16px">
        <h3 style="margin:0">OAuth 免密钥接入 <span style="font-weight:400;font-size:12px;color:#64748b">（替代 Global Key：最小权限 + 可随时撤销，无需粘贴密钥）</span></h3>
        <div class="small" style="margin-top:6px;line-height:1.9">
          ① 打开 Cloudflare <b>dash → Manage Account → OAuth clients</b> → Create client（需 Super Administrator / Administrator 角色）。<br>
          ② Grant type 选 <b>authorization_code</b>；Token authentication 选 <b>Client secret (POST)</b> 或 Basic（选 none=PKCE 则无需 Secret）。<br>
          ③ Redirect URL 填：<code id="oauthRedirectHint" style="background:#f1f5f9;padding:1px 6px;border-radius:4px"></code><br>
          ④ 按需勾选 scope（命名与 API Token 权限一致，如 account:read、workers:read、zone:read…），保存后将 Client ID / Secret 填到下方保存，再点「前往 Cloudflare 授权」。<br>
          <span style="color:#b45309">提示：client 设为 private 时仅创建账号的成员可授权；要给其他 CF 账号授权需先在 dash 把 client 改为 public（需域名 TXT 验证）。</span>
        </div>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
          <input id="oauthClientId" class="input" style="flex:1;min-width:220px" placeholder="Client ID">
          <input id="oauthClientSecret" class="input" style="flex:1;min-width:220px" placeholder="Client Secret（仅保存时填写）">
        </div>
        <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <select id="oauthAuthMethod" class="input" style="width:auto">
            <option value="post">Token 认证：client_secret_post</option>
            <option value="basic">Token 认证：client_secret_basic</option>
            <option value="none">Token 认证：none（PKCE，免 Secret）</option>
          </select>
          <button class="btn primary" onclick="saveOAuthConfig()">保存配置</button>
          <button class="btn" onclick="oauthConnect()">前往 Cloudflare 授权</button>
        </div>
        <div id="oauthConnBox" class="small" style="margin-top:12px;white-space:pre-wrap;color:#475569"></div>
      </div>

      <!-- 新增：Telegram 反馈加群按钮 -->
      <div class="card" style="margin-top:16px; display:flex; justify-content:center; padding:24px;">
        <a href="https://t.me/yifang_chat" target="_blank" style="text-decoration:none; text-align:center; color:#334155;">
          <div style="
              width: 60px;
              height: 60px;
              background: #229ED9;
              border-radius: 50%;
              display: flex;
              align-items: center;
              justify-content: center;
              margin: 0 auto;
              box-shadow: 0 4px 10px rgba(34, 158, 217, 0.4);
              transition: transform 0.2s;
            "
            onmouseover="this.style.transform='scale(1.05)'" 
            onmouseout="this.style.transform='scale(1)'">
            <!-- Telegram Icon SVG -->
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-left:-2px;margin-top:2px;">
              <line x1="22" y1="2" x2="11" y2="13"></line>
              <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
            </svg>
          </div>
          <div style="margin-top:10px; font-weight:600; font-size:14px;">反馈加群</div>
        </a>
      </div>

    <!-- TG 推送设置 -->
    <div class="card" style="margin-top:16px">
      <h3 style="margin:0">Telegram 推送设置</h3>
      <div class="small" style="margin-top:8px">配置 Bot Token 与 Chat ID 后，可定时推送每日请求报告与配额告警到你的 TG 机器人（10 个账号已支持，凭据从 KV 读取）。</div>
      <div style="margin-top:12px;display:grid;gap:8px">
        <input id="tgBotToken" class="input" placeholder="Bot Token（格式：123456:ABCdef...）">
        <input id="tgChatId" class="input" placeholder="Chat ID（你的 TG 账号或群 ID）">
      </div>
      <div style="margin-top:10px;display:flex;gap:16px;flex-wrap:wrap">
        <label><input type="checkbox" id="tgEnabled" checked> 启用推送</label>
        <label><input type="checkbox" id="tgDaily" checked> 每日日报</label>
        <label><input type="checkbox" id="tgAlerts" checked> 配额告警(50/80/95%)</label>
        <label><input type="checkbox" id="tgTraffic" checked> 流量突增/归零告警</label>
      </div>
      <div style="margin-top:8px;display:flex;flex-direction:column;gap:6px">
        <div style="display:flex;align-items:flex-start;gap:8px;color:#475569;flex-wrap:wrap">
          <span style="padding-top:4px">日报时段(北京时,可多选)：</span>
          <div id="tgReportHours" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center"></div>
        </div>
        <span class="small" style="color:#94a3b8">每个整点后第 23 分触发，一天可推多次（多选=早/中/晚各一份）；默认北京 7 点(=UTC 23)</span>
      </div>
      <div style="margin-top:6px;display:flex;gap:16px;flex-wrap:wrap;align-items:center;color:#475569">
        <span>日报包含：</span>
        <label><input type="checkbox" id="tgSegQuota" checked> 配额用量</label>
        <label><input type="checkbox" id="tgSegTraffic" checked> 流量 / Zones</label>
        <label><input type="checkbox" id="tgSegHealth" checked> 健康段(异常/证书/探活/WAF)</label>
      </div>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn primary" onclick="saveTGConfig()">保存配置</button>
        <button class="btn" onclick="testTG()">测试推送</button>
        <button class="btn" onclick="pushTGNow()">立即推送日报</button>
        <button class="btn" onclick="refreshTGUsage()">刷新今日全账号请求</button>
      </div>
      <div class="small" style="margin-top:12px">机器人菜单（在 TG 里发 /report 可手动触发日报）：需先把 Webhook 指向本 Worker，并注册指令菜单。</div>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" onclick="setupTGWebhook()">设置机器人 Webhook</button>
        <button class="btn" onclick="setupTGCommands()">注册菜单指令</button>
        <button class="btn" onclick="showTGWebhook()">查看 Webhook</button>
      </div>
      <div id="tgUsageBox" class="small" style="margin-top:12px;white-space:pre-wrap;font-family:monospace"></div>
    </div>

    <!-- 多通道通知（全局 · 鉴权即可用） -->
    <div class="card" style="margin-top:16px">
      <h3 style="margin:0">多通道通知（保活）</h3>
      <div class="small" style="margin-top:8px">除 Telegram 外再挂一条通道（TG 在国内常被墙）。告警/日报会同时发送到所有已启用通道，任一送达即视为成功。这些配置鉴权后即可设置，与是否选择 CF 账号无关。</div>
      <div style="margin-top:12px;display:grid;gap:10px">
        <div style="border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px">
          <label style="display:flex;align-items:center;gap:6px;font-weight:600"><input type="checkbox" id="ndEnabled"> Discord Webhook</label>
          <input id="ndWebhook" class="input" style="margin-top:6px" placeholder="https://discord.com/api/webhooks/...">
        </div>
        <div style="border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px">
          <label style="display:flex;align-items:center;gap:6px;font-weight:600"><input type="checkbox" id="nbEnabled"> Bark（iOS 推送）</label>
          <div style="display:grid;grid-template-columns:1fr 2fr;gap:8px;margin-top:6px">
            <input id="nbServer" class="input" placeholder="服务器(默认 api.day.app)">
            <input id="nbKey" class="input" placeholder="DeviceKey（推送 key）">
          </div>
        </div>
        <div style="border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px">
          <label style="display:flex;align-items:center;gap:6px;font-weight:600"><input type="checkbox" id="nwEnabled"> 企业微信群机器人</label>
          <input id="nwKey" class="input" style="margin-top:6px" placeholder="webhook key（URL 中 key= 后面的值）">
        </div>
      </div>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn primary" onclick="saveNotifyConfig()">保存通知配置</button>
        <button class="btn" onclick="testNotify()">测试全部通道</button>
      </div>
    </div>
    </div>

    <!-- Monitor Page -->
    <div id="monitor-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">监控中心</div>
        <div>
          <button class="btn" onclick="runMonitorNow()">立即巡检</button>
          <button class="btn primary" onclick="loadMonitor()">刷新</button>
        </div>
      </div>
      <div class="small" style="margin:4px 0 12px">数据由 Cron 自动采集（每日 23:55 UTC 快照 / 每 4h 探活+WAF），也可点「立即巡检」手动触发。异常会通过 TG 告警。</div>

      <div class="grid">
        <div class="card">
          <h2 style="margin:0 0 4px">请求用量趋势（近 30 天）</h2>
          <div class="small" id="trendPrediction">加载中...</div>
          <div id="trendChart" style="margin-top:10px"></div>
        </div>
        <div class="card">
          <h2 style="margin:0 0 8px">存储限额监控</h2>
          <div id="storageBox" class="small" style="white-space:pre-wrap;font-family:monospace">加载中...</div>
        </div>
      </div>

      <div class="card" style="margin-top:16px">
        <h2 style="margin:0 0 8px">各账号用量趋势（近 30 天）</h2>
        <div id="accountTrendBox" class="small">加载中...</div>
      </div>

      <div class="grid" style="margin-top:16px">
        <div class="card">
          <h2 style="margin:0 0 8px">账号存活 / 资产变更审计</h2>
          <div id="assetBox" class="small" style="white-space:pre-wrap;font-family:monospace">加载中...</div>
        </div>
        <div class="card">
          <h2 style="margin:0 0 8px">外部探活</h2>
          <div id="probeBox" class="small" style="white-space:pre-wrap;font-family:monospace">加载中...</div>
        </div>
      </div>

      <div class="grid" style="margin-top:16px">
        <div class="card">
          <h2 style="margin:0 0 8px">SSL 证书到期</h2>
          <div id="certBox" class="small" style="white-space:pre-wrap;font-family:monospace">加载中...</div>
        </div>
        <div class="card">
          <h2 style="margin:0 0 8px">WAF 拦截量（24h）</h2>
          <div id="wafBox" class="small" style="white-space:pre-wrap;font-family:monospace">加载中...</div>
        </div>
      </div>

      <div class="card" style="margin-top:16px">
        <h2 style="margin:0 0 8px">操作审计日志</h2>
        <div id="auditBox" class="small" style="white-space:pre-wrap;font-family:monospace;max-height:320px;overflow:auto">加载中...</div>
      </div>
    </div>

    <!-- Bulk Page -->
    <!-- WAF Page（资源 · 需执行账号） -->
    <div id="waf-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">WAF 自定义规则</div>
        <button class="btn primary" onclick="openWafRuleModal()">新建规则</button>
      </div>
      <div class="small" style="margin:4px 0 12px">基于 Ruleset 引擎的 zone 级 custom rules（同 dash → Security → WAF → Custom rules）。需要执行账号有对应 zone 权限。</div>
      <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <select id="wafZoneSel" class="input" style="flex:1;min-width:220px" onchange="loadWafRules()"></select>
        <button class="btn" onclick="loadWafRules()">刷新</button>
      </div>
      <div id="wafBox" class="small" style="white-space:pre-wrap;font-family:monospace">选择域名后加载…</div>
      <div id="wafRuleList"></div>
    </div>

    <!-- Tunnels Page（资源 · 需执行账号） -->
    <div id="tunnels-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">Cloudflare Tunnel 隧道</div>
        <button class="btn primary" onclick="openTunnelModal()">新建隧道</button>
      </div>
      <div class="small" style="margin:4px 0 12px">远程托管隧道（config_src=cloudflare）：创建后复制 token，在任一主机执行 <code>cloudflared service install &lt;token&gt;</code> 即建立连接。</div>
      <div id="tunnelList" class="small" style="font-family:monospace">加载中…</div>
    </div>

    <!-- Redirects Page（资源 · 需执行账号） -->
    <div id="redirects-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">批量重定向 Bulk Redirects</div>
        <div style="display:flex;gap:8px">
          <button class="btn primary" onclick="openRedirectListModal()">新建列表</button>
        </div>
      </div>
      <div class="small" style="margin:4px 0 12px">结构：redirect 列表(存条目) + 「启用列表」规则(account ruleset phase http_request_redirect)。需先建列表→添加重定向→添加启用规则。被重定向的域名须经 Cloudflare 代理。</div>
      <div id="redirectListBox" class="small" style="font-family:monospace">加载中…</div>
      <div style="margin-top:16px">
        <h3 style="margin:0 0 8px">启用列表的规则</h3>
        <div id="redirectRulesBox" class="small" style="font-family:monospace">加载中…</div>
      </div>
    </div>

    <!-- Optimize Page（资源 · Zone 安全/缓存/流量） -->
    <div id="optimize-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">站点优化</div>
        <div style="display:flex;gap:8px;align-items:center">
          <select id="optZoneSel" class="input" style="min-width:220px" onchange="loadOptimizePage()"></select>
        </div>
      </div>
      <div class="card" style="margin-top:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <h3 style="margin:0">安全与性能设置</h3>
          <button class="btn" onclick="zoneHarden()">一键加固（HTTPS + 最低 TLS1.2）</button>
        </div>
        <div id="zoneSettingsBox" class="small" style="margin-top:10px;font-family:monospace">加载中…</div>
      </div>
      <div class="card" style="margin-top:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <h3 style="margin:0">Cache Rules 缓存规则 <span style="font-weight:400;font-size:12px;color:#64748b">免费额度 10 条</span></h3>
          <button class="btn primary" onclick="openCacheRuleModal()">新建规则</button>
        </div>
        <div id="cacheRuleList" class="small" style="margin-top:10px">加载中…</div>
      </div>
      <div class="card" style="margin-top:14px">
        <h3 style="margin:0">24 小时流量 <span style="font-weight:400;font-size:12px;color:#64748b">GraphQL 免费额度</span></h3>
        <div id="zoneAnalyticsBox" class="small" style="margin-top:10px;font-family:monospace">加载中…</div>
      </div>
    </div>

    <!-- Email Routing Page（资源 · 需执行账号） -->
    <div id="email-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">邮箱转发 Email Routing</div>
        <div style="display:flex;gap:8px;align-items:center">
          <select id="emailZoneSel" class="input" style="min-width:220px" onchange="loadEmailPage()"></select>
        </div>
      </div>
      <div class="card" style="margin-top:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <h3 style="margin:0">路由开关</h3>
          <label style="display:flex;align-items:center;gap:8px;color:#475569"><input id="emailRoutingToggle" type="checkbox" onchange="setEmailRouting(this.checked)"> 启用接收</label>
        </div>
        <div class="small" style="margin-top:6px;line-height:1.8" id="emailHintBox"></div>
      </div>
      <div class="card" style="margin-top:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <h3 style="margin:0">转发规则</h3>
          <button class="btn primary" onclick="openEmailRuleModal()">新建规则</button>
        </div>
        <div id="emailRuleList" class="small" style="margin-top:10px">加载中…</div>
      </div>
      <div class="card" style="margin-top:14px">
        <h3 style="margin:0">目标地址（已验证收件邮箱）</h3>
        <div id="emailAddrList" class="small" style="margin-top:10px;font-family:monospace">加载中…</div>
      </div>
    </div>

    <!-- R2 Page（资源 · 桶列表） -->
    <div id="r2-page" class="page-content">
      <div class="header">
        <div style="font-size:20px;font-weight:700">R2 对象存储</div>
        <button class="btn" onclick="loadR2Page()">刷新</button>
      </div>
      <div class="small" style="margin:4px 0 12px;line-height:1.8">桶级管理。桶内对象上传/下载需账号级 R2 API Token（S3 签名，Global Key 无法做对象级操作）——可在 Cloudflare 创建 token 后在此列表基础上自行扩展。</div>
      <div id="r2BucketList" class="small" style="font-family:monospace">加载中…</div>
    </div>

    <div id="bulk-page" class="page-content">
      <div class="header"><div style="font-size:20px;font-weight:700">批量操作</div></div>
      <div class="grid">
        <div class="card">
          <h2 style="margin:0 0 6px">批量部署 Worker（跨账号）</h2>
          <div class="small">选择账号，将同一脚本部署到各账号。部署结果会写入审计日志并可在 TG 收到回报。</div>
          <div id="bulkAccountList" style="margin:10px 0;max-height:180px;overflow:auto;border:1px solid #eef2f6;border-radius:8px;padding:8px"></div>
          <input id="bulkScriptName" class="input" placeholder="Worker 名称（如 api-gateway）" style="margin-bottom:8px">
          <textarea id="bulkScriptSource" class="input" placeholder="Worker 脚本源码（留空则用默认响应）" style="min-height:120px;font-family:monospace"></textarea>
          <div style="margin-top:10px"><button class="btn primary" onclick="deployBulk()">批量部署</button></div>
          <div id="bulkDeployLog" class="small" style="margin-top:10px;white-space:pre-wrap;font-family:monospace"></div>
        </div>
        <div class="card">
          <h2 style="margin:0 0 6px">批量清缓存 / DNS 代理（当前账号）</h2>
          <div class="small">勾选域名后，可批量清除缓存或切换 DNS 代理状态（暂停=false 即开启代理）。</div>
          <div id="bulkZoneList" style="margin:10px 0;max-height:180px;overflow:auto;border:1px solid #eef2f6;border-radius:8px;padding:8px"></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn" onclick="bulkPurge()">批量清缓存</button>
            <button class="btn" onclick="bulkDns(false)">开启代理</button>
            <button class="btn danger" onclick="bulkDns(true)">暂停代理</button>
          </div>
          <div id="bulkDnsLog" class="small" style="margin-top:10px;white-space:pre-wrap;font-family:monospace"></div>
        </div>
      </div>
    </div>

<!-- Modals -->
<div id="dashZoneModal" class="modal"><div class="modal-box" style="max-width:560px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 style="margin:0">Zones 下钻</h3>
    <button class="trash-btn" onclick="closeModal('dashZoneModal')">✕</button>
  </div>
  <div id="dashZoneBox" class="small" style="font-family:monospace;max-height:340px;overflow:auto"></div>
</div></div>

<div id="dnsIOModal" class="modal"><div class="modal-box" style="max-width:720px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 style="margin:0">DNS 导出 / 导入（BIND 格式）</h3>
    <button class="trash-btn" onclick="closeModal('dnsIOModal')">✕</button>
  </div>
  <select id="dnsIoZoneSel" class="input"></select>
  <div style="display:flex;gap:8px;margin:10px 0;flex-wrap:wrap">
    <button class="btn primary" onclick="exportDnsNow()">导出该域名 BIND</button>
    <button class="btn" onclick="downloadExportedDns()">下载 .txt</button>
  </div>
  <textarea id="dnsIoOut" class="input" style="min-height:130px;font-family:monospace" placeholder="导出内容会显示在这里…"></textarea>
  <hr style="margin:12px 0">
  <div class="small" style="margin-bottom:6px">导入（覆盖式追加，冲突记录会跳过）</div>
  <textarea id="dnsIoIn" class="input" style="min-height:110px;font-family:monospace" placeholder="example.com. 300 IN A 1.2.3.4&#10;@ IN MX 10 mail.example.com."></textarea>
  <div style="display:flex;align-items:center;gap:12px;margin-top:8px">
    <label style="display:flex;align-items:center;gap:6px;color:#475569"><input id="dnsIoProxied" type="checkbox"> 代理(橙色云)</label>
    <button class="btn primary" onclick="importDnsNow()">开始导入</button>
    <span id="dnsIoResult" class="small"></span>
  </div>
</div></div>

<div id="cacheRuleModal" class="modal"><div class="modal-box">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 id="cacheRuleModalTitle" style="margin:0">新建缓存规则</h3>
    <button class="trash-btn" onclick="closeModal('cacheRuleModal')">✕</button>
  </div>
  <div class="small" style="margin-bottom:4px">匹配表达式</div>
  <textarea id="crExpr" class="input" style="min-height:56px;font-family:monospace" placeholder='(http.host eq "cdn.example.com")'></textarea>
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:8px">
    <label style="display:flex;align-items:center;gap:6px;color:#475569"><input id="crCache" type="checkbox" checked> 可缓存</label>
    <select id="crTtlMode" class="input" style="width:auto">
      <option value="">沿用来源(不设 TTL)</option>
      <option value="respect_origin">尊重源站 Cache-Control</option>
      <option value="bypass_by_default">默认绕过(不缓存)</option>
      <option value="override_origin">覆盖源站 TTL</option>
      <option value="set_ttl">固定 TTL</option>
    </select>
    <input id="crTtlSec" class="input" type="number" min="0" placeholder="TTL 秒" style="width:110px">
  </div>
  <input id="crDesc" class="input" style="margin-top:8px" placeholder="描述（可选）">
  <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end">
    <button class="btn" onclick="closeModal('cacheRuleModal')">取消</button>
    <button class="btn primary" onclick="saveCacheRule()">保存</button>
  </div>
</div></div>

<div id="emailRuleModal" class="modal"><div class="modal-box">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 id="emailRuleModalTitle" style="margin:0">新建转发规则</h3>
    <button class="trash-btn" onclick="closeModal('emailRuleModal')">✕</button>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <select id="erMatchType" class="input" style="width:auto">
      <option value="literal">指定地址</option>
      <option value="all">Catch-all 全部收件</option>
    </select>
    <input id="erAddress" class="input" style="flex:1;min-width:180px" placeholder="info@你的域名">
    <select id="erAction" class="input" style="width:auto">
      <option value="forward">转发到</option>
      <option value="drop">丢弃</option>
    </select>
    <input id="erTargets" class="input" style="flex:1;min-width:180px" placeholder="目标邮箱（多个用逗号分隔）">
  </div>
  <div class="small" style="margin:6px 0">目标邮箱需先在账号内验证（面板下方列表展示已验证地址）。</div>
  <div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end">
    <button class="btn" onclick="closeModal('emailRuleModal')">取消</button>
    <button class="btn primary" onclick="saveEmailRule()">保存</button>
  </div>
</div></div>

<div id="wafRuleModal" class="modal"><div class="modal-box">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 id="wafRuleModalTitle" style="margin:0">新建 WAF 规则</h3>
    <button class="trash-btn" onclick="closeModal('wafRuleModal')">✕</button>
  </div>
  <div class="small" style="margin-bottom:4px">表达式（目标域名的流量需经 Cloudflare 代理）</div>
  <textarea id="wafExpr" class="input" style="min-height:64px;font-family:monospace" placeholder='(ip.geoip.country eq "CN") and http.request.uri.path contains "/admin"'></textarea>
  <div style="margin:6px 0;display:flex;gap:6px;flex-wrap:wrap">
    <button class="btn small" onclick="wafExprPlus('ip.geoip.country eq ')">国家=</button>
    <button class="btn small" onclick="wafExprPlus('(http.host eq \&quot;example.com\&quot;)')">域名=</button>
    <button class="btn small" onclick="wafExprPlus('http.request.uri.path contains ')">路径含</button>
    <button class="btn small" onclick="wafExprPlus(' and ')">AND</button>
    <button class="btn small" onclick="wafExprPlus(' or ')">OR</button>
    <button class="btn small" onclick="wafExprPlus(' not ')">NOT</button>
  </div>
  <div class="small" style="margin-bottom:6px">动作</div>
  <select id="wafAction" class="input">
    <option value="block">Block 阻止(403)</option>
    <option value="challenge">Challenge 验证码(旧)</option>
    <option value="js_challenge">JS Challenge</option>
    <option value="managed_challenge">Managed Challenge 托管验证</option>
    <option value="log">Log 仅记录</option>
    <option value="allow">Allow 放行</option>
  </select>
  <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
    <input id="wafDesc" class="input" style="flex:2;min-width:200px" placeholder="描述（可选）">
    <label style="display:flex;align-items:center;gap:6px;flex:0 0 auto;color:#475569"><input id="wafEnabled" type="checkbox" checked> 启用</label>
  </div>
  <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end">
    <button class="btn" onclick="closeModal('wafRuleModal')">取消</button>
    <button class="btn primary" onclick="saveWafRule()">保存规则</button>
  </div>
</div></div>

<div id="tunnelModal" class="modal"><div class="modal-box">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 style="margin:0">新建隧道</h3>
    <button class="trash-btn" onclick="closeModal('tunnelModal')">✕</button>
  </div>
  <input id="tunnelName" class="input" placeholder="隧道名称（如 home-nas）">
  <div class="small" style="margin:6px 0">创建为远程托管隧道，随后在列表中点「令牌命令」获取 cloudflared 安装命令。</div>
  <div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end">
    <button class="btn" onclick="closeModal('tunnelModal')">取消</button>
    <button class="btn primary" onclick="createTunnel()">创建</button>
  </div>
</div></div>

<div id="redirectListModal" class="modal"><div class="modal-box">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 style="margin:0">新建重定向列表</h3>
    <button class="trash-btn" onclick="closeModal('redirectListModal')">✕</button>
  </div>
  <input id="rlName" class="input" placeholder="列表名称（如 my_redirect_list）">
  <input id="rlDesc" class="input" style="margin-top:8px" placeholder="描述（可选）">
  <div class="small" style="margin:6px 0">创建后请向列表添加条目（源|目标|状态码），再用「启用列表」规则激活。</div>
  <div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end">
    <button class="btn" onclick="closeModal('redirectListModal')">取消</button>
    <button class="btn primary" onclick="createRedirectList()">创建</button>
  </div>
</div></div>

<div id="redirectItemsModal" class="modal"><div class="modal-box" style="max-width:720px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
    <h3 id="rlItemsTitle" style="margin:0">列表条目</h3>
    <button class="trash-btn" onclick="closeModal('redirectItemsModal')">✕</button>
  </div>
  <div class="small" style="margin-bottom:6px">批量添加，每行一条：<code>源|目标|状态码(可选)</code>，如 <code>example.com/blog/|https://example.com/blog/latest|301</code></div>
  <textarea id="rlItemsInput" class="input" style="min-height:84px;font-family:monospace" placeholder="example.com/blog/|https://example.com/blog/latest&#10;example.net/|https://example.net/new|307"></textarea>
  <div style="margin:6px 0"><button class="btn primary small" onclick="addRedirectItems()">批量添加</button></div>
  <div id="rlItemsList" class="small" style="max-height:300px;overflow:auto"></div>
</div></div>

<div id="redirectEnableModal" class="modal"><div class="modal-box">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 style="margin:0">启用列表（添加重定向规则）</h3>
    <button class="trash-btn" onclick="closeModal('redirectEnableModal')">✕</button>
  </div>
  <select id="reListSel" class="input"></select>
  <div class="small" style="margin:6px 0">规则表达式固定为 <code>http.request.full_uri in $列表名</code>，按 full_uri 精确匹配列表条目源地址。</div>
  <div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end">
    <button class="btn" onclick="closeModal('redirectEnableModal')">取消</button>
    <button class="btn primary" onclick="enableRedirectList()">启用</button>
  </div>
</div></div>

<div id="accountModal" class="modal"><div class="modal-box small">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
     <h3 style="margin:0">切换账号</h3>
     <button class="trash-btn" onclick="closeAccountSwitcher()">✕</button>
  </div>
  <div style="margin-bottom:12px"><button class="btn small" onclick="restoreFromKV()">从 KV 恢复账号</button></div>
  <div id="accountListContainer"></div>
</div></div>

<div id="confirmModal" class="modal" style="display:none"><div class="modal-box confirm-box">
  <h3 id="confirmTitle" style="margin:0 0 10px">请确认</h3>
  <div id="confirmMsg" class="small" style="margin:0 0 20px;white-space:pre-wrap"></div>
  <div style="display:flex;gap:8px;justify-content:flex-end">
    <button class="btn" id="confirmCancel">取消</button>
    <button class="btn danger" id="confirmOk">确定</button>
  </div>
</div></div>

<div id="envModal" class="modal" style="display:none"><div class="modal-box">
  <h3>管理环境变量</h3>
  <div class="label">为 Worker 配置环境变量（文本 / 密钥 / JSON）</div>
  <div id="envRows" style="margin-top:8px"></div>
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="addEnvRow()">添加变量</button>
    <button class="btn" onclick="saveEnv()">保存</button>
    <button class="btn" onclick="closeEnvModal()">取消</button>
  </div>
</div></div>

<div id="bindModal" class="modal" style="display:none"><div class="modal-box">
  <h3>绑定 KV / D1</h3>
  <div class="label">选择要绑定的资源（下拉自动拉取）</div>
  <div style="display:flex;gap:8px;margin-top:8px">
    <select id="bindType" class="input" onchange="refreshBindList()"><option value="kv">KV 命名空间</option><option value="d1">D1 数据库</option></select>
  </div>
  <div style="margin-top:8px"><select id="bindSelect" class="input"></select></div>
  <div style="margin-top:8px"><input id="bindName" class="input" placeholder="绑定名，例如 MY_KV"></div>
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="confirmBind()">确认绑定</button>
    <button class="btn" onclick="closeBindModal()">取消</button>
  </div>
</div></div>

<div id="createModal" class="modal fullscreen-overlay" style="display:none"><div class="modal-box fullscreen">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-shrink:0">
    <h3 style="margin:0">新建 / 编辑 Worker</h3>
    <button class="btn" style="background:#e5e7eb;color:#111" onclick="closeCreate()">&#10005; 关闭</button>
  </div>
  <div style="flex-shrink:0"><div class="label">Worker 名称</div><input id="createName" class="input" placeholder="worker-name"></div>
  <div class="label" style="margin-top:8px;flex-shrink:0">脚本 (.js)</div>
  <textarea id="createScript" class="input" style="font-family:monospace;font-size:13px;white-space:pre;overflow:auto">export default {
  async fetch(request, env, ctx) {
    return new Response('Hello World');
  }
};</textarea>
  <div style="display:flex;gap:8px;margin-top:12px;flex-shrink:0">
    <button class="btn primary" onclick="confirmCreate()">保存并部署</button>
    <button class="btn" onclick="closeCreate()">取消</button>
  </div>
</div></div>

<div id="createKVModal" class="modal" style="display:none"><div class="modal-box small">
  <h3>创建 KV 命名空间</h3>
  <div class="label">输入命名空间名称</div>
  <input id="kvNamespaceName" class="input" placeholder="my-kv-namespace">
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="confirmCreateKVNamespace()">创建</button>
    <button class="btn" onclick="closeCreateKVModal()">取消</button>
  </div>
</div></div>

<div id="kvValueModal" class="modal" style="display:none"><div class="modal-box">
  <h3>添加/更新键值</h3>
  <div class="label">Key</div>
  <input id="kvKey" class="input" placeholder="例如：user123">
  <div class="label" style="margin-top:8px">Value</div>
  <textarea id="kvValue" class="input" rows="6" placeholder='例如：{"name": "John", "age": 30}'></textarea>
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="confirmKVPut()">保存</button>
    <button class="btn" onclick="closeKVValueModal()">取消</button>
  </div>
</div></div>

<div id="createD1Modal" class="modal" style="display:none"><div class="modal-box small">
  <h3>创建 D1 数据库</h3>
  <div class="label">输入数据库名称</div>
  <input id="d1DatabaseName" class="input" placeholder="my-d1-database">
  <div class="label" style="margin-top:12px">选择区域 (位置)</div>
  <select id="d1Location" class="input">
    <option value="auto">自动 (默认)</option>
    <option value="wnam">北美西部</option>
    <option value="enam">北美东部</option>
    <option value="weur">西欧</option>
    <option value="eeur">东欧</option>
    <option value="apac">亚太地区</option>
    <option value="oc">大洋洲</option>
  </select>
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="confirmCreateD1Database()">创建</button>
    <button class="btn" onclick="closeCreateD1Modal()">取消</button>
  </div>
</div></div>

<div id="addDomainModal" class="modal" style="display:none"><div class="modal-box small">
  <h3>绑定自定义域名</h3>
  <div class="label">输入要绑定的完整域名 (例如: app.example.com)</div>
  <input id="newDomainInput" class="input" placeholder="app.example.com">
  <div class="small" style="margin-top:4px">请确保该域名已接入您的 Cloudflare 账号。</div>
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="confirmAddDomain()">绑定</button>
    <button class="btn" onclick="closeAddDomainModal()">取消</button>
  </div>
</div></div>

<div id="addZoneModal" class="modal" style="display:none"><div class="modal-box small">
  <h3>添加新域名</h3>
  <div class="label">输入您想要接入 Cloudflare 的域名</div>
  <input id="zoneName" class="input" placeholder="example.com">
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="confirmAddZone()">添加</button>
    <button class="btn" onclick="closeAddZoneModal()">取消</button>
  </div>
</div></div>

<div id="addDNSRecordModal" class="modal" style="display:none"><div class="modal-box">
  <h3 id="dnsRecordModalTitle">添加 DNS 记录</h3>
  <div class="label">记录类型</div>
  <select id="dnsRecordType" class="input">
    <option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option><option value="MX">MX</option><option value="TXT">TXT</option><option value="NS">NS</option>
  </select>
  <div class="label" style="margin-top:8px">记录名称</div>
  <input id="dnsRecordName" class="input" placeholder="例如：www 或 @">
  <div class="label" style="margin-top:8px">记录内容</div>
  <input id="dnsRecordContent" class="input" placeholder="例如：192.0.2.1">
  <div class="label" style="margin-top:8px">TTL (秒)</div>
  <select id="dnsRecordTTL" class="input">
    <option value="1">自动</option><option value="120">2分钟</option><option value="300">5分钟</option><option value="3600">1小时</option><option value="86400">1天</option>
  </select>
  <div style="margin-top:8px"><label><input type="checkbox" id="dnsRecordProxied"> 启用代理（橙色云）</label></div>
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" id="dnsRecordSubmitBtn" onclick="confirmAddDNSRecord()">添加记录</button>
    <button class="btn" onclick="closeAddDNSRecordModal()">取消</button>
  </div>
</div></div>

<div id="editDNSRecordModal" class="modal" style="display:none"><div class="modal-box">
  <h3>编辑 DNS 记录</h3>
  <div class="label">记录类型</div>
  <select id="editDnsRecordType" class="input">
    <option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option><option value="MX">MX</option><option value="TXT">TXT</option><option value="NS">NS</option>
  </select>
  <div class="label" style="margin-top:8px">记录名称</div>
  <input id="editDnsRecordName" class="input">
  <div class="label" style="margin-top:8px">记录内容</div>
  <input id="editDnsRecordContent" class="input">
  <div class="label" style="margin-top:88px">TTL (秒)</div>
  <select id="editDnsRecordTTL" class="input">
    <option value="1">自动</option><option value="120">2分钟</option><option value="300">5分钟</option><option value="3600">1小时</option><option value="86400">1天</option>
  </select>
  <div style="margin-top:8px"><label><input type="checkbox" id="editDnsRecordProxied"> 启用代理（橙色云）</label></div>
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="confirmEditDNSRecord()">保存修改</button>
    <button class="btn" onclick="closeEditDNSRecordModal()">取消</button>
  </div>
</div></div>


<!-- Snippet Modals -->
<div id="createSnippetModal" class="modal fullscreen-overlay" style="display:none"><div class="modal-box fullscreen">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-shrink:0">
    <h3 style="margin:0">创建 / 编辑 Snippet</h3>
    <button class="btn" style="background:#e5e7eb;color:#111" onclick="closeCreateSnippet()">&#10005; 关闭</button>
  </div>
  <div style="flex-shrink:0"><div class="label">Snippet 名称 (仅支持字母、数字、下划线、连字符)</div><input id="snippetName" class="input" placeholder="my-snippet"></div>
  <div class="label" style="margin-top:8px;flex-shrink:0">JavaScript 代码 (ES Module 格式)</div>
  <textarea id="snippetCode" class="input" style="font-family:monospace;font-size:13px;white-space:pre;overflow:auto;min-height:50vh">export default { async fetch(request, env, ctx) { return new Response('Hello from Snippet!'); } };</textarea>
  <div style="display:flex;gap:8px;margin-top:12px;flex-shrink:0">
    <button class="btn primary" onclick="confirmDeploySnippet()">保存并部署</button>
    <button class="btn" onclick="closeCreateSnippet()">取消</button>
  </div>
</div></div>

<div id="addSnippetRuleModal" class="modal" style="display:none"><div class="modal-box">
  <h3>添加 Snippet 路由规则</h3>
  <div class="label">选择 Snippet</div>
  <select id="ruleSnippetSelect" class="input"></select>
  
  <div class="label" style="margin-top:12px">如果传入请求匹配：</div>
  <div id="ruleConditionsContainer" style="display:flex;flex-direction:column;gap:8px;background:#f8fafc;padding:12px;border-radius:8px;border:1px solid #e2e8f0"></div>
  <button class="btn small" style="margin-top:8px" onclick="addRuleCondition()">+ 添加条件</button>
  
  <div class="label" style="margin-top:12px">生成的表达式预览</div>
  <input id="ruleExpression" class="input" readonly style="background:#f1f5f9;font-family:monospace;font-weight:600">
  <div class="small" style="margin-top:4px">系统会自动解析表达式中的「主机名」，若该主机名在 DNS 中无记录，将自动创建指向 100:: 的代理记录。</div>
  
  <div class="label" style="margin-top:8px">描述 (可选)</div>
  <input id="ruleDescription" class="input" placeholder="规则描述">
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn primary" onclick="confirmAddSnippetRule()">添加规则</button>
    <button class="btn" onclick="closeAddSnippetRuleModal()">取消</button>
  </div>
</div></div>

<div id="outModal" class="modal" style="display:none"><div class="modal-box">
  <h3>调试输出</h3>
  <pre id="debugOut" style="height:300px;overflow:auto"></pre>
  <div style="display:flex;justify-content:flex-end;margin-top:8px"><button class="btn" onclick="closeOut()">关闭</button></div>
</div></div>

<script async src="https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js"></script><script async src="https://cdn.jsdelivr.net/npm/spark-md5@3.0.2/spark-md5.min.js"></script><script src="/static.js"></script>
</body>
</html>`;
}

// ---------------- Static JS ----------------
function renderStaticJS(env) {
  let safeUrls = "[]";
  let safeNames = "[]";

  try {
      if (env && typeof env === 'object') {
          if (env.BATCH_URLS) safeUrls = typeof env.BATCH_URLS === 'string' ? env.BATCH_URLS : JSON.stringify(env.BATCH_URLS);
          if (env.BATCH_NAMES) safeNames = typeof env.BATCH_NAMES === 'string' ? env.BATCH_NAMES : JSON.stringify(env.BATCH_NAMES);
      } else {
          if (typeof BATCH_URLS !== 'undefined') safeUrls = typeof BATCH_URLS === 'string' ? BATCH_URLS : JSON.stringify(BATCH_URLS);
          if (typeof BATCH_NAMES !== 'undefined') safeNames = typeof BATCH_NAMES === 'string' ? BATCH_NAMES : JSON.stringify(BATCH_NAMES);
      }
  } catch(e) {}

  if (!safeUrls.trim().startsWith('[')) safeUrls = "[]";
  if (!safeNames.trim().startsWith('[')) safeNames = "[]";

  return `(function(){
  function el(id){ return document.getElementById(id); }
  function safeParse(s){ try { return JSON.parse(s); } catch(e){ return null; } }
  function getActiveCreds(){
    const oaId = localStorage.getItem('cf_active_oauth');
    if (oaId) {
      const arr = loadSaved();
      const a = arr.find(x => x && x.oauth && x.oauthId === oaId);
      if (a) return { email: a.email || a.name || oaId, key: '', oauthId: oaId, name: a.name || a.email || oaId };
    }
    return { email: localStorage.getItem('cf_active_email')||'', key: localStorage.getItem('cf_active_key')||'' };
  }
  (async function(){ if(document.body.dataset.page==='login' && getActiveCreds().email){ try{ const r=await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'check-features'})}); if(r.ok) location.replace('/workers'); }catch(e){} } })();
  
  function loadSaved(){ try { return JSON.parse(localStorage.getItem('cf_accounts')||'[]'); } catch(e){ return []; } }
  function saveAccounts(arr){ localStorage.setItem('cf_accounts', JSON.stringify(arr)); fetch('/api', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'save-accounts-kv', accounts: arr }) }).catch(()=>{}); }

  const BATCH_CONFIG = {
    urls: ${safeUrls},
    names: ${safeNames}
  };

  const DEFAULT_WORKER_SCRIPT = "export default {\\n  async fetch(request, env, ctx) {\\n    return new Response('Hello World');\\n  }\\n};";

  function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.innerHTML = message;
    notification.style.cssText = \`
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 20px;
      border-radius: 8px;
      color: white;
      background: \${type === 'success' ? '#10b981' : '#ef4444'};
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 10000;
      max-width: 400px;
      animation: slideIn 0.3s ease-out;
    \`;
    document.body.appendChild(notification);
    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease-in';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
    
    if (!document.querySelector('#notification-styles')) {
      const style = document.createElement('style');
      style.id = 'notification-styles';
      style.textContent = \`
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(100%); opacity: 0; }
        }
      \`;
      document.head.appendChild(style);
    }
  }

  function copyToClipboard(text, event) {
    if (event) event.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
      showNotification('已复制到剪贴板');
    }).catch(err => {
      console.error('复制失败:', err);
      showNotification('复制失败', 'error');
    });
  }

  let _busy = 0;
  function updateBusy(){ const b = el('globalBusy'); if (b) b.style.display = _busy > 0 ? 'inline-block' : 'none'; }
  function stampRefresh(){ const s = el('lastUpdated'); if (s) s.textContent = '最后更新 ' + new Date().toLocaleTimeString('zh-CN', { hour12:false }); }
  let _zonesCache = null, _zonesCacheT = 0, _zonesCacheEmail = '', _zonesCacheOa = '';
  async function api(action, body) {
    const c = getActiveCreds();
    // 会话内 zone 列表缓存 60s：WAF/优化/邮箱等页面频繁 list-zones，省一次后端往返与 REST 配额
    if (action === 'list-zones' && !(body && body.forceRefresh) && _zonesCache && Date.now() - _zonesCacheT < 60000 && c.email === _zonesCacheEmail && (c.oauthId || '') === _zonesCacheOa) {
      return { success: true, result: _zonesCache };
    }
    _busy++; updateBusy();
    try {
      const payload = Object.assign({ action }, c, body);
      const r = await fetch('/api', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
      let j = null; try { j = await r.json(); } catch (e) {}
      if (j) { stampRefresh(); if (action === 'list-zones' && j.success && Array.isArray(j.result)) { _zonesCache = j.result; _zonesCacheT = Date.now(); _zonesCacheEmail = c.email; _zonesCacheOa = c.oauthId || ''; } return j; }
      const txt = await r.text(); stampRefresh(); return txt;
    } finally { _busy--; updateBusy(); }
  }

  function ensureConfirmModal(){
    let box = el('confirmModal');
    if (box) return box;
    box = document.createElement('div');
    box.id = 'confirmModal'; box.className = 'modal'; box.style.display = 'none';
    box.innerHTML = '<div class="modal-box confirm-box">' +
      '<h3 id="confirmTitle" style="margin:0 0 10px">请确认</h3>' +
      '<div id="confirmMsg" class="small" style="margin:0 0 20px;white-space:pre-wrap"></div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end">' +
      '<button class="btn" id="confirmCancel">取消</button>' +
      '<button class="btn danger" id="confirmOk">确定</button></div></div>';
    document.body.appendChild(box);
    return box;
  }
  function confirmDialog(msg, onYes, title){
    const box = ensureConfirmModal();
    el('confirmMsg').textContent = msg;
    el('confirmTitle').textContent = title || '请确认';
    box.style.display = 'flex';
    const ok = el('confirmOk'), cancel = el('confirmCancel');
    const done = (yes) => { box.style.display = 'none'; ok.onclick = null; cancel.onclick = null; if (yes) onYes(); };
    ok.onclick = () => done(true);
    cancel.onclick = () => done(false);
  }
  window.confirmDialog = confirmDialog;

  const page = document.body && document.body.dataset && document.body.dataset.page;
  
  if (page === 'login') {
    function renderSaved(){
      const cont = el('savedAccounts'); const arr = loadSaved();
      cont.innerHTML = '';
      if (!arr.length) { cont.textContent = '未找到已保存账号'; return; }
      arr.forEach((a, idx) => {
        const d = document.createElement('div');
        d.className = 'account-row';
        if (a && a.oauth) {
          d.innerHTML = '<div><div style="font-weight:600">' + (a.name || a.email || 'OAuth 连接') + ' <span class="badge">OAuth</span></div><div class="small">' + (a.scope || 'OAuth 授权连接') + '</div></div><div><button class="btn" data-oauth="1">授权管理</button></div>';
        } else {
          d.innerHTML = '<div><div style="font-weight:600">' + a.email + '</div><div class="small">添加于 ' + (a.added || '') + '</div></div><div><button class="btn" data-idx="' + idx + '">快速登录</button></div>';
        }
        cont.appendChild(d);
      });
      Array.from(cont.querySelectorAll('button')).forEach(btn => {
        if (btn.dataset.oauth) { btn.addEventListener('click', function(){ location.replace('/settings'); }); return; }
        btn.addEventListener('click', function(){ const idx = +this.dataset.idx; const arr = loadSaved(); if (!arr[idx]) return alert('账号不存在'); localStorage.setItem('cf_active_email', arr[idx].email); localStorage.setItem('cf_active_key', arr[idx].key); localStorage.removeItem('cf_active_oauth'); location.replace('/workers'); });
      });
    }

    document.getElementById('verifyBtn').addEventListener('click', async function(){
      const email = el('newEmail').value.trim(); 
      const key = el('newKey').value.trim();
      if (!email || !key) return alert('请输入邮箱和 API Key');
      
      const r = await fetch('/api', { 
        method:'POST', 
        headers:{'Content-Type':'application/json'}, 
        body: JSON.stringify({ action:'validate-credentials', email, key }) 
      });
      let res;
      try { res = await r.json(); } catch(e) { res = await r.text(); }
      
      if (res && (res.result || (res.success===true))) {
        const arr = loadSaved();
        const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }).replace(/\\//g, '-');
        const existIdx = arr.findIndex(x => x.email === email);
        if (existIdx !== -1) arr.splice(existIdx, 1);
        arr.unshift({ email, key, added: now });
        saveAccounts(arr);
        localStorage.setItem('cf_active_email', email);
        localStorage.setItem('cf_active_key', key);
        location.replace('/workers');
      } else {
        alert('验证失败：' + (res && (res.errors||res.message||res.error) || 'unknown'));
      }
    });

    document.getElementById('openBatchModalBtn').addEventListener('click', function(){ el('batchLoginModal').style.display='flex'; });
    document.getElementById('confirmBatchLogin').addEventListener('click', function(){
       const raw = el('batchLoginInput').value;
       if (!raw.trim()) return alert('请输入内容');
       const lines = raw.split('\\n');
       const newAccs = [];
       const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }).replace(/\\//g, '-');
       lines.forEach(line => {
           const parts = line.split('|');
           if (parts.length >= 2) {
               const email = parts[0].trim(); const key = parts[1].trim();
               if (email && key) newAccs.push({ email, key, added: now });
           }
       });
       if (newAccs.length > 0) {
           const current = loadSaved();
           newAccs.forEach(acc => {
               const idx = current.findIndex(c => c.email === acc.email);
               if (idx !== -1) current[idx] = acc; else current.unshift(acc);
           });
           saveAccounts(current); renderSaved(); el('batchLoginModal').style.display='none'; el('batchLoginInput').value = ''; showNotification(\`已导入 \${newAccs.length} 个账号\`);
       } else { alert('未解析到有效账号，请检查格式'); }
    });
    document.getElementById('clearBtn').addEventListener('click', function(){ confirmDialog('确定清除所有保存的账号？KV 中也会一并清空，不可恢复。', () => { saveAccounts([]); renderSaved(); }); });

    // ===== 密码保护 + KV 账号同步 =====
    // saveAccounts 已提到外层公共区（同时写 localStorage 与 KV）


    window.submitPw = async function() {
      const pw = document.getElementById('pwInput').value;
      document.getElementById('pwError').textContent = '';
      try {
        const r = await fetch('/auth', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: pw }) });
        const res = await r.json();
        if (res.success) {
          // 两级结构：密码鉴权即进入主工作台，无需先登录任何 CF 账户
          location.replace('/workers');
        } else {
          document.getElementById('pwError').textContent = res.error || '密码错误，请重试';
          document.getElementById('pwInput').value = '';
          document.getElementById('pwInput').focus();
        }
      } catch(e) { document.getElementById('pwError').textContent = '网络错误，请刷新重试'; }
    }

    async function initLogin() {
      try {
        const r = await fetch('/api', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'check-features' }) });
        if (r.status === 401) {
          const ov = document.getElementById('pwOverlay');
          if (ov) { ov.style.display = 'flex'; setTimeout(() => document.getElementById('pwInput').focus(), 100); }
          return;
        }
        // 会话有效（或未设密码）：直接进入主工作台
        location.replace('/workers');
        return;
      } catch(e) {}
      location.replace('/workers');
    }
    // ===== end =====

    initLogin();
    return;
  }

  if (page === 'app') {
    function escapeHtml(s){ return s ? s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;') : ''; }
    function debugOut(v){ el('debugOut').textContent = typeof v === 'string' ? v : JSON.stringify(v,null,2); el('outModal').style.display='flex'; }

    (function initBatchDropdown() {
        if (!el('batchBuiltinSelect')) return;
        const sel = el('batchBuiltinSelect');
        sel.innerHTML = '';
        if (BATCH_CONFIG.names && BATCH_CONFIG.names.length > 0) {
            BATCH_CONFIG.names.forEach((name, idx) => {
                const opt = document.createElement('option'); opt.value = idx; opt.textContent = name; sel.appendChild(opt);
            });
        } else { sel.innerHTML = '<option value="">未在环境变量配置 BATCH_NAMES</option>'; }
    })();

    function acctLabel(a){ return (a && a.oauth) ? (a.name || a.email || a.oauthId) : (a && a.email) ? a.email : '未命名'; }
    function isActiveAccount(a, cur){ return (a && a.oauth) ? cur.oauthId === a.oauthId : cur.email === a.email; }
    function openAccountSwitcher() {
      const arr = loadSaved(); const current = getActiveCreds(); const cont = el('accountListContainer'); cont.innerHTML = '';
      if (arr.length === 0) {
        cont.innerHTML = '<div style="padding:16px;text-align:center;color:#64748b">暂无账号</div>' +
          '<div style="text-align:center;padding:0 16px 14px"><button class="btn small" onclick="goAccounts()">去账号库添加</button></div>';
      } else {
        arr.forEach((acc, idx) => {
          const isActive = isActiveAccount(acc, current); const div = document.createElement('div'); div.className = 'acct-row ' + (isActive ? 'acct-active' : '');
          div.innerHTML = \`<div style="flex:1;cursor:pointer" onclick="switchAccount(\${idx})"><div style="font-weight:600;display:flex;align-items:center">\${escapeHtml(acctLabel(acc))}\${isActive ? '<span class="badge">当前</span>' : ''}\${acc && acc.oauth ? '<span class="badge" style="background:#eef2ff;color:#3730a3">OAuth</span>' : ''}</div><div class="small" style="margin-bottom:0">\${acc && acc.oauth ? (acc.scope || 'OAuth 连接') : (acc.added || '')}</div></div>\${!isActive ? \`<button class="trash-btn" onclick="removeAccount(\${idx})" title="移除账号">✕</button>\` : ''}\`; cont.appendChild(div);
        });
      }
      el('accountModal').style.display = 'flex';
    }
    function switchAccount(idx) {
      const arr = loadSaved(); if (!arr[idx]) return;
      const acc = arr[idx];
      if (acc && acc.oauth) { localStorage.setItem('cf_active_oauth', acc.oauthId); localStorage.removeItem('cf_active_email'); localStorage.removeItem('cf_active_key'); }
      else { localStorage.setItem('cf_active_email', acc.email); localStorage.setItem('cf_active_key', acc.key); localStorage.removeItem('cf_active_oauth'); }
      localStorage.removeItem('cf_accountId');
      const fkey = dashFollowKey(acc); if (fkey) localStorage.setItem('dash_scope', fkey);
      showNotification('正在切换账号...'); setTimeout(() => location.reload(), 500);
    }
    function removeAccount(idx) {
      const arr0 = loadSaved(); const target = arr0[idx];
      const tip = (target && target.oauth) ? '确定断开该 OAuth 连接？本面板将删除其访问令牌。如需在 Cloudflare 侧彻底撤销授权，请到 dash → My Profile → 授权应用 操作。' : '确定移除该账号？KV 中同名账号也会一并移除。';
      confirmDialog(tip, () => { const arr = loadSaved(); const rm = arr[idx]; arr.splice(idx, 1); saveAccounts(arr); if (rm && rm.oauth && getActiveCreds().oauthId === rm.oauthId) localStorage.removeItem('cf_active_oauth'); const ap = el('accounts-page'); if (ap && ap.classList.contains('active')) { renderAccounts(); } else openAccountSwitcher(); });
    }
    function closeAccountSwitcher() { el('accountModal').style.display = 'none'; }
    function goAccounts(){ closeAccountSwitcher(); navTo('accounts'); }

    // 两级结构：资源页需要"执行账号"，未选择时先引导（不再影响全局页）
    const RESOURCE_PAGES = ['workers','pages-manager','snippets','kv','d1','dns','waf','tunnels','redirects','optimize','email','r2','batch','pages','bulk'];
    function ensureAccount(){
      const a = getActiveCreds();
      if (a.oauthId || (a.email && a.key)) return true;
      showNotification('该页面需要执行账号：请先选择或添加一个 CF 账号（Global Key 或 OAuth）', 'error');
      openAccountSwitcher();
      return false;
    }
    function navTo(page) {
      // 资源页需执行账号：未选择时先引导，不切换页面（全局页不受影响）
      if (RESOURCE_PAGES.indexOf(page) !== -1 && !ensureAccount()) return;
      document.querySelectorAll('.nav .item').forEach(i => i.classList.remove('active'));
      document.querySelectorAll('.page-content').forEach(p => p.classList.remove('active'));
      const activeNav = Array.from(document.querySelectorAll('.nav .item')).find(i => i.dataset.page === page);
      const activePage = el(page + '-page');
      if (activeNav) activeNav.classList.add('active'); if (activePage) activePage.classList.add('active');
      const sb = document.querySelector('.sidebar'); if (sb) sb.classList.remove('open');
      switch(page) {
        case 'overview': renderOverview(); break;
        case 'accounts': renderAccounts(); break;
        case 'workers': refreshWorkers(); break;
        case 'batch': renderBatchPage(); break; case 'pages': renderPagesBatchPage(); break; case 'pages-manager': refreshPagesManager(); break;
        case 'kv': refreshKVNamespaces(); break;
        case 'd1': refreshD1Databases(); break;
        case 'dns': showZonesList(); break; case 'snippets': showSnippetsZonesList(); break;
        case 'waf': loadWafPage(); break; case 'tunnels': loadTunnelsPage(); break; case 'redirects': loadRedirectsPage(); break;
        case 'optimize': loadOptimizePage(); break; case 'email': loadEmailPage(); break; case 'r2': loadR2Page(); break;
        case 'monitor': loadMonitor(); break; case 'bulk': renderBulkAccounts(); renderBulkZones(); break;
        case 'settings': loadSettingsAll(); break;
      }
    }

    // ===== 总览 / 账号库（全局能力）=====
    function accountStatusText(a){
      if (!a || !a.status || a.status === 'ok') return { t:'有效', c:'#0f6e56' };
      if (a.status === 'abnormal') return { t:'异常/封号', c:'#a32d2d' };
      return { t:'接口错误', c:'#854F0B' };
    }
    async function kvMergeAccounts(){
      try {
        const r = await api('load-accounts-kv', {});
        if (r && r.success && Array.isArray(r.accounts)) {
          const cur = loadSaved(); const m = r.accounts.slice();
          cur.forEach(a => {
            if (!a) return;
            const i = (a.oauth ? m.findIndex(x => x && x.oauth && x.oauthId === a.oauthId) : m.findIndex(x => x && !x.oauth && x.email === a.email));
            if (i > -1) { if (a.group && !m[i].group) m[i].group = a.group; } else m.push(a);
          });
          localStorage.setItem('cf_accounts', JSON.stringify(m));
          return m;
        }
      } catch(e){}
      return loadSaved();
    }
    // ===== 总览仪表板（全部账号/单账号隔离）=====
    let dashCache = null;
    function fmtNum(v){
      v = v || 0;
      if (v >= 1e9) return (v / 1e9).toFixed(2) + 'B';
      if (v >= 1e6) return (v / 1e6).toFixed(2) + 'M';
      if (v >= 1e3) return (v / 1e3).toFixed(1) + 'k';
      return String(v);
    }
    // 总览作用域：手动选择持久化 + 切执行账号跟随
    function dashScopeChanged(){
      const v = el('dashScope').value;
      if (v) localStorage.setItem('dash_scope', v); else localStorage.removeItem('dash_scope');
      renderDash();
    }
    function trendDays(){
      const s = el('dashTrendDays'); if (!s) return 14;
      if (!s.dataset.done) { s.dataset.done = '1'; const saved = localStorage.getItem('dash_trend_days'); if (saved && ['7','14','30','90'].indexOf(saved) !== -1) s.value = saved; else s.value = '14'; }
      return parseInt(s.value, 10) || 14;
    }
    function trendDaysChanged(){
      const s = el('dashTrendDays'); if (s) localStorage.setItem('dash_trend_days', s.value);
      renderDash();
    }
    function dashFollowKey(acc){ return (acc && (acc.email || acc.name || acc.oauthId)) || ''; }
    function dashApplyScope(key){
      const sel = el('dashScope');
      if (!sel) return;
      const ok = key && Array.from(sel.options).some(o => o.value === key);
      if (ok) { sel.value = key; localStorage.setItem('dash_scope', key); }
      else { sel.value = ''; localStorage.removeItem('dash_scope'); }
      if (dashCache) renderDash();
    }
    function dashScopeLabel(){
      const v = el('dashScope').value;
      if (!v) return '全部账号';
      const opt = el('dashScope').selectedOptions[0];
      return opt ? opt.textContent : v;
    }
    function dashPick(data){
      const v = el('dashScope').value;
      if (!v) return Object.keys(data || {}).map(k => data[k]);
      const rec = (data || {})[v];
      return rec ? [rec] : [];
    }
    function barHtml(pts, w){
      const max = Math.max.apply(null, pts.map(p => p.v)) || 1;
      return '<div style="display:flex;align-items:flex-end;gap:3px;height:86px">' + pts.map(p =>
        '<div style="flex:1;min-width:0;background:#93c5fd;border-radius:2px 2px 0 0;height:' + Math.max(2, Math.round((p.v / max) * 80)) + 'px" title="' + escAttr(p.l + '  ' + fmtNum(p.v)) + '"></div>').join('') +
        '</div><div style="display:flex;justify-content:space-between;color:#94a3b8;font-size:10px;margin-top:2px"><span>' + escAttr((pts[0] && pts[0].l) || '') + '</span><span>' + escAttr((pts[pts.length - 1] && pts[pts.length - 1].l) || '') + '</span></div>';
    }
    function dashUsagePct(usage){
      const dates = Object.keys(usage || {}).sort();
      if (!dates.length) return null;
      const day = usage[dates[dates.length - 1]] || [];
      const v = el('dashScope').value;
      const rows = v ? day.filter(r => r.email === v) : day;
      return { total: rows.reduce((t, r) => t + (r.total || 0), 0), rows, label: dates[dates.length - 1] };
    }
    async function renderOverview(){
      const arr = await kvMergeAccounts();
      const sel = el('dashScope');
      if (sel && sel.options.length === 0) {
        sel.innerHTML = '<option value="">全部账号</option>' + arr.map(a => '<option value="' + escAttr(a.email || a.name || a.oauthId) + '">' + escAttr(a.oauth ? (a.name || a.oauthId) : a.email) + '</option>').join('');
        const saved = localStorage.getItem('dash_scope') || '';
        if (saved && Array.from(sel.options).some(o => o.value === saved)) sel.value = saved;
      }
      if (!dashCache) {
        const r = await api('get-dashboard', {});
        dashCache = (r && r.success) ? r.dash : null;
      }
      renderDash();
    }
    async function collectAnalyticsNow(){
      const btn = el('dashCollectBtn');
      if (btn) { btn.disabled = true; btn.textContent = '采集中…'; }
      try {
        const r = await api('collect-analytics-now', {});
        if (!r || !r.success) { showNotification((r && r.error) || '采集失败', 'error'); return; }
        dashCache = null;
        const d = await api('get-dashboard', {});
        dashCache = (d && d.success) ? d.dash : null;
        showNotification('采集完成：成功 ' + r.ok + ' 个账号' + (r.fail ? '，失败 ' + r.fail + ' 个' : ''));
        renderDash();
      } finally { if (btn) { btn.disabled = false; btn.textContent = '立即采集'; } }
    }
    async function backfillUsageHistory(){
      confirmDialog('将按天向官方查询最近 30 天配额用量（每账号每天 1 次 GraphQL；免费单次窗口≤1 天，故逐日回填），结果入官方配额历史供趋势图直读。继续？', async () => {
        const btn = el('dashCollectBtn');
        const r = await api('backfill-usage-history', { days: 30 });
        if (r && r.success) {
          dashCache = null;
          const d = await api('get-dashboard', {});
          dashCache = (d && d.success) ? d.dash : null;
          showNotification('回填完成：成功 ' + r.ok + ' 个账号' + (r.fail ? '，失败 ' + r.fail : '') + '，覆盖 ' + r.days + ' 天');
          renderDash();
        } else showNotification((r && r.error) || '回填失败', 'error');
      });
    }
    function renderDash(){
      const d = dashCache;
      const t = (id, txt) => { const e = el(id); if (e) e.textContent = txt; };
      if (!d || !d.snap || !d.snap.data) {
        t('dashReq', '-'); t('dashBytes', '-'); t('dashUniq', '-'); t('dashCache', '-'); t('dashThreats', '-'); t('dashQuota', '-'); t('dashBad', '-'); t('dashTs', '未采集');
        el('dashTrend').innerHTML = '<span style="color:#94a3b8">暂无数据 —— 点击右上「立即采集」</span>';
        el('dashShare').innerHTML = ''; el('dashShareTitle').textContent = '各账号请求占比';
        el('dashDaily').innerHTML = '<span style="color:#94a3b8">-</span>';
        el('dashQuotaChart').innerHTML = '<span style="color:#94a3b8">-</span>';
        el('dashTable').innerHTML = '';
        return;
      }
      const data = d.snap.data;
      const recs = dashPick(data);
      const req = recs.reduce((s, r) => s + (r.req || 0), 0);
      const bytes = recs.reduce((s, r) => s + (r.bytes || 0), 0);
      const uniq = recs.reduce((s, r) => s + (r.uniq || 0), 0);
      t('dashReq', fmtNum(req)); t('dashBytes', fmtBytes(bytes)); t('dashUniq', fmtNum(uniq));
      // 缓存命中率 / 威胁拦截：官方按日(httpRequests1dGroups 的 cachedRequests/threats)最近一天，按作用域聚合
      const odMap = (d.officialDaily && Object.keys(d.officialDaily).length) ? d.officialDaily : null;
      if (odMap) {
        const lastD = Object.keys(odMap).sort().pop();
        const rows = Object.values(odMap[lastD] || {});
        const selV2 = el('dashScope').value;
        const rs2 = rows.filter(r => !selV2 || r.email === selV2);
        const oReq = rs2.reduce((s, r) => s + (r.req || 0), 0);
        const oCached = rs2.reduce((s, r) => s + (r.cachedRequests || 0), 0);
        const oThreats = rs2.reduce((s, r) => s + (r.threats || 0), 0);
        if (oReq > 0) { t('dashCache', Math.round((oCached / oReq) * 100) + '%'); t('dashThreats', fmtNum(oThreats)); }
        else { t('dashCache', '-'); t('dashThreats', '-'); }
      } else { t('dashCache', '-'); t('dashThreats', '-'); }
      const bad = dashPick(d.accounts).filter(a => a.status && a.status !== 'ok').length;
      t('dashBad', String(bad));
      t('dashTs', new Date(d.snap.ts).toLocaleString('zh-CN', { hour12: false }));
      const up = dashUsagePct(d.usage);
      const scopeSingle = !!el('dashScope').value;
      if (scopeSingle && up && up.rows.length) {
        const pct = Math.round((up.total / 100000) * 100);
        t('dashQuota', pct + '%');
      } else if (up) {
        const high = up.rows.filter(r => (r.total || 0) >= 50000).length;
        const maxPct = up.rows.length ? Math.round((Math.max.apply(null, up.rows.map(r => r.total || 0)) / 100000) * 100) : 0;
        t('dashQuota', maxPct + '%' + (high ? ' (' + high + ' 高危)' : ''));
      } else t('dashQuota', '-');
      // 24h 趋势
      const hourMap = {};
      recs.forEach(r => (r.points || []).forEach(p => { hourMap[p.t] = (hourMap[p.t] || 0) + (p.req || 0); }));
      const hours = Object.keys(hourMap).sort();
      const pts = hours.map(h => ({ l: h.slice(0, 5), v: hourMap[h] }));
      t('dashTrend', pts.length ? '' : '无请求数据');
      el('dashTrend').innerHTML = pts.length ? barHtml(pts) : '<span style="color:#94a3b8">近 24h 无请求</span>';
      // 占比 / zones
      const st = el('dashShareTitle');
      if (scopeSingle && recs[0]) {
        st.textContent = dashScopeLabel() + ' · Zones 排行';
        const zs = (recs[0].zones || []).slice(0, 8);
        const zmax = Math.max.apply(null, zs.map(z => z.req)) || 1;
        el('dashShare').innerHTML = zs.length ? zs.map(z =>
          '<div style="display:flex;align-items:center;gap:6px;margin-bottom:5px"><div style="flex:0 0 auto;font-size:11px;color:#334155;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escAttr(z.name) + '</div>' +
          '<div style="flex:1;height:12px;background:#f1f5f9;border-radius:6px"><div style="height:12px;width:' + Math.max(2, Math.round((z.req / zmax) * 100)) + '%;background:#8b5cf6;border-radius:6px"></div></div>' +
          '<div style="flex:0 0 auto;font-size:11px;color:#64748b">' + fmtNum(z.req) + '</div></div>').join('')
          : '<span style="color:#94a3b8">该账号无 zones 数据</span>';
      } else {
        st.textContent = '各账号请求占比';
        const all = Object.keys(data).map(k => data[k]).sort((a, b) => (b.req || 0) - (a.req || 0)).slice(0, 8);
        const amax = Math.max.apply(null, all.map(a => a.req)) || 1;
        el('dashShare').innerHTML = all.length ? all.map(a =>
          '<div style="display:flex;align-items:center;gap:6px;margin-bottom:5px"><div style="flex:0 0 auto;font-size:11px;color:#334155;max-width:110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escAttr(a.email || a.name || '?') + '</div>' +
          '<div style="flex:1;height:12px;background:#f1f5f9;border-radius:6px"><div style="height:12px;width:' + Math.max(2, Math.round(((a.req || 0) / amax) * 100)) + '%;background:#3b82f6;border-radius:6px"></div></div>' +
          '<div style="flex:0 0 auto;font-size:11px;color:#64748b">' + fmtNum(a.req) + '</div></div>').join('')
          : '<span style="color:#94a3b8">暂无账号请求数据</span>';
      }
      // 请求趋势：官方直读(httpRequests1dGroups,免费 365 天)优先，自采 an_daily 兜底
      const daysN = trendDays();
      const od = (d.officialDaily && Object.keys(d.officialDaily).length) ? d.officialDaily : null;
      const srcD = od || d.daily || {};
      const srcLabel = od ? '官方直读 · 365天可查' : '自采(每日累积)';
      const srcHint = el('dashDailySrc'); if (srcHint) srcHint.textContent = srcLabel + (od && d.officialFetchedAt ? ' · 更新 ' + new Date(d.officialFetchedAt).toLocaleDateString('zh-CN') : '');
      const dk = Object.keys(srcD).sort().slice(-daysN);
      const dpts = dk.map(dd => {
        const rows = Object.keys(srcD[dd] || {}).map(k => srcD[dd][k]);
        const selV = el('dashScope').value;
        const sum = rows.filter(r => !selV || r.email === selV).reduce((s, r) => s + (r.req || 0), 0);
        return { l: dd.slice(5), v: sum };
      });
      el('dashDaily').innerHTML = dpts.length ? barHtml(dpts) : '<span style="color:#94a3b8">暂无数据（官方：点「立即采集」；自采需每日累积）</span>';
      // 配额 14 天：官方逐日历史(official_usage)优先，自采 usage_history 兜底
      const usageSrc = (d.officialUsage && Object.keys(d.officialUsage).length) ? d.officialUsage : (d.usage || {});
      const ql = el('dashQuotaSrc'); if (ql) ql.textContent = (d.officialUsage && Object.keys(d.officialUsage).length) ? '官方直读(逐日累积)' : '自采(每日累积)';
      const uk = Object.keys(usageSrc).sort().slice(-14);
      const qpts = uk.map(dd => {
        const rows = (usageSrc[dd] || []).filter(r => !el('dashScope').value || r.email === el('dashScope').value);
        return { l: dd.slice(5), v: rows.reduce((s, r) => s + (r.total || 0), 0) };
      });
      const quotaWarn = qpts.length >= 3 && qpts.slice(-7).reduce((s, p) => s + p.v, 0) / Math.min(7, qpts.length) > 80000;
      el('dashQuotaChart').innerHTML = (qpts.length ? barHtml(qpts) : '<span style="color:#94a3b8">-</span>') + (quotaWarn ? '<div style="color:#b45309;margin-top:4px;font-size:11px">近 7 日均值 &gt; 8 万，可能提前耗尽配额</div>' : '');
      // 数据源标注
      const snote = el('dashSrcNote');
      if (snote) {
        const l = (iso) => iso ? new Date(iso).toLocaleString('zh-CN', { hour12:false }) : '';
        const odA = d.officialFetchedAt ? new Date(d.officialFetchedAt).toLocaleDateString('zh-CN') : '';
        const ouA = d.officialUsageFetchedAt ? new Date(d.officialUsageFetchedAt).toLocaleDateString('zh-CN') : '';
        const uhLast = Object.keys(d.usage || {}).sort().pop() || '';
        snote.innerHTML = '数据源：24h 走势/带宽/访问=官方 1hGroups（采集 ' + l((d.snap && d.snap.ts) || '') + '）· 请求趋势/缓存命中/威胁=官方 1dGroups（' + (odA || '未采') + '）· 配额=官方 workersInvocations（' + (ouA || '未采') + (ouA ? '' : '，自采至 ' + uhLast) + '）· 证书/WAF/状态=官方(≤6h 现查)。免费计划官方小时级仅 3 天、日级 365 天；点「立即采集」按官方现查刷新。';
      }
      // 明细表
      const rowsHtml = recs.map(a => {
        const accMeta = (d.accounts || []).find(x => (x.email || x.name) === (a.email || a.name));
        const okStatus = !accMeta || !accMeta.status || accMeta.status === 'ok';
        const pct = up && scopeSingle ? Math.round((up.total / 100000) * 100) : null;
        return '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;padding:7px 0;border-bottom:1px dashed #eef2f6;flex-wrap:wrap">' +
          '<div style="flex:1;min-width:150px"><span style="color:' + (okStatus ? '#0f6e56' : '#a32d2d') + '">●</span> <b>' + escAttr(a.email || a.name || '?') + '</b>' + (a.zones ? ' <span style="color:#94a3b8;font-size:11px">' + a.zones.length + ' zones</span>' : '') + '</div>' +
          '<div style="font-size:12px;color:#475569;width:70px;text-align:right">' + fmtNum(a.req) + '</div>' +
          '<div style="font-size:12px;color:#475569;width:76px;text-align:right">' + fmtBytes(a.bytes) + '</div>' +
          '<div style="font-size:12px;color:#d97706;width:52px;text-align:right">' + (pct != null ? pct + '%' : '') + '</div>' +
          '<div style="display:flex;gap:6px">' +
          '<button class="btn small" onclick="openDashZones(\\'' + (a.email || a.name) + '\\')">Zones</button>' +
          '<button class="btn small" onclick="dashSetActive(\\'' + (a.email || a.name) + '\\')">设为执行</button></div></div>';
      }).join('');
      el('dashTable').innerHTML = recs.length ? rowsHtml : '<span style="color:#94a3b8">该作用域暂无数据（点「立即采集」拉取）</span>';
    }
    function openDashZones(emailKey){
      const data = (dashCache && dashCache.snap && dashCache.snap.data) || {};
      const rec = data[emailKey];
      if (!rec) return showNotification('无该账号分析数据', 'error');
      el('dashZoneBox').innerHTML = '<div style="font-weight:700;margin-bottom:8px">' + escAttr(emailKey) + ' · Zones（24h 请求降序）</div>' +
        (rec.zones && rec.zones.length ? rec.zones.map(z =>
          '<div style="display:flex;justify-content:space-between;gap:8px;padding:5px 0;border-bottom:1px dashed #eef2f6"><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escAttr(z.name) + '</span><span style="color:#475569">' + fmtNum(z.req) + ' req</span><span style="color:#94a3b8;width:76px;text-align:right">' + fmtBytes(z.bytes) + '</span></div>').join('')
          : '<span style="color:#94a3b8">无 zones 数据</span>');
      el('dashZoneModal').style.display = 'flex';
    }
    function dashSetActive(emailKey){
      const arr = loadSaved();
      const i = arr.findIndex(a => (a.email || a.name || a.oauthId) === emailKey);
      if (i === -1) return showNotification('本地账号库未找到该账号，请先「从 KV 同步/账号库添加」', 'error');
      if (arr[i] && arr[i].oauth) { localStorage.setItem('cf_active_oauth', arr[i].oauthId); localStorage.removeItem('cf_active_email'); localStorage.removeItem('cf_active_key'); }
      else { localStorage.setItem('cf_active_email', arr[i].email); localStorage.setItem('cf_active_key', arr[i].key); localStorage.removeItem('cf_active_oauth'); }
      localStorage.removeItem('cf_accountId'); updateAcctBadge();
      dashApplyScope(emailKey);
      showNotification('已设为执行账号：' + emailKey + '（总览已切到该账号）');
    }
    window.renderDash = renderDash; window.dashScopeChanged = dashScopeChanged; window.trendDaysChanged = trendDaysChanged; window.backfillUsageHistory = backfillUsageHistory; window.collectAnalyticsNow = collectAnalyticsNow; window.openDashZones = openDashZones; window.dashSetActive = dashSetActive;
    async function renderAccounts(){
      const arr = await kvMergeAccounts();
      const box = el('accountsBox'); if (!box) return;
      const act = getActiveCreds();
      box.innerHTML = '';
      if (!arr.length) { box.innerHTML = '<div style="padding:18px;color:#64748b;text-align:center">暂无账号 —— 点击右上「添加账号」（Global Key）或到「设置 → OAuth 免密钥接入」授权连接</div>'; return; }
      arr.forEach((a, idx) => {
        const isOa = !!(a && a.oauth);
        const st = accountStatusText(a); const isActive = isActiveAccount(a, act);
        const row = document.createElement('div');
        row.className = 'worker-row';
        row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:10px;padding:12px;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:8px';
        const left = document.createElement('div'); left.style.cssText = 'flex:1;min-width:0';
        const emailLine = document.createElement('div'); emailLine.style.cssText = 'font-weight:600;display:flex;align-items:center;gap:8px;flex-wrap:wrap';
        emailLine.appendChild(document.createTextNode(acctLabel(a)));
        if (isActive) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = '执行账号'; emailLine.appendChild(b); }
        if (isOa) { const b = document.createElement('span'); b.style.cssText = 'font-size:11px;background:#eef2ff;color:#3730a3;border-radius:4px;padding:1px 6px'; b.textContent = (a && a.key) ? 'Key + OAuth' : 'OAuth 授权'; emailLine.appendChild(b); }
        if (a.group) { const g = document.createElement('span'); g.style.cssText = 'font-size:11px;background:#eef2ff;color:#3730a3;border-radius:4px;padding:1px 6px'; g.textContent = a.group; emailLine.appendChild(g); }
        const st2 = document.createElement('span'); st2.style.cssText = 'font-size:11px;color:' + st.c; st2.textContent = st.t; emailLine.appendChild(st2);
        const meta = document.createElement('div'); meta.className = 'small'; meta.style.cssText = 'margin:0;color:#94a3b8';
        const metaParts = [];
        if (isOa) {
          if (a.scope) metaParts.push('Scope: ' + String(a.scope).slice(0, 90) + (a.scope.length > 90 ? '…' : ''));
          if (a.accountId) metaParts.push('Account: ' + String(a.accountId).slice(0, 10) + '…');
          if (a.expiresAt) { const ex = new Date(a.expiresAt); metaParts.push('Token 过期 ' + (ex.getTime() < Date.now() ? '（已过期，将自动刷新）' : ex.toLocaleString('zh-CN', { hour12:false }))); }
          if (a.added) metaParts.push('授权于 ' + a.added);
        } else {
          if (a.statusReason) metaParts.push(a.statusReason);
          if (a.added) metaParts.push('添加于 ' + a.added);
        }
        meta.textContent = metaParts.join(' · ');
        left.appendChild(emailLine); left.appendChild(meta); row.appendChild(left);
        const btns = document.createElement('div'); btns.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap';
        btns.innerHTML = '<button class="btn small" onclick="setActiveAccount(' + idx + ')">设为执行账号</button>' +
          (isOa
            ? '<button class="btn small" onclick="oauthDisconnect(\\'' + a.oauthId + '\\')">断开</button>'
            : '<button class="btn small" onclick="editAccountGroup(' + idx + ')">分组</button>') +
          '<button class="btn small" style="background:#fee2e2;color:#b91c1c" onclick="removeAccount(' + idx + ')">移除</button>';
        row.appendChild(btns); box.appendChild(row);
      });
    }
    function openAddAccount(){ el('addAccEmail').value=''; el('addAccKey').value=''; el('addAccGroup').value=''; el('addAccountModal').style.display='flex'; }
    function closeAddAccount(){ el('addAccountModal').style.display='none'; }
    async function confirmAddAccount(){
      const email = el('addAccEmail').value.trim(); const key = el('addAccKey').value.trim();
      const group = el('addAccGroup').value.trim();
      if (!email || !key) return showNotification('请输入邮箱和 API Key', 'error');
      const r = await api('validate-credentials', { email, key });
      if (!r || !(r.result || r.success === true)) return showNotification('校验失败：' + ((r && (r.errors || r.message || r.error)) || '凭据无效'), 'error');
      const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }).replace(/\\//g, '-');
      const arr = loadSaved(); const i = arr.findIndex(x => x.email === email);
      const acc = { email, key, added: now }; if (group) acc.group = group;
      if (i !== -1) arr[i] = acc; else arr.unshift(acc);
      saveAccounts(arr);
      localStorage.setItem('cf_active_email', email); localStorage.setItem('cf_active_key', key); localStorage.removeItem('cf_active_oauth'); localStorage.removeItem('cf_accountId');
      updateAcctBadge(); closeAddAccount(); showNotification('已添加并设为执行账号');
      setTimeout(() => location.reload(), 400);
    }
    function openBatchImport(){ el('importAccInput').value=''; el('importAccountsModal').style.display='flex'; }
    function closeBatchImport(){ el('importAccountsModal').style.display='none'; }
    function confirmBatchImport(){
      const raw = el('importAccInput').value || ''; if (!raw.trim()) return showNotification('请输入内容', 'error');
      const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }).replace(/\\//g, '-');
      const cur = loadSaved(); let n = 0;
      raw.split('\\n').forEach(line => {
        const parts = line.split('|');
        if (parts.length >= 2) {
          const email = parts[0].trim(); const key = parts[1].trim(); const group = (parts[2] || '').trim();
          if (!email || !key) return;
          const acc = { email, key, added: now }; if (group) acc.group = group;
          const i = cur.findIndex(c => c.email === email); if (i !== -1) cur[i] = acc; else cur.unshift(acc); n++;
        }
      });
      if (!n) return showNotification('未解析到有效账号（邮箱|GlobalKey）', 'error');
      saveAccounts(cur); closeBatchImport();
      showNotification('已导入 ' + n + ' 个账号');
      renderAccounts();
    }
    function editAccountGroup(idx){
      const arr = loadSaved(); if (!arr[idx]) return;
      const g = prompt('设置分组（可为空）：', arr[idx].group || '');
      if (g === null) return;
      arr[idx].group = g.trim(); saveAccounts(arr); renderAccounts();
    }
    function setActiveAccount(idx){
      const arr = loadSaved(); if (!arr[idx]) return;
      const acc = arr[idx];
      if (acc && acc.oauth) { localStorage.setItem('cf_active_oauth', acc.oauthId); localStorage.removeItem('cf_active_email'); localStorage.removeItem('cf_active_key'); }
      else { localStorage.setItem('cf_active_email', acc.email); localStorage.setItem('cf_active_key', acc.key); localStorage.removeItem('cf_active_oauth'); }
      localStorage.removeItem('cf_accountId'); updateAcctBadge(); showNotification('已切换执行账号');
      dashApplyScope(dashFollowKey(acc));
      renderAccounts();
    }
    // 构建日报时段多选 chips（北京时 06:23–23:23，18 档；UTC=北京-8）
    function buildTgHourChips(){
      const box = el('tgReportHours');
      if (!box || box.dataset.built) return;
      box.dataset.built = '1';
      box.innerHTML = '';
      const chipStyle = 'display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border:1px solid #e2e8f0;border-radius:999px;cursor:pointer;font-size:12px;color:#475569';
      for (let bj = 6; bj <= 23; bj++) {
        const lab = document.createElement('label');
        lab.style.cssText = chipStyle;
        const cb = document.createElement('input');
        cb.type = 'checkbox'; cb.value = String(bj);
        lab.appendChild(cb);
        const sp = document.createElement('span');
        sp.textContent = String(bj).padStart(2, '0') + ':23';
        lab.appendChild(sp);
        box.appendChild(lab);
      }
      const util = document.createElement('div');
      util.style.cssText = 'display:flex;gap:12px;align-items:center;width:100%';
      const mk = (txt, fn) => {
        const a = document.createElement('a');
        a.href = 'javascript:void(0)';
        a.textContent = txt;
        a.style.cssText = 'font-size:12px;color:#2563eb';
        a.addEventListener('click', fn);
        util.appendChild(a);
      };
      mk('全部勾选', () => box.querySelectorAll('input[type=checkbox]').forEach(c => c.checked = true));
      mk('只留默认 07:23', () => { box.querySelectorAll('input[type=checkbox]').forEach(c => c.checked = false); const d = box.querySelector('input[value="7"]'); if (d) d.checked = true; });
      mk('清除全部', () => box.querySelectorAll('input[type=checkbox]').forEach(c => c.checked = false));
      box.appendChild(util);
    }
    async function loadSettingsAll(){
      loadSubdomainSettings();
      loadOAuthUI();
      try { const r = await api('load-tg-config', {}); if (r && r.success && r.config) {
        if (r.config.botTokenSet) el('tgBotToken').placeholder = '已保存 (' + r.config.botToken + ')';
        if (r.config.chatId) el('tgChatId').value = r.config.chatId;
        el('tgEnabled').checked = r.config.enabled !== false; el('tgDaily').checked = r.config.dailyReport !== false; el('tgAlerts').checked = r.config.alerts !== false; if (el('tgTraffic')) el('tgTraffic').checked = r.config.alertsTraffic !== false;
        const hrs = (r.config.reportHours && r.config.reportHours.length) ? r.config.reportHours : [23];
        buildTgHourChips();
        const want = new Set(hrs.map(h => (h + 8) % 24));
        document.querySelectorAll('#tgReportHours input[type=checkbox]').forEach(c => { c.checked = want.has(Number(c.value)); });
        const any = Array.from(document.querySelectorAll('#tgReportHours input[type=checkbox]')).some(c => c.checked);
        if (!any) { const d = document.querySelector('#tgReportHours input[value="7"]'); if (d) d.checked = true; }
        const seg = r.config.segments || {};
        if (el('tgSegQuota')) el('tgSegQuota').checked = seg.quota !== false;
        if (el('tgSegTraffic')) el('tgSegTraffic').checked = seg.traffic !== false;
        if (el('tgSegHealth')) el('tgSegHealth').checked = seg.health !== false;
      } } catch(e){}
      try { const r = await api('load-notify-config', {}); if (r && r.success && r.config) { fillNotifyConfig(r.config); } } catch(e){}
    }

    // ===== 管理面三件套：WAF / Tunnel / Bulk Redirects =====
    const ctx3 = { waf:null, tunnels:[], redirLists:[], redirRules:[] };
    function closeModal(id){ const m = el(id); if (m) m.style.display = 'none'; }
    function escAttr(s){ return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;'); }
    function statusChip(status){
      const map = { healthy:['#0f6e56','在线'], degraded:['#854F0B','降级'], inactive:['#64748b','未运行'], down:['#a32d2d','离线'], disabled:['#94a3b8','停用'] };
      const m = map[status] || ['#475569', status || '未知'];
      return '<span style="color:' + m[0] + ';font-weight:700">● ' + m[1] + '</span>';
    }

    // ---------- WAF 自定义规则 ----------
    async function loadWafPage(){
      try {
        const sel = el('wafZoneSel');
        const r = await api('list-zones', {});
        if (r && r.success && Array.isArray(r.result) && r.result.length) {
          sel.innerHTML = r.result.map(z => '<option value="' + escAttr(z.id) + '">' + escAttr(z.name) + '</option>').join('');
          const saved = localStorage.getItem('waf_zone');
          sel.value = (saved && r.result.find(z => z.id === saved)) ? saved : r.result[0].id;
          localStorage.setItem('waf_zone', sel.value);
        } else {
          sel.innerHTML = '<option value="">无可用域名</option>';
        }
      } catch(e){}
      loadWafRules();
    }
    async function loadWafRules(){
      const box = el('wafRuleList'); const zoneId = el('wafZoneSel').value;
      if (!zoneId) { box.innerHTML = '<div style="color:#94a3b8;padding:8px">请先选择域名</div>'; return; }
      localStorage.setItem('waf_zone', zoneId);
      box.innerHTML = '<div style="color:#94a3b8;padding:8px">加载中…</div>';
      const r = await api('list-waf-rules', { zoneId });
      if (!r || !r.success) { box.innerHTML = '<div style="color:#b91c1c;padding:8px">' + escAttr((r && r.error) || '加载失败') + '</div>'; return; }
      ctx3.waf = { zoneId, exists: r.exists, rulesetId: r.rulesetId || '', rules: r.rules || [] };
      renderWafRules();
    }
    function renderWafRules(){
      const box = el('wafRuleList'); const ctx = ctx3.waf;
      if (!ctx) return;
      if (!ctx.rules.length) { box.innerHTML = '<div style="color:#94a3b8;padding:8px">暂无自定义规则 —— 点击右上「新建规则」</div>'; return; }
      const rows = ctx.rules.map((rule, i) => {
        const act = String(rule.action || '').toUpperCase();
        const color = { BLOCK:'#a32d2d', CHALLENGE:'#854F0B', JS_CHALLENGE:'#854F0B', MANAGED_CHALLENGE:'#3730a3', LOG:'#64748b', ALLOW:'#0f6e56' }[act] || '#475569';
        const on = rule.enabled !== false;
        return '<div class="worker-row" style="padding:10px;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:8px">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap">' +
          '<div style="flex:1;min-width:220px">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><span style="color:#94a3b8;font-size:12px">#' + (i + 1) + '</span><span style="font-weight:700;color:' + color + '">' + act + '</span>' + (on ? '<span style="font-size:11px;color:#0f6e56">启用</span>' : '<span style="font-size:11px;color:#94a3b8">停用</span>') + (rule.description ? '<span style="font-size:11px;color:#64748b">' + escAttr(rule.description) + '</span>' : '') + '</div>' +
          '<div style="font-family:monospace;font-size:12px;color:#334155;margin-top:4px;word-break:break-all">' + escAttr(rule.expression) + '</div>' +
          '</div>' +
          '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">' +
          '<label class="switch" style="margin:0" title="启停"><input type="checkbox" ' + (on ? 'checked' : '') + ' onchange="toggleWafRule(' + i + ', this.checked)"><span class="slider"></span></label>' +
          '<button class="btn small" onclick="editWafRule(' + i + ')">编辑</button>' +
          '<button class="btn small" style="background:#fee2e2;color:#b91c1c" onclick="deleteWafRule(' + i + ')">删除</button>' +
          '</div></div></div>';
      }).join('');
      box.innerHTML = rows;
    }
    function wafExprPlus(t){ const t1 = el('wafExpr'); t1.value = (t1.value ? t1.value + ' ' : '') + t; t1.focus(); }
    function openWafRuleModal(editIdx){
      ctx3.wafEditIdx = (editIdx == null ? null : editIdx);
      el('wafRuleModalTitle').textContent = editIdx == null ? '新建 WAF 规则' : '编辑 WAF 规则';
      if (editIdx != null && ctx3.waf && ctx3.waf.rules[editIdx]) {
        const rule = ctx3.waf.rules[editIdx];
        el('wafExpr').value = rule.expression || '';
        el('wafAction').value = rule.action || 'block';
        el('wafDesc').value = rule.description || '';
        el('wafEnabled').checked = rule.enabled !== false;
      } else {
        el('wafExpr').value = ''; el('wafAction').value = 'block'; el('wafDesc').value = ''; el('wafEnabled').checked = true;
      }
      el('wafRuleModal').style.display = 'flex';
    }
    function editWafRule(i){ openWafRuleModal(i); }
    async function saveWafRule(){
      const expression = el('wafExpr').value.trim();
      if (!expression) return showNotification('请填写表达式', 'error');
      const rule = { expression, action: el('wafAction').value, description: el('wafDesc').value.trim(), enabled: el('wafEnabled').checked };
      const ctx = ctx3.waf; if (!ctx) return;
      const idx = ctx3.wafEditIdx;
      try {
        if (idx != null && ctx.rules[idx] && ctx.rules[idx].id) {
          const r = await api('update-waf-rule', { zoneId: ctx.zoneId, rulesetId: ctx.rulesetId, ruleId: ctx.rules[idx].id, rule });
          if (!r || !r.success) return showNotification((r && r.error) || '更新失败', 'error');
        } else if (!ctx.exists) {
          const r = await api('create-waf-entrypoint', { zoneId: ctx.zoneId, rules: [rule] });
          if (!r || !r.success) return showNotification((r && r.error) || '创建失败', 'error');
          ctx.exists = true; ctx.rulesetId = r.rulesetId;
        } else {
          const r = await api('create-waf-rule', { zoneId: ctx.zoneId, rulesetId: ctx.rulesetId, rule });
          if (!r || !r.success) return showNotification((r && r.error) || '创建失败', 'error');
        }
        closeModal('wafRuleModal'); showNotification('已保存'); loadWafRules();
      } catch(e){ showNotification('保存异常：' + e.message, 'error'); }
    }
    async function toggleWafRule(i, on){
      const ctx = ctx3.waf; if (!ctx || !ctx.rules[i]) return;
      const rule = ctx.rules[i];
      const r = await api('update-waf-rule', { zoneId: ctx.zoneId, rulesetId: ctx.rulesetId, ruleId: rule.id, rule: { enabled: on } });
      if (!r || !r.success) { showNotification((r && r.error) || '操作失败', 'error'); renderWafRules(); return; }
      ctx.rules[i].enabled = on; renderWafRules();
    }
    function deleteWafRule(i){
      const ctx = ctx3.waf; const rule = ctx.rules[i];
      if (!rule) return;
      confirmDialog('删除该 WAF 规则？\\n' + String(rule.description || rule.expression).slice(0, 80), async () => {
        const r = await api('delete-waf-rule', { zoneId: ctx.zoneId, rulesetId: ctx.rulesetId, ruleId: rule.id });
        if (!r || !r.success) return showNotification((r && r.error) || '删除失败', 'error');
        showNotification('已删除'); loadWafRules();
      });
    }

    // ---------- Cloudflare Tunnel ----------
    async function loadTunnelsPage(){
      const box = el('tunnelList'); box.innerHTML = '<div style="color:#94a3b8">加载中…</div>';
      const r = await api('list-tunnels', {});
      if (!r || !r.success) { box.innerHTML = '<div style="color:#b91c1c">' + escAttr((r && r.error) || '加载失败') + '</div>'; return; }
      ctx3.tunnels = r.tunnels || [];
      if (!ctx3.tunnels.length) { box.innerHTML = '<div style="color:#94a3b8">暂无隧道 —— 点击右上「新建隧道」</div>'; return; }
      const rows = ctx3.tunnels.map(t => {
        const on = t.status === 'healthy' || t.status === 'degraded';
        return '<div class="worker-row" style="padding:12px;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:8px">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">' +
          '<div style="flex:1;min-width:200px"><div style="font-weight:700">' + escAttr(t.name) + '</div>' +
          '<div style="font-size:12px;color:#94a3b8">' + String(t.id || '').slice(0, 12) + '… · ' + (on ? statusChip(t.status) : statusChip('inactive')) + ' · 创建于 ' + escAttr(String(t.created_at || '').slice(0, 10)) + '</div></div>' +
          '<div style="display:flex;gap:6px;flex-wrap:wrap">' +
          '<button class="btn small" onclick="showTunnelCmd(\\'' + t.id + '\\', \\'' + escAttr(t.name) + '\\')">令牌命令</button>' +
          '<button class="btn small" style="background:#fee2e2;color:#b91c1c" onclick="deleteTunnel(\\'' + t.id + '\\', \\'' + escAttr(t.name) + '\\')">删除</button>' +
          '</div></div></div>';
      }).join('');
      box.innerHTML = rows;
    }
    function openTunnelModal(){ el('tunnelName').value = ''; el('tunnelModal').style.display = 'flex'; }
    async function createTunnel(){
      const name = el('tunnelName').value.trim();
      if (!name) return showNotification('请输入隧道名称', 'error');
      const r = await api('create-tunnel', { name });
      if (!r || !r.success) return showNotification((r && r.error) || '创建失败', 'error');
      closeModal('tunnelModal'); showNotification('隧道已创建：' + name); loadTunnelsPage();
    }
    async function showTunnelCmd(id, name){
      const r = await api('get-tunnel-token', { tunnelId: id });
      if (!r || !r.success) return showNotification((r && r.error) || '获取 token 失败', 'error');
      const token = r.token;
      const cmd1 = 'cloudflared service install ' + token;
      const cmd2 = 'cloudflared tunnel run --token ' + token;
      const wrap = document.createElement('div');
      wrap.innerHTML = '<div class="small" style="white-space:pre-wrap;font-family:monospace;background:#f1f5f9;padding:10px;border-radius:8px;max-height:180px;overflow:auto">' +
        '<b style="color:#334155">' + escAttr(name) + '</b>\\n' + escAttr(cmd1) + '\\n\\n# 或\\n' + escAttr(cmd2) + '</div>';
      // 放入 accountModal 容器复用？不：用 confirmDialog 无复制。创建临时预览
      showCmdOverlay(cmd1, name);
    }
    function showCmdOverlay(cmd, name){
      let ov = el('cmdOverlay');
      if (!ov) {
        ov = document.createElement('div'); ov.id = 'cmdOverlay'; ov.className = 'modal'; ov.style.cssText = 'display:none';
        ov.innerHTML = '<div class="modal-box" style="max-width:640px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><h3 style="margin:0">cloudflared 安装命令</h3><button class="trash-btn" onclick="closeCmdOverlay()">✕</button></div>' +
          '<div class="small" style="margin-bottom:8px">在任一台能访问内网的机器上执行（首次会提示以服务运行）。点击复制后粘贴到终端。</div>' +
          '<div id="cmdText" style="font-family:monospace;font-size:12px;background:#0f172a;color:#a5f3fc;padding:12px;border-radius:8px;word-break:break-all;white-space:pre-wrap"></div>' +
          '<div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end"><button class="btn primary" onclick="copyCmd()">复制命令</button></div></div>';
        document.body.appendChild(ov);
      }
      ov.style.display = 'flex';
      ov.querySelector('#cmdText').textContent = cmd;
      document.getElementById('cmdOverlay').dataset.name = name || '';
    }
    function copyCmd(){ const ov = el('cmdOverlay'); copyToClipboard(ov.querySelector('#cmdText').textContent); }
    function closeCmdOverlay(){ el('cmdOverlay').style.display = 'none'; }
    function deleteTunnel(id, name){
      confirmDialog('删除隧道「' + name + '」？\\n若已配置公网域名请先到 DNS 移除对应 CNAME（<id>.cfargotunnel.com），否则需在 Cloudflare 侧清理。', async () => {
        const r = await api('delete-tunnel', { tunnelId: id });
        if (!r || !r.success) return showNotification((r && r.error) || '删除失败', 'error');
        showNotification('已删除'); loadTunnelsPage();
      });
    }

    // ---------- Bulk Redirects ----------
    async function loadRedirectsPage(){ await Promise.all([loadRedirectLists(), loadRedirectRules()]); }
    async function loadRedirectLists(){
      const box = el('redirectListBox');
      const r = await api('list-redirect-lists', {});
      if (!r || !r.success) { box.innerHTML = '<span style="color:#b91c1c">' + escAttr((r && r.error) || '加载失败') + '</span>'; return; }
      ctx3.redirLists = r.lists || [];
      if (!ctx3.redirLists.length) { box.innerHTML = '<span style="color:#94a3b8">暂无 redirect 列表 —— 点「新建列表」</span>'; return; }
      box.innerHTML = '<div style="display:flex;flex-direction:column;gap:8px">' + ctx3.redirLists.map(l =>
        '<div class="worker-row" style="padding:10px;border:1px solid #e2e8f0;border-radius:10px;display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">' +
        '<div style="flex:1;min-width:180px"><b>' + escAttr(l.name) + '</b> <span style="color:#94a3b8">' + (l.num_items || 0) + ' 条</span>' + (l.description ? ' <span style="font-size:12px;color:#64748b">' + escAttr(l.description) + '</span>' : '') + '</div>' +
        '<div style="display:flex;gap:6px">' +
        '<button class="btn small" onclick="viewRedirectItems(\\'' + l.id + '\\', \\'' + escAttr(l.name) + '\\')">条目</button>' +
        '<button class="btn small" onclick="enableRedirectListFrom(\\'' + l.id + '\\', \\'' + escAttr(l.name) + '\\')">启用此列表</button>' +
        '<button class="btn small" style="background:#fee2e2;color:#b91c1c" onclick="deleteRedirectList(\\'' + l.id + '\\', \\'' + escAttr(l.name) + '\\')">删除</button>' +
        '</div></div>').join('') + '</div>';
    }
    async function loadRedirectRules(){
      const box = el('redirectRulesBox');
      const r = await api('get-redirect-rules', {});
      if (!r || !r.success) { box.innerHTML = '<span style="color:#b91c1c">' + escAttr((r && r.error) || '加载失败') + '</span>'; return; }
      ctx3.redirRules = { exists: r.exists, rulesetId: r.rulesetId || '', rules: r.rules || [] };
      const rs = ctx3.redirRules.rules;
      const head = '<div style="display:flex;gap:8px;margin-bottom:8px"><button class="btn small" onclick="openRedirectEnable()">添加启用规则</button></div>';
      if (!rs.length) { box.innerHTML = head + '<span style="color:#94a3b8">未启用任何列表（建好列表并添加条目后，点「添加启用规则」生效）</span>'; return; }
      box.innerHTML = head + rs.map((rule, i) => {
        const on = rule.enabled !== false;
        const listName = (rule.action_parameters && rule.action_parameters.from_list && rule.action_parameters.from_list.name) || '';
        return '<div style="border:1px solid #e2e8f0;border-radius:10px;padding:10px;margin-bottom:8px">' +
          '<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center">' +
          '<div style="flex:1;min-width:180px"><b style="font-size:13px">' + escAttr(listName) + '</b> ' + (on ? '<span style="color:#0f6e56;font-size:12px">启用</span>' : '<span style="color:#94a3b8;font-size:12px">停用</span>') +
          '<div style="font-family:monospace;font-size:11px;color:#64748b;word-break:break-all">' + escAttr(rule.expression) + '</div></div>' +
          '<div style="display:flex;gap:6px;align-items:center"><label class="switch" style="margin:0"><input type="checkbox" ' + (on ? 'checked' : '') + ' onchange="toggleRedirectRule(' + i + ', this.checked)"><span class="slider"></span></label>' +
          '<button class="btn small" style="background:#fee2e2;color:#b91c1c" onclick="removeRedirectRule(' + i + ')">删除</button></div></div></div>';
      }).join('');
    }
    function openRedirectListModal(){ el('rlName').value = ''; el('rlDesc').value = ''; el('redirectListModal').style.display = 'flex'; }
    async function createRedirectList(){
      const name = el('rlName').value.trim();
      if (!name) return showNotification('请输入列表名称', 'error');
      const r = await api('create-redirect-list', { name, description: el('rlDesc').value.trim() });
      if (!r || !r.success) return showNotification((r && r.error) || '创建失败', 'error');
      closeModal('redirectListModal'); showNotification('列表已创建'); loadRedirectLists();
    }
    function deleteRedirectList(id, name){
      confirmDialog('删除重定向列表「' + name + '」？已引用该列表的规则将失效。', async () => {
        const r = await api('delete-redirect-list', { listId: id });
        if (!r || !r.success) return showNotification((r && r.error) || '删除失败', 'error');
        showNotification('已删除'); loadRedirectsPage();
      });
    }
    function viewRedirectItems(id, name){
      el('rlItemsTitle').textContent = '列表条目：' + name;
      el('rlItemsInput').value = '';
      ctx3.itemsCtx = { listId: id, name };
      el('redirectItemsModal').style.display = 'flex';
      refreshRedirectItems();
    }
    async function refreshRedirectItems(){
      const box = el('rlItemsList'); const c = ctx3.itemsCtx; if (!c) return;
      box.innerHTML = '<span style="color:#94a3b8">加载中…</span>';
      const r = await api('list-redirect-items', { listId: c.listId });
      if (!r || !r.success) { box.innerHTML = '<span style="color:#b91c1c">' + escAttr((r && r.error) || '加载失败') + '</span>'; return; }
      const items = r.items || [];
      if (!items.length) { box.innerHTML = '<span style="color:#94a3b8">（空）在上方按行添加条目</span>'; return; }
      box.innerHTML = items.map(it => {
        const rd = (it.redirect || {});
        return '<div style="display:flex;justify-content:space-between;gap:8px;align-items:center;border-bottom:1px dashed #e2e8f0;padding:6px 0;flex-wrap:wrap">' +
          '<div style="flex:1;min-width:200px;font-size:12px"><div><b style="color:#b91c1c">' + escAttr(rd.source_url) + '</b> → <b style="color:#0f6e56">' + escAttr(rd.target_url) + '</b>' + (rd.status_code ? ' <span style="color:#475569">[' + rd.status_code + ']</span>' : '') + '</div>' +
          (rd.include_subdomains || rd.subpath_matching || rd.preserve_query_string ? '<div style="color:#94a3b8">' + (rd.include_subdomains ? '含子域 ' : '') + (rd.subpath_matching ? '子路径匹配 ' : '') + (rd.preserve_query_string ? '保留查询串' : '') + '</div>' : '') + '</div>' +
          '<button class="btn small" style="background:#fee2e2;color:#b91c1c" onclick="deleteRedirectItem(\\'' + it.id + '\\')">删除</button></div>';
      }).join('');
    }
    async function addRedirectItems(){
      const c = ctx3.itemsCtx; if (!c) return;
      const raw = el('rlItemsInput').value || '';
      const items = [];
      raw.split('\\n').forEach(line => {
        line = line.trim(); if (!line) return;
        const p = line.split('|');
        if (p.length < 2) return;
        const redirect = { source_url: p[0].trim(), target_url: p[1].trim() };
        const code = parseInt(p[2], 10);
        if (code === 301 || code === 302 || code === 307 || code === 308) redirect.status_code = code;
        items.push({ redirect });
      });
      if (!items.length) return showNotification('未解析到有效条目（源|目标|状态码）', 'error');
      const r = await api('add-redirect-items', { listId: c.listId, items });
      if (!r || !r.success) return showNotification((r && r.error) || '添加失败', 'error');
      el('rlItemsInput').value = '';
      showNotification('已提交 ' + items.length + ' 条'); refreshRedirectItems();
    }
    async function deleteRedirectItem(itemId){
      const c = ctx3.itemsCtx; if (!c || !itemId) return;
      const r = await api('delete-redirect-item', { listId: c.listId, itemId });
      if (!r || !r.success) return showNotification((r && r.error) || '删除失败', 'error');
      showNotification('已删除'); refreshRedirectItems();
    }
    function openRedirectEnable(){
      if (!ctx3.redirLists.length) { showNotification('请先创建 redirect 列表', 'error'); return; }
      el('reListSel').innerHTML = ctx3.redirLists.map(l => '<option value="' + escAttr(l.name) + '">' + escAttr(l.name) + ' (' + (l.num_items || 0) + ' 条)</option>').join('');
      el('redirectEnableModal').style.display = 'flex';
    }
    function enableRedirectListFrom(id, name){ openRedirectEnable(); el('reListSel').value = name; }
    async function enableRedirectList(){
      const listName = el('reListSel').value; if (!listName) return;
      const rr = ctx3.redirRules;
      const dup = rr && rr.rules.find(x => x.action === 'redirect' && x.action_parameters && x.action_parameters.from_list && x.action_parameters.from_list.name === listName);
      if (dup) { closeModal('redirectEnableModal'); showNotification('该列表已在启用规则中', 'error'); return; }
      const rule = { expression: 'http.request.full_uri in $' + listName, description: 'Bulk Redirect: ' + listName, action: 'redirect', action_parameters: { from_list: { name: listName, key: 'http.request.full_uri' } }, enabled: true };
      const r = await api('save-redirect-rules', { rules: [rule] });
      if (!r || !r.success) return showNotification((r && r.error) || '启用失败', 'error');
      closeModal('redirectEnableModal'); showNotification('已启用'); loadRedirectRules();
    }
    async function toggleRedirectRule(i, on){
      const rr = ctx3.redirRules; if (!rr || !rr.rules[i]) return;
      const rules = rr.rules.map((x, j) => j === i ? Object.assign({}, x, { enabled: on }) : x);
      const r = await api('save-redirect-rules', { rules });
      if (!r || !r.success) { showNotification((r && r.error) || '操作失败', 'error'); loadRedirectRules(); return; }
      loadRedirectRules();
    }
    function removeRedirectRule(i){
      const rr = ctx3.redirRules; if (!rr) return;
      const rule = rr.rules[i]; if (!rule) return;
      const listName = (rule.action_parameters && rule.action_parameters.from_list && rule.action_parameters.from_list.name) || '';
      confirmDialog('移除对该列表的引用（不删除列表本身）？\\n' + listName, async () => {
        const rules = rr.rules.filter((x, j) => j !== i);
        const r = await api('save-redirect-rules', { rules });
        if (!r || !r.success) return showNotification((r && r.error) || '失败', 'error');
        showNotification('已移除'); loadRedirectRules();
      });
    }
    window.closeModal = closeModal;
    window.wafExprPlus = wafExprPlus; window.openWafRuleModal = openWafRuleModal; window.saveWafRule = saveWafRule; window.toggleWafRule = toggleWafRule; window.editWafRule = editWafRule; window.deleteWafRule = deleteWafRule;
    window.openTunnelModal = openTunnelModal; window.createTunnel = createTunnel; window.showTunnelCmd = showTunnelCmd; window.deleteTunnel = deleteTunnel; window.copyCmd = copyCmd; window.closeCmdOverlay = closeCmdOverlay;
    window.openRedirectListModal = openRedirectListModal; window.createRedirectList = createRedirectList; window.deleteRedirectList = deleteRedirectList; window.viewRedirectItems = viewRedirectItems; window.addRedirectItems = addRedirectItems; window.deleteRedirectItem = deleteRedirectItem;
    window.openRedirectEnable = openRedirectEnable; window.enableRedirectList = enableRedirectList; window.enableRedirectListFrom = enableRedirectListFrom; window.toggleRedirectRule = toggleRedirectRule; window.removeRedirectRule = removeRedirectRule;

    // ===== 第四批：站点优化 / 邮箱转发 / DNS IO / R2 =====
    const ctx4 = { cacheRules: [], cacheEdit: null, email: null, dnsZone: '' };
    const ZONE_LABELS = { always_use_https:'强制 HTTPS', min_tls_version:'最低 TLS 版本', ssl:'SSL 模式', tls_1_3:'TLS 1.3', '0rtt':'0-RTT', http2:'HTTP/2', http3:'HTTP/3', brotli:'Brotli 压缩', websockets:'WebSocket', opportunistic_encryption:'机会性加密', automatic_https_rewrites:'自动 HTTPS 重写', ipv6:'IPv6', hotlink_protection:'防盗链', email_obfuscation:'邮箱混淆', browser_check:'浏览器完整性检查', security_level:'安全级别', challenge_ttl:'验证码有效期(秒)' };
    const ZONE_SWITCHES = ['always_use_https','tls_1_3','0rtt','http2','http3','brotli','websockets','opportunistic_encryption','automatic_https_rewrites','ipv6','hotlink_protection','email_obfuscation','browser_check'];
    const ZONE_SELECTS = { min_tls_version:['1.0','1.1','1.2','1.3'], ssl:['off','flexible','full','strict'], security_level:['essentially_off','low','medium','high','under_attack'] };
    async function fillZoneSel(selId, key){
      const sel = el(selId); if (!sel) return;
      try {
        const r = await api('list-zones', {});
        if (r && r.success && Array.isArray(r.result) && r.result.length) {
          sel.innerHTML = r.result.map(z => '<option value="' + escAttr(z.id) + '">' + escAttr(z.name) + '</option>').join('');
          const saved = localStorage.getItem(key);
          sel.value = (saved && r.result.find(z => z.id === saved)) ? saved : r.result[0].id;
          localStorage.setItem(key, sel.value);
        } else sel.innerHTML = '<option value="">无可用域名</option>';
      } catch(e){}
    }
    function zoneChips(s){
      return '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px dashed #eef2f6"><span style="display:inline-block;width:170px;color:#334155;flex:0 0 auto">' + s + '</span>';
    }
    async function loadOptimizePage(){ await fillZoneSel('optZoneSel', 'opt_zone'); loadZoneSettings(); loadCacheRules(); loadZoneAnalytics(); }
    async function loadZoneSettings(){
      const box = el('zoneSettingsBox'); const z = el('optZoneSel').value;
      if (!z) { box.innerHTML = ''; return; }
      box.textContent = '加载中…';
      const r = await api('get-zone-settings', { zoneId: z });
      if (!r || !r.success) { box.innerHTML = '<span style="color:#b91c1c">' + escAttr((r && r.error) || '加载失败') + '</span>'; return; }
      const st = r.settings || {}; let html = '';
      for (const id of Object.keys(ZONE_LABELS)) {
        const it = st[id]; if (!it) continue;
        const lbl = escAttr(ZONE_LABELS[id]);
        if (ZONE_SWITCHES.indexOf(id) !== -1) {
          const on = it.value === 'on';
          html += '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px dashed #eef2f6"><span style="display:inline-block;width:170px;color:#334155;flex:0 0 auto">' + lbl + '</span>' +
            '<label class="switch"><input type="checkbox" ' + (on ? 'checked' : '') + (it.editable ? '' : ' disabled') + ' onchange="setZoneSetting(\\'' + id + '\\', this.checked ? \\'on\\' : \\'off\\')"><span class="slider"></span></label></div>';
        } else if (ZONE_SELECTS[id]) {
          const opts = ZONE_SELECTS[id].map(o => '<option value="' + o + '"' + (it.value === o ? ' selected' : '') + '>' + o + '</option>').join('');
          html += '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px dashed #eef2f6"><span style="display:inline-block;width:170px;color:#334155;flex:0 0 auto">' + lbl + '</span>' +
            '<select style="width:auto" ' + (it.editable ? '' : ' disabled') + ' onchange="setZoneSetting(\\'' + id + '\\', this.value)">' + opts + '</select></div>';
        } else {
          html += '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px dashed #eef2f6"><span style="display:inline-block;width:170px;color:#334155;flex:0 0 auto">' + lbl + '</span>' +
            '<input class="input" style="width:120px" value="' + escAttr(it.value) + '"' + (it.editable ? '' : ' disabled') + ' onchange="setZoneSetting(\\'' + id + '\\', this.value)"></div>';
        }
      }
      box.innerHTML = html || '<span style="color:#94a3b8">（白名单设置项不可用）</span>';
    }
    async function setZoneSetting(name, value){
      const zoneId = el('optZoneSel').value;
      const r = await api('set-zone-setting', { zoneId, name, value });
      if (r && r.success) { showNotification(ZONE_LABELS[name] + ' = ' + value); }
      else { showNotification((r && r.error) || '设置失败', 'error'); loadZoneSettings(); }
    }
    async function zoneHarden(){
      const zoneId = el('optZoneSel').value;
      if (!zoneId) return showNotification('请先选择域名', 'error');
      const steps = [['always_use_https','on'], ['min_tls_version','1.2'], ['automatic_https_rewrites','on']];
      showNotification('执行一键加固…');
      for (const [name, value] of steps) {
        const r = await api('set-zone-setting', { zoneId, name, value });
        if (!r || !r.success) { showNotification('「' + ZONE_LABELS[name] + '」失败：' + ((r && r.error) || ''), 'error'); }
      }
      showNotification('一键加固完成（强制 HTTPS + 最低 TLS1.2 + 自动重写）');
      loadZoneSettings();
    }
    async function loadCacheRules(){
      const box = el('cacheRuleList'); const zoneId = el('optZoneSel').value;
      if (!zoneId) { box.innerHTML = ''; return; }
      box.innerHTML = '<span style="color:#94a3b8">加载中…</span>';
      const r = await api('list-cache-rules', { zoneId });
      if (!r || !r.success) { box.innerHTML = '<span style="color:#b91c1c">' + escAttr((r && r.error) || '加载失败') + '</span>'; return; }
      ctx4.cacheRules = r.rules || [];
      renderCacheRules();
    }
    function renderCacheRules(){
      const box = el('cacheRuleList');
      if (!ctx4.cacheRules.length) { box.innerHTML = '<span style="color:#94a3b8">暂无缓存规则 —— 免费额度 10 条</span>'; return; }
      box.innerHTML = ctx4.cacheRules.map((rule, i) => {
        const on = rule.enabled !== false;
        const ap = rule.action_parameters || {};
        const ttlMode = (ap.edge_ttl && ap.edge_ttl.mode) || '';
        const desc = [ap.cache === false ? '不缓存' : (ap.cache === true ? '缓存' : ''), ttlMode ? ('TTL:' + ttlMode + (ap.edge_ttl.ttl ? ' ' + ap.edge_ttl.ttl + 's' : '')) : ''].filter(Boolean).join(' · ');
        return '<div style="border:1px solid #e2e8f0;border-radius:10px;padding:10px;margin-bottom:8px"><div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center">' +
          '<div style="flex:1;min-width:200px"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b style="font-size:13px">' + escAttr(rule.description || '缓存规则') + '</b> ' + (on ? '<span style="color:#0f6e56;font-size:12px">启用</span>' : '<span style="color:#94a3b8;font-size:12px">停用</span>') + (desc ? '<span style="color:#64748b;font-size:12px">' + escAttr(desc) + '</span>' : '') + '</div>' +
          '<div style="font-family:monospace;font-size:11px;color:#64748b;word-break:break-all">' + escAttr(rule.expression) + '</div></div>' +
          '<div style="display:flex;gap:6px;align-items:center"><label class="switch" style="margin:0"><input type="checkbox" ' + (on ? 'checked' : '') + ' onchange="toggleCacheRule(' + i + ', this.checked)"><span class="slider"></span></label>' +
          '<button class="btn small" onclick="removeCacheRule(' + i + ')">删除</button></div></div></div>';
      }).join('');
    }
    function openCacheRuleModal(){
      ctx4.cacheEdit = null;
      el('cacheRuleModalTitle').textContent = '新建缓存规则';
      el('crExpr').value = ''; el('crCache').checked = true; el('crTtlMode').value = ''; el('crTtlSec').value = ''; el('crDesc').value = '';
      el('cacheRuleModal').style.display = 'flex';
    }
    async function saveCacheRule(){
      const zoneId = el('optZoneSel').value;
      const expression = el('crExpr').value.trim();
      if (!zoneId || !expression) return showNotification('请填写表达式', 'error');
      const ap = { cache: el('crCache').checked };
      const mode = el('crTtlMode').value; const sec = parseInt(el('crTtlSec').value, 10);
      if (mode) { ap.edge_ttl = { mode: mode }; if ((mode === 'override_origin' || mode === 'set_ttl') && sec > 0) ap.edge_ttl.ttl = sec; }
      const rule = { expression: expression, description: el('crDesc').value.trim() || undefined, action: 'set_cache_settings', action_parameters: ap, enabled: true };
      const rules = ctx4.cacheRules.slice(); rules.push(rule);
      const r = await api('save-cache-rules', { zoneId, rules });
      if (!r || !r.success) return showNotification((r && r.error) || '保存失败', 'error');
      closeModal('cacheRuleModal'); showNotification('缓存规则已保存'); loadCacheRules();
    }
    async function toggleCacheRule(i, on){
      const zoneId = el('optZoneSel').value;
      const rules = ctx4.cacheRules.map((x, j) => j === i ? Object.assign({}, x, { enabled: on }) : x);
      const r = await api('save-cache-rules', { zoneId, rules });
      if (!r || !r.success) { showNotification((r && r.error) || '操作失败', 'error'); loadCacheRules(); return; }
      loadCacheRules();
    }
    function removeCacheRule(i){
      const zoneId = el('optZoneSel').value;
      const rules = ctx4.cacheRules.filter((x, j) => j !== i);
      confirmDialog('删除该缓存规则？', async () => {
        const r = await api('save-cache-rules', { zoneId, rules });
        if (!r || !r.success) return showNotification((r && r.error) || '删除失败', 'error');
        showNotification('已删除'); loadCacheRules();
      });
    }
    async function loadZoneAnalytics(){
      const box = el('zoneAnalyticsBox'); const zoneId = el('optZoneSel').value;
      if (!zoneId) { box.innerHTML = ''; return; }
      box.innerHTML = '<span style="color:#94a3b8">查询中…</span>';
      const r = await api('get-zone-analytics', { zoneId });
      if (!r || !r.success) { box.innerHTML = '<span style="color:#b91c1c">' + escAttr((r && r.error) || '查询失败') + '</span>'; return; }
      const groups = r.groups || [];
      if (!groups.length) { box.innerHTML = '<span style="color:#94a3b8">近 24h 无请求数据</span>'; return; }
      const pts = groups.map(g => ({ t: String(g.dimensions && g.dimensions.datetimeHour || '').slice(11, 16), req: (g.sum && g.sum.requests) || 0, bytes: (g.sum && g.sum.bytes) || 0 }));
      const max = Math.max.apply(null, pts.map(p => p.req)) || 1;
      const total = pts.reduce((a, b) => a + b.req, 0);
      const bytes = pts.reduce((a, b) => a + b.bytes, 0);
      box.innerHTML = '<div style="margin-bottom:6px">24h 请求 ' + total + ' · 流量 ' + fmtBytes(bytes) + '</div>' +
        '<div style="display:flex;align-items:flex-end;gap:2px;height:90px">' + pts.map(p =>
          '<div style="flex:1;min-width:0;background:#93c5fd;border-radius:2px 2px 0 0;height:' + Math.max(2, Math.round((p.req / max) * 88)) + 'px" title="' + escAttr(p.t + ' ' + p.req + ' req') + '"></div>').join('') + '</div>' +
        '<div style="display:flex;justify-content:space-between;color:#94a3b8;font-size:11px;margin-top:2px"><span>' + pts[0].t + '</span><span>' + pts[pts.length - 1].t + '</span></div>';
    }
    function fmtBytes(b){
      if (!b) return '0 B'; const u = ['B','KB','MB','GB','TB']; let i = 0; let v = b;
      while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
      return v.toFixed(1) + ' ' + u[i];
    }
    // ---- 邮箱转发 ----
    async function loadEmailPage(){ await fillZoneSel('emailZoneSel', 'email_zone'); loadEmailData(); }
    async function loadEmailData(){
      const zoneId = el('emailZoneSel').value;
      if (!zoneId) return;
      const r = await api('get-email-routing', { zoneId });
      if (!r || !r.success) { el('emailRuleList').innerHTML = '<span style="color:#b91c1c">' + escAttr((r && r.error) || '加载失败') + '</span>'; return; }
      ctx4.email = r.email || { enabled:false, rules:[], addresses:[] };
      const e = ctx4.email;
      const tg = el('emailRoutingToggle'); if (tg) tg.checked = !!e.enabled;
      const hint = el('emailHintBox');
      if (hint) hint.innerHTML = e.enabled
        ? '<span style="color:#0f6e56">已启用</span>。若域名 MX 记录尚未指向 Cloudflare，请先在 DNS 添加：MX mail 0（目标 mail.<zone> 或 cf 指引）与 TXT v=spf1 include:_spf.mx.cloudflare.net ~all。'
        : '未启用。启用后需在 DNS 添加 MX/TXT 记录（面板添加的域名若为 Cloudflare 代理可直接开）。';
      const rl = el('emailRuleList');
      if (!e.rules.length) rl.innerHTML = '<span style="color:#94a3b8">暂无规则 —— 点「新建规则」</span>';
      else rl.innerHTML = e.rules.map((rule, i) => {
        const on = rule.enabled !== false;
        const m0 = (rule.matchers && rule.matchers[0]) || {};
        const src = m0.type === 'all' ? '*@域名（Catch-all）' : (m0.value || '');
        const a0 = (rule.actions && rule.actions[0]) || {};
        const dst = a0.type === 'forward' ? ('转发 → ' + ((a0.value || []).join(', '))) : '丢弃';
        return '<div style="border:1px solid #e2e8f0;border-radius:10px;padding:10px;margin-bottom:8px"><div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center">' +
          '<div style="flex:1;min-width:200px"><b>' + escAttr(src) + '</b> <span style="color:#475569">' + escAttr(dst) + '</span> ' + (on ? '<span style="color:#0f6e56;font-size:12px">启用</span>' : '<span style="color:#94a3b8;font-size:12px">停用</span>') + '</div>' +
          '<div style="display:flex;gap:6px;align-items:center"><label class="switch" style="margin:0"><input type="checkbox" ' + (on ? 'checked' : '') + ' onchange="toggleEmailRule(' + i + ', this.checked)"><span class="slider"></span></label>' +
          '<button class="btn small" style="background:#fee2e2;color:#b91c1c" onclick="removeEmailRule(' + i + ')">删除</button></div></div></div>';
      }).join('');
      const al = el('emailAddrList');
      if (!e.addresses.length) al.innerHTML = '<span style="color:#94a3b8">无目标地址（需先在 dash → Email → Destination addresses 验证收件邮箱）</span>';
      else al.innerHTML = e.addresses.map(a => '<div style="padding:3px 0">' + escAttr(a.email) + ' ' + (a.verified ? '<span style="color:#0f6e56">已验证</span>' : '<span style="color:#b45309">未验证</span>') + '</div>').join('');
    }
    async function setEmailRouting(on){
      const zoneId = el('emailZoneSel').value;
      const r = await api('set-email-routing', { zoneId, enabled: on });
      if (!r || !r.success) { showNotification((r && r.error) || '切换失败', 'error'); loadEmailData(); return; }
      showNotification(on ? '已启用接收' : '已停用'); loadEmailData();
    }
    function openEmailRuleModal(){
      el('emailRuleModalTitle').textContent = '新建转发规则';
      el('erMatchType').value = 'literal'; el('erAddress').value = ''; el('erAction').value = 'forward'; el('erTargets').value = '';
      el('emailRuleModal').style.display = 'flex';
    }
    async function saveEmailRule(){
      const zoneId = el('emailZoneSel').value;
      if (!zoneId) return showNotification('请先选择域名', 'error');
      const kind = el('erMatchType').value;
      const addr = el('erAddress').value.trim();
      const act = el('erAction').value;
      const targets = el('erTargets').value.split(',').map(s => s.trim()).filter(Boolean);
      const matchers = kind === 'all' ? [{ field: 'to', type: 'all' }] : [{ field: 'to', type: 'literal', value: addr }];
      if (kind !== 'all' && !addr) return showNotification('请填写收件地址', 'error');
      const actions = act === 'drop' ? [{ type: 'drop' }] : [{ type: 'forward', value: targets }];
      if (act === 'forward' && !targets.length) return showNotification('请填写转发目标邮箱', 'error');
      const rule = { matchers, actions, enabled: true, name: 'mycf-rule-' + Date.now() };
      const r = await api('add-email-rule', { zoneId, rule });
      if (!r || !r.success) return showNotification((r && r.error) || '保存失败', 'error');
      closeModal('emailRuleModal'); showNotification('规则已添加'); loadEmailData();
    }
    async function toggleEmailRule(i, on){
      const zoneId = el('emailZoneSel').value; const e = ctx4.email;
      if (!e || !e.rules[i]) return;
      const rule = Object.assign({}, e.rules[i], { enabled: on });
      const r = await api('update-email-rule', { zoneId, ruleId: e.rules[i].id, rule });
      if (!r || !r.success) { showNotification((r && r.error) || '操作失败', 'error'); loadEmailData(); return; }
      loadEmailData();
    }
    function removeEmailRule(i){
      const zoneId = el('emailZoneSel').value; const e = ctx4.email;
      if (!e || !e.rules[i]) return;
      confirmDialog('删除该转发规则？', async () => {
        const r = await api('delete-email-rule', { zoneId, ruleId: e.rules[i].id });
        if (!r || !r.success) return showNotification((r && r.error) || '删除失败', 'error');
        showNotification('已删除'); loadEmailData();
      });
    }
    // ---- DNS 导入导出 ----
    async function openDnsExportImport(){
      const sel = el('dnsIoZoneSel');
      try {
        const r = await api('list-zones', {});
        if (r && r.success && Array.isArray(r.result)) sel.innerHTML = r.result.map(z => '<option value="' + escAttr(z.id) + '">' + escAttr(z.name) + '</option>').join('');
      } catch(e){}
      el('dnsIoOut').value = ''; el('dnsIoIn').value = ''; el('dnsIoResult').textContent = '';
      el('dnsIOModal').style.display = 'flex';
    }
    async function exportDnsNow(){
      const zoneId = el('dnsIoZoneSel').value;
      if (!zoneId) return showNotification('请选择域名', 'error');
      const r = await api('export-dns', { zoneId });
      if (!r || !r.success) return showNotification((r && r.error) || '导出失败', 'error');
      el('dnsIoOut').value = r.text || '';
      ctx4.dnsZone = zoneId;
      showNotification('已导出，可点「下载 .txt」');
    }
    function downloadExportedDns(){
      const txt = el('dnsIoOut').value;
      if (!txt) return showNotification('请先导出', 'error');
      const name = (ctx4.dnsZone || 'zone') + '-dns.txt';
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([txt], { type: 'text/plain' }));
      a.download = name; a.click();
    }
    async function importDnsNow(){
      const zoneId = el('dnsIoZoneSel').value;
      const text = el('dnsIoIn').value;
      if (!zoneId) return showNotification('请选择域名', 'error');
      if (!text.trim()) return showNotification('请粘贴 BIND 文本', 'error');
      const r = await api('import-dns', { zoneId, bindText: text, proxied: el('dnsIoProxied').checked });
      const box = el('dnsIoResult');
      if (!r || !r.success) { box.textContent = (r && r.error) || '导入失败'; box.style.color = '#b91c1c'; return; }
      const res = r.result || {};
      const msg = '解析 ' + (res.total_parsed != null ? res.total_parsed : '?') + '，新增 ' + (res.recs_added != null ? res.recs_added : (res.total_imported != null ? res.total_imported : '?')) + ' 条' + (res.recs_skipped ? '，跳过 ' + res.recs_skipped : '');
      box.textContent = msg; box.style.color = '#0f6e56';
    }
    // ---- R2 ----
    async function loadR2Page(){
      const box = el('r2BucketList');
      box.innerHTML = '<span style="color:#94a3b8">加载中…</span>';
      const r = await api('list-r2-buckets', {});
      if (!r || !r.success) { box.innerHTML = '<span style="color:#b91c1c">' + escAttr((r && r.error) || '加载失败') + '</span>'; return; }
      const buckets = r.buckets || [];
      if (!buckets.length) { box.innerHTML = '<span style="color:#94a3b8">该账号暂无 R2 桶</span>'; return; }
      box.innerHTML = buckets.map(b =>
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:6px"><b>' + escAttr(b.name) + '</b>' +
        '<span style="color:#94a3b8;font-size:12px">创建于 ' + escAttr(String(b.creation_date || b.created_on || '').slice(0, 10)) + '</span></div>').join('');
    }
    window.setZoneSetting = setZoneSetting; window.zoneHarden = zoneHarden;
    window.openCacheRuleModal = openCacheRuleModal; window.saveCacheRule = saveCacheRule; window.toggleCacheRule = toggleCacheRule; window.removeCacheRule = removeCacheRule;
    window.setEmailRouting = setEmailRouting; window.openEmailRuleModal = openEmailRuleModal; window.saveEmailRule = saveEmailRule; window.toggleEmailRule = toggleEmailRule; window.removeEmailRule = removeEmailRule;
    window.openDnsExportImport = openDnsExportImport; window.exportDnsNow = exportDnsNow; window.downloadExportedDns = downloadExportedDns; window.importDnsNow = importDnsNow;

    // ===== OAuth 免密钥接入（设置页）=====
    async function loadOAuthUI(){
      const hint = el('oauthRedirectHint'); if (hint) hint.textContent = location.origin + '/oauth/callback';
      try {
        const r = await api('load-oauth-client', {});
        if (!r || !r.success) return;
        if (r.configured) {
          const ci = el('oauthClientId'); if (ci) ci.value = r.clientId || '';
          const sel = el('oauthAuthMethod'); if (sel && r.authMethod) sel.value = r.authMethod;
          if (r.hasSecret) { const cs = el('oauthClientSecret'); if (cs) { cs.placeholder = 'Secret 已保存（留空保持不变）'; cs.value = ''; } }
        }
        const box = el('oauthConnBox');
        if (box) {
          if (!r.connections || !r.connections.length) box.innerHTML = '尚未授权任何连接。保存配置后点「前往 Cloudflare 授权」。';
          else box.innerHTML = r.connections.map(c =>
            '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 0;border-bottom:1px dashed #e2e8f0">' +
            '<span><b>' + escapeHtml(c.name) + '</b> <span style="color:#94a3b8">' + escapeHtml(String(c.scope || '').slice(0, 60)) + '</span></span>' +
            '<button class="btn small" style="background:#fee2e2;color:#b91c1c" onclick="oauthDisconnect(\\'' + c.oauthId + '\\')">断开</button></div>'
          ).join('');
        }
      } catch(e){}
    }
    async function saveOAuthConfig(){
      const clientId = (el('oauthClientId').value || '').trim();
      if (!clientId) return showNotification('请填写 Client ID', 'error');
      const secret = (el('oauthClientSecret').value || '').trim();
      const authMethod = el('oauthAuthMethod').value;
      const r = await api('save-oauth-client', { clientId, clientSecret: secret, authMethod });
      if (r && r.success) { showNotification('OAuth 配置已保存'); loadOAuthUI(); }
      else showNotification((r && r.error) || '保存失败', 'error');
    }
    async function oauthConnect(){
      const r = await api('oauth-begin', {});
      if (r && r.success && r.url) { location.href = r.url; }
      else showNotification((r && r.error) || '无法生成授权地址：请先保存 OAuth 配置', 'error');
    }
    async function oauthDisconnect(oauthId){
      confirmDialog('断开该账号的 OAuth 授权？仅移除 OAuth 令牌' + (true ? '' : '') + '；若账号同时存有 Global Key 将保留，仍可用 Key 通道管理。如需在 Cloudflare 侧彻底撤销，请到 dash → My Profile → 授权应用。', async () => {
        const r = await api('oauth-revoke-account', { oauthId });
        const arr = loadSaved();
        const i = arr.findIndex(a => a && a.oauth && a.oauthId === oauthId);
        if (i !== -1) {
          const rec = arr[i];
          if (rec && rec.key) {
            // 双通道：降级为纯 Global Key 账号
            const keyRec = { email: rec.email || '', key: rec.key, group: rec.group || '', added: rec.added || '', status: 'ok' };
            arr.splice(i, 1, keyRec);
          } else {
            arr.splice(i, 1);
          }
        }
        if (getActiveCreds().oauthId === oauthId) localStorage.removeItem('cf_active_oauth');
        localStorage.setItem('cf_accounts', JSON.stringify(arr));
        saveAccounts(arr);
        if (r && r.success) showNotification('已断开 OAuth（Global Key 保留可用）'); else showNotification('服务端断开失败：' + ((r && r.error) || '未知'), 'error');
        renderAccounts(); loadOAuthUI(); updateAcctBadge();
      });
    }
    window.saveOAuthConfig = saveOAuthConfig; window.oauthConnect = oauthConnect; window.oauthDisconnect = oauthDisconnect;

    // ===== UI 增强：账号徽标 / 暗色 / 抽屉 / 确认弹窗 / 搜索排序 / 键盘 =====
    function maskEmailShort(e){ const i = String(e||'').indexOf('@'); if (i <= 0) return e||'未登录'; const u = e.slice(0,i), d = e.slice(i+1); return (u.length <= 1 ? '*' : u.slice(0,1)+'***') + '@' + d; }
    function updateAcctBadge(){ const a = getActiveCreds(); const el1 = el('acctInfo'); if (!el1) return; el1.textContent = a.oauthId ? (a.name || 'OAuth') : a.email ? maskEmailShort(a.email) : '未登录'; }
    function toggleSidebar(){ const s = document.querySelector('.sidebar'); if (s) s.classList.toggle('open'); }
    function closeAllModals(){ document.querySelectorAll('.modal').forEach(m => { if (m.id !== 'accountModal') m.style.display = 'none'; }); }
    // confirmDialog / closeAllModals 已在顶层公共区定义
    function toggleDark(){
      const dark = document.body.classList.toggle('dark');
      localStorage.setItem('mycf_dark', dark ? '1' : '0');
      const t = el('darkToggle'); if (t) t.textContent = dark ? '浅色' : '暗色';
    }
    window.toggleDark = toggleDark;
    async function restoreFromKV(){ try { const r = await fetch('/api', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'load-accounts-kv' }) }); const d = await r.json(); if (d.success && d.accounts && d.accounts.length) { const local = loadSaved(); const merged = d.accounts.slice(); local.forEach(a => { if (!merged.find(x => x.email === a.email)) merged.push(a); }); localStorage.setItem('cf_accounts', JSON.stringify(merged)); showNotification('已从 KV 恢复 ' + merged.length + ' 个账号'); updateAcctBadge(); openAccountSwitcher(); } else { showNotification('KV 中暂无账号', 'error'); } } catch(e){ showNotification('恢复失败', 'error'); } }
    function filterRows(containerId, q){ const c = el(containerId); if (!c) return; q = (q||'').toLowerCase().trim(); const rows = c.querySelectorAll('.worker-row, .kv-item, tbody tr'); if (!q) { rows.forEach(r => r.style.display = ''); return; } rows.forEach(r => { r.style.display = (r.textContent||'').toLowerCase().includes(q) ? '' : 'none'; }); }
    function sortTable(th, idx, type){ const table = th.closest('table'); if (!table) return; const tbody = table.querySelector('tbody'); const rows = Array.from(tbody.querySelectorAll('tr')); const asc = th.dataset.asc !== '1'; rows.sort((a,b) => { const va = (a.children[idx].textContent||'').trim(); const vb = (b.children[idx].textContent||'').trim(); let c = 0; if (type === 'num') { c = (parseFloat((va||'').replace(/[^0-9.]/g,''))||0) - (parseFloat((vb||'').replace(/[^0-9.]/g,''))||0); } else { c = va.localeCompare(vb, 'zh'); } return asc ? c : -c; }); rows.forEach(r => tbody.appendChild(r)); table.querySelectorAll('th[onclick]').forEach(h => h.dataset.asc = ''); th.dataset.asc = asc ? '1' : '0'; }
    document.addEventListener('keydown', function(e){
      if (e.key === 'Escape') { closeAllModals(); el('accountModal').style.display = 'none'; return; }
      const t = e.target; if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
      if (e.key === '/') { const s = document.querySelector('.list-search'); if (s) { e.preventDefault(); s.focus(); } return; }
      if (e.key === 'g') { window.__gNext = true; setTimeout(() => window.__gNext = false, 1000); return; }
      if (window.__gNext) { window.__gNext = false; const map = { w:'workers', d:'dns', k:'kv', i:'d1', m:'monitor', b:'bulk', s:'settings', p:'pages-manager', n:'snippets', o:'overview', a:'accounts' }; const pg = map[e.key.toLowerCase()]; if (pg) navTo(pg); }
    });
    (function initApp(){
      updateAcctBadge();
      if (localStorage.getItem('mycf_dark') === '1') { document.body.classList.add('dark'); const t = el('darkToggle'); if (t) t.textContent = '浅色'; }
      if (!getActiveCreds().email) {
        window.__kvRestorePromise = fetch('/api', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'load-accounts-kv' }) })
          .then(r => r.json()).then(d => {
            if (d.success && d.accounts && d.accounts.length) {
              const local = loadSaved(); const merged = d.accounts.slice(); local.forEach(a => { if (!merged.find(x => x.email === a.email)) merged.push(a); });
              localStorage.setItem('cf_accounts', JSON.stringify(merged));
              updateAcctBadge();
            }
          }).catch(()=>{});
      } else {
        window.__kvRestorePromise = Promise.resolve();
      }
    })();

    function renderBatchPage() {
        const arr = loadSaved(); const list = el('batchAccountList'); list.innerHTML = '';
        if (arr.length === 0) { list.innerHTML = '<div style="padding:10px;color:#999">请先在「账号库」添加账号</div>'; return; }
        arr.forEach((acc, idx) => {
            const div = document.createElement('div'); div.className = 'account-check-item';
            div.innerHTML = \`<label style="flex:1;cursor:pointer;display:flex;align-items:center"><input type="checkbox" class="batch-acc-chk" value="\${idx}" style="margin-right:8px"><span style="font-size:13px">\${escapeHtml(acc.email)}</span></label>\`; list.appendChild(div);
        });
        el('batchEnvList').innerHTML = ''; 
    }
    window.toggleSelectAllAccounts = function(checkbox) { document.querySelectorAll('.batch-acc-chk').forEach(c => c.checked = checkbox.checked); };
    window.toggleBatchSourceInput = function() {
      const type = el('batchScriptSourceType').value;
      el('batchSourceBuiltinDiv').style.display = (type==='builtin') ? 'block' : 'none';
      el('batchSourceUrlDiv').style.display    = (type==='url')     ? 'block' : 'none';
      el('batchSourceCustomDiv').style.display = (type==='custom')  ? 'block' : 'none';
      if (type === 'custom') {
        const saved = localStorage.getItem('cf_custom_worker_script');
        if (saved && !el('batchCustomScript').value) el('batchCustomScript').value = saved;
      }
    };
    function appendBatchLog(msg, color='#e2e8f0') { const log = el('batchLog'); const span = document.createElement('div'); span.style.color = color; span.textContent = \`[\${new Date().toLocaleTimeString()}] \${msg}\`; log.appendChild(span); log.scrollTop = log.scrollHeight; }
    
    // ==================== 自动解析 + 自定义脚本 ====================
    function parseScriptDeps(scriptContent, workerName) {
      var kvB=[], d1B=[], envV=[], seen={}, m;
      var reKv=new RegExp('env[.]([A-Za-z][A-Za-z0-9_]*)[.](?:get|put|delete|list|getWithMetadata)[ \\t]*[(]','g');
      var reD1=new RegExp('env[.]([A-Za-z][A-Za-z0-9_]*)[.](?:prepare|exec|batch|dump)[ \\t]*[(]','g');
      var reAll=new RegExp('env[.]([A-Za-z][A-Za-z0-9_]*)','g');
      var kvSet={}, d1Set={};
      while((m=reKv.exec(scriptContent))!==null) kvSet[m[1]]=true;
      while((m=reD1.exec(scriptContent))!==null) d1Set[m[1]]=true;
      while((m=reAll.exec(scriptContent))!==null) seen[m[1]]=true;
      Object.keys(seen).forEach(function(n){
        if(d1Set[n]) d1B.push(n);
        else if(kvSet[n]) kvB.push(n);
        else envV.push(n);
      });
      return {kvB:kvB, d1B:d1B, envV:envV};
    }

    function renderDepPreview(kvB, d1B, envV, wn) {
      var el2=el('scriptDepPreview'); if(!el2) return;
      if(!kvB.length&&!d1B.length&&!envV.length){el2.style.display='none';return;}
      var h='<div style="font-weight:600;margin-bottom:8px;color:#374151">&#128269; 检测到以下依赖（已自动填充到下方表单）</div>';
      var tag=function(bg,c,b,t){return '<span style="background:'+bg+';color:'+c+';border:1px solid '+b+';border-radius:4px;padding:1px 7px;font-size:11px;font-weight:600;margin-right:6px">'+t+'</span>';};
      var pill=function(v){return '<span style="background:#f1f5f9;border-radius:4px;padding:2px 8px;margin-right:4px;font-family:monospace">'+v+'</span>';};
      if(kvB.length){
        h+='<div style="margin-bottom:6px">'+tag('#eff6ff','#1e40af','#bfdbfe','KV');
        kvB.forEach(function(b){h+=pill(b)+'<span style="color:#9ca3af;font-size:11px">&#8594;'+wn+'-'+b+'</span>&ensp;';});
        h+='</div>';
      }
      if(d1B.length){
        h+='<div style="margin-bottom:6px">'+tag('#fff7ed','#9a3412','#fed7aa','D1');
        d1B.forEach(function(b){h+=pill(b)+'<span style="color:#9ca3af;font-size:11px">&#8594;'+wn+'-'+b+'</span>&ensp;';});
        h+='</div>';
      }
      if(envV.length){
        h+='<div>'+tag('#f0fdf4','#166534','#bbf7d0','ENV');
        envV.forEach(function(v){h+=pill(v);});
        h+='<span style="color:#ef4444;font-size:11px;margin-left:6px">&#9888;&#65039; 请在下方填写变量值</span></div>';
      }
      el2.innerHTML=h; el2.style.display='block';
    }

    function fillDepsFromScript(scriptContent, wn) {
      var d=parseScriptDeps(scriptContent,wn);
      el('batchKvList').innerHTML=''; el('batchD1List').innerHTML=''; el('batchEnvList').innerHTML='';
      d.kvB.forEach(function(b){addBatchKvRow(b,wn+'-'+b);});
      d.d1B.forEach(function(b){addBatchD1Row(b,wn+'-'+b);});
      d.envV.forEach(function(v){
        var div=document.createElement('div');
        div.className='env-row-batch'; div.style.cssText='display:flex;gap:8px;margin-top:6px';
        div.innerHTML='<input class="input b-env-key" placeholder="Key" value="'+v+'" style="flex:1">'
                     +'<input class="input b-env-val" placeholder="请填写变量值" style="flex:1">'
                     +'<button class="trash-btn" onclick="this.parentElement.remove()">&#10005;</button>';
        el('batchEnvList').appendChild(div);
      });
      renderDepPreview(d.kvB,d.d1B,d.envV,wn);
      var total=d.kvB.length+d.d1B.length+d.envV.length;
      var st=el('autoParseStatus');
      if(st) st.textContent=total>0?('✅ KV:'+d.kvB.length+'  D1:'+d.d1B.length+'  ENV:'+d.envV.length):'✅ 无依赖，可直接部署';
      showNotification(total>0?('解析完成 KV:'+d.kvB.length+' D1:'+d.d1B.length+' ENV:'+d.envV.length+(d.envV.length?'，请填写 ENV 值':'')):'未检测到依赖，可直接部署');
    }

    // ===== GitHub URL 智能转换 =====
    var WORKER_FILENAMES = ['_worker.js', 'worker.js', 'index.js', 'src/worker.js', 'src/index.js'];

    function githubToRaw(ghUrl) {
      // https://github.com/user/repo/blob/branch/path -> raw
      var m = ghUrl.match(new RegExp('github[.]com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)'));

      if (m) return 'https://raw.githubusercontent.com/' + m[1] + '/' + m[2] + '/' + m[3] + '/' + m[4];
      // https://github.com/user/repo/tree/branch -> raw base (partial, needs file)
      return null;
    }

    function isRawUrl(url) {
      return url.includes('raw.githubusercontent.com') || url.includes('raw.github.com') || url.includes('cdn.jsdelivr.net');
    }

    function isGithubRepo(url) {
      // matches github.com/user/repo with optional trailing /tree/branch but NO /blob/ and NO raw
      return new RegExp('github[.]com/[^/]+/[^/]+(/tree/[^/]+)?/?$').test(url) && !url.includes('/blob/') && !isRawUrl(url);

    }

    window.normalizeGithubUrl = function(input) {
      var val = input.value.trim();
      var hint = el('urlConvertHint');
      if (!val || isRawUrl(val)) { if(hint) hint.style.display='none'; return; }
      var raw = githubToRaw(val);
      if (raw) {
        input.value = raw;
        if(hint){ hint.textContent = '✅ 已转换为 raw 链接'; hint.style.display='block'; }
        return;
      }
      if (isGithubRepo(val)) {
        if(hint){ hint.textContent = '🔍 检测到 GitHub 仓库，点击「自动解析」将自动查找 _worker.js'; hint.style.display='block'; }
      } else {
        if(hint) hint.style.display='none';
      }
    };

    async function resolveScriptUrl(inputUrl) {
      // Already a raw/direct URL
      if (isRawUrl(inputUrl)) return { url: inputUrl, converted: false };

      // blob URL -> convert to raw
      var raw = githubToRaw(inputUrl);
      if (raw) return { url: raw, converted: true, msg: '已转换 blob 链接为 raw 链接' };

      // GitHub repo URL -> search for worker file
      if (isGithubRepo(inputUrl)) {
        // Extract user/repo/branch
        var m = inputUrl.match(new RegExp('github[.]com/([^/]+)/([^/]+)(?:/tree/([^/]+))?'));

        if (!m) return { url: inputUrl, converted: false };
        var user = m[1], repo = m[2], branch = m[3] || null;

        // Get default branch if not specified
        if (!branch) {
          try {
            var apiUrl = 'https://api.github.com/repos/' + user + '/' + repo;
            var r = await fetch(apiUrl, { headers: { 'Accept': 'application/vnd.github.v3+json' } });
            if (r.ok) { var info = await r.json(); branch = info.default_branch || 'main'; }
            else branch = 'main';
          } catch(e) { branch = 'main'; }
        }

        // Search for worker files in order
        for (var i = 0; i < WORKER_FILENAMES.length; i++) {
          var fname = WORKER_FILENAMES[i];
          var rawUrl = 'https://raw.githubusercontent.com/' + user + '/' + repo + '/' + branch + '/' + fname;
          try {
            var resp = await fetch(rawUrl, { method: 'HEAD' });
            if (resp.ok) {
              return { url: rawUrl, converted: true, msg: '找到 ' + fname + '，已转换为 raw 链接' };
            }
          } catch(e) {}
        }
        // Try GitHub API tree to find any .js file
        try {
          var treeUrl = 'https://api.github.com/repos/' + user + '/' + repo + '/git/trees/' + branch + '?recursive=1';
          var tr = await fetch(treeUrl, { headers: { 'Accept': 'application/vnd.github.v3+json' } });
          if (tr.ok) {
            var tree = await tr.json();
            var jsFiles = (tree.tree || []).filter(function(f){ return f.type === 'blob' && f.path.endsWith('.js') && !f.path.includes('node_modules'); });
            if (jsFiles.length > 0) {
              var best = jsFiles.sort(function(a,b){ return a.path.length - b.path.length; })[0];
              var rawUrl2 = 'https://raw.githubusercontent.com/' + user + '/' + repo + '/' + branch + '/' + best.path;
              return { url: rawUrl2, converted: true, msg: '未找到 _worker.js，使用 ' + best.path };
            }
          }
        } catch(e) {}
        return { url: inputUrl, converted: false, error: '未能在该仓库找到 JS 文件' };
      }

      return { url: inputUrl, converted: false };
    }

    window.autoFillFromRemoteScript = async function() {
      var url=el('batchScriptUrl').value.trim();
      if(!url) return showNotification('请先输入脚本链接','error');
      var wn=(el('batchWorkerName').value.trim()||'worker');
      var st=el('autoParseStatus'); if(st) st.textContent='⏳ 正在解析链接...';
      var hint=el('urlConvertHint');
      var btn=document.querySelector('[onclick="autoFillFromRemoteScript()"]');
      if(btn){btn.disabled=true;btn.textContent='⏳ 解析中...';}
      // Step1: 智能解析 URL（GitHub 仓库自动查找 _worker.js）
      var resolved;
      try{
        if(st) st.textContent='⏳ 正在查找脚本文件...';
        resolved = await resolveScriptUrl(url);
        if(resolved.error){if(st)st.textContent='❌ '+resolved.error; showNotification(resolved.error,'error'); if(btn){btn.disabled=false;btn.textContent='\uD83D\uDD0D 自动解析';} return;}
        if(resolved.converted){
          el('batchScriptUrl').value = resolved.url;
          if(hint){hint.textContent='✅ '+resolved.msg;hint.style.display='block';}
          showNotification(resolved.msg);
        }
        url = resolved.url;
      }catch(e){
        if(st)st.textContent='❌ 链接解析失败: '+e.message;
        if(btn){btn.disabled=false;btn.textContent='\uD83D\uDD0D 自动解析';} return;
      }
      if(st) st.textContent='⏳ 正在获取脚本内容...';
      // 15秒超时
      var controller=new AbortController();
      var timer=setTimeout(function(){controller.abort();},15000);
      try{
        // 直接在前端 fetch，避免经过 Worker 中转的延迟
        var fetchRes=await fetch(url,{signal:controller.signal,headers:{'User-Agent':'Mozilla/5.0'}}).catch(function(){
          return null;
        });
        clearTimeout(timer);
        var scriptContent=null;
        if(fetchRes && fetchRes.ok){
          scriptContent=await fetchRes.text();
        } else {
          // 前端直接 fetch 失败（跨域等），回退到 Worker 中转
          if(st) st.textContent='⏳ 直连失败，通过服务器中转获取...';
          var controller2=new AbortController();
          var timer2=setTimeout(function(){controller2.abort();},20000);
          try{
            var res=await api('fetch-external-script',{url:url});
            clearTimeout(timer2);
            if(!res.success){if(st)st.textContent='❌ '+(res.error||'获取失败');return;}
            scriptContent=res.content;
          }catch(e2){
            clearTimeout(timer2);
            if(st)st.textContent='❌ 中转超时，请检查链接是否可访问';
            showNotification('获取失败：'+e2.message,'error');
            return;
          }
        }
        if(!scriptContent){if(st)st.textContent='❌ 获取到空内容';return;}
        fillDepsFromScript(scriptContent,wn);
      }catch(e){
        clearTimeout(timer);
        var msg=e.name==='AbortError'?'请求超时(15s)，链接可能无法访问':e.message;
        if(st)st.textContent='❌ '+msg;
        showNotification(msg,'error');
      }finally{
        if(btn){btn.disabled=false;btn.textContent='\uD83D\uDD0D 自动解析';}
      }
    }

    window.autoFillFromCustomScript = function() {
      var s=el('batchCustomScript').value.trim();
      if(!s) return showNotification('脚本内容为空','error');
      fillDepsFromScript(s,(el('batchWorkerName').value.trim()||'worker'));
    }

    window.saveCustomScriptFile = function() {
      var s=el('batchCustomScript').value;
      if(!s.trim()) return showNotification('脚本内容为空','error');
      localStorage.setItem('cf_custom_worker_script',s);
      var blob=new Blob([s],{type:'text/javascript'});
      var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='_worker.js';
      a.click(); URL.revokeObjectURL(a.href);
      showNotification('已保存并下载为 _worker.js');
    }

    var _cstTimer=null;
    document.addEventListener('input',function(e){
      if(e.target&&e.target.id==='batchCustomScript'){
        localStorage.setItem('cf_custom_worker_script',e.target.value);
        clearTimeout(_cstTimer);
        var val=e.target.value;
        _cstTimer=setTimeout(function(){
          if(val.trim()) fillDepsFromScript(val,(el('batchWorkerName')&&el('batchWorkerName').value.trim()||'worker'));
        },800);
      }
    });

    window.addBatchKvRow = function(bind,name){
      bind=bind||''; name=name||'';
      var div=document.createElement('div');
      div.className='env-row-batch batch-kv-row'; div.style.cssText='display:flex;gap:8px;margin-top:6px';
      div.innerHTML='<input class="input b-kv-bind" placeholder="绑定变量名 (如 MY_KV)" value="'+bind+'" style="flex:1">'
                   +'<input class="input b-kv-name" placeholder="KV空间名(留空自动命名)" value="'+name+'" style="flex:1">'
                   +'<button class="trash-btn" onclick="this.parentElement.remove()">&#10005;</button>';
      el('batchKvList').appendChild(div);
    }

    window.addBatchD1Row = function(bind,name){
      bind=bind||''; name=name||'';
      var div=document.createElement('div');
      div.className='env-row-batch batch-d1-row'; div.style.cssText='display:flex;gap:8px;margin-top:6px';
      div.innerHTML='<input class="input b-d1-bind" placeholder="绑定变量名 (如 DB)" value="'+bind+'" style="flex:1">'
                   +'<input class="input b-d1-name" placeholder="数据库名(留空自动命名)" value="'+name+'" style="flex:1">'
                   +'<button class="trash-btn" onclick="this.parentElement.remove()">&#10005;</button>';
      el('batchD1List').appendChild(div);
    }
    // ==================== end ====================

    window.addBatchEnvRow = function() {
        const div = document.createElement('div'); div.className='env-row-batch';
        div.innerHTML = \`<input class="input b-env-key" placeholder="Key" style="flex:1"><input class="input b-env-val" placeholder="Value" style="flex:1"><button class="trash-btn" onclick="this.parentElement.remove()">✕</button>\`;
        el('batchEnvList').appendChild(div);
    };

    async function startBatchCreate() {
        const name = el('batchWorkerName').value.trim();
        if (!name) return alert('请输入 Worker 名称');
        const chks = Array.from(document.querySelectorAll('.batch-acc-chk:checked'));
        if (chks.length === 0) return alert('请至少选择一个账号');

        const enableSubdomain = el('batchEnableSubdomain').checked;

        const sourceType = el('batchScriptSourceType').value;
        let scriptUrl = '', _customScript = '';
        if (sourceType === 'builtin') {
            const idx = el('batchBuiltinSelect').value;
            if (idx === '' || !BATCH_CONFIG.urls[idx]) return alert('请选择有效的模板或检查环境变量配置');
            scriptUrl = BATCH_CONFIG.urls[idx];
        } else if (sourceType === 'custom') {
            _customScript = el('batchCustomScript').value.trim();
            if (!_customScript) return alert('自定义脚本内容为空，请先编写脚本');
        } else {
            scriptUrl = el('batchScriptUrl').value.trim();
            if (!scriptUrl) return alert('请输入脚本链接');
        }

        const bindings = [];
        el('batchEnvList').querySelectorAll('.env-row-batch').forEach(row => {
            const k = row.querySelector('.b-env-key').value.trim();
            const v = row.querySelector('.b-env-val').value;
            if (k) bindings.push({ type: 'plain_text', name: k, text: v });
        });
        
        const _wn = el('batchWorkerName').value.trim() || 'worker';
        const kvRows = [...el('batchKvList').querySelectorAll('.batch-kv-row')].map(r => ({
            bind: r.querySelector('.b-kv-bind').value.trim(),
            name: r.querySelector('.b-kv-name').value.trim() || (_wn+'-'+r.querySelector('.b-kv-bind').value.trim())
        })).filter(r => r.bind);
        const d1Rows = [...el('batchD1List').querySelectorAll('.batch-d1-row')].map(r => ({
            bind: r.querySelector('.b-d1-bind').value.trim(),
            name: r.querySelector('.b-d1-name').value.trim() || (_wn+'-'+r.querySelector('.b-d1-bind').value.trim())
        })).filter(r => r.bind);

        let scriptContent = '';
        if (_customScript) {
            scriptContent = _customScript;
            appendBatchLog('使用自定义脚本（' + scriptContent.length + ' 字符）', '#60a5fa');
        } else {
            appendBatchLog('正在获取远程脚本: ' + scriptUrl, '#60a5fa');
            try {
                const res = await api('fetch-external-script', { url: scriptUrl });
                if (res.success) { scriptContent = res.content; appendBatchLog('脚本获取成功', '#4ade80'); }
                else { appendBatchLog('脚本获取失败: ' + res.error, '#f87171'); return; }
            } catch (e) { appendBatchLog('脚本获取异常: ' + e.message, '#ef4444'); return; }
        }

        if (!scriptContent) return alert('脚本内容为空');

        const accounts = loadSaved();
        el('batchLog').innerHTML = ''; 
        let _wSuccess = 0, _wFail = 0, _wFailedAccts = [];
        appendBatchLog(\`开始批量部署，共选中 \${chks.length} 个账号\`, '#fbbf24');

        for (const chk of chks) {
            const idx = parseInt(chk.value);
            const acc = accounts[idx];
            if (!acc) continue;
            
            const creds = { email: acc.email, key: acc.key };

            appendBatchLog(\`正在处理账号: \${acc.email} ...\`);
            
            try {
                const accRes = await api('list-accounts', creds);
                if (!accRes.success || !accRes.result || !accRes.result.length) {
                    _wFail++; _wFailedAccts.push(acc.email);
                    appendBatchLog(\`❌ \${acc.email}: 获取账户ID失败\`, '#ef4444'); continue;
                }
                const accountId = accRes.result[0].id;
                creds.accountId = accountId;

                const localBindings = [...bindings];

                // 处理多 KV
                const _kvListRes = kvRows.length > 0 ? await api('list-kv-namespaces', creds) : null;
                for (const kv of kvRows) {
                    appendBatchLog('   ↳ 检查 KV: ' + kv.name + '', '#94a3b8');
                    let targetKv = (_kvListRes && _kvListRes.result) ? _kvListRes.result.find(k => k.title === kv.name) : null;
                    if (!targetKv) {
                        appendBatchLog('   ↳ 创建 KV: ' + kv.name + '', '#fbbf24');
                        const createKv = await api('create-kv-namespace', { ...creds, title: kv.name });
                        if (createKv.success && createKv.result) targetKv = createKv.result;
                        else { appendBatchLog('   ⚠️ KV创建失败: ' + (createKv.error||''), '#ef4444'); continue; }
                    }
                    if (targetKv) localBindings.push({ type: 'kv_namespace', name: kv.bind, namespace_id: targetKv.id });
                }

                // 处理多 D1
                const _d1ListRes = d1Rows.length > 0 ? await api('list-d1', creds) : null;
                for (const d1 of d1Rows) {
                    appendBatchLog('   ↳ 检查 D1: ' + d1.name + '', '#9ca3af');
                    let targetD1 = (_d1ListRes && _d1ListRes.result) ? _d1ListRes.result.find(d => d.name === d1.name) : null;
                    if (!targetD1) {
                        appendBatchLog('   ↳ 创建 D1: ' + d1.name + '', '#fbbf24');
                        const createD1 = await api('create-d1-database', { ...creds, name: d1.name });
                        if (createD1.success && createD1.result) targetD1 = createD1.result;
                        else { appendBatchLog('   ⚠️ D1创建失败: ' + (createD1.error||''), '#ef4444'); continue; }
                    }
                    if (targetD1) localBindings.push({ type: 'd1', name: d1.bind, id: targetD1.uuid || targetD1.id });
                }

                const enableCpuLimit = true;
                const deployRes = await api('deploy-worker', { 
                    ...creds,
                    scriptName: name,
                    scriptSource: scriptContent,
                    metadataBindings: localBindings,
                    enableCpuLimit
                });

                if (deployRes.success) {
                    _wSuccess++;
                    appendBatchLog(\`✅ \${acc.email}: 部署成功\`, '#4ade80');
                    if (deployRes.autoDowngraded) {
                        appendBatchLog('   ⚠️ 免费计划不支持部署CPU限制已略过', '#fbbf24');
                    } else {
                        appendBatchLog('   ✅ 已经成功部署CPU限制', '#4ade80');
                    }

                    const enableSubdomain = el('batchEnableSubdomain').checked;
                    appendBatchLog(\`   ↳ 设置子域名: \${enableSubdomain ? '开启' : '关闭'}\`, '#9ca3af');
                    const toggleRes = await api('toggle-worker-subdomain', { ...creds, scriptName: name, enabled: enableSubdomain });
                    
                    if (enableSubdomain) {
                        const subRes = await api('get-workers-subdomain', creds);
                        if (subRes.success && subRes.result.subdomain) {
                            const fullUrl = \`https://\${name}.\${subRes.result.subdomain}.workers.dev\`;
                            appendBatchLog(\`   🔗 \${fullUrl}\`, '#60a5fa');
                        } else {
                            appendBatchLog(\`   ⚠️ 无法获取子域名信息，请确认账号已配置 Workers 子域名\`, '#fbbf24');
                        }
                    }

                } else {
                    _wFail++; _wFailedAccts.push(acc.email);
                    appendBatchLog(\`❌ \${acc.email}: \${deployRes.error}\`, '#ef4444');
                }

            } catch (e) {
                _wFail++; _wFailedAccts.push(acc.email);
                appendBatchLog(\`❌ \${acc.email}: 异常 \${e.message}\`, '#ef4444');
            }
        }
        appendBatchLog('批量操作结束', '#fcd34d');
        appendBatchLog(\`总计: \${chks.length} 个账号，成功: \${_wSuccess} 个，失败: \${_wFail} 个\`, '#fbbf24');
        if (_wFailedAccts.length > 0) {
            appendBatchLog('失败账号: ' + _wFailedAccts.join(', '), '#f87171');
        }
    }
    window.startBatchCreate = startBatchCreate;

let pagesSelectedFiles = [];
let pagesUploadInited = false;
function pagesNode(id) { return document.getElementById(id); }
function pagesLog(text, color) { const box=pagesNode('pagesBatchLog'); if(!box)return; const d=document.createElement('div'); d.style.color=color||'#e2e8f0'; d.textContent='['+new Date().toLocaleTimeString()+'] '+text; box.appendChild(d); box.scrollTop=box.scrollHeight; }
function pagesMime(path, type) { if(type)return type; const x=(path.split('.').pop()||'').toLowerCase(); return ({html:'text/html',htm:'text/html',css:'text/css',js:'application/javascript',mjs:'application/javascript',json:'application/json',svg:'image/svg+xml',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',webp:'image/webp',gif:'image/gif',ico:'image/x-icon',woff:'font/woff',woff2:'font/woff2',ttf:'font/ttf',wasm:'application/wasm',txt:'text/plain',map:'application/json'})[x]||'application/octet-stream'; }
function pagesSummary(label) { const n=pagesSelectedFiles.reduce(function(a,x){return a+x.file.size;},0); const out=pagesNode('pagesFileSummary'); if(out)out.textContent=label+'：'+pagesSelectedFiles.length+' 个文件，'+(n/1048576).toFixed(2)+' MiB'; }
async function pagesEntry(entry,prefix,out) { if(entry.isFile){const f=await new Promise(function(ok,bad){entry.file(ok,bad);});out.push({path:prefix+f.name,file:f,stripRoot:true});return;} if(!entry.isDirectory)return;const r=entry.createReader();let all=[];while(true){const a=await new Promise(function(ok,bad){r.readEntries(ok,bad);});if(!a.length)break;all=all.concat(Array.from(a));}for(const e of all)await pagesEntry(e,prefix+entry.name+'/',out); }
async function pagesZip(file){if(typeof JSZip==='undefined')throw new Error('JSZip 加载失败，请刷新页面');const z=await JSZip.loadAsync(await file.arrayBuffer());const out=[];for(const name of Object.keys(z.files)){const e=z.files[name];if(e.dir)continue;const bytes=await e.async('uint8array');const blob=new Blob([bytes],{type:pagesMime(name,'')});out.push({path:name,file:new File([blob],name,{type:blob.type}),stripRoot:false});}return out;}
function pagesPath(item){let p=String(item.path||'').split(String.fromCharCode(92)).join('/');while(p.startsWith('/'))p=p.slice(1);if(item.stripRoot){const n=p.indexOf('/');if(n>0)p=p.slice(n+1);}return '/'+p;}
function initPagesUploadArea(){if(pagesUploadInited)return;const drop=pagesNode('pagesUploadDrop'),folder=pagesNode('pagesFolderInput'),zip=pagesNode('pagesZipInput'),mode=pagesNode('pagesUploadMode');if(!drop||!folder||!zip||!mode)return;pagesUploadInited=true;drop.onclick=function(){(mode.value==='zip'?zip:folder).click();};['dragenter','dragover'].forEach(function(k){drop.addEventListener(k,function(e){e.preventDefault();drop.style.borderColor='#2563eb';});});['dragleave','drop'].forEach(function(k){drop.addEventListener(k,function(e){e.preventDefault();drop.style.borderColor='#cbd5e1';});});drop.addEventListener('drop',async function(e){try{if(mode.value==='zip'){const f=Array.from(e.dataTransfer.files||[]).find(function(x){return String(x.name).toLowerCase().endsWith('.zip');;});if(!f)throw new Error('ZIP 模式请拖入 .zip 文件');pagesSelectedFiles=await pagesZip(f);pagesSummary('ZIP '+f.name);}else{const out=[];const entries=Array.from(e.dataTransfer.items||[]).map(function(x){return x.webkitGetAsEntry&&x.webkitGetAsEntry();}).filter(Boolean);if(entries.length){for(const entry of entries)await pagesEntry(entry,'',out);}else Array.from(e.dataTransfer.files||[]).forEach(function(f){out.push({path:f.webkitRelativePath||f.name,file:f,stripRoot:!!f.webkitRelativePath});});pagesSelectedFiles=out;pagesSummary('拖入文件夹');}}catch(err){showNotification(err.message||String(err),'error');}});folder.onchange=function(){pagesSelectedFiles=Array.from(folder.files||[]).map(function(f){return{path:f.webkitRelativePath||f.name,file:f,stripRoot:!!f.webkitRelativePath};});pagesSummary('选择文件夹');};zip.onchange=async function(){try{if(!zip.files[0])return;pagesSelectedFiles=await pagesZip(zip.files[0]);pagesSummary('ZIP '+zip.files[0].name);}catch(err){showNotification(err.message||String(err),'error');}};}
function renderPagesBatchPage(){initPagesUploadArea();const list=pagesNode('pagesAccountList');if(!list)return;const accounts=loadSaved();list.innerHTML='';accounts.forEach(function(a,i){const row=document.createElement('div');row.className='account-check-item';row.innerHTML='<label style="display:flex;align-items:center;flex:1;cursor:pointer;font-size:13px"><input type="checkbox" class="pages-acc-chk" value="'+i+'" style="margin-right:8px">'+escapeHtml(a.email)+'</label>';list.appendChild(row);});}
window.toggleSelectAllPagesAccounts=function(box){document.querySelectorAll('.pages-acc-chk').forEach(function(x){x.checked=!!box.checked;});};
async function pagesFiles(){if(!pagesSelectedFiles.length)throw new Error('请先选择文件夹或 ZIP');if(pagesSelectedFiles.length>1000)throw new Error('文件数超过 1000');if(typeof SparkMD5==='undefined')throw new Error('SparkMD5 加载失败，请刷新页面');const result=[],seen=new Set();for(let i=0;i<pagesSelectedFiles.length;i++){const item=pagesSelectedFiles[i],file=item.file,path=pagesPath(item);if(path==='/'||path.includes('/../')||seen.has(path))throw new Error('非法或重复路径：'+path);if(file.size>25*1024*1024)throw new Error('单文件超过 25 MiB：'+path);seen.add(path);const buf=await file.arrayBuffer(),bytes=new Uint8Array(buf);let bin='';for(let p=0;p<bytes.length;p+=0x8000)bin+=String.fromCharCode.apply(null,bytes.subarray(p,Math.min(p+0x8000,bytes.length)));let hashPath=path;if(!hashPath.startsWith('/'))hashPath='/'+hashPath;const assetHasher=new SparkMD5.ArrayBuffer();assetHasher.append(buf);assetHasher.append(new TextEncoder().encode(hashPath).buffer);result.push({path:path,hash:assetHasher.end(),base64:btoa(bin),contentType:pagesMime(path,file.type)});if((i+1)%20===0)pagesLog('已处理 '+(i+1)+'/'+pagesSelectedFiles.length+' 文件','#60a5fa');}return result;}
async function startPagesBatchDeploy(){const name=String(pagesNode('pagesProjectName').value||'').trim().toLowerCase(),branch=String(pagesNode('pagesBranch').value||'main').trim()||'main',enableCpuLimit=true,checks=Array.from(document.querySelectorAll('.pages-acc-chk:checked'));if(!/^[a-z0-9](?:[a-z0-9-]{0,56}[a-z0-9])?$/.test(name))return showNotification('项目名仅支持小写字母、数字、连字符，长度 2-58','error');if(!checks.length)return showNotification('至少选择一个账号','error');const log=pagesNode('pagesBatchLog');if(log)log.innerHTML='';try{pagesLog('正在读取和 hash 文件…','#93c5fd');const files=await pagesFiles(),accounts=loadSaved();pagesLog('共 '+files.length+' 个文件，开始部署。','#fcd34d');var _pSuccess=0,_pFail=0,_pFailedAccts=[];for(const c of checks){const a=accounts[Number(c.value)];if(!a)continue;const creds={email:a.email,key:a.key};const ars=await api('list-accounts',creds),aid=ars&&ars.result&&ars.result[0]&&ars.result[0].id;if(!aid){pagesLog('✗ '+a.email+'：无法获取 Account ID','#f87171');_pFail++;_pFailedAccts.push(a.email);continue;}const r=await api('deploy-pages-direct',{email:a.email,key:a.key,accountId:aid,projectName:name,branch:branch,enableCpuLimit:enableCpuLimit,cpuMs:300000,files:files});if(r&&r.success){_pSuccess++;pagesLog('✓ '+a.email+'：部署成功','#4ade80');if(r.autoDowngraded){pagesLog('   ⚠️ 免费计划不支持部署CPU限制已略过','#fbbf24');}else{pagesLog('   ✅ 已经成功部署CPU限制','#4ade80');}pagesLog('  '+(r.url||'https://'+name+'.pages.dev'),'#60a5fa');}else{_pFail++;_pFailedAccts.push(a.email);pagesLog('✗ '+a.email+' ['+((r&&r.step)||'unknown')+']：'+((r&&r.error)||'部署失败'),'#f87171');}}pagesLog('全部任务结束。','#fcd34d');pagesLog('总计: '+checks.length+' 个账号，成功: '+_pSuccess+' 个，失败: '+_pFail+' 个','#fbbf24');if(_pFailedAccts.length>0)pagesLog('失败账号: '+_pFailedAccts.join(', '),'#f87171');}catch(e){pagesLog('✗ '+(e.message||String(e)),'#f87171');}}
window.startPagesBatchDeploy=startPagesBatchDeploy;

async function refreshPagesManager(){
  const box=el('pagesManagerList'); if(!box)return; box.innerHTML='<div class="small">正在读取 Pages 项目...</div>';
  try{
    // 账号可在登录页切换：每次都以当前凭据重新获取 ID，不能复用上一账号缓存。
    const ar=await api('list-accounts');
    const accountId=ar&&ar.result&&ar.result[0]&&ar.result[0].id;
    if(accountId)localStorage.setItem('cfaccountId',accountId);
    if(!accountId)throw new Error((ar&&ar.error)||'无法获取当前账号的 Account ID');
    const res=await api('list-pages-projects',{accountId:accountId}); const projects=res&&res.success&&Array.isArray(res.result)?res.result:[];
    box.innerHTML=''; if(!projects.length){box.innerHTML='<div class="small">当前账号没有 Pages 项目。</div>';return;}
    projects.sort(function(x,y){return String(y.created_on||'').localeCompare(String(x.created_on||''));});
    projects.forEach(function(p){
      const name=p.name||p.id||'unknown', domain=p.subdomain||(name+'.pages.dev'), latest=p.latest_deployment||p.canonical_deployment||{};
      const row=document.createElement('div');row.className='worker-row';
      const cb=document.createElement('input');cb.type='checkbox';cb.className='pages-cb';cb.value=name;cb.style.marginRight='16px';cb.style.alignSelf='center';row.appendChild(cb);
      const info=document.createElement('div');info.className='worker-info';
      const title=document.createElement('div');title.style.fontWeight='700';title.textContent=name;
      const meta=document.createElement('div');meta.className='worker-meta';meta.textContent='生产分支：'+(p.production_branch||'main')+'　创建时间：'+(p.created_on?new Date(p.created_on).toLocaleString():'-');
      const deploy=document.createElement('div');deploy.className='worker-meta';deploy.style.marginTop='5px';deploy.textContent='最近部署：'+(latest.created_on?new Date(latest.created_on).toLocaleString():'-');
      const link=document.createElement('a');link.className='domain-tag workers-dev';link.href='https://'+domain;link.target='_blank';link.rel='noopener';link.textContent=domain;
      info.append(title,meta,deploy,link);
      const right=document.createElement('div');right.className='worker-right';const buttons=document.createElement('div');buttons.className='btns';
      const open=document.createElement('button');open.className='btn';open.textContent='打开站点';open.onclick=function(){window.open('https://'+domain,'_blank','noopener');};
      const del=document.createElement('button');del.className='btn danger';del.textContent='删除项目';del.onclick=function(){deletePagesProject(name,domain);};
      buttons.append(open,del);right.appendChild(buttons);row.append(info,right);box.appendChild(row);
    });
  }catch(e){box.innerHTML='<div class="small" style="color:#ef4444">读取失败：'+escapeHtml(e.message||String(e))+'</div>';}
}
async function deletePagesProject(name,domain){
  confirmDialog('确定删除 Pages 项目「'+name+'」？删除全部部署且不可恢复。\\n默认域名：'+domain, async () => {
    try{const ar=await api('list-accounts');const accountId=ar&&ar.result&&ar.result[0]&&ar.result[0].id;if(!accountId)throw new Error((ar&&ar.error)||'无法获取当前账号的 Account ID');localStorage.setItem('cfaccountId',accountId);const r=await api('delete-pages-project',{accountId:accountId,projectName:name});if(r&&r.success){showNotification('已删除：'+name);refreshPagesManager();}else showNotification((r&&r.error)||'删除失败','error');}catch(e){showNotification(e.message||String(e),'error');}
  });
}
window.refreshPagesManager=refreshPagesManager;window.deletePagesProject=deletePagesProject;



    async function refreshWorkers() {
      el('workersList').innerHTML = '加载中...';
      const accounts = await api('list-accounts');
      if (!accounts || !accounts.result) { 
        el('workersList').innerHTML = '无法获取账户'; 
        return; 
      }
      const accountId = accounts.result[0].id || accounts.result[0].account_id;
      localStorage.setItem('cf_accountId', accountId);
      const res = await api('list-workers', { accountId });
      if (!res || !res.result) { 
        el('workersList').innerHTML = '获取 Workers 失败'; 
        return; 
      }
      
      el('workersList').innerHTML = '';
      res.result.forEach(w => {
        const name = w.id || w.name || w.script_name;
        const created = w.created_on || w.created_at || w.modified_on || '';
        const defaultDomain = w.defaultDomain;
        const domains = w.domains || [];
        const bindings = w.bindings || [];
        const subdomainEnabled = w.subdomainEnabled !== false;
        
        const envBindings = bindings.filter(b => b.type === 'plain_text' || b.type === 'secret_text');
        const kvBindings = bindings.filter(b => b.type === 'kv_namespace');
        const d1Bindings = bindings.filter(b => b.type === 'd1' || b.type === 'd1_database');
        
        const div = document.createElement('div'); 
        div.className='worker-row';
        div.innerHTML = \`
          <input type="checkbox" class="worker-cb" value="\${name}" style="margin-right: 16px; align-self: center;">
          <div class="worker-info">
            <div style="font-weight:700">\${name}</div>
            <div class="worker-meta">创建时间：\${created}</div>
            
            \${defaultDomain ? \`
              <div class="worker-domains">
                <div class="small" style="margin-bottom:2px;">默认域名:</div>
                <div style="display:flex;align-items:center;gap:12px">
                  <a href="https://\${defaultDomain.hostname}" target="_blank" class="domain-tag workers-dev">
                    \${defaultDomain.hostname}
                    <span class="domain-status \${subdomainEnabled ? 'active' : 'inactive'}">\${subdomainEnabled ? '已启用' : '已禁用'}</span>
                  </a>
                  <div class="domain-control" style="margin:0">
                     <label class="switch">
                       <input type="checkbox" \${subdomainEnabled ? 'checked' : ''} onchange="toggleWorkerSubdomain('\${name}', this.checked)">
                       <span class="slider"></span>
                     </label>
                     <span class="small" style="margin-left:8px">\${subdomainEnabled ? '已开启' : '已关闭'}</span>
                  </div>
                </div>
              </div>
            \` : '<div class="worker-meta" style="color:#ef4444">Workers 域名未设置</div>'}
            
            <div class="worker-domains" style="margin-top:8px">
              <div class="small" style="margin-bottom:2px;">自定义域名:</div>
              \${domains.length > 0 ? domains.map(domain => {
                const status = domain.status || 'active';
                const statusText = status === 'active' ? '已启用' : '待处理';
                const statusClass = status === 'active' ? 'active' : 'pending';
                
                return \`
                  <div style="display:inline-block;position:relative">
                    <a href="https://\${escapeHtml(domain.hostname)}" target="_blank" class="domain-tag">
                      \${escapeHtml(domain.hostname)}
                      <span class="domain-status \${statusClass}">\${statusText}</span>
                    </a>
                    <span class="del-domain-btn" title="删除域名" onclick="deleteWorkerDomain('\${name}', '\${domain.id}', '\${escapeHtml(domain.hostname)}')">✕</span>
                  </div>
                \`;
              }).join('') : '<span class="small" style="color:#94a3b8">暂无自定义域名</span>'}
            </div>
          </div>
          
          <div class="worker-right">
            <div class="worker-tags">
              \${envBindings.map(b => \`<span class="res-tag env">ENV: \${escapeHtml(b.name)}</span>\`).join('')}
              \${kvBindings.map(b => \`<span class="res-tag kv">KV: \${escapeHtml(b.name)}</span>\`).join('')}
              \${d1Bindings.map(b => \`<span class="res-tag d1">D1: \${escapeHtml(b.name)}</span>\`).join('')}
            </div>

            <div class="btns">
              <button class="btn" data-name="\${name}" data-act="env">环境</button>
              <button class="btn" data-name="\${name}" data-act="bind">绑定资源</button>
              <button class="btn" data-name="\${name}" data-act="addDomain">绑定域名</button>
              <button class="btn" data-name="\${name}" data-act="edit">编辑</button>
              <button class="btn danger" data-name="\${name}" data-act="delete">删除</button>
            </div>
          </div>
        \`;
        el('workersList').appendChild(div);
      });
      
      Array.from(document.querySelectorAll('.btns .btn')).forEach(b => {
        b.addEventListener('click', async function(e) {
          e.stopPropagation();
          const act = this.dataset.act; 
          const name = this.dataset.name;
          if (act === 'env') openEnvFor(name);
          if (act === 'bind') openBindFor(name);
          if (act === 'edit') editWorker(name);
          if (act === 'delete') deleteWorker(name);
          if (act === 'addDomain') openAddDomainModal(name);
        });
      });

      updateWorkerMetrics();
    }

    async function toggleWorkerSubdomain(scriptName, enabled) { const accountId = localStorage.getItem('cf_accountId'); const res = await api('toggle-worker-subdomain', { accountId, scriptName, enabled }); if (res && res.success) { showNotification(enabled ? 'Workers 子域名已启用' : 'Workers 子域名已禁用'); setTimeout(refreshWorkers, 1000); } else { showNotification(res.error || '操作失败', 'error'); refreshWorkers(); } }
    
    let currentWorkerForDomain = '';
    function openAddDomainModal(scriptName) { currentWorkerForDomain = scriptName; el('newDomainInput').value = ''; el('addDomainModal').style.display = 'flex'; }
    function closeAddDomainModal() { el('addDomainModal').style.display = 'none'; currentWorkerForDomain = ''; }
    async function confirmAddDomain() { const hostname = el('newDomainInput').value.trim(); const scriptName = currentWorkerForDomain; if (!hostname) return showNotification('请输入域名', 'error'); const accountId = localStorage.getItem('cf_accountId'); const res = await api('add-worker-domain', { accountId, scriptName, hostname }); if (res && res.success) { showNotification('域名绑定成功'); closeAddDomainModal(); refreshWorkers(); } else { showNotification(res.error || '绑定失败', 'error'); } }
    async function deleteWorkerDomain(scriptName, domainId, hostname) { confirmDialog('确定解除绑定域名 ' + hostname + '？', async () => { const accountId = localStorage.getItem('cf_accountId'); const res = await api('delete-worker-domain', { accountId, scriptName, domainId, hostname }); if (res && res.success) { showNotification('域名解绑成功'); refreshWorkers(); } else { showNotification(res.error || '解绑失败', 'error'); } }); }

    async function updateWorkerMetrics() { try { const usageRes = await api('get-usage-today', { accountId: localStorage.getItem('cf_accountId') }); if (usageRes && usageRes.success && usageRes.data) { const data = usageRes.data; const total = data.total || 0; const workers = data.workers || 0; const pages = data.pages || 0; const percentage = data.percentage || 0; el('metricCount').textContent = \`\${total.toLocaleString()} / 100,000\`; el('metricBar').style.width = \`\${percentage}%\`; el('workersRequests').textContent = workers.toLocaleString(); el('pagesRequests').textContent = pages.toLocaleString(); } else { el('metricCount').textContent = '0 / 100,000'; el('metricBar').style.width = '0%'; el('workersRequests').textContent = '0'; el('pagesRequests').textContent = '0'; } } catch (e) { console.error(e); } }
    async function editWorker(name){ const accounts = await api('list-accounts'); const accountId = accounts.result?.[0]?.id; const res = await api('get-worker-script', { accountId, scriptName: name }); if (res && res.rawScript !== undefined) { el('createName').value = name; el('createName').readOnly = true; const ta = el('createScript'); ta.value = ''; ta.style.minHeight = '60vh'; ta.style.maxHeight = '70vh'; ta.style.overflowY = 'auto'; ta.style.whiteSpace = 'pre'; ta.style.fontFamily = 'monospace'; ta.style.fontSize = '13px'; setTimeout(() => { ta.value = res.rawScript; ta.scrollTop = 0; window._createScriptSnapshot = res.rawScript; }, 0); el('createModal').style.display='flex'; } else { showNotification('获取 Worker 脚本失败', 'error'); debugOut(res); } }
    async function confirmCreate(){ const name = el('createName').value.trim(); const script = el('createScript').value; if (!name) return showNotification('请输入 Worker 名称', 'error'); const accountId = (await api('list-accounts')).result?.[0]?.id; const res = await api('deploy-worker', { accountId, scriptName: name, scriptSource: script, metadataBindings: [] }); if (res && res.success) { showNotification(res.message || 'Worker 部署成功'); window._createScriptSnapshot = script; el('createModal').style.display='none'; setTimeout(refreshWorkers, 800); } else { showNotification(res.error || '部署失败', 'error'); debugOut(res); } }
    function closeCreate(){ const current = el('createScript').value; const nameVal = el('createName').value; const isNew = !el('createName').readOnly; const hasChanged = current !== window._createScriptSnapshot || (isNew && nameVal.trim() !== ''); if (hasChanged) { confirmDialog('有未保存的更改，确定要关闭吗？', () => { el('createModal').style.display='none'; }); return; } el('createModal').style.display='none'; }
    async function deleteWorker(name){ confirmDialog('确定要删除 Worker: '+name+' 吗？', async () => { const accountId = (await api('list-accounts')).result?.[0]?.id; const res = await api('delete-worker', { accountId, scriptName: name }); if (res && res.success) { showNotification(res.message || 'Worker 删除成功'); setTimeout(refreshWorkers, 600); } else { showNotification(res.error || '删除失败', 'error'); debugOut(res); } }); }
    
    let currentWorkerForEnv = '';
    async function loadEnvVars(scriptName) { currentWorkerForEnv = scriptName; const accountId = localStorage.getItem('cf_accountId'); const res = await api('get-worker-variables', { accountId, scriptName }); el('envRows').innerHTML = ''; if (res && res.result && res.result.vars) { res.result.vars.forEach(v => { let value = v.value || v.text || ''; if (v.type === 'json' || (value && value.startsWith('{') && value.endsWith('}'))) { try { value = JSON.stringify(JSON.parse(value), null, 2); } catch (e) {} } addEnvRow(v.name, v.type || 'plain_text', value); }); } else { addEnvRow(); } }
    function addEnvRow(name='',type='plain_text',value=''){ const rows=el('envRows'); const id='r_'+Math.random().toString(36).slice(2,8); const div=document.createElement('div'); div.id=id; div.style.display='flex'; div.style.gap='8px'; div.style.marginTop='8px'; div.style.alignItems='center'; div.innerHTML = \`<input class="input env-name" placeholder="变量名" value="\${name?escapeHtml(name):''}" style="flex:2"><select class="input env-type" style="width:140px"><option value="plain_text">文本</option><option value="secret_text">密钥</option><option value="json">JSON</option></select><textarea class="input env-value" placeholder="变量值" style="flex:3;min-height:60px;resize:vertical">\${value?escapeHtml(value):''}</textarea><button class="btn danger">删除</button>\`; rows.appendChild(div); div.querySelector('button').addEventListener('click', ()=>div.remove()); div.querySelector('select').value=type; }
    async function saveEnv(){ const script = currentWorkerForEnv; if(!script) return showNotification('请选择 Worker 名称', 'error'); const rows = Array.from(el('envRows').children); const vars=[]; for(const row of rows){ const name = row.querySelector('.env-name').value.trim(); const type = row.querySelector('.env-type').value; let value = row.querySelector('.env-value').value; if(!name) continue; if(type==='json'){ try{ JSON.parse(value); }catch{ showNotification('JSON 变量格式错误: '+name, 'error'); return; } } vars.push({ name, value, type }); } const accountId = localStorage.getItem('cf_accountId') || (await api('list-accounts')).result?.[0]?.id; const res = await api('put-worker-variables', { accountId, scriptName: script, variables: vars }); if (res && res.success) { showNotification(res.message || '环境变量保存成功'); el('envModal').style.display='none'; refreshWorkers(); } else { showNotification(res.error || '保存失败', 'error'); debugOut(res); } }
    function closeEnvModal(){ el('envModal').style.display='none'; }
    
    async function refreshKVNamespaces() { const accountId = localStorage.getItem('cf_accountId'); if (!accountId) return; const res = await api('list-kv-namespaces', { accountId }); const namespaces = res.result || []; el('kvNamespacesList').innerHTML = ''; if (namespaces.length === 0) { el('kvNamespacesList').innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无 KV 命名空间</div>'; return; } namespaces.forEach(ns => { const div = document.createElement('div'); div.className = 'kv-item'; div.innerHTML = \`<div style="flex:1"><div style="font-weight:600">\${ns.title || ns.id}</div><div class="small">ID: \${ns.id}</div></div><div class="btns"><button class="btn" data-id="\${ns.id}" data-act="view">查看键值</button><button class="btn danger" data-id="\${ns.id}" data-act="delete">删除</button></div>\`; el('kvNamespacesList').appendChild(div); }); Array.from(el('kvNamespacesList').querySelectorAll('.btn')).forEach(btn => { btn.addEventListener('click', function() { const namespaceId = this.dataset.id; const act = this.dataset.act; if (act === 'view') viewKVNamespace(namespaceId); if (act === 'delete') deleteKVNamespace(namespaceId); }); }); }
    async function viewKVNamespace(namespaceId) { currentKVNamespaceId = namespaceId; const accountId = localStorage.getItem('cf_accountId'); const res = await api('list-kv-keys', { accountId, namespaceId }); if (res && res.result) { const keys = res.result; let html = '<h4>KV 键值列表</h4><div style="margin:8px 0 12px"><button class="btn primary" id="addKVBtn">+ 添加键值</button></div>'; if (keys.length === 0) { html += '<p>暂无键值对</p>'; } else { html += '<ul style="list-style:none;padding:0;margin:0">'; keys.forEach(function(key){ html += '<li class="kv-key-row" data-name="' + encodeURIComponent(key.name) + '" style="padding:8px 10px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px;cursor:pointer;display:flex;justify-content:space-between;align-items:center"><span>' + escapeHtml(key.name) + '</span><span class="small">点击编辑</span></li>'; }); html += '</ul>'; } el('debugOut').innerHTML = html; el('outModal').style.display = 'flex'; const addBtn = el('addKVBtn'); if (addBtn) addBtn.addEventListener('click', function(){ openKVValueModal(); }); Array.from(el('debugOut').querySelectorAll('.kv-key-row')).forEach(function(li){ li.addEventListener('click', function(){ editKVKey(li.dataset.name); }); }); } else { showNotification('获取键值列表失败', 'error'); } }
    async function deleteKVNamespace(namespaceId) { confirmDialog('确定要删除此 KV 命名空间吗？此操作不可逆！', async () => { const accountId = localStorage.getItem('cf_accountId'); const res = await api('delete-kv-namespace', { accountId, namespaceId }); if (res && res.success) { showNotification('KV 命名空间删除成功'); refreshKVNamespaces(); } else { showNotification(res.error || '删除失败', 'error'); } }); }
    function closeCreateKVModal(){ el('createKVModal').style.display='none'; }
    let currentKVNamespaceId = null;
    function openKVValueModal(key, value) { el('kvKey').value = key || ''; el('kvValue').value = (value != null) ? value : ''; el('kvValueModal').style.display = 'flex'; }
    async function editKVKey(encName) { const name = decodeURIComponent(encName); const accountId = localStorage.getItem('cf_accountId'); const r = await api('get-kv-value', { accountId, namespaceId: currentKVNamespaceId, key: name }); openKVValueModal(name, r && r.value != null ? r.value : ''); }
    async function confirmKVPut() { const key = el('kvKey').value.trim(); const value = el('kvValue').value; if (!key) return showNotification('请输入 Key', 'error'); if (!currentKVNamespaceId) return showNotification('命名空间未选择', 'error'); const accountId = localStorage.getItem('cf_accountId'); const r = await api('put-kv-value', { accountId, namespaceId: currentKVNamespaceId, key: key, value: value }); if (r && r.success) { showNotification('键值已保存'); closeKVValueModal(); viewKVNamespace(currentKVNamespaceId); } else showNotification((r && r.error) || '保存失败', 'error'); }
    function closeKVValueModal() { el('kvValueModal').style.display = 'none'; }
    async function confirmCreateKVNamespace() { const name = el('kvNamespaceName').value.trim(); if (!name) return showNotification('请输入命名空间名称', 'error'); const accountId = localStorage.getItem('cf_accountId'); const res = await api('create-kv-namespace', { accountId, title: name }); if (res && res.result) { showNotification('KV 命名空间创建成功'); el('createKVModal').style.display = 'none'; refreshKVNamespaces(); } else { showNotification(res.error || '创建失败', 'error'); } }
    
    async function refreshD1Databases() { const accountId = localStorage.getItem('cf_accountId'); if (!accountId) return; const res = await api('list-d1', { accountId }); const databases = res.result || []; el('d1DatabasesList').innerHTML = ''; el('d1DatabaseSelect').innerHTML = '<option value="">- 选择数据库 -</option>'; if (databases.length === 0) { el('d1DatabasesList').innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无 D1 数据库</div>'; return; } databases.forEach(db => { const div = document.createElement('div'); div.className = 'kv-item'; div.innerHTML = \`<div style="flex:1"><div style="font-weight:600">\${db.name || db.id}</div><div class="small">ID: \${db.uuid || db.id} | 版本: \${db.version || 'N/A'}</div></div><div class="btns"><button class="btn danger" data-id="\${db.uuid || db.id}" data-act="delete">删除</button></div>\`; el('d1DatabasesList').appendChild(div); const option = document.createElement('option'); option.value = db.uuid || db.id; option.textContent = \`\${db.name} (\${db.uuid || db.id})\`; el('d1DatabaseSelect').appendChild(option); }); Array.from(el('d1DatabasesList').querySelectorAll('.btn')).forEach(btn => { btn.addEventListener('click', function() { const databaseId = this.dataset.id; const act = this.dataset.act; if (act === 'delete') deleteD1Database(databaseId); }); }); }
    async function deleteD1Database(databaseId) { confirmDialog('确定要删除此 D1 数据库吗？此操作不可逆！', async () => { const accountId = localStorage.getItem('cf_accountId'); const res = await api('delete-d1-database', { accountId, databaseId }); if (res && res.success) { showNotification('D1 数据库删除成功'); refreshD1Databases(); } else { showNotification(res.error || '删除失败', 'error'); } }); }
    function closeCreateD1Modal(){ el('createD1Modal').style.display='none'; }
    async function confirmCreateD1Database() { const name = el('d1DatabaseName').value.trim(); const location = el('d1Location').value; if (!name) return showNotification('请输入数据库名称', 'error'); const accountId = localStorage.getItem('cf_accountId'); const payload = { accountId, name }; if (location && location !== 'auto') { payload.primary_location_hint = location; } const res = await api('create-d1-database', payload); if (res && res.result) { showNotification('D1 数据库创建成功'); el('createD1Modal').style.display = 'none'; refreshD1Databases(); } else { showNotification(res.error || '创建失败', 'error'); } }
    async function executeD1Query() { const databaseId = el('d1DatabaseSelect').value; const query = el('d1Query').value.trim(); if (!databaseId || !query) return showNotification('请选择数据库并输入查询语句', 'error'); const accountId = localStorage.getItem('cf_accountId'); const res = await api('execute-d1-query', { accountId, databaseId, query }); if (res && res.result) { el('d1QueryResults').innerHTML = '<pre>' + JSON.stringify(res.result, null, 2) + '</pre>'; } else { showNotification(res.error || '查询失败', 'error'); } }
    function refreshD1Tables() { }

    let currentZoneId = null; let currentEditingRecord = null;
    async function refreshZones() { const res = await api('list-zones'); const zones = res.result || []; el('zonesList').innerHTML = ''; if (zones.length === 0) { el('zonesList').innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无域名</div>'; return; } const table = document.createElement('table'); table.className = 'domain-list-table'; table.innerHTML = \`<thead><tr><th style="cursor:pointer;user-select:none" onclick="sortTable(this,0,'str')" title="点击排序">域名 <span class="sort-ind"></span></th><th style="width:100px;cursor:pointer;user-select:none" onclick="sortTable(this,1,'str')" title="点击排序">状态 <span class="sort-ind"></span></th><th style="cursor:pointer;user-select:none" onclick="sortTable(this,2,'str')" title="点击排序">区域 ID (Zone ID) <span class="sort-ind"></span></th><th style="width:120px;text-align:right">操作</th></tr></thead><tbody></tbody>\`; const tbody = table.querySelector('tbody'); zones.forEach(zone => { const row = document.createElement('tr'); let statusHtml = \`\`; if (zone.status === 'active') { statusHtml = '<span style="background:#f0fdf4;color:#166534;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600">已激活</span>'; } else { statusHtml = '<span style="background:#fffbeb;color:#d97706;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600">待处理</span>'; } let nsSection = ''; if (zone.status === 'pending' && zone.name_servers && zone.name_servers.length > 0) { nsSection = \`<div style="margin-top:8px;font-size:12px;color:#64748b">请设置 NS 为:</div><div style="display:flex;flex-wrap:wrap;gap:0;margin-top:4px">\`; zone.name_servers.forEach(ns => { nsSection += \`<div class="ns-pill">\${ns}<span class="ns-copy-icon" onclick="event.stopPropagation(); copyToClipboard('\${ns}', event)"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></span></div>\`; }); nsSection += \`<button class="copy-btn" style="margin-left:4px;height:20px;padding:0 6px" onclick="event.stopPropagation(); copyToClipboard('\${zone.name_servers.join(', ')}', event)">复制全部</button></div>\`; } row.innerHTML = \`<td><div style="font-weight:600;font-size:14px">\${escapeHtml(zone.name)}</div><div style="font-size:11px;color:#64748b;margin-top:2px">计划: \${zone.plan?.name || 'Free'}</div>\${nsSection}</td><td>\${statusHtml}</td><td style="font-family:monospace;color:#64748b;font-size:11px">\${zone.id}</td><td><div class="domain-row-actions"><button class="trash-btn" style="color:#2563eb;border-color:#dbeafe;background:#eff6ff" title="管理 DNS" onclick="event.stopPropagation(); viewZoneDNS('\${zone.id}', '\${escapeHtml(zone.name)}')">管理 DNS</button><button class="trash-btn" title="删除域名" onclick="event.stopPropagation(); deleteZone('\${zone.id}')">删除</button></div></td>\`; tbody.appendChild(row); }); el('zonesList').appendChild(table); window.viewZoneDNS = viewZoneDNS; window.deleteZone = deleteZone; }
    function showZonesList() { el('zonesList').style.display = 'block'; el('dnsRecordsSection').style.display = 'none'; currentZoneId = null; refreshZones(); }
    function viewZoneDNS(zoneId, zoneName) { currentZoneId = zoneId; el('zonesList').style.display = 'none'; el('dnsRecordsSection').style.display = 'block'; el('selectedZoneName').textContent = \`\${zoneName} - DNS 记录管理\`; el('selectedZoneInfo').textContent = \`管理 \${zoneName} 的 DNS 记录\`; refreshDNSRecords(zoneId); }
    function backToZones() { showZonesList(); }
    async function refreshDNSRecords(zoneId) { const res = await api('list-dns-records', { zoneId }); const records = res.result || []; el('dnsRecordsList').innerHTML = ''; if (records.length === 0) { el('dnsRecordsList').innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无 DNS 记录</div>'; return; } const table = document.createElement('table'); table.className = 'dns-table'; table.innerHTML = \`<thead><tr><th style="cursor:pointer;user-select:none" onclick="sortTable(this,0,'str')">类型 <span class="sort-ind"></span></th><th style="cursor:pointer;user-select:none" onclick="sortTable(this,1,'str')">名称 <span class="sort-ind"></span></th><th style="cursor:pointer;user-select:none" onclick="sortTable(this,2,'str')">内容 <span class="sort-ind"></span></th><th style="cursor:pointer;user-select:none" onclick="sortTable(this,3,'num')">TTL <span class="sort-ind"></span></th><th style="cursor:pointer;user-select:none" onclick="sortTable(this,4,'str')">代理 <span class="sort-ind"></span></th><th>操作</th></tr></thead><tbody></tbody>\`; const tbody = table.querySelector('tbody'); records.forEach(record => { const row = document.createElement('tr'); row.innerHTML = \`<td>\${record.type}</td><td>\${record.name}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${record.content}</td><td>\${record.ttl}</td><td>\${record.proxied ? '开启' : '关闭'}</td><td><button class="btn small" data-id="\${record.id}" data-act="edit">编辑</button><button class="btn small danger" data-id="\${record.id}" data-act="delete">删除</button></td>\`; tbody.appendChild(row); }); el('dnsRecordsList').appendChild(table); Array.from(el('dnsRecordsList').querySelectorAll('.btn')).forEach(btn => { btn.addEventListener('click', function() { const recordId = this.dataset.id; const act = this.dataset.act; if (act === 'edit') editDNSRecord(zoneId, recordId); if (act === 'delete') deleteDNSRecord(zoneId, recordId); }); }); }
    async function editDNSRecord(zoneId, recordId) { const res = await api('list-dns-records', { zoneId }); const record = res.result.find(r => r.id === recordId); if (record) { currentEditingRecord = record; el('editDnsRecordType').value = record.type; el('editDnsRecordName').value = record.name; el('editDnsRecordContent').value = record.content; el('editDnsRecordTTL').value = record.ttl; el('editDnsRecordProxied').checked = record.proxied; el('editDNSRecordModal').style.display = 'flex'; } }
    async function confirmEditDNSRecord() { const zoneId = currentZoneId; const recordId = currentEditingRecord.id; const type = el('editDnsRecordType').value; const name = el('editDnsRecordName').value.trim(); const content = el('editDnsRecordContent').value.trim(); const ttl = parseInt(el('editDnsRecordTTL').value); const proxied = el('editDnsRecordProxied').checked; if (!zoneId || !type || !name || !content) { return showNotification('请填写完整的 DNS 记录信息', 'error'); } const res = await api('update-dns-record', { zoneId, recordId, type, name, content, ttl, proxied }); if (res && res.result) { showNotification('DNS 记录更新成功'); el('editDNSRecordModal').style.display = 'none'; currentEditingRecord = null; refreshDNSRecords(zoneId); } else { showNotification(res.error || '更新失败', 'error'); } }
    function closeEditDNSRecordModal() { el('editDNSRecordModal').style.display = 'none'; currentEditingRecord = null; }
    async function confirmAddDNSRecord() { const zoneId = currentZoneId; const type = el('dnsRecordType').value; const name = el('dnsRecordName').value.trim(); const content = el('dnsRecordContent').value.trim(); const ttl = parseInt(el('dnsRecordTTL').value); const proxied = el('dnsRecordProxied').checked; if (!zoneId || !type || !name || !content) { return showNotification('请填写完整的 DNS 记录信息', 'error'); } const res = await api('create-dns-record', { zoneId, type, name, content, ttl, proxied }); if (res && res.result) { showNotification('DNS 记录添加成功'); el('addDNSRecordModal').style.display = 'none'; refreshDNSRecords(zoneId); } else { showNotification(res.error || '添加失败', 'error'); } }
    function closeAddDNSRecordModal() { el('addDNSRecordModal').style.display = 'none'; }
    async function deleteDNSRecord(zoneId, recordId) { confirmDialog('确定要删除此 DNS 记录吗？', async () => { const res = await api('delete-dns-record', { zoneId, recordId }); if (res && res.success) { showNotification('DNS 记录删除成功'); refreshDNSRecords(zoneId); } else { showNotification(res.error || '删除失败', 'error'); } }); }
    async function deleteZone(zoneId) { confirmDialog('确定要删除此域名吗？此操作不可逆！', async () => { const res = await api('delete-zone', { zoneId }); if (res && res.success) { showNotification('域名删除成功'); refreshZones(); } else { showNotification(res.error || '删除失败', 'error'); } }); }
    function closeAddZoneModal() { el('addZoneModal').style.display = 'none'; }
    async function confirmAddZone() { const name = el('zoneName').value.trim(); if (!name) return showNotification('请输入域名', 'error'); const res = await api('create-zone', { name }); if (res && res.result) { showNotification('域名添加成功，请在域名注册商处修改 NS 记录'); el('addZoneModal').style.display = 'none'; refreshZones(); if (typeof refreshSnippetZones === 'function') refreshSnippetZones(); } else { showNotification(res.error || '添加失败', 'error'); } }
    async function loadSubdomainSettings() { const accountId = localStorage.getItem('cf_accountId'); if (!accountId) return; const res = await api('get-workers-subdomain', { accountId }); if (res && res.result) { const subdomain = res.result.subdomain; el('subdomainInput').value = subdomain || ''; } }
    async function saveSubdomain() { const subdomain = el('subdomainInput').value.trim(); if (!subdomain) return showNotification('请输入子域名', 'error'); const accountId = localStorage.getItem('cf_accountId'); const res = await api('put-workers-subdomain', { accountId, subdomain }); if (res && res.success) { showNotification(res.message || 'Workers 域名设置成功'); setTimeout(refreshWorkers, 1000); } else { showNotification(res.error || '设置保存失败', 'error'); } }

    function maskEmailFront(e){ const i = String(e||'').indexOf('@'); if(i <= 0) return e||''; const u = e.slice(0,i), d = e.slice(i+1); return (u.length <= 1 ? '*' : u.slice(0,1) + '***') + '@' + d; }
    async function saveTGConfig(){
      const checkedBjs = Array.from(document.querySelectorAll('#tgReportHours input[type=checkbox]:checked')).map(c => Number(c.value));
      const reportHours = checkedBjs.length ? checkedBjs.map(bj => (bj - 8 + 24) % 24).sort((a, b) => a - b) : [23];
      const config = {
        botToken: el('tgBotToken').value.trim(),
        chatId: el('tgChatId').value.trim(),
        enabled: el('tgEnabled').checked,
        dailyReport: el('tgDaily').checked,
        alerts: el('tgAlerts').checked,
        alertsTraffic: !el('tgTraffic') || el('tgTraffic').checked,
        reportHours,
        segments: {
          quota: !el('tgSegQuota') || el('tgSegQuota').checked,
          traffic: !el('tgSegTraffic') || el('tgSegTraffic').checked,
          health: !el('tgSegHealth') || el('tgSegHealth').checked
        }
      };
      const r = await api('save-tg-config', { config });
      if(r && r.success){ if (!checkedBjs.length) showNotification('未勾选时段，已按默认北京 7 点(UTC 23)推送'); else showNotification('TG 配置已保存（日报 ' + reportHours.length + ' 个时段）' + (reportHours.length > 3 ? '⚠ 每次推送都会现场官方查询，建议 ≤3 档' : '')); }
      else showNotification((r&&r.error)||'保存失败','error');
    }
    async function testTG(){
      const r = await api('push-tg-test', {});
      if(r && r.success) showNotification('测试消息已发送，请查看 TG'); else showNotification((r&&r.error)||'发送失败','error');
    }
    // ===== P0-B 多通道通知（全局）=====
    function fillNotifyConfig(cfg){
      cfg = cfg || {};
      const d = cfg.discord || {}, b = cfg.bark || {}, w = cfg.wecom || {};
      if (el('ndEnabled')) el('ndEnabled').checked = !!d.enabled;
      if (el('ndWebhook')) el('ndWebhook').value = d.webhook || '';
      if (el('nbEnabled')) el('nbEnabled').checked = !!b.enabled;
      if (el('nbKey')) el('nbKey').value = b.deviceKey || '';
      if (el('nbServer')) el('nbServer').value = b.server || '';
      if (el('nwEnabled')) el('nwEnabled').checked = !!w.enabled;
      if (el('nwKey')) el('nwKey').value = w.key || '';
    }
    async function saveNotifyConfig(){
      const config = {
        discord: { enabled: el('ndEnabled').checked, webhook: el('ndWebhook').value.trim() },
        bark: { enabled: el('nbEnabled').checked, deviceKey: el('nbKey').value.trim(), server: el('nbServer').value.trim() },
        wecom: { enabled: el('nwEnabled').checked, key: el('nwKey').value.trim() }
      };
      const r = await api('save-notify-config', { config });
      if (r && r.success) showNotification('通知配置已保存'); else showNotification((r && r.error) || '保存失败', 'error');
    }
    async function testNotify(){
      const r = await api('push-tg-test', {});
      if (r && r.success) showNotification('测试消息已发送到全部启用通道'); else showNotification((r && r.error) || '发送失败', 'error');
    }
    async function pushTGNow(){
      const r = await api('push-tg-now', {});
      if(r && r.success) showNotification('日报已推送'); else showNotification((r&&r.error)||'推送失败','error');
    }
    async function refreshTGUsage(){
      const box = el('tgUsageBox'); box.textContent = '加载中...';
      const r = await api('get-all-usage', {});
      if(!r || !r.success){ box.textContent = (r&&r.error)||'获取失败'; return; }
      let txt = '日期(UTC): ' + r.date + '\\n';
      for(const u of r.results){
        const m = maskEmailFront(u.email);
        if(u.error){ txt += '\\n[' + m + '] 失败: ' + u.error; continue; }
        txt += '\\n[' + m + (u.name ? ' ' + u.name : '') + '] ' + (u.total||0).toLocaleString() + ' / 100,000 (' + (u.percent||0).toFixed(1) + '%)  W:' + (u.workers||0) + ' P:' + (u.pages||0) + '\\n';
        (u.byScript||[]).slice(0,5).forEach(s=> txt += '   - ' + s.script + ': ' + (s.requests||0).toLocaleString() + '\\n');
      }
      box.textContent = txt;
    }
    async function setupTGWebhook(){
      const r = await api('set-tg-webhook', {});
      if(r && r.success){ showNotification('Webhook 已设置: ' + (r.webhook||'')); }
      else showNotification((r&&r.error)||'Webhook 设置失败', 'error');
    }
    async function setupTGCommands(){
      const r = await api('set-tg-commands', {});
      if(r && r.success){ showNotification('菜单指令已注册（/report /probe /help）'); }
      else showNotification((r&&r.error)||'注册失败', 'error');
    }
    async function showTGWebhook(){
      const r = await api('get-tg-webhook', {});
      if(r && r.success){ const info = r.info||{}; const err = info.last_error ? ('  ⚠️ 最近错误: '+info.last_error) : ''; showNotification('Webhook: ' + (info.url||'未设置') + '  待处理更新: ' + (info.pending_update_count||0) + err); }
      else showNotification((r&&r.error)||'获取失败', 'error');
    }
    // ================= 监控中心 =================
    function renderTrendChart(series){
      const box = el('trendChart');
      if(!series || !series.length){ box.innerHTML = '<div class="small">暂无历史数据（需 Cron 运行至少一天）</div>'; return; }
      const max = Math.max(1, ...series.map(s=>s.total));
      const w = 600, h = 160, pad = 28;
      const stepX = (w-pad*2)/Math.max(1, series.length-1);
      const pts = series.map((s,i)=>{ const x = pad + i*stepX; const y = h-pad - (s.total/max)*(h-pad*2); return x.toFixed(1)+','+y.toFixed(1); });
      const bars = series.map((s,i)=>{ const x = pad + i*stepX; const bh = (s.total/max)*(h-pad*2); return '<rect x="'+(x-3)+'" y="'+(h-pad-bh)+'" width="6" height="'+bh.toFixed(1)+'" fill="#0070f3" rx="2"></rect>'; }).join('');
      const labels = series.filter((_,i)=>i%Math.ceil(series.length/6)===0).map((s,i)=>{ const x = pad + i*stepX*Math.ceil(series.length/6); return '<text x="'+Math.min(w-pad,x).toFixed(1)+'" y="'+(h-8)+'" font-size="9" fill="#94a3b8">'+s.date.slice(5)+'</text>'; }).join('');
      box.innerHTML = '<svg viewBox="0 0 '+w+' '+h+'" width="100%" style="max-width:600px">'+bars+'<polyline points="'+pts.join(' ')+'" fill="none" stroke="#00d4ff" stroke-width="2"/>'+labels+'</svg>';
    }
    function renderAccountTrends(list){
      const box = el('accountTrendBox');
      if(!list || !list.length){ box.textContent = '暂无按账号的历史数据（需 Cron 每日快照运行至少一天）'; return; }
      const max = Math.max(1, ...list.flatMap(a=>a.series.map(s=>s.total)));
      box.innerHTML = list.map(a => {
        const w=240,h=44,pad=4,n=a.series.length,stepX=(w-pad*2)/Math.max(1,n-1);
        const pts=a.series.map((s,i)=>{ const x=pad+i*stepX; const y=h-pad-(s.total/max)*(h-pad*2); return x.toFixed(1)+','+y.toFixed(1); }).join(' ');
        const last=a.series[n-1]?a.series[n-1].total:0;
        const peak=a.series.reduce((m,s)=>Math.max(m,s.total),0);
        const pct=peak>0?Math.round(last/peak*100):0;
        return '<div style="display:flex;align-items:center;gap:8px;margin:5px 0"><div style="width:190px;font-size:12px;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'+escapeHtml(a.name)+'">'+escapeHtml(a.name)+'</div><svg viewBox="0 0 '+w+' '+h+'" width="240" height="44" style="background:#f8fafc;border-radius:6px;flex:none"><polyline points="'+pts+'" fill="none" stroke="#0070f3" stroke-width="1.5"/></svg><div style="font-size:12px;color:#0f172a;min-width:70px;text-align:right">'+last.toLocaleString()+'<span style="color:#94a3b8"> ('+pct+'%)</span></div></div>';
      }).join('');
    }
    async function loadMonitor(){
      try {
        const t = await api('get-usage-trend', {});
        if(t && t.success){
          renderTrendChart(t.trend);
          renderAccountTrends(t.accounts);
          const p = t.prediction;
          el('trendPrediction').textContent = p ? ('预测: ' + p.trend + (p.daysToLimit!=null ? ('，日均增长 '+p.dailyGrowth + '，约 ' + p.daysToLimit + ' 天后接近上限 (' + p.eta + ')') : '，暂无需担心')) : '数据不足，无法预测';
        }
        const s = await api('get-storage-usage', {});
        if(s && s.success){ el('storageBox').textContent = (s.data||[]).map(d=> d.error ? ('['+maskEmailFront(d.email)+'] 查询失败') : ('['+maskEmailFront(d.email)+(d.name?' '+d.name:'')+'] D1库:'+d.d1Count+' R2操作:'+(d.r2Ops||0).toLocaleString()+' KV操作:'+(d.kvOps||0).toLocaleString())).join('\\n') || '无数据'; }
        const a = await api('get-asset-audit', {});
        if(a && a.success){ const snap = a.snapshot; if(!snap){ el('assetBox').textContent='暂无快照'; } else { const lines=[]; for(const e of Object.keys(snap.accounts||{})){ const c = snap.accounts[e]; if(!c.alive){ lines.push('✗ '+maskEmailFront(e)+' 失效: '+(c.error||'')); continue; } const accs = c.accounts||[]; const wsum = accs.reduce((t,x)=>t+(x.workers||[]).length,0); const zsum = accs.reduce((t,x)=>t+(x.zones||[]).length,0); lines.push('✓ '+maskEmailFront(e)+' 账号'+accs.length+' Workers'+wsum+' Zones'+zsum); } el('assetBox').textContent = lines.join('\\n'); } }
        const pr = await api('get-health-probe', {});
        if(pr && pr.success){ el('probeBox').textContent = (pr.results||[]).map(r=> (r.ok?'✓':'✗')+' '+r.worker+' ['+r.account+'] '+(r.status<0?'超时':r.status)+' '+(r.ms||0)+'ms').join('\\n') || '无数据'; }
        const ce = await api('get-cert-expiry', {});
        if(ce && ce.success){ el('certBox').textContent = (ce.certs||[]).map(c=> '['+maskEmailFront(c.email)+'] '+c.zone+': '+(c.days!=null?c.days+' 天':'无证书')).join('\\n') || '无数据'; }
        const wf = await api('get-waf-status', {});
        if(wf && wf.success){ el('wafBox').textContent = (wf.waf||[]).map(w=> '['+maskEmailFront(w.email)+'] '+w.zone+': 拦截 '+(w.blocked||0).toLocaleString()).join('\\n') || '无数据'; }
        const al = await api('get-audit-log', {});
        if(al && al.success){ el('auditBox').textContent = (al.log||[]).map(l=> l.ts+'  '+(l.action||'')+(l.count?(' x'+l.count):'')).join('\\n') || '暂无审计日志'; }
      } catch(e){ showNotification('监控加载失败: '+e.message, 'error'); }
    }
    async function runMonitorNow(){
      const btn = event && event.target; if(btn) btn.disabled = true;
      try { const r = await api('run-monitor-now', {}); if(r && r.success){ showNotification('巡检完成'); setTimeout(loadMonitor, 800); } else showNotification((r&&r.error)||'失败','error'); }
      catch(e){ showNotification('失败: '+e.message,'error'); }
      finally { if(btn) btn.disabled = false; }
    }
    // ================= 批量操作 =================
    function renderBulkAccounts(){
      const arr = loadSaved(); const list = el('bulkAccountList'); list.innerHTML = '';
      if(!arr.length){ list.innerHTML = '<div class="small">请先在登录页添加账号</div>'; return; }
      arr.forEach((acc, idx) => { const d = document.createElement('div'); d.style.cssText='padding:6px 0'; d.innerHTML = '<label style="cursor:pointer;display:flex;align-items:center"><input type="checkbox" class="bulk-acc-chk" value="'+idx+'" style="margin-right:8px"><span style="font-size:13px">'+escapeHtml(acc.email)+'</span></label>'; list.appendChild(d); });
    }
    async function renderBulkZones(){
      const c = getActiveCreds(); const list = el('bulkZoneList'); list.innerHTML = '加载中...';
      if(!c.email){ list.innerHTML = '<div class="small">请先登录一个账号</div>'; return; }
      const r = await api('list-zones', {});
      if(!r || !r.success){ list.innerHTML = '<div class="small">获取域名失败</div>'; return; }
      list.innerHTML = '';
      (r.result||[]).forEach(z => { const d = document.createElement('div'); d.style.cssText='padding:6px 0'; d.innerHTML = '<label style="cursor:pointer;display:flex;align-items:center"><input type="checkbox" class="bulk-zone-chk" value="'+z.id+'" style="margin-right:8px"><span style="font-size:13px">'+escapeHtml(z.name)+'</span></label>'; list.appendChild(d); });
    }
    async function deployBulk(){
      const log = el('bulkDeployLog'); log.textContent = '准备中...';
      const name = el('bulkScriptName').value.trim(); if(!name){ showNotification('请填写 Worker 名称','error'); return; }
      const src = el('bulkScriptSource').value;
      const arr = loadSaved(); const targets = []; const checked = Array.from(document.querySelectorAll('.bulk-acc-chk:checked'));
      if(!checked.length){ showNotification('请选择至少一个账号','error'); return; }
      for(const ch of checked){ const acc = arr[+ch.value]; if(!acc) continue; const r = await api('list-accounts', { email:acc.email, key:acc.key }); if(r && r.success){ for(const a of (r.result||[])) targets.push({ email:acc.email, key:acc.key, accountId:a.id }); } }
      if(!targets.length){ log.textContent = '未解析到目标账号'; return; }
      log.textContent = '部署到 ' + targets.length + ' 个账号...';
      const r = await api('bulk-deploy', { scriptName:name, scriptSource:src, targets });
      if(!r || !r.success){ log.textContent = (r&&r.error)||'失败'; return; }
      log.textContent = r.results.map(x=> (x.ok?'✓':'✗')+' '+x.accountId+': '+(x.message||'')).join('\\n');
      showNotification('批量部署完成');
    }
    async function bulkPurge(){
      const log = el('bulkDnsLog'); const c = getActiveCreds();
      const zoneIds = Array.from(document.querySelectorAll('.bulk-zone-chk:checked')).map(x=>x.value);
      if(!zoneIds.length){ showNotification('请勾选域名','error'); return; }
      log.textContent = '清缓存中...';
      const r = await api('bulk-purge', { zoneIds, email:c.email, key:c.key, everything:true });
      log.textContent = r && r.success ? r.results.map(x=>(x.ok?'✓':'✗')+' '+x.zoneId+(x.message?(': '+x.message):'')).join('\\n') : ((r&&r.error)||'失败');
    }
    async function bulkDns(paused){
      const log = el('bulkDnsLog'); const c = getActiveCreds();
      const zoneIds = Array.from(document.querySelectorAll('.bulk-zone-chk:checked')).map(x=>x.value);
      if(!zoneIds.length){ showNotification('请勾选域名','error'); return; }
      log.textContent = (paused?'暂停':'开启')+'代理中...';
      const r = await api('bulk-dns', { zoneIds, email:c.email, key:c.key, paused });
      log.textContent = r && r.success ? r.results.map(x=>(x.ok?'✓':'✗')+' '+x.zoneId).join('\\n') : ((r&&r.error)||'失败');
    }
    (async function loadTGOnSettings(){
      try { const r = await api('load-tg-config', {}); if(r && r.success && r.config){
        if(r.config.botTokenSet) el('tgBotToken').placeholder = '已保存 (' + r.config.botToken + ')';
        if(r.config.chatId) el('tgChatId').value = r.config.chatId;
        el('tgEnabled').checked = r.config.enabled !== false;
        el('tgDaily').checked = r.config.dailyReport !== false;
        el('tgAlerts').checked = r.config.alerts !== false;
      }} catch(e){}
    })();
    
    let currentBindType = 'kv';
    async function refreshBindList(){ const type = el('bindType').value; currentBindType = type; const accountId = localStorage.getItem('cf_accountId') || (await api('list-accounts')).result?.[0]?.id; if (!accountId) { el('bindSelect').innerHTML='<option>无 account</option>'; return; } el('bindSelect').innerHTML = '<option value="">加载中...</option>'; try { if (type==='kv') { const kv = await api('list-kv-namespaces', { accountId }); const arr = kv.result || []; el('bindSelect').innerHTML=''; if(arr.length) { arr.forEach(ns=>{ const opt=document.createElement('option'); opt.value=ns.id; opt.textContent=(ns.title||ns.name||ns.id) + ' (' + ns.id + ')'; el('bindSelect').appendChild(opt); }); } else { el('bindSelect').innerHTML='<option value="">未找到 KV 命名空间</option>'; } } else { const d1 = await api('list-d1', { accountId }); const arr = d1.result || []; el('bindSelect').innerHTML=''; if(arr.length) { arr.forEach(db=>{ const id=db.uuid||db.id; const opt=document.createElement('option'); opt.value=id; opt.textContent=(db.name||db.uuid||db.id) + ' (' + id + ')'; el('bindSelect').appendChild(opt); }); } else { el('bindSelect').innerHTML='<option value="">未找到 D1 数据库</option>'; } } } catch (error) { console.error('刷新绑定列表失败:', error); el('bindSelect').innerHTML='<option value="">加载失败</option>'; } }
    function closeBindModal(){ el('bindModal').style.display='none'; }
    async function confirmBind(){ const type = currentBindType; const ref = el('bindSelect').value; const bindName = el('bindName').value.trim() || (type==='kv'?'MY_KV':'MY_DB'); const script = el('createName').value.trim(); if (!script) return showNotification('请选择 Worker 名称', 'error'); if (!ref) return showNotification('请选择要绑定的资源', 'error'); const accountId = localStorage.getItem('cf_accountId'); let currentScript; let currentBindings = []; try { const scriptRes = await api('get-worker-script', { accountId, scriptName: script }); if (scriptRes && scriptRes.rawScript) { currentScript = scriptRes.rawScript; const scriptInfoRes = await api('get-worker-variables', { accountId, scriptName: script }); if (scriptInfoRes && scriptInfoRes.result && scriptInfoRes.result.vars) { const fullScriptRes = await fetch(\`/api\`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ action: 'get-worker-script', email: getActiveCreds().email, key: getActiveCreds().key, accountId: accountId, scriptName: script }) }); const fullScriptData = await fullScriptRes.json(); if (fullScriptData && fullScriptData.rawScript) { try { const scriptJson = JSON.parse(fullScriptData.rawScript); if (scriptJson.result && scriptJson.result.bindings) { currentBindings = scriptJson.result.bindings; } } catch (e) { } } } } else { currentScript = DEFAULT_WORKER_SCRIPT; } } catch (error) { console.error('获取当前脚本失败:', error); currentScript = DEFAULT_WORKER_SCRIPT; } const newBinding = (type==='kv') ? { type:'kv_namespace', name:bindName, namespace_id:ref } : { type:'d1', name:bindName, id:ref }; const otherBindings = currentBindings.filter(b => { if (b.type === 'plain_text' || b.type === 'secret_text') return true; return !(b.type === newBinding.type && b.name === newBinding.name); }); const finalBindings = [...otherBindings, newBinding]; const res = await api('deploy-worker', { accountId, scriptName: script, scriptSource: currentScript, metadataBindings: finalBindings }); if (res && res.success) { showNotification('资源绑定成功'); el('bindModal').style.display='none'; setTimeout(refreshWorkers,800); } else { showNotification(res.error || '绑定失败', 'error'); debugOut(res); } }

    (async function init() {
      let creds = getActiveCreds();
      if (!(creds.oauthId || (creds.email && creds.key))) {
        // 等 KV 恢复完成：把账号库并进本地，但不强制激活任何账号
        try { await (window.__kvRestorePromise || Promise.resolve()); } catch(e){}
        creds = getActiveCreds();
        if (!(creds.oauthId || (creds.email && creds.key))) {
          // 两级结构：无执行账号也可使用全局页（总览/监控中心/账号库/设置）
          updateAcctBadge(); navTo('overview'); return;
        }
      }
      el('acctInfo').textContent = creds.email; updateAcctBadge();
      navTo('overview');
      setTimeout(() => { try { if (getActiveCreds().email) refreshWorkers(); } catch(e) { console.log(e); } }, 300);
    })();

    window.navTo = navTo;
    window.logout = function() {
      localStorage.removeItem('cf_active_email'); localStorage.removeItem('cf_active_key'); localStorage.removeItem('cf_active_oauth');
      // 同时清掉密码会话，否则 /login 会因会话有效自动跳回面板
      fetch('/logout').catch(()=>{}).finally(() => { location.href = '/login'; });
    };
    window.openAccountSwitcher = openAccountSwitcher; window.closeAccountSwitcher = closeAccountSwitcher;
    window.goAccounts = goAccounts;
    window.renderOverview = renderOverview; window.renderAccounts = renderAccounts;
    window.openAddAccount = openAddAccount; window.closeAddAccount = closeAddAccount; window.confirmAddAccount = confirmAddAccount;
    window.openBatchImport = openBatchImport; window.closeBatchImport = closeBatchImport; window.confirmBatchImport = confirmBatchImport;
    window.editAccountGroup = editAccountGroup; window.setActiveAccount = setActiveAccount;
    window.saveNotifyConfig = saveNotifyConfig; window.testNotify = testNotify;
    window.switchAccount = switchAccount; window.removeAccount = removeAccount;
    window.filterRows = filterRows; window.sortTable = sortTable; window.restoreFromKV = restoreFromKV;
    window.toggleDark = toggleDark; window.toggleSidebar = toggleSidebar;
    window.saveTGConfig = saveTGConfig; window.testTG = testTG; window.pushTGNow = pushTGNow; window.refreshTGUsage = refreshTGUsage;
    window.setupTGWebhook = setupTGWebhook; window.setupTGCommands = setupTGCommands; window.showTGWebhook = showTGWebhook;
    window.openKVValueModal = openKVValueModal; window.editKVKey = editKVKey; window.confirmKVPut = confirmKVPut; window.closeKVValueModal = closeKVValueModal;
    window.openCreateWorker = function(){ el('createName').value=''; el('createName').readOnly = false; el('createScript').value = DEFAULT_WORKER_SCRIPT; window._createScriptSnapshot = DEFAULT_WORKER_SCRIPT; el('createModal').style.display='flex'; };
    window.openEnvFor = function(name){ el('createName').value = name; el('envModal').style.display='flex'; loadEnvVars(name); };
    window.openBindFor = function(name){ el('createName').value = name; el('bindModal').style.display='flex'; refreshBindList(); };
    window.addEnvRow = addEnvRow; window.saveEnv = saveEnv; window.closeEnvModal = closeEnvModal;
    window.closeBindModal = closeBindModal; window.confirmBind = confirmBind;
    window.editWorker = editWorker; window.deleteWorker = deleteWorker;
    window.closeCreate = closeCreate; window.confirmCreate = confirmCreate;
    window.closeOut = function(){ el('outModal').style.display='none'; };
    window.openCreateKVNamespace = function(){ el('createKVModal').style.display='flex'; };
    window.closeCreateKVModal = closeCreateKVModal; window.confirmCreateKVNamespace = confirmCreateKVNamespace;
    window.openCreateD1Database = function(){ el('createD1Modal').style.display='flex'; };
    window.closeCreateD1Modal = closeCreateD1Modal; window.confirmCreateD1Database = confirmCreateD1Database;
    window.executeD1Query = executeD1Query; window.refreshD1Tables = refreshD1Tables;
    window.openAddZone = function(){ el('addZoneModal').style.display='flex'; };
    window.closeAddZoneModal = closeAddZoneModal; window.confirmAddZone = confirmAddZone;
    window.openAddDNSRecord = function(){ if (!currentZoneId) { return showNotification('请先选择域名', 'error'); } el('addDNSRecordModal').style.display='flex'; };
    window.closeAddDNSRecordModal = closeAddDNSRecordModal; window.confirmAddDNSRecord = confirmAddDNSRecord;
    window.refreshDNSRecords = refreshDNSRecords; window.saveSubdomain = saveSubdomain;
    window.backToZones = backToZones; window.copyToClipboard = copyToClipboard;
    window.toggleWorkerSubdomain = toggleWorkerSubdomain;
    window.editDNSRecord = editDNSRecord; window.confirmEditDNSRecord = confirmEditDNSRecord;
    window.closeEditDNSRecordModal = closeEditDNSRecordModal;
    window.refreshKVNamespaces = refreshKVNamespaces; window.refreshD1Databases = refreshD1Databases;
    window.refreshZones = refreshZones; window.refreshBindList = refreshBindList;
    window.openAddDomainModal = openAddDomainModal; window.closeAddDomainModal = closeAddDomainModal;
    window.confirmAddDomain = confirmAddDomain; window.deleteWorkerDomain = deleteWorkerDomain;

    // ===== Snippets Management =====
    var currentSnippetZoneId = null;
    var currentSnippetZoneName = '';

    async function refreshSnippetZones() {
      var res = await api('list-zones');
      var zones = (res && res.result) ? res.result : [];
      var list = el('snippetsZonesList');
      list.innerHTML = '';
      if (zones.length === 0) {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无域名，请先添加域名</div>';
        return;
      }
      var table = document.createElement('table');
      table.className = 'domain-list-table';
      table.innerHTML = '<thead><tr><th>域名</th><th style="width:100px">状态</th><th style="width:140px;text-align:right">操作</th></tr></thead><tbody></tbody>';
      var tbody = table.querySelector('tbody');
      zones.forEach(function(zone) {
        var row = document.createElement('tr');
        var statusHtml = zone.status === 'active'
          ? '<span style="background:#f0fdf4;color:#166534;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600">已激活</span>'
          : '<span style="background:#fffbeb;color:#d97706;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600">待处理</span>';
        row.innerHTML = \`<td><div style="font-weight:600;font-size:14px">\${escapeHtml(zone.name)}</div></td><td>\${statusHtml}</td><td><div class="domain-row-actions"><button class="trash-btn" style="color:#2563eb;border-color:#dbeafe;background:#eff6ff" onclick="viewZoneSnippets('\${zone.id}', '\${escapeHtml(zone.name)}')">管理 Snippets</button></div></td>\`;
        tbody.appendChild(row);
      });
      list.appendChild(table);
    }

    function showSnippetsZonesList() {
      if (el('snippetsZonesList')) el('snippetsZonesList').style.display = 'block';
      if (el('snippetsSection')) el('snippetsSection').style.display = 'none';
      currentSnippetZoneId = null;
      refreshSnippetZones();
    }

    function viewZoneSnippets(zoneId, zoneName) {
      currentSnippetZoneId = zoneId;
      currentSnippetZoneName = zoneName;
      el('snippetsZonesList').style.display = 'none';
      el('snippetsSection').style.display = 'block';
      el('selectedSnippetZoneName').textContent = zoneName + ' - Snippets';
      el('selectedSnippetZoneInfo').textContent = '管理 ' + zoneName + ' 的 Snippets 和路由规则';
      refreshSnippets();
      refreshSnippetRules();
    }

    function backToSnippetZones() { showSnippetsZonesList(); }

    async function refreshSnippets() {
      var res = await api('list-snippets', { zoneId: currentSnippetZoneId });
      var snippets = (res && res.success && res.result) ? res.result : [];
      var list = el('snippetsList');
      list.innerHTML = '';
      if (snippets.length === 0) {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无 Snippets，点击上方「创建 Snippet」按钮添加</div>';
        return;
      }
      snippets.forEach(function(snippet) {
        var name = snippet.snippet_name || snippet.name || 'unknown';
        var created = snippet.created_on || '';
        var modified = snippet.modified_on || '';
        var div = document.createElement('div');
        div.className = 'worker-row';
        div.innerHTML = \`<div class="worker-info"><div style="font-weight:700">\${escapeHtml(name)}</div><div class="worker-meta">创建：\${created}\${modified ? ' | 修改：' + modified : ''}</div></div><div class="worker-right"><div class="btns"><button class="btn" onclick="editSnippet('\${escapeHtml(name)}')">编辑</button><button class="btn danger" onclick="deleteSnippet('\${escapeHtml(name)}')">删除</button></div></div>\`;
        list.appendChild(div);
      });
    }

    async function refreshSnippetRules() {
      var res = await api('list-snippet-rules', { zoneId: currentSnippetZoneId });
      var rules = (res && res.success && res.result && res.result.rules) ? res.result.rules : [];
      var list = el('snippetRulesList');
      list.innerHTML = '';
      if (rules.length === 0) {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:#6b7280">暂无路由规则，点击上方「添加路由规则」按钮配置</div>';
        return;
      }
      var table = document.createElement('table');
      table.className = 'dns-table';
      table.innerHTML = '<thead><tr><th>Snippet</th><th>表达式</th><th>描述</th><th style="width:80px">操作</th></tr></thead><tbody></tbody>';
      var tbody = table.querySelector('tbody');
      rules.forEach(function(rule) {
        var sn = (rule.action_parameters && rule.action_parameters.snippet) || '';
        var expr = rule.expression || '';
        var desc = rule.description || '';
        var rid = rule.id || '';
        var row = document.createElement('tr');
        row.innerHTML = \`<td><span class="res-tag env">\${escapeHtml(sn)}</span></td><td style="font-family:monospace;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="\${escapeHtml(expr)}">\${escapeHtml(expr)}</td><td>\${escapeHtml(desc)}</td><td><button class="btn small danger" onclick="deleteSnippetRule('\${rid}', '\${escapeHtml(sn)}')">删除</button></td>\`;
        tbody.appendChild(row);
      });
      list.appendChild(table);
    }

    function openCreateSnippet() {
      currentEditingSnippet = '';
      el('snippetName').value = '';
      el('snippetName').readOnly = false;
      el('snippetCode').value = "export default { async fetch(request, env, ctx) { return new Response('Hello from Snippet!'); } };";
      el('createSnippetModal').style.display = 'flex';
    }

    async function editSnippet(name) {
      currentEditingSnippet = name;
      showNotification('正在获取 Snippet 代码...');
      var res = await api('get-snippet', { zoneId: currentSnippetZoneId, snippetName: name });
      el('snippetName').value = name;
      el('snippetName').readOnly = true;
      el('snippetCode').value = (res && res.success && res.code) ? res.code : "export default { async fetch(request, env, ctx) { return new Response('Hello from Snippet!'); } };";
      el('createSnippetModal').style.display = 'flex';
    }

    function closeCreateSnippet() {
      el('createSnippetModal').style.display = 'none';
      currentEditingSnippet = '';
    }

    async function confirmDeploySnippet() {
      var name = el('snippetName').value.trim();
      var snippetCode = el('snippetCode').value;
      if (!name) return showNotification('请输入 Snippet 名称', 'error');
      if (!currentSnippetZoneId) return showNotification('请先选择域名', 'error');
      if (!/^[a-zA-Z0-9_-]+$/.test(name)) return showNotification('Snippet 名称仅支持字母、数字、下划线、连字符', 'error');
      var res = await api('deploy-snippet', { zoneId: currentSnippetZoneId, snippetName: name, snippetCode: snippetCode });
      if (res && res.success) {
        showNotification('Snippet 部署成功');
        closeCreateSnippet();
        refreshSnippets();
      } else {
        showNotification((res && res.errors && res.errors[0] && res.errors[0].message) || (res && res.error) || '部署失败', 'error');
        debugOut(res);
      }
    }

    async function deleteSnippet(name) {
      confirmDialog('确定要删除 Snippet: ' + name + '？相关路由规则需要手动删除。', async () => {
        var res = await api('delete-snippet', { zoneId: currentSnippetZoneId, snippetName: name });
        if (res && res.success) {
          showNotification('Snippet 删除成功');
          refreshSnippets();
          refreshSnippetRules();
        } else {
          showNotification((res && res.errors && res.errors[0] && res.errors[0].message) || (res && res.error) || '删除失败', 'error');
        }
      });
    }

    function addRuleCondition() {
      var container = el('ruleConditionsContainer');
      var div = document.createElement('div');
      div.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';
      div.innerHTML = \`
        <select class="input rule-field" style="flex:1;min-width:120px" onchange="updateRuleExpression()">
          <option value="http.host">主机名</option>
          <option value="http.request.uri.path">URI 路径</option>
          <option value="http.request.uri">URI 完整</option>
          <option value="http.request.uri.query">URI 查询字符串</option>
          <option value="http.request.method">HTTP 方法</option>
        </select>
        <select class="input rule-op" style="flex:1;min-width:100px" onchange="updateRuleExpression()">
          <option value="eq">等于</option>
          <option value="ne">不等于</option>
          <option value="contains">包含</option>
          <option value="startsWith">开头是</option>
          <option value="endsWith">结尾是</option>
        </select>
        <input type="text" class="input rule-val" style="flex:2;min-width:150px" placeholder="值" oninput="updateRuleExpression()">
        <select class="input rule-logic" style="width:80px" onchange="updateRuleExpression()">
          <option value="and">并且</option>
          <option value="or">或者</option>
        </select>
        <button class="trash-btn" style="height:38px" onclick="this.parentElement.remove(); updateRuleExpression()">✕</button>
      \`;
      container.appendChild(div);
      updateRuleExpression();
    }

    function updateRuleExpression() {
      var rows = el('ruleConditionsContainer').children;
      var parts = [];
      for (var i = 0; i < rows.length; i++) {
        var field = rows[i].querySelector('.rule-field').value;
        var op = rows[i].querySelector('.rule-op').value;
        var val = rows[i].querySelector('.rule-val').value.trim();
        if (!val) continue;
        
        if (field === 'http.request.method') {
          parts.push(field + ' ' + op + ' ' + val.toUpperCase());
        } else {
          parts.push(field + ' ' + op + ' "' + val + '"');
        }
        
        if (i < rows.length - 1) {
          var logic = rows[i].querySelector('.rule-logic').value;
          parts.push(logic);
        }
      }
      
      var finalExpr = parts.join(' ');
      if (parts.length > 1) {
        finalExpr = '(' + finalExpr + ')';
      }
      el('ruleExpression').value = finalExpr;
    }

    function openAddSnippetRule() {
      var select = el('ruleSnippetSelect');
      select.innerHTML = '<option value="">加载中...</option>';
      api('list-snippets', { zoneId: currentSnippetZoneId }).then(function(res) {
        var snippets = (res && res.success && res.result) ? res.result : [];
        select.innerHTML = '';
        if (snippets.length === 0) {
          select.innerHTML = '<option value="">暂无 Snippets，请先创建</option>';
        } else {
          snippets.forEach(function(s) {
            var name = s.snippet_name || s.name;
            var opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            select.appendChild(opt);
          });
        }
      });
      el('ruleConditionsContainer').innerHTML = '';
      addRuleCondition();
      el('ruleDescription').value = '';
      el('addSnippetRuleModal').style.display = 'flex';
    }

    function closeAddSnippetRuleModal() { el('addSnippetRuleModal').style.display = 'none'; }

    async function confirmAddSnippetRule() {
      var snippetName = el('ruleSnippetSelect').value;
      var expression = el('ruleExpression').value.trim();
      var description = el('ruleDescription').value.trim();
      if (!snippetName) return showNotification('请选择 Snippet', 'error');
      if (!expression) return showNotification('请输入路由表达式', 'error');
      var res = await api('add-snippet-rule', {
        zoneId: currentSnippetZoneId,
        snippetName: snippetName,
        expression: expression,
        description: description || 'Route to ' + snippetName
      });
      if (res && res.success) {
        showNotification('路由规则添加成功');
        closeAddSnippetRuleModal();
        refreshSnippetRules();
      } else {
        showNotification((res && res.errors && res.errors[0] && res.errors[0].message) || (res && res.error) || '添加失败', 'error');
        debugOut(res);
      }
    }

    async function deleteSnippetRule(ruleId, snippetName) {
      confirmDialog('确定要删除此路由规则吗？(Snippet: ' + snippetName + ')', async () => {
        var res = await api('delete-snippet-rule', { zoneId: currentSnippetZoneId, ruleId: ruleId });
        if (res && res.success) {
          showNotification('路由规则删除成功');
          refreshSnippetRules();
        } else {
          showNotification((res && res.errors && res.errors[0] && res.errors[0].message) || (res && res.error) || '删除失败', 'error');
        }
      });
    }

    window.showSnippetsZonesList = showSnippetsZonesList;
    window.viewZoneSnippets = viewZoneSnippets;
    window.backToSnippetZones = backToSnippetZones;
    window.refreshSnippetZones = refreshSnippetZones;
    window.openCreateSnippet = openCreateSnippet;
    window.editSnippet = editSnippet;
    window.closeCreateSnippet = closeCreateSnippet;
    window.confirmDeploySnippet = confirmDeploySnippet;
    window.deleteSnippet = deleteSnippet;
    window.addRuleCondition = addRuleCondition;
    window.updateRuleExpression = updateRuleExpression;
    window.openAddSnippetRule = openAddSnippetRule;
    window.closeAddSnippetRuleModal = closeAddSnippetRuleModal;
    window.confirmAddSnippetRule = confirmAddSnippetRule;
    window.deleteSnippetRule = deleteSnippetRule;


    window.toggleSelectAllWorkers = function(cb) {
      document.querySelectorAll('.worker-cb').forEach(function(c){ c.checked = cb.checked; });
    };
    async function batchDeleteWorkers() {
      const checked = Array.from(document.querySelectorAll('.worker-cb:checked'));
      if (checked.length === 0) return showNotification('请至少选择一个要删除的 Worker', 'error');
      confirmDialog('确定要删除选中的 ' + checked.length + ' 个 Worker 吗？此操作不可逆！', async () => {
        const accountId = localStorage.getItem('cf_accountId');
        let okCount = 0, failCount = 0;
        showNotification('正在批量删除 ' + checked.length + ' 个 Worker...');
        const chunks = [];
        for (let i = 0; i < checked.length; i += 10) {
          chunks.push(checked.slice(i, i + 10));
        }
        for (const chunk of chunks) {
          await Promise.all(chunk.map(async (cb) => {
            const name = cb.value;
            const res = await api('delete-worker', { accountId, scriptName: name });
            if (res && res.success) okCount++;
            else failCount++;
          }));
        }
        showNotification('删除完成：成功 ' + okCount + ' 个，失败 ' + failCount + ' 个');
        if (typeof refreshWorkers === 'function') refreshWorkers();
      });
    }
    window.batchDeleteWorkers = batchDeleteWorkers;

    window.toggleSelectAllPages = function(cb) {
      document.querySelectorAll('.pages-cb').forEach(function(c){ c.checked = cb.checked; });
    };
    async function batchDeletePages() {
      const checked = Array.from(document.querySelectorAll('.pages-cb:checked'));
      if (checked.length === 0) return showNotification('请至少选择一个要删除的 Pages 项目', 'error');
      confirmDialog('确定要删除选中的 ' + checked.length + ' 个 Pages 项目吗？此操作不可逆！', async () => {
        let okCount = 0, failCount = 0;
        showNotification('正在批量删除 ' + checked.length + ' 个 Pages 项目...');
        const chunks = [];
        for (let i = 0; i < checked.length; i += 10) {
          chunks.push(checked.slice(i, i + 10));
        }
        let accountId = localStorage.getItem('cf_accountId');
        if (!accountId) {
          const ar = await api('list-accounts');
          accountId = ar && ar.result && ar.result[0] && ar.result[0].id;
          if (accountId) localStorage.setItem('cfaccountId', accountId);
        }
        if (!accountId) return showNotification('无法获取 Account ID', 'error');
        for (const chunk of chunks) {
          await Promise.all(chunk.map(async (cb) => {
            const name = cb.value;
            const res = await api('delete-pages-project', { accountId, projectName: name });
            if (res && res.success) okCount++;
            else failCount++;
          }));
        }
        showNotification('删除完成：成功 ' + okCount + ' 个，失败 ' + failCount + ' 个');
        if (typeof refreshPagesManager === 'function') refreshPagesManager();
      });
    }
    window.batchDeletePages = batchDeletePages;

    window.viewZoneDNS = viewZoneDNS; window.deleteZone = deleteZone;
  }
})();`;
}

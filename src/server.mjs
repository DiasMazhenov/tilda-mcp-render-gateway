import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createHash } from 'node:crypto';
import { authUtils, isAllowedChatGptRedirect, limitFormSize } from './auth.mjs';

const ORIGIN=(process.env.PUBLIC_BASE_URL||'').replace(/\/$/,'');
const upstream='https://tilda.kz/api/mcp/';
const port=Number(process.env.PORT||3000);
const now=()=>Math.floor(Date.now()/1000);
const password=process.env.ADMIN_PASSWORD||'';
if(!/^https:\/\/[^/?#]+$/.test(ORIGIN)) throw Error('PUBLIC_BASE_URL must be the HTTPS public origin');
if(password.length<10 || /REPLACE/i.test(password)) throw Error('ADMIN_PASSWORD must be a unique secret of 10+ characters');
const auth=authUtils(process.env.OAUTH_SIGNING_SECRET||'');
function knownResource(value){
 try{
 const u=new URL(value);
 const match=u.pathname.match(/^\/mcp\/([a-z][a-z0-9-]{0,63})$/);
 return u.origin===ORIGIN && !u.search && !u.hash && !u.username && !u.password && match ? value : null;
 }catch{return null;}
}
function normalizeTildaToken(value){
 if(typeof value!=='string')return null;
 const token=value.trim().replace(/^Bearer +/i,'');
 return /^[\x21-\x7e]{1,4096}$/.test(token)?token:null;
}
const allowedScope='tilda:read tilda:write';
const usedCodes=new Map();
const throttling=new Map();

function json(res,code,body,headers={}){
 res.writeHead(code,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers});res.end(JSON.stringify(body));
}
function fail(res,code,codeText,description){json(res,code,{error:codeText,error_description:description});}
function text(res,code,body,headers={}){res.writeHead(code,{'content-type':'text/plain; charset=utf-8','cache-control':'no-store',...headers});res.end(body);}
function escapeHTML(s){return String(s).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));}
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(s=>s.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2));}
async function readBody(req,max=16384){
 if(!limitFormSize(req,max)) throw Error('Body too large');
 const parts=[];let size=0;
 for await(const part of req){size+=part.length;if(size>max)throw Error('Body too large');parts.push(part);}
 return Buffer.concat(parts).toString('utf8');
}
function params(body,type){return type?.includes('application/json')?JSON.parse(body):Object.fromEntries(new URLSearchParams(body));}
function validClient(clientId,redirect){
 try{
  const c=auth.verify(clientId);
  if(c.typ!=='client' || !Array.isArray(c.redirects) || !c.redirects.includes(redirect) || !isAllowedChatGptRedirect(redirect))return false;
  return true;
 }catch{return false;}
}
function requestParams(q){
 const o=Object.fromEntries(['client_id','redirect_uri','response_type','code_challenge','code_challenge_method','state','scope','resource'].map(k=>[k,q.get(k)||'']));
 if(o.response_type!=='code'||o.code_challenge_method!=='S256'||!/^[A-Za-z0-9_-]{43}$/.test(o.code_challenge))throw Error('authorization_code with PKCE S256 is required');
 if(!validClient(o.client_id,o.redirect_uri))throw Error('Invalid OAuth client or callback');
 if(!knownResource(o.resource)) throw Error('A valid site resource is required');
 if(o.scope && o.scope.split(' ').some(s=>!['tilda:read','tilda:write','offline_access'].includes(s)))throw Error('Unsupported scope');
 if(o.state.length>2048)throw Error('State too long');
 return o;
}
function challenge(res,resource){
 const meta=ORIGIN+'/.well-known/oauth-protected-resource'+new URL(resource).pathname;
 json(res,401,{error:'unauthorized'}, {'www-authenticate':`Bearer resource_metadata="${meta}", scope="tilda:read tilda:write"`});
}
function issue(res,values){
 const data={iss:ORIGIN,sub:'single-user',aud:values.resource,client_id:values.client_id,scope:allowedScope,tildaToken:values.tildaToken};
 const access=auth.encrypt({...data,typ:'access',exp:now()+3600,jti:auth.random()});
 const refresh=auth.encrypt({...data,typ:'refresh',exp:now()+2592000,jti:auth.random()});
 json(res,200,{access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refresh,scope:allowedScope});
}
function adminRateLimited(){
 const t=Date.now();const key='global';const hits=(throttling.get(key)||[]).filter(i=>t-i<60000);
 hits.push(t);throttling.set(key,hits);return hits.length>20;
}
async function handle(req,res){
 try{
 const url=new URL(req.url||'/',ORIGIN);
 const path=url.pathname;
 const resource=knownResource(ORIGIN+path.replace(/\/$/,''));
 const metadataResource=path.startsWith('/.well-known/oauth-protected-resource/') ? knownResource(ORIGIN+path.slice('/.well-known/oauth-protected-resource'.length)) : null;
 if(path==='/healthz' && req.method==='GET')return json(res,200,{ok:true,service:'tilda-mcp-gateway'});
 if(metadataResource && req.method==='GET')return json(res,200,{resource:metadataResource,authorization_servers:[ORIGIN],scopes_supported:['tilda:read','tilda:write','offline_access'],bearer_methods_supported:['header']});
 if(path==='/.well-known/oauth-authorization-server' && req.method==='GET')return json(res,200,{
  issuer:ORIGIN,authorization_endpoint:ORIGIN+'/authorize',token_endpoint:ORIGIN+'/token',registration_endpoint:ORIGIN+'/register',
  response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],
  token_endpoint_auth_methods_supported:['none'],code_challenge_methods_supported:['S256'],scopes_supported:['tilda:read','tilda:write','offline_access']
 });
 if(path==='/register' && req.method==='POST'){
  const input=JSON.parse(await readBody(req,32768));
  const redirects=input.redirect_uris;
  if(!Array.isArray(redirects)||redirects.length<1||redirects.length>5||!redirects.every(isAllowedChatGptRedirect))return fail(res,400,'invalid_redirect_uri','Only ChatGPT official redirect URLs are allowed');
  if(input.token_endpoint_auth_method && input.token_endpoint_auth_method!=='none')return fail(res,400,'invalid_client_metadata','Only public PKCE clients supported');
  const id=auth.sign({typ:'client',redirects,exp:now()+31536000,jti:auth.random()});
  return json(res,201,{client_id:id,client_id_issued_at:now(),client_id_expires_at:now()+31536000,redirect_uris:redirects,grant_types:['authorization_code','refresh_token'],response_types:['code'],token_endpoint_auth_method:'none',client_name:'ChatGPT Tilda MCP',scope:allowedScope});
 }
 if(path==='/authorize' && req.method==='GET'){
  let p;
  try{p=requestParams(url.searchParams);}catch(e){return fail(res,400,'invalid_request',e.message);}
  const nonce=auth.sign({typ:'csrf',exp:now()+600,jti:auth.random(),q:createHash('sha256').update(JSON.stringify(p)).digest('hex')});
  res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",'referrer-policy':'no-referrer','set-cookie':`__Host-mcp_csrf=${encodeURIComponent(nonce)}; Path=/; Secure; HttpOnly; SameSite=Lax`});
  const fields=Object.entries(p).map(([k,v])=>`<input type="hidden" name="${escapeHTML(k)}" value="${escapeHTML(v)}">`).join('');
  res.end(`<!doctype html><html lang="ru"><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><title>Разрешить доступ к Tilda MCP</title><style>body{font:16px system-ui;background:#f4f5f7;color:#182029;margin:0;display:grid;place-items:center;min-height:100vh}.card{background:white;padding:32px;border-radius:16px;max-width:420px;width:calc(100% - 64px);box-shadow:0 4px 18px #0001}input[type=password]{width:100%;box-sizing:border-box;padding:12px;margin:12px 0 18px;border:1px solid #aaa;border-radius:8px}button{background:#004341;color:#fff;border:0;border-radius:8px;padding:12px 18px;cursor:pointer}</style><main class="card"><h1>Подключение Tilda MCP</h1><p>Подключение: <strong>${escapeHTML(new URL(p.resource).pathname.split('/').pop())}</strong>. Введи пароль владельца шлюза и токен Tilda для этого сайта. Токен будет зашифрован для этого подключения.</p><form action="/authorize" method="POST">${fields}<input type="hidden" name="csrf" value="${escapeHTML(nonce)}"><label>Пароль владельца<input type="password" name="password" required autofocus autocomplete="off"></label><label>Токен Tilda MCP<input type="password" name="tilda_token" required maxlength="4103" autocomplete="off" spellcheck="false"></label><button type="submit">Подключить сайт</button></form></main></html>`);
  return;
 }
 if(path==='/authorize' && req.method==='POST'){
  if(req.headers.origin!==ORIGIN)return fail(res,403,'access_denied','Invalid origin');
  if(adminRateLimited())return fail(res,429,'slow_down','Too many attempts');
  const body=params(await readBody(req,32768),req.headers['content-type']);
  let p;try{p=requestParams(new URLSearchParams(body));}catch(e){return fail(res,400,'invalid_request',e.message);}
  let csrf;
  try{csrf=auth.verify(body.csrf);}catch{return fail(res,403,'access_denied','CSRF validation failed');}
  const q=createHash('sha256').update(JSON.stringify(p)).digest('hex');
  if(csrf.typ!=='csrf'||csrf.q!==q||!auth.secureEqual(cookies(req)['__Host-mcp_csrf']||'',body.csrf)||!auth.secureEqual(body.password||'',password))return fail(res,403,'access_denied','Incorrect password or session');
  const tildaToken=normalizeTildaToken(body.tilda_token);
  if(!tildaToken)return fail(res,400,'invalid_request','Enter a valid Tilda MCP token');
  const code=auth.encrypt({tildaToken,typ:'code',exp:now()+300,client_id:p.client_id,redirect_uri:p.redirect_uri,code_challenge:p.code_challenge,resource:p.resource,scope:allowedScope,jti:auth.random()});
  const redirect=new URL(p.redirect_uri);redirect.searchParams.set('code',code);if(p.state)redirect.searchParams.set('state',p.state);
  res.writeHead(302,{'location':redirect.toString(),'cache-control':'no-store','referrer-policy':'no-referrer','set-cookie':'__Host-mcp_csrf=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0'});res.end();return;
 }
 if(path==='/token' && req.method==='POST'){
  const p=params(await readBody(req,32768),req.headers['content-type']);
  if(p.client_secret)return fail(res,401,'invalid_client','Public client only');
  if(p.grant_type==='authorization_code'){
   let code;try{code=auth.decrypt(p.code);}catch{return fail(res,400,'invalid_grant','Expired or invalid code');}
   if(code.typ!=='code'||code.client_id!==p.client_id||code.redirect_uri!==p.redirect_uri||!knownResource(code.resource)||!validClient(p.client_id,p.redirect_uri))return fail(res,400,'invalid_grant','Client mismatch');
   if(typeof p.code_verifier!=='string'||p.code_verifier.length<43||p.code_verifier.length>128||!auth.secureEqual(code.code_challenge,auth.pkce(p.code_verifier)))return fail(res,400,'invalid_grant','PKCE verification failed');
   if(p.resource && p.resource!==code.resource)return fail(res,400,'invalid_target','Invalid resource');
   for(const [id,exp] of usedCodes)if(exp<now())usedCodes.delete(id);
   if(usedCodes.has(code.jti))return fail(res,400,'invalid_grant','Authorization code already used');
   usedCodes.set(code.jti,code.exp);
   return issue(res,code);
  }
  if(p.grant_type==='refresh_token'){
   let refresh;try{refresh=auth.decrypt(p.refresh_token);}catch{return fail(res,400,'invalid_grant','Expired or invalid refresh token');}
   if(refresh.typ!=='refresh'||refresh.iss!==ORIGIN||!knownResource(refresh.aud)||refresh.client_id!==p.client_id)return fail(res,400,'invalid_grant','Invalid refresh token');
   if(p.resource && p.resource!==refresh.aud)return fail(res,400,'invalid_target','Invalid resource');
   return issue(res,{...refresh,resource:refresh.aud});
  }
  return fail(res,400,'unsupported_grant_type','Use authorization_code or refresh_token');
 }
 if(resource){
  const bearer=(req.headers.authorization||'').match(/^Bearer (.+)$/i);
  let decoded;try{decoded=bearer?auth.decrypt(bearer[1]):null;}catch{}
  if(!decoded||decoded.typ!=='access'||decoded.iss!==ORIGIN||decoded.aud!==resource||decoded.scope!==allowedScope||!normalizeTildaToken(decoded.tildaToken))return challenge(res,resource);
  if(!['GET','POST','DELETE'].includes(req.method))return text(res,405,'Method not allowed',{'allow':'GET, POST, DELETE'});
  const upstreamHeaders=new Headers();
  for(const name of ['accept','content-type','mcp-session-id','mcp-protocol-version','last-event-id'])if(req.headers[name])upstreamHeaders.set(name,req.headers[name]);
  upstreamHeaders.set('authorization','Bearer '+decoded.tildaToken);
  const init={method:req.method,headers:upstreamHeaders,redirect:'manual',signal:AbortSignal.timeout(120000)};
  if(req.method==='POST')init.body=await readBody(req,2*1024*1024);
  let upstreamRes;
  try{upstreamRes=await fetch(upstream,init);}catch(e){return fail(res,502,'bad_gateway','Tilda MCP is unavailable');}
  const outHeaders={'cache-control':'no-store','x-content-type-options':'nosniff'};
  for(const name of ['content-type','mcp-session-id','mcp-protocol-version','retry-after','www-authenticate']){
   const value=upstreamRes.headers.get(name);if(value)outHeaders[name]=value;
  }
  res.writeHead(upstreamRes.status,outHeaders);
  if(!upstreamRes.body){res.end();return;}
  try{await pipeline(Readable.fromWeb(upstreamRes.body),res);}catch{res.destroy();}
  return;
 }
 text(res,404,'Not found');
 } catch(e){
  if(!res.headersSent)fail(res,400,'invalid_request','Invalid request');
  else res.destroy();
 }
}

const server=createServer(handle);
server.headersTimeout=30000;
server.requestTimeout=130000;
server.listen(port,'0.0.0.0',()=>console.log(`Tilda MCP gateway listening on ${port}`));

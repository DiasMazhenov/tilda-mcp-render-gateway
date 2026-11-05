import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { authUtils, isAllowedChatGptRedirect } from '../src/auth.mjs';

const base='https://example.onrender.com';
const local='http://127.0.0.1:39831';
const pwd='TestPass10';
const key='a'.repeat(64);
const callback='https://chatgpt.com/connector_platform_oauth_redirect';
const app=spawn(process.execPath,['--import','./test-support/upstream.mjs','src/server.mjs'],{
 cwd:new URL('..',import.meta.url).pathname,
 env:{...process.env,PORT:'39831',PUBLIC_BASE_URL:base,ADMIN_PASSWORD:pwd,OAUTH_SIGNING_SECRET:key},
 stdio:['ignore','pipe','pipe']
});
app.stderr.on('data',d=>process.stderr.write(d));
test.after(()=>app.kill());
for(let i=0;i<100;i++){
 try{if((await fetch(local+'/healthz')).ok)break;}catch{}
 if(i===99)throw Error('Server not ready without site tokens in Environment');
 await new Promise(r=>setTimeout(r,50));
}

async function authorization(site){
 const reg=await fetch(local+'/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:[callback],token_endpoint_auth_method:'none'})});
 assert.equal(reg.status,201);
 const {client_id}=await reg.json();
 const verifier=randomBytes(40).toString('base64url');
 const challenge=createHash('sha256').update(verifier).digest('base64url');
 const request={client_id,redirect_uri:callback,response_type:'code',code_challenge:challenge,code_challenge_method:'S256',state:'testState',scope:'tilda:read tilda:write offline_access',resource:base+'/mcp/'+site};
 const form=await fetch(local+'/authorize?'+new URLSearchParams(request));
 assert.equal(form.status,200);
 assert.equal(form.headers.get('referrer-policy'),'same-origin');
 const html=await form.text();
 assert.match(html,/name="tilda_token"/);
 const csrf=html.match(/name="csrf" value="([^"]+)"/)?.[1];
 assert.ok(csrf);
 return {request,verifier,csrf,cookie:form.headers.get('set-cookie').split(';')[0],html};
}
async function login(a,token,extra={}){
 return fetch(local+'/authorize',{method:'POST',redirect:'manual',headers:{'content-type':'application/x-www-form-urlencoded',origin:base,cookie:a.cookie},body:new URLSearchParams({...a.request,csrf:a.csrf,password:pwd,tilda_token:token,...extra})});
}
async function exchange(a,code,extra={}){
 return fetch(local+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:a.request.client_id,redirect_uri:callback,code,code_verifier:a.verifier,resource:a.request.resource,...extra})});
}
async function connect(site,token){
 const a=await authorization(site);
 const loggedIn=await login(a,token);
 assert.equal(loggedIn.status,302);
 const location=loggedIn.headers.get('location');
 assert.ok(!location.includes(token));
 const redirect=new URL(location);
 assert.equal(redirect.searchParams.get('state'),'testState');
 const code=redirect.searchParams.get('code');
 const response=await exchange(a,code);
 assert.equal(response.status,200);
 const tokens=await response.json();
 assert.ok(!JSON.stringify(tokens).includes(token));
 return {...a,code,tokens};
}

test('only official ChatGPT redirect URIs are allowed',()=>{
 assert.equal(isAllowedChatGptRedirect(callback),true);
 for(const url of ['https://evil.com/cb','http://chatgpt.com/connector_platform_oauth_redirect','https://chatgpt.com.evil.com/connector_platform_oauth_redirect'])assert.equal(isAllowedChatGptRedirect(url),false);
});

test('new sites need no configuration and remain protected',async()=>{
 const r=await fetch(local+'/mcp/new-site',{method:'POST'});
 assert.equal(r.status,401);
 assert.match(r.headers.get('www-authenticate'),/oauth-protected-resource\/mcp\/new-site/);
 const m=await (await fetch(local+'/.well-known/oauth-protected-resource/mcp/new-site')).json();
 assert.equal(m.resource,base+'/mcp/new-site');
 assert.equal((await fetch(local+'/mcp/INVALID')).status,404);
});

test('login rejects missing token, invalid token, wrong password and CSRF',async()=>{
 const a=await authorization('alpha');
 assert.equal((await login(a,'')).status,400);
 assert.equal((await login(a,'bad\r\ntoken')).status,400);
 assert.equal((await login(a,'TEST_ALPHA',{password:'wrong'})).status,403);
 assert.equal((await login(a,'TEST_ALPHA',{csrf:'wrong'})).status,403);
 assert.ok(!a.html.includes('TEST_ALPHA'));
});

test('form token is encrypted, forwarded only for its site and survives refresh',async()=>{
 const a=await connect('alpha','Bearer TEST_ALPHA');
 const decoded=authUtils(key).decrypt(a.tokens.access_token);
 assert.equal(decoded.aud,base+'/mcp/alpha');
 assert.equal(decoded.tildaToken,'TEST_ALPHA');
 const r=await fetch(local+'/mcp/alpha',{method:'POST',headers:{authorization:'Bearer '+a.tokens.access_token,'mcp-session-id':'incoming'},body:'{}'});
 assert.equal(r.status,200);
 assert.equal(r.headers.get('mcp-session-id'),'test-session');
 assert.deepEqual(await r.json(),{receivedToken:'Bearer TEST_ALPHA',session:'incoming'});
 assert.equal((await fetch(local+'/mcp/beta',{headers:{authorization:'Bearer '+a.tokens.access_token}})).status,401);
 const refreshed=await fetch(local+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:a.request.client_id,refresh_token:a.tokens.refresh_token,resource:a.request.resource})});
 assert.equal(refreshed.status,200);
 const fresh=await refreshed.json();
 assert.equal(authUtils(key).decrypt(fresh.access_token).tildaToken,'TEST_ALPHA');
 const wrong=await fetch(local+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:a.request.client_id,refresh_token:a.tokens.refresh_token,resource:base+'/mcp/beta'})});
 assert.equal(wrong.status,400);
 assert.equal((await exchange(a,a.code)).status,400);
});

test('separate form entries and reconnects preserve credential isolation',async()=>{
 const a=await connect('alpha','TEST_ALPHA');
 const b=await connect('beta','TEST_BETA');
 const replacement=await connect('alpha','TEST_REPLACEMENT');
 for(const [entry,site,token] of [[a,'alpha','TEST_ALPHA'],[b,'beta','TEST_BETA'],[replacement,'alpha','TEST_REPLACEMENT']]){
 const r=await fetch(local+'/mcp/'+site,{headers:{authorization:'Bearer '+entry.tokens.access_token}});
 assert.equal(r.status,200);
 assert.equal((await r.json()).receivedToken,'Bearer '+token);
 }
});

test('PKCE mismatch and corrupted encrypted credentials are rejected',async()=>{
 const a=await authorization('alpha');
 const l=await login(a,'TEST_ALPHA');
 const code=new URL(l.headers.get('location')).searchParams.get('code');
 assert.equal((await exchange(a,code,{code_verifier:'wrong'.repeat(15)})).status,400);
 const response=await exchange(a,code);
 assert.equal(response.status,200);
 const {access_token}=await response.json();
 const broken=(access_token[0]==='A'?'B':'A')+access_token.slice(1);
 assert.equal((await fetch(local+'/mcp/alpha',{headers:{authorization:'Bearer '+broken}})).status,401);
});

test('authorization rejects foreign, null and absent Origin headers',async()=>{
 for(const origin of ['https://evil.example','null',undefined]){
 const headers={'content-type':'application/x-www-form-urlencoded'};
 if(origin!==undefined)headers.origin=origin;
 const r=await fetch(local+'/authorize',{method:'POST',headers,body:''});
 assert.equal(r.status,403);
 assert.equal((await r.json()).error_description,'Invalid origin');
 }
});

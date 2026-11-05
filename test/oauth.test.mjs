import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { authUtils, isAllowedChatGptRedirect } from '../src/auth.mjs';

const base='https://example.onrender.com';
const local='http://127.0.0.1:39831';
const pwd='test-password-long-enough-123456789';
const key='a'.repeat(64);
const callback='https://chatgpt.com/connector_platform_oauth_redirect';
const pkceVerifier=randomBytes(40).toString('base64url');
const pkceChallenge=createHash('sha256').update(pkceVerifier).digest('base64url');

const waitReady=async()=>{
 for(let i=0;i<100;i++){
  try {const r=await fetch(local+'/healthz');if(r.ok)return;}catch{}
  await new Promise(r=>setTimeout(r,50));
 }
 throw Error('Server not ready');
};
const app=spawn(process.execPath,['--import','./test-support/upstream.mjs','src/server.mjs'],{
 cwd:new URL('..',import.meta.url).pathname,
 env:{...process.env,PORT:'39831',PUBLIC_BASE_URL:base,TILDA_TOKEN_ALPHA:'TEST_ALPHA',TILDA_TOKEN_BETA:'TEST_BETA',ADMIN_PASSWORD:pwd,OAUTH_SIGNING_SECRET:key},
 stdio:['ignore','pipe','pipe']
});
app.stderr.on('data',d=>process.stderr.write(d));
await waitReady();
test.after(()=>app.kill());

test('only ChatGPT redirect URIs allowed',()=>{
 assert.equal(isAllowedChatGptRedirect(callback),true);
 assert.equal(isAllowedChatGptRedirect('https://chatgpt.com/connector/oauth/abcde'),true);
 assert.equal(isAllowedChatGptRedirect('https://evil.example.com/oauth'),false);
 assert.equal(isAllowedChatGptRedirect('http://chatgpt.com/connector_platform_oauth_redirect'),false);
 assert.equal(isAllowedChatGptRedirect('https://chatgpt.com.evil.com/connector_platform_oauth_redirect'),false);
});

test('protected MCP and well-known metadata', async()=>{
 const u=await fetch(local+'/mcp/alpha',{method:'POST'});
 assert.equal(u.status,401);
 assert.match(u.headers.get('www-authenticate'),/oauth-protected-resource/);
 const m=await (await fetch(local+'/.well-known/oauth-protected-resource/mcp/alpha')).json();
 assert.equal(m.resource,base+'/mcp/alpha');
 const as=await (await fetch(local+'/.well-known/oauth-authorization-server')).json();
 assert.ok(as.code_challenge_methods_supported.includes('S256'));
});

test('OAuth registration, browser login, PKCE token exchange, protected MCP',async()=>{
 const bad=await fetch(local+'/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:['https://evil.com/cb']})});
 assert.equal(bad.status,400);
 const reg=await fetch(local+'/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:[callback],token_endpoint_auth_method:'none'})});
 assert.equal(reg.status,201);
 const {client_id}=await reg.json();
 const request={client_id,redirect_uri:callback,response_type:'code',code_challenge:pkceChallenge,code_challenge_method:'S256',state:'testState',scope:'tilda:read tilda:write',resource:base+'/mcp/alpha'};
 const qs=new URLSearchParams(request);
 const form=await fetch(local+'/authorize?'+qs);
 assert.equal(form.status,200);
 const cookie=form.headers.get('set-cookie');
 const html=await form.text();
 assert.match(html,/Пароль владельца/);
 const csrf=html.match(/name="csrf" value="([^"]+)"/)?.[1];
 assert.ok(csrf);
 const login=await fetch(local+'/authorize',{method:'POST',redirect:'manual',headers:{'content-type':'application/x-www-form-urlencoded',origin:base,cookie:cookie.split(';')[0]},body:new URLSearchParams({...request,csrf,password:pwd})});
 assert.equal(login.status,302);
 const redirect=new URL(login.headers.get('location'));
 assert.equal(redirect.origin,'https://chatgpt.com');
 const code=redirect.searchParams.get('code');
 assert.ok(code);
 const badVerifier=await fetch(local+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id,redirect_uri:callback,code,code_verifier:'wrong-verifier-value'.repeat(4)})});
 assert.equal(badVerifier.status,400);
 const tokenResponse=await fetch(local+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id,redirect_uri:callback,code,code_verifier:pkceVerifier,resource:base+'/mcp/alpha'})});
 assert.equal(tokenResponse.status,200);
 const tokens=await tokenResponse.json();
 assert.ok(tokens.access_token);
 assert.ok(tokens.refresh_token);
 const replay=await fetch(local+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id,redirect_uri:callback,code,code_verifier:pkceVerifier})});
 assert.equal(replay.status,400);
 const verify=authUtils(key).verify(tokens.access_token);
 assert.equal(verify.aud,base+'/mcp/alpha');
 assert.equal(verify.typ,'access');
 const refreshed=await fetch(local+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id,refresh_token:tokens.refresh_token})});
 assert.equal(refreshed.status,200);
 const crossSite=await fetch(local+'/mcp/beta',{headers:{authorization:'Bearer '+tokens.access_token}});
 assert.equal(crossSite.status,401);
 const wrongRefresh=await fetch(local+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id,refresh_token:tokens.refresh_token,resource:base+'/mcp/beta'})});
 assert.equal(wrongRefresh.status,400);
 const protectedRequest=await fetch(local+'/mcp/alpha',{method:'GET',headers:{authorization:'Bearer '+tokens.access_token}});
 assert.equal(protectedRequest.status,200);
 assert.equal(protectedRequest.headers.get('mcp-session-id'),'test-session');
 assert.equal((await protectedRequest.json()).receivedToken,'Bearer TEST_ALPHA');
 const betaToken=authUtils(key).sign({typ:'access',iss:base,aud:base+'/mcp/beta',scope:'tilda:read tilda:write',exp:Math.floor(Date.now()/1000)+60});
 const beta=await fetch(local+'/mcp/beta',{method:'POST',headers:{authorization:'Bearer '+betaToken,'mcp-session-id':'incoming'},body:'{}'});
 const betaResult=await beta.json();
 assert.equal(betaResult.receivedToken,'Bearer TEST_BETA');
 assert.equal(betaResult.session,'incoming');
 assert.equal((await fetch(local+'/mcp/missing')).status,404);
});

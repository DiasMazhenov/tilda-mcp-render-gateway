// Real Chromium form navigation over intercepted HTTPS, with no real accounts or keys.
// npm run test:browser (set BROWSER_EXECUTABLE_PATH for a preinstalled Chromium).
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import {createStore} from '../src/store.mjs';

const directory=await mkdtemp(join(tmpdir(),'tilda-browser-'));
const local='http://127.0.0.1:39835',origin='https://example.onrender.com';
const password='BrowserTestPassword10',secret='a'.repeat(64);
let app,browser;
try{
 const store=await createStore({DATA_DIR:directory},secret);
 await store.add('Тестовый проект','NOT_A_REAL_TILDA_KEY');
 store.close();
 app=spawn(process.execPath,['src/server.mjs'],{cwd:new URL('..',import.meta.url).pathname,env:{...process.env,DATABASE_URL:'',RENDER:'',PORT:'39835',PUBLIC_BASE_URL:origin,ADMIN_PASSWORD:password,OAUTH_SIGNING_SECRET:secret,DATA_DIR:directory},stdio:'ignore'});
 for(let i=0;i<100;i++){
  try{if((await fetch(local+'/healthz')).ok)break;}catch{}
  if(i===99)throw Error('Local gateway failed to start');
  await new Promise(r=>setTimeout(r,50));
 }
 let postStatus;
 browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXECUTABLE_PATH?{executablePath:process.env.BROWSER_EXECUTABLE_PATH}:{}),args:['--no-proxy-server','--no-sandbox','--disable-dev-shm-usage','--use-gl=angle','--use-angle=swiftshader']});
 for(const callback of ['https://chatgpt.com/connector_platform_oauth_redirect','https://chatgpt.com/connector/oauth/test-client']){
  const reg=await (await fetch(local+'/register',{method:'POST',body:JSON.stringify({redirect_uris:[callback]})})).json();
  const verifier=randomBytes(40).toString('base64url');
  const params={client_id:reg.client_id,redirect_uri:callback,response_type:'code',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',resource:origin+'/mcp/tilda',state:'browser-test'};
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();
  // CDP intercepts every redirect hop as well as the initial form request.
  const cdp=await context.newCDPSession(page);
  let interceptionError;
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:'https://example.onrender.com/*'},{urlPattern:'https://chatgpt.com/*'}]});
  cdp.on('Fetch.requestPaused',async({requestId,request})=>{
   try{
    if(new URL(request.url).origin==='https://chatgpt.com'){
     await cdp.send('Fetch.fulfillRequest',{requestId,responseCode:200,responseHeaders:[{name:'content-type',value:'text/plain'}],body:Buffer.from('Test OAuth callback reached').toString('base64')});return;
    }
    const u=new URL(request.url);
    const response=await fetch(local+u.pathname+u.search,{method:request.method,headers:request.headers,body:request.postData,redirect:'manual'});
    if(request.method==='POST')postStatus=response.status;
    const headers=Object.fromEntries(response.headers);
    if(process.env.TEST_FORCE_SELF_CSP==='yes' && headers['content-security-policy'])headers['content-security-policy']=headers['content-security-policy'].replace(/form-action[^;]+/,"form-action 'self'");
    await cdp.send('Fetch.fulfillRequest',{requestId,responseCode:response.status,responseHeaders:Object.entries(headers).map(([name,value])=>({name,value})),body:Buffer.from(await response.arrayBuffer()).toString('base64')});
   }catch(e){interceptionError=e;await cdp.send('Fetch.failRequest',{requestId,errorReason:'Failed'}).catch(()=>{});}
  });

  let blocked=false;
  page.on('console',m=>{if(m.text().includes('form-action')&&/violat|blocked|Refused/i.test(m.text()))blocked=true;});
  await page.goto(origin+'/authorize?'+new URLSearchParams(params));
  await page.locator('[name=password]').fill(password);
  // Exactly the user's scenario: saved connection; both new-key fields stay empty.
  assert.equal(await page.locator('[name=tilda_token]').inputValue(),'');
  await page.locator('button[type=submit]').click();
  try{await page.waitForURL(url=>url.origin==='https://chatgpt.com',{timeout:5000});}catch{}
  assert.equal(interceptionError,undefined);
  assert.equal(blocked,false,'CSP blocked the OAuth callback');
  assert.equal(postStatus,302);
  const returned=new URL(page.url());
  assert.equal(returned.origin,'https://chatgpt.com');
  assert.equal(returned.pathname,new URL(callback).pathname);
  assert.equal(returned.searchParams.get('state'),'browser-test');
  const tokenResponse=await fetch(local+'/token',{method:'POST',body:new URLSearchParams({grant_type:'authorization_code',client_id:reg.client_id,redirect_uri:callback,code:returned.searchParams.get('code'),code_verifier:verifier,resource:params.resource})});
  assert.equal(tokenResponse.status,200);
  const tokens=await tokenResponse.json();
  const tools=await (await fetch(local+'/mcp/tilda',{method:'POST',headers:{authorization:'Bearer '+tokens.access_token},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})})).json();
  assert.ok(tools.result.tools.some(t=>t.name==='list_connections'));
  await context.close();
  console.log('PASS browser form, callback, token exchange and tools/list: '+new URL(callback).pathname);
 }
}finally{
 await browser?.close();
 if(app&&app.exitCode===null){const ended=new Promise(resolve=>app.once('exit',resolve));app.kill();await ended;}
 await rm(directory,{recursive:true,force:true});
}

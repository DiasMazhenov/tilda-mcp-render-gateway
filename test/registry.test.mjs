import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createStore} from '../src/store.mjs';
import {TildaClient,registryRpc} from '../src/registry.mjs';
test('one MCP connection selects named credentials explicitly and never falls back to another key',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'tilda-rpc-'));
 const store=await createStore({DATA_DIR:dir},'a'.repeat(64));
 const calls=[];
 const client=new TildaClient(async(url,init)=>{
 assert.equal(url,'https://tilda.kz/api/mcp/');
 const token=init.headers.get('authorization');
 const msg=JSON.parse(init.body);calls.push({token,msg,session:init.headers.get('mcp-session-id')});
 if(msg.method==='initialize')return Response.json({jsonrpc:'2.0',id:msg.id,result:{protocolVersion:'2025-11-25',capabilities:{tools:{}}}},{headers:{'mcp-session-id':token.slice(7)}});
 if(msg.method==='notifications/initialized')return new Response(null,{status:202});
 assert.equal(init.headers.get('mcp-session-id'),token.slice(7));
 if(msg.method==='tools/list')return Response.json({jsonrpc:'2.0',id:msg.id,result:{tools:[{name:'read_pages',description:'Read pages',inputSchema:{type:'object',properties:{}}}]}});
 return Response.json({jsonrpc:'2.0',id:msg.id,result:{content:[{type:'text',text:token==='Bearer TOKEN_A'?'alpha-pages':'beta-pages'}]}});
 });
 try{
 const a=await store.add('Альфа','TOKEN_A'),b=await store.add('Бета','TOKEN_B');
 const context={store,client,origin:'https://example.onrender.com'};
 const rpc=(name,args)=>registryRpc({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}},context);
 const listed=await rpc('list_connections',{});
 assert.ok(JSON.stringify(listed).includes('Альфа'));
 assert.ok(!JSON.stringify(listed).includes('TOKEN_'));
 const discovery=await registryRpc({jsonrpc:'2.0',id:1,method:'tools/list'},context);
 assert.ok(discovery.result.tools.some(t=>t.name==='call_tilda_tool'));
 const missing=await rpc('call_tilda_tool',{tool_name:'read_pages',arguments:{}});
 assert.equal(missing.result.isError,true);
 assert.equal(calls.length,0);
 const [first,second]=await Promise.all([rpc('call_tilda_tool',{connection_id:a.id,tool_name:'read_pages',arguments:{}}),rpc('call_tilda_tool',{connection_id:b.id,tool_name:'read_pages',arguments:{}})]);
 assert.equal(first.result.content[0].text,'alpha-pages');
 assert.equal(second.result.content[0].text,'beta-pages');
 await store.remove(a.id,a.version);
 const before=calls.length;
 const deleted=await rpc('call_tilda_tool',{connection_id:a.id,tool_name:'read_pages',arguments:{}});
 assert.equal(deleted.result.isError,true);
 assert.equal(calls.length,before);
 const unknown=await rpc('call_tilda_tool',{connection_id:b.id,tool_name:'publish_everything',arguments:{}});
 assert.equal(unknown.result.isError,true);
 assert.ok(!calls.some(c=>c.msg.params?.name==='publish_everything'));
 }finally{store.close();await rm(dir,{recursive:true,force:true});}
});

test('SSE response is consumed when result arrives without waiting for stream closure',async()=>{
 const {responseJson}=await import('../src/registry.mjs');
 const stream=new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n'));}});
 const response=new Response(stream,{headers:{'content-type':'text/event-stream'}});
 const result=await Promise.race([responseJson(response,1),new Promise((_,reject)=>setTimeout(()=>reject(Error('Waited for SSE stream to close')),250))]);
 assert.equal(result.result.ok,true);
});

const endpoint='https://tilda.kz/api/mcp/';
const protocol='2025-11-25';
const object=value=>value!==null && typeof value==='object' && !Array.isArray(value);
const textResult=value=>({content:[{type:'text',text:JSON.stringify(value)}]});
const failure=message=>({content:[{type:'text',text:message}],isError:true});
const tools=[
 {name:'list_connections',description:'List saved Tilda connections by name and ID. Resolve the project named by the user before any Tilda request. Never guess a connection or switch projects silently.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:true,openWorldHint:false}},
 {name:'list_tilda_tools',description:'Read the actual Tilda tool names, descriptions and input schemas available for one saved connection. Use before calling a Tilda tool.',inputSchema:{type:'object',properties:{connection_id:{type:'string',description:'Exact ID returned by list_connections'}},required:['connection_id'],additionalProperties:false},annotations:{readOnlyHint:true,openWorldHint:true}},
 {name:'call_tilda_tool',description:'Invoke a discovered Tilda tool for the explicitly selected saved connection. Always supply connection_id. May modify or publish a site depending on tool_name. Use only the project and action requested by the user.',inputSchema:{type:'object',properties:{connection_id:{type:'string'},tool_name:{type:'string'},arguments:{type:'object',additionalProperties:true}},required:['connection_id','tool_name','arguments'],additionalProperties:false},annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:true,idempotentHint:false}}
];
export async function responseJson(response,id){
 const reader=response.body?.getReader();
 if(!reader)return null;
 const sse=(response.headers.get('content-type')||'').includes('text/event-stream');
 const decoder=new TextDecoder();let size=0,buffer='';
 const eventMessage=event=>{
  const data=event.split(/\r?\n/).filter(l=>l.startsWith('data:')).map(l=>l.slice(5).trimStart()).join('\n');
  if(!data || data==='[DONE]')return null;
  const msg=JSON.parse(data);return msg.id===id?msg:null;
 };
 try{
  while(true){
   const {done,value}=await reader.read();
   if(done){buffer+=decoder.decode();break;}
   size+=value.length;if(size>8*1024*1024)throw Error('Tilda response too large');
   buffer+=decoder.decode(value,{stream:true});
   if(sse){
    let match;
    while((match=/\r?\n\r?\n/.exec(buffer))){
     const event=buffer.slice(0,match.index);buffer=buffer.slice(match.index+match[0].length);
     const result=eventMessage(event);if(result)return result;
    }
   }
  }
  if(!buffer.trim())return null;
  if(!sse)return JSON.parse(buffer);
  const result=eventMessage(buffer);if(result)return result;
  throw Error('No matching Tilda response');
 }finally{await reader.cancel().catch(()=>{});}
}
export class TildaClient{
 constructor(fetchImpl=fetch){this.fetch=fetchImpl;}
 async connect(token){
 let session;let id=0;
 const rpc=async(method,params,notification=false)=>{
 const headers=new Headers({'content-type':'application/json',accept:'application/json, text/event-stream',authorization:'Bearer '+token});
 if(method!=='initialize')headers.set('mcp-protocol-version',protocol);
 if(session)headers.set('mcp-session-id',session);
 const requestId=notification?undefined:++id;
 const response=await this.fetch(endpoint,{method:'POST',headers,body:JSON.stringify({jsonrpc:'2.0',...(notification?{}:{id:requestId}),method,...(params===undefined?{}:{params})}),redirect:'manual',signal:AbortSignal.timeout(120000)});
 if(!response.ok){await response.body?.cancel();throw Error(response.status===401||response.status===403?'Tilda rejected this connection token':'Tilda request failed (HTTP '+response.status+')');}
 session=response.headers.get('mcp-session-id')||session;
 const msg=await responseJson(response,requestId);
 if(notification)return null;
 if(!msg || msg.id!==requestId || msg.error)throw Error('Tilda MCP returned an error; check tool arguments and connection access');
 return msg.result;
 };
 const info=await rpc('initialize',{protocolVersion:protocol,capabilities:{},clientInfo:{name:'tilda-named-gateway',version:'0.4.0'}});
 if(info?.protocolVersion!==protocol)throw Error('Unsupported Tilda protocol version');
 await rpc('notifications/initialized',undefined,true);
 const list=async()=>{
 const result=[];let cursor;const seen=new Set();
 do{
 const page=await rpc('tools/list',cursor?{cursor}:{});
 if(!Array.isArray(page?.tools))throw Error('Invalid Tilda tools response');
 result.push(...page.tools);cursor=page.nextCursor;
 if(cursor){if(seen.has(cursor)||seen.size>=100)throw Error('Invalid Tilda pagination');seen.add(cursor);}
 }while(cursor);
 return result;
 };
 return {rpc,list};
 }
 async list(token){return (await this.connect(token)).list();}
 async call(token,name,args){
 const connection=await this.connect(token);
 const available=await connection.list();
 if(!available.some(tool=>tool.name===name))throw Error('Tool is not available for this connection');
 return connection.rpc('tools/call',{name,arguments:args});
 }
}
export async function registryRpc(message,{store,client,origin}){
 const id=message?.id??null;
 const reply=result=>({jsonrpc:'2.0',id,result});
 const error=(code,text)=>({jsonrpc:'2.0',id,error:{code,message:text}});
 if(!object(message)||message.jsonrpc!=='2.0'||typeof message.method!=='string')return error(-32600,'Invalid request');
 if(message.method.startsWith('notifications/'))return null;
 if(message.method==='initialize'){
 const supported=['2025-06-18','2025-11-25','2026-07-28'];
 const requested=message.params?.protocolVersion;
 return reply({protocolVersion:supported.includes(requested)?requested:protocol,capabilities:{tools:{}},serverInfo:{name:'tilda-named-gateway',version:'0.4.0'},instructions:'One plugin manages multiple named Tilda credentials. Use list_connections to resolve the project requested by the user. Every Tilda call requires its explicit connection_id; never assume a shared active project. Use list_tilda_tools for actual tool schemas. Saved keys can only be managed in the protected browser page '+origin+'/settings. Never request or output raw keys in chat.'});
 }
 if(message.method==='ping')return reply({});
 if(message.method==='tools/list')return reply({tools});
 if(message.method!=='tools/call')return error(-32601,'Method not found');
 if(!store)return reply(failure('Persistent connection storage is not configured. Open '+origin+'/settings.'));
 const name=message.params?.name,args=message.params?.arguments||{};
 if(!object(args))return reply(failure('Tool arguments must be an object'));
 if(name==='list_connections'){
 try{return reply(textResult({connections:await store.list(),management_url:origin+'/settings'}));}
 catch{return reply(failure('Connection storage is unavailable'));}
 }
 if(!['list_tilda_tools','call_tilda_tool'].includes(name))return error(-32602,'Unknown gateway tool');
 if(typeof args.connection_id!=='string'||!args.connection_id)return reply(failure('Choose a connection ID from list_connections; no project was selected'));
 let connection;
 try{connection=await store.get(args.connection_id);}catch{return reply(failure('Connection storage or decryption is unavailable'));}
 if(!connection)return reply(failure('Connection was not found or was deleted. Use list_connections again'));
 try{
 const redact=value=>{
  if(typeof value==='string')return value.replaceAll(connection.token,'[REDACTED]');
  if(Array.isArray(value))return value.map(redact);
  if(object(value))return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,redact(v)]));
  return value;
 };
 if(name==='list_tilda_tools')return reply(textResult(redact({connection_id:connection.id,name:connection.name,tools:await client.list(connection.token)})));
 if(typeof args.tool_name!=='string'||!object(args.arguments))return reply(failure('Provide tool_name and an arguments object from list_tilda_tools'));
 return reply(redact(await client.call(connection.token,args.tool_name,args.arguments)));
 }catch(e){return reply(failure(String(e.message).replaceAll(connection.token,'[REDACTED]')));}
}

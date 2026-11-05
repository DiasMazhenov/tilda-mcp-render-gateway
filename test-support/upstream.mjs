const originalFetch=globalThis.fetch;
globalThis.fetch=(url,init)=>{
 if(String(url)==='https://tilda.kz/api/mcp/')return Promise.resolve(new Response(JSON.stringify({receivedToken:init.headers.get('authorization'),session:init.headers.get('mcp-session-id')}),{headers:{'content-type':'application/json','mcp-session-id':'test-session'}}));
 return originalFetch(url,init);
};

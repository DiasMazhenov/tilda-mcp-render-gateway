import {createHash} from 'node:crypto';
const now=()=>Math.floor(Date.now()/1000);
const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hidden=(name,value)=>'<input type="hidden" name="'+name+'" value="'+escape(value)+'">';
function cookie(req,name){
 const raw=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='));
 return raw?decodeURIComponent(raw.slice(name.length+1)):'';
}
function page(res,body,setCookie){
 const headers={'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'same-origin','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"};
 if(setCookie)headers['set-cookie']=setCookie;
 res.writeHead(200,headers);
 res.end('<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tilda MCP · Подключения</title><style>body{margin:0;background:#f3f5f4;color:#18362e;font:16px/1.5 system-ui}main{max-width:860px;margin:40px auto;padding:24px}h1{font-size:30px}section{background:white;border:1px solid #dce4df;border-radius:16px;padding:24px;margin:20px 0}label{display:block;margin:12px 0}input{font:inherit;box-sizing:border-box;display:block;width:100%;padding:11px;border:1px solid #a5b7ae;border-radius:8px}button{font:inherit;background:#004341;color:white;border:0;border-radius:8px;padding:10px 16px;margin:8px 8px 0 0;cursor:pointer}.danger{background:#8a2929}small{color:#53685f}code{overflow-wrap:anywhere}.note{background:#fff4d6;padding:12px;border-radius:8px}a{color:#004341}@media(max-width:600px){main{margin:0;padding:16px}section{padding:18px}}</style><main><h1>Tilda MCP</h1>'+body+'</main></html>');
}
function redirect(res,location,setCookie){
 const headers={location,'cache-control':'no-store'};if(setCookie)headers['set-cookie']=setCookie;
 res.writeHead(303,headers);res.end();
}
const makeCookie=(name,value,age)=>name+'='+encodeURIComponent(value)+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+age;
export async function handleSettings(req,res,ctx){
 const {url,store,auth,password,origin,readBody,params,fail,rateLimited}=ctx;
 if(url.pathname==='/'&&req.method==='GET'){redirect(res,'/settings');return true;}
 if(!url.pathname.startsWith('/settings'))return false;
 const version=createHash('sha256').update(password).digest('hex');
 let session;
 try{session=auth.decrypt(cookie(req,'__Host-tilda_admin'));}catch{}
 const authenticated=session?.typ==='admin' && session.iss===origin && session.passwordVersion===version;
 if(url.pathname==='/settings'&&req.method==='GET'){
 if(!authenticated){
 const csrf=auth.sign({typ:'settings-login',exp:now()+600,jti:auth.random()});
 page(res,'<p>Вход в управление подключениями.</p><section><form method="post" action="/settings/login">'+hidden('csrf',csrf)+'<label>Пароль владельца<input type="password" name="password" required minlength="10" autocomplete="current-password"></label><button>Войти</button></form></section>',makeCookie('__Host-tilda_login',csrf,600));
 return true;
 }
 if(!store){
 page(res,'<p class="note">Постоянное хранилище ещё не подключено. Подключи постоянное хранилище по инструкции в README. Ключи не сохраняются во временные файлы.</p>');
 return true;
 }
 let rows;
 try{rows=await store.list();}catch{page(res,'<p class="note">Хранилище недоступно. Проверь настройки базы данных.</p>');return true;}
 const csrf=hidden('csrf',session.csrf);
 let body='<p>Именованные ключи для одного универсального подключения. Сохранённые токены не отображаются.</p><p>Адрес MCP: <code>'+escape(origin+'/mcp/tilda')+'</code></p>';
 if(url.searchParams.get('saved')==='1')body+='<p class="note">Изменения сохранены.</p>';
 body+='<section><h2>Добавить подключение</h2><form method="post" action="/settings/add">'+csrf+'<label>Название проекта<input name="name" required maxlength="100" placeholder="Название проекта"></label><label>Токен Tilda MCP<input type="password" name="token" required maxlength="4103" autocomplete="off" spellcheck="false"></label><button>Сохранить подключение</button></form></section>';
 for(const row of rows){
 const fields=csrf+hidden('id',row.id)+hidden('version',row.version);
 body+='<section><h2>'+escape(row.name)+'</h2><small>ID: '+escape(row.id)+'</small><form method="post" action="/settings/update">'+fields+'<label>Название<input name="name" required maxlength="100" value="'+escape(row.name)+'"></label><label>Новый токен<input type="password" name="token" maxlength="4103" autocomplete="off" placeholder="Оставь пустым, чтобы сохранить текущий"></label><button>Сохранить изменения</button></form><form method="post" action="/settings/delete">'+fields+'<label><input type="checkbox" name="confirm_delete" value="yes" required style="display:inline;width:auto"> Подтверждаю удаление подключения</label><button class="danger">Удалить подключение</button></form></section>';
 }
 if(!rows.length)body+='<p>Пока нет сохранённых подключений.</p>';
 body+='<form method="post" action="/settings/logout">'+csrf+'<button>Выйти</button></form>';
 page(res,body);return true;
 }
 if(req.method!=='POST'){fail(res,404,'not_found','Not found');return true;}
 if(req.headers.origin!==origin){fail(res,403,'access_denied','Invalid origin');return true;}
 if(url.pathname==='/settings/login'){
 if(rateLimited()){fail(res,429,'slow_down','Too many attempts');return true;}
 const body=params(await readBody(req,32768),req.headers['content-type']);
 let nonce;try{nonce=auth.verify(body.csrf);}catch{}
 if(nonce?.typ!=='settings-login'){fail(res,403,'access_denied','Login form expired. Open /settings again.');return true;}
 if(!auth.secureEqual(body.csrf||'',cookie(req,'__Host-tilda_login'))){fail(res,403,'access_denied','Login session cookie is missing or was replaced. Open /settings again in one tab.');return true;}
 if(!auth.secureEqual(body.password||'',password)){fail(res,403,'access_denied','Incorrect owner password. Use the current ADMIN_PASSWORD from Render.');return true;}
 const value=auth.encrypt({typ:'admin',iss:origin,passwordVersion:version,csrf:auth.random(),exp:now()+28800});
 redirect(res,'/settings',makeCookie('__Host-tilda_admin',value,28800));return true;
 }
 if(!authenticated){fail(res,401,'unauthorized','Sign in to settings');return true;}
 const body=params(await readBody(req,32768),req.headers['content-type']);
 if(!auth.secureEqual(body.csrf||'',session.csrf)){fail(res,403,'access_denied','CSRF validation failed');return true;}
 if(url.pathname==='/settings/logout'){redirect(res,'/settings',makeCookie('__Host-tilda_admin','',0));return true;}
 if(!store){fail(res,503,'storage_unavailable','Configure persistent storage first');return true;}
 try{
 if(url.pathname==='/settings/add')await store.add(body.name,body.token);
 else if(url.pathname==='/settings/update')await store.update(body.id,body.name,body.token,body.version);
 else if(url.pathname==='/settings/delete'){
 if(body.confirm_delete!=='yes'){fail(res,400,'invalid_request','Confirm deletion');return true;}
 await store.remove(body.id,body.version);
 }else{fail(res,404,'not_found','Not found');return true;}
 }catch(e){
 page(res,'<p class="note">'+escape(e.message)+'</p><p><a href="/settings">Вернуться к подключениям</a></p>');return true;
 }
 redirect(res,'/settings?saved=1');return true;
}

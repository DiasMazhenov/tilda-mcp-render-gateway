import {randomBytes,randomUUID,hkdfSync,createCipheriv,createDecipheriv} from 'node:crypto';
import {mkdir,chmod} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';

export function normalizeToken(value){
 if(typeof value!=='string')throw Error('Enter a Tilda token');
 const token=value.trim().replace(/^Bearer +/i,'');
 if(!/^[\x21-\x7e]{1,4096}$/.test(token))throw Error('Invalid Tilda token format');
 return token;
}
function connectionName(value){
 if(typeof value!=='string')throw Error('Enter a connection name');
 const name=value.normalize('NFKC').trim();
 if(!name || name.length>100 || /[\u0000-\u001f\u007f]/.test(name))throw Error('Name must contain 1–100 printable characters');
 return name;
}
export function publicConnection(row){
 return {id:row.id,name:row.name,version:row.version,created_at:row.created_at,updated_at:row.updated_at};
}
function vault(secret){
 if(!/^[a-f0-9]{64}$/i.test(secret))throw Error('Invalid encryption key');
 const key=Buffer.from(hkdfSync('sha256',Buffer.from(secret,'hex'),Buffer.alloc(0),'tilda-connection-v1',32));
 return {
 seal(id,value){
 const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
 cipher.setAAD(Buffer.from(id));
 const data=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
 return Buffer.concat([iv,cipher.getAuthTag(),data]).toString('base64url');
 },
 open(id,value){
 const data=Buffer.from(value,'base64url'),decipher=createDecipheriv('aes-256-gcm',key,data.subarray(0,12));
 decipher.setAAD(Buffer.from(id));decipher.setAuthTag(data.subarray(12,28));
 return Buffer.concat([decipher.update(data.subarray(28)),decipher.final()]).toString('utf8');
 }
 };
}
export async function createStore(env,secret){
 let backend;
 if(env.DATABASE_URL){
 let parsed;try{parsed=new URL(env.DATABASE_URL);}catch{throw Error('Invalid DATABASE_URL');}
 if(!['postgres:','postgresql:'].includes(parsed.protocol)||!parsed.hostname.endsWith('.neon.tech')||!parsed.username||!parsed.password||parsed.pathname.length<2)throw Error('DATABASE_URL must be a Neon PostgreSQL connection string');
 const {neon}=await import('@neondatabase/serverless');
 const {postgresBackend}=await import('./neon-store.mjs');
 let sql;try{sql=neon(env.DATABASE_URL);}catch{throw Error('Invalid Neon DATABASE_URL');}
 backend=await postgresBackend((text,values)=>sql.query(text,values,{fetchOptions:{signal:AbortSignal.timeout(20000)}}));
 }else if(env.DATA_DIR){
 if(!isAbsolute(env.DATA_DIR))throw Error('DATA_DIR must be an absolute persistent directory');
 if(env.RENDER && env.PERSISTENT_DISK_CONFIRMED!=='yes')throw Error('A persistent disk is required for DATA_DIR on Render');
 backend=await sqliteBackend(env.DATA_DIR);
 }else return null;
 return connectionStore(backend,secret);
}
export function connectionStore(backend,secret){
 const crypto=vault(secret);
 return {
 async list(){return (await backend.list()).map(publicConnection);},
 async get(id){
 const row=await backend.get(id);if(!row)return null;
 try{return {...publicConnection(row),token:crypto.open(row.id,row.encrypted_token)};}
 catch{throw Error('Could not decrypt connection; restore the original encryption key');}
 },
 async add(name,token){
 const id=randomUUID(),time=new Date().toISOString();
 const row={id,name:connectionName(name),encrypted_token:crypto.seal(id,normalizeToken(token)),version:randomUUID(),created_at:time,updated_at:time};
 row.name_key=row.name.toLowerCase();
 await backend.add(row);return publicConnection(row);
 },
 async update(id,name,token,version){
 if(!version)throw Error('Reload settings before updating');
 const row={name:connectionName(name),name_key:connectionName(name).toLowerCase(),version:randomUUID(),updated_at:new Date().toISOString()};
 if(token?.trim())row.encrypted_token=crypto.seal(id,normalizeToken(token));
 const updated=await backend.update(id,row,version);
 if(!updated)throw Error('Connection changed or was deleted; reload settings');
 return publicConnection(updated);
 },
 async remove(id,version){
 if(!version || !await backend.remove(id,version))throw Error('Connection changed or was deleted; reload settings');
 },
 close(){backend.close?.();}
 };
}
async function sqliteBackend(dir){
 await mkdir(dir,{recursive:true,mode:0o700});
 const {DatabaseSync}=await import('node:sqlite');
 const file=join(dir,'connections.sqlite'),db=new DatabaseSync(file);
 await chmod(file,0o600);
 db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS tilda_gateway_connections (id TEXT PRIMARY KEY,name TEXT NOT NULL,name_key TEXT NOT NULL UNIQUE,encrypted_token TEXT NOT NULL,version TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)');
 const get=id=>db.prepare('SELECT * FROM tilda_gateway_connections WHERE id=?').get(id);
 const error=e=>{if(String(e.message).includes('UNIQUE'))throw Error('A connection with this name already exists');throw Error('Connection storage unavailable');};
 return {
 list:async()=>db.prepare('SELECT * FROM tilda_gateway_connections ORDER BY name_key').all(),
 get:async id=>get(id),
 add:async r=>{try{db.prepare('INSERT INTO tilda_gateway_connections VALUES (?,?,?,?,?,?,?)').run(r.id,r.name,r.name_key,r.encrypted_token,r.version,r.created_at,r.updated_at);}catch(e){error(e);}},
 update:async(id,r,version)=>{
 try{
 const sql=r.encrypted_token?'UPDATE tilda_gateway_connections SET name=?,name_key=?,version=?,updated_at=?,encrypted_token=? WHERE id=? AND version=?':'UPDATE tilda_gateway_connections SET name=?,name_key=?,version=?,updated_at=? WHERE id=? AND version=?';
 const values=[r.name,r.name_key,r.version,r.updated_at];if(r.encrypted_token)values.push(r.encrypted_token);values.push(id,version);
 return db.prepare(sql).run(...values).changes?get(id):null;
 }catch(e){error(e);}
 },
 remove:async(id,version)=>Boolean(db.prepare('DELETE FROM tilda_gateway_connections WHERE id=? AND version=?').run(id,version).changes),
 close:()=>db.close()
 };
}

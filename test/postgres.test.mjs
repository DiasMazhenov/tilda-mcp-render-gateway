import test from 'node:test';
import assert from 'node:assert/strict';
import {PGlite} from '@electric-sql/pglite';
import {postgresBackend} from '../src/neon-store.mjs';
import {connectionStore} from '../src/store.mjs';

test('Neon SQL schema and CRUD execute on PostgreSQL, bind names, reject stale updates and keep secrets encrypted',async()=>{
 const db=new PGlite();
 try{
 const query=async(sql,values)=>(await db.query(sql,values)).rows;
 const backend=await postgresBackend(query);
 const store=connectionStore(backend,'a'.repeat(64));
 const row=await store.add("Проект ' ; DROP TABLE x; --",'REAL_SECRET');
 assert.equal((await store.get(row.id)).token,'REAL_SECRET');
 const [saved]=await query('SELECT * FROM tilda_gateway.connections');
 assert.ok(!saved.encrypted_token.includes('REAL_SECRET'));
 await assert.rejects(store.add("Проект ' ; DROP TABLE x; --",'DUPLICATE'),/already exists/);
 await store.update(row.id,'Новое имя','NEW_TOKEN',row.version);
 await assert.rejects(store.update(row.id,'Старый запрос','BAD_TOKEN',row.version),/changed/);
 assert.equal((await store.get(row.id)).token,'NEW_TOKEN');
 const now=await store.get(row.id);
 const reopened=connectionStore(await postgresBackend(query),'a'.repeat(64));
 assert.equal((await reopened.get(row.id)).name,'Новое имя');
 await reopened.remove(row.id,now.version);
 assert.equal((await reopened.list()).length,0);
 }finally{await db.close();}
});

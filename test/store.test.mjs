import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createStore, publicConnection} from '../src/store.mjs';

test('encrypted connections survive reopening; names, replacements and deletion are isolated',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'tilda-store-'));
 const env={DATA_DIR:dir,ALLOW_LOCAL_STORAGE:'yes'};
 const key='a'.repeat(64);
 let store=await createStore(env,key);
 try{
 const alpha=await store.add('Мой сайт','TOKEN_ALPHA');
 const beta=await store.add('Второй сайт','TOKEN_BETA');
 assert.equal((await store.list()).length,2);
 assert.ok(!JSON.stringify(publicConnection(alpha)).includes('TOKEN_ALPHA'));
 assert.equal((await store.get(alpha.id)).token,'TOKEN_ALPHA');
 await assert.rejects(store.add(' МОЙ САЙТ ','TOKEN_DUPLICATE'),/already exists/);
 store.close();
 const file=await readFile(join(dir,'connections.sqlite'));
 assert.ok(!file.includes(Buffer.from('TOKEN_ALPHA')));
 store=await createStore(env,key);
 assert.equal((await store.get(alpha.id)).token,'TOKEN_ALPHA');
 await store.update(alpha.id,'Новое имя','TOKEN_REPLACED',alpha.version);
 assert.equal((await store.get(alpha.id)).token,'TOKEN_REPLACED');
 await assert.rejects(store.update(alpha.id,'Stale','BAD',alpha.version),/changed/);
 assert.equal((await store.get(beta.id)).token,'TOKEN_BETA');
 await store.remove(alpha.id,(await store.get(alpha.id)).version);
 assert.equal(await store.get(alpha.id),null);
 assert.equal((await store.list()).length,1);
 }finally{store.close();await rm(dir,{recursive:true,force:true});}
});

test('production never silently uses ephemeral storage',async()=>{
 assert.equal(await createStore({},'a'.repeat(64)),null);
 await assert.rejects(createStore({RENDER:'true',DATA_DIR:'/tmp/unsafe'},'a'.repeat(64)),/persistent/);
});

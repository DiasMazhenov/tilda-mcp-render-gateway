// All values are bound parameters. Schema/table identifiers are fixed constants.
export async function postgresBackend(query){
 const run=async(text,values=[])=>{
 try{return await query(text,values);}
 catch(e){
 if(e.code==='23505')throw Error('A connection with this name already exists');
 throw Error('Neon storage unavailable; check DATABASE_URL and database permissions');
 }
 };
 await run('CREATE SCHEMA IF NOT EXISTS tilda_gateway');
 await run('REVOKE ALL ON SCHEMA tilda_gateway FROM PUBLIC');
 await run('CREATE TABLE IF NOT EXISTS tilda_gateway.connections (id uuid PRIMARY KEY, name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100), name_key text NOT NULL UNIQUE, encrypted_token text NOT NULL, version uuid NOT NULL, created_at text NOT NULL, updated_at text NOT NULL)');
 await run('REVOKE ALL ON tilda_gateway.connections FROM PUBLIC');
 return {
 list:()=>run('SELECT * FROM tilda_gateway.connections ORDER BY name_key'),
 get:async id=>(await run('SELECT * FROM tilda_gateway.connections WHERE id=$1',[id]))[0]||null,
 add:r=>run('INSERT INTO tilda_gateway.connections (id,name,name_key,encrypted_token,version,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',[r.id,r.name,r.name_key,r.encrypted_token,r.version,r.created_at,r.updated_at]),
 update:async(id,r,version)=>{
 const withToken=Object.hasOwn(r,'encrypted_token');
 const sql=withToken?'UPDATE tilda_gateway.connections SET name=$1,name_key=$2,version=$3,updated_at=$4,encrypted_token=$5 WHERE id=$6 AND version=$7 RETURNING *':'UPDATE tilda_gateway.connections SET name=$1,name_key=$2,version=$3,updated_at=$4 WHERE id=$5 AND version=$6 RETURNING *';
 const values=[r.name,r.name_key,r.version,r.updated_at];if(withToken)values.push(r.encrypted_token);values.push(id,version);
 return (await run(sql,values))[0]||null;
 },
 remove:async(id,version)=>(await run('DELETE FROM tilda_gateway.connections WHERE id=$1 AND version=$2 RETURNING id',[id,version])).length>0
 };
}

import { createHash, createHmac, randomBytes, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
const b64 = v => Buffer.from(v).toString('base64url');
const unb64 = v => Buffer.from(v, 'base64url');
const digest = v => createHash('sha256').update(v).digest();
const secureEqual = (a,b) => {
  const A=Buffer.from(String(a)); const B=Buffer.from(String(b));
  return A.length===B.length && timingSafeEqual(A,B);
};
export function authUtils(secretHex) {
  const key=Buffer.from(secretHex,'hex');
  if (key.length!==32 || !/^[0-9a-f]{64}$/i.test(secretHex)) throw Error('OAUTH_SIGNING_SECRET must be exactly 64 hex chars');
  function sign(payload) {
    const body=b64(JSON.stringify(payload));
    const sig=b64(createHmac('sha256', key).update(body).digest());
    return body+'.'+sig;
  }
  function verify(value) {
    if(typeof value!=='string' || value.length>12000) throw Error('Malformed token');
    const pieces=value.split('.');
    if(pieces.length!==2 || !pieces[0] || !pieces[1]) throw Error('Malformed token');
    const expected=b64(createHmac('sha256',key).update(pieces[0]).digest());
    if(!secureEqual(expected,pieces[1])) throw Error('Invalid signature');
    const data=JSON.parse(unb64(pieces[0]).toString('utf8'));
    if(!data || typeof data!=='object' || typeof data.exp!=='number' || data.exp <= Math.floor(Date.now()/1000)) throw Error('Expired token');
    return data;
  }
  function encrypt(payload) {
    const iv=randomBytes(12);
    const cipher=createCipheriv('aes-256-gcm',key,iv);
    const body=Buffer.concat([cipher.update(JSON.stringify(payload),'utf8'),cipher.final()]);
    return b64(Buffer.concat([iv,cipher.getAuthTag(),body]));
  }
  function decrypt(token) {
    if (typeof token!=='string'||token.length>12000) throw Error('Malformed code');
    const bytes=unb64(token);
    if(bytes.length<29) throw Error('Malformed code');
    const decipher=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));
    decipher.setAuthTag(bytes.subarray(12,28));
    const obj=JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)),decipher.final()]).toString('utf8'));
    if(typeof obj.exp!=='number'||obj.exp <= Math.floor(Date.now()/1000)) throw Error('Expired code');
    return obj;
  }
  return { sign, verify, encrypt, decrypt, secureEqual, random:()=>b64(randomBytes(24)), pkce:verifier=>b64(digest(verifier)) };
}
export function isAllowedChatGptRedirect(url) {
  try {
    const u=new URL(url);
    if(u.protocol!=='https:' || u.username || u.password || u.search || u.hash || u.port) return false;
    return (u.hostname==='chatgpt.com' || u.hostname==='chat.openai.com') &&
      (/^\/connector\/oauth\/[a-zA-Z0-9_-]{4,150}$/.test(u.pathname) ||
       u.pathname==='/connector_platform_oauth_redirect');
  } catch {return false;}
}
export function limitFormSize(request, max=16384) {
  const len=Number(request.headers['content-length']||'0');
  return Number.isFinite(len) && len <= max;
}

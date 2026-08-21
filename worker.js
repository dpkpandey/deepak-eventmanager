const MAX_STATE_BYTES = 1024 * 1024;
const SESSION_DAYS = 30;

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || new URL(request.url).origin;
  return {'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET, POST, OPTIONS','Access-Control-Max-Age':'86400',Vary:'Origin'};
}
function json(body,status,request,extraHeaders={}) { return new Response(JSON.stringify(body),{status,headers:{...corsHeaders(request),'Content-Type':'application/json',...extraHeaders}}); }
function parseCookies(request) { return Object.fromEntries((request.headers.get('Cookie')||'').split(';').filter(Boolean).map(part=>{const [key,...value]=part.trim().split('=');return[key,decodeURIComponent(value.join('='))];})); }
async function digest(value) { const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)); return [...new Uint8Array(bytes)].map(byte=>byte.toString(16).padStart(2,'0')).join(''); }
function randomString(bytes=32) { const buffer=new Uint8Array(bytes);crypto.getRandomValues(buffer);return btoa(String.fromCharCode(...buffer)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }
async function hashPassword(password,salt) { const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:120000,hash:'SHA-256'},key,256);return [...new Uint8Array(bits)].map(byte=>byte.toString(16).padStart(2,'0')).join(''); }
async function requestBody(request) { try{return await request.json();}catch{return null;} }
async function currentUser(request,env) { const rawToken=parseCookies(request).pp_session;if(!rawToken)return null;return env.DB.prepare(`SELECT u.id,u.email,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).bind(await digest(rawToken),Date.now()).first(); }
function sessionCookie(token) { return `pp_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS*86400}`; }
function clearSessionCookie() { return 'pp_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'; }
function oauthStateCookie(state) { return `oauth_state=${encodeURIComponent(state)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`; }
function clearOauthStateCookie() { return 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'; }
function redirect(location, cookies=[]) { const headers=new Headers({Location:location,'Cache-Control':'no-store'});cookies.forEach(cookie=>headers.append('Set-Cookie',cookie));return new Response(null,{status:302,headers}); }
async function createSession(userId,env,request) { const token=randomString();await env.DB.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').bind(await digest(token),userId,Date.now()+SESSION_DAYS*86400000).run();return json({ok:true},200,request,{'Set-Cookie':sessionCookie(token)}); }

async function authRoute(url,request,env) {
  if(url.pathname==='/api/auth/google'&&request.method==='GET'){
    if(!env.GOOGLE_CLIENT_ID)return json({error:'Google login is not configured.'},503,request);
    const state=crypto.randomUUID(),siteUrl=env.SITE_URL||url.origin,authUrl=new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id',env.GOOGLE_CLIENT_ID);authUrl.searchParams.set('redirect_uri',`${siteUrl}/api/auth/google/callback`);authUrl.searchParams.set('response_type','code');authUrl.searchParams.set('scope','openid email profile');authUrl.searchParams.set('state',state);authUrl.searchParams.set('access_type','online');
    return redirect(authUrl.toString(),[oauthStateCookie(state)]);
  }
  if(url.pathname==='/api/auth/google/callback'&&request.method==='GET'){
    const siteUrl=env.SITE_URL||url.origin,state=url.searchParams.get('state'),code=url.searchParams.get('code'),savedState=parseCookies(request).oauth_state;
    if(url.searchParams.get('error'))return redirect(`${siteUrl}/?auth_error=google_cancelled`,[clearOauthStateCookie()]);
    if(!code||!state||state!==savedState)return redirect(`${siteUrl}/?auth_error=invalid_google_state`,[clearOauthStateCookie()]);
    try{
      const tokenResponse=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code,client_id:env.GOOGLE_CLIENT_ID,client_secret:env.GOOGLE_CLIENT_SECRET,redirect_uri:`${siteUrl}/api/auth/google/callback`,grant_type:'authorization_code'})});
      if(!tokenResponse.ok)return redirect(`${siteUrl}/?auth_error=google_token_failed`,[clearOauthStateCookie()]);
      const tokens=await tokenResponse.json(),profileResponse=await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{Authorization:`Bearer ${tokens.access_token}`}});
      if(!profileResponse.ok)return redirect(`${siteUrl}/?auth_error=google_profile_failed`,[clearOauthStateCookie()]);
      const profile=await profileResponse.json();if(!profile.sub||!profile.email||profile.email_verified===false)return redirect(`${siteUrl}/?auth_error=google_email_unverified`,[clearOauthStateCookie()]);
      let user=await env.DB.prepare('SELECT id FROM users WHERE google_id=?').bind(profile.sub).first();
      if(!user)user=await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(profile.email.toLowerCase()).first();
      const userId=user?.id||crypto.randomUUID(),name=String(profile.name||profile.email.split('@')[0]).slice(0,80),email=profile.email.toLowerCase();
      if(user)await env.DB.prepare('UPDATE users SET email=?,name=?,google_id=?,avatar=?,provider=? WHERE id=?').bind(email,name,profile.sub,profile.picture||null,'google',userId).run();
      else {const salt=randomString(16),passwordHash=await hashPassword(randomString(32),salt);await env.DB.prepare('INSERT INTO users (id,email,name,password_hash,password_salt,created_at,google_id,avatar,provider) VALUES (?,?,?,?,?,?,?,?,?)').bind(userId,email,name,passwordHash,salt,Date.now(),profile.sub,profile.picture||null,'google').run();await env.DB.prepare('INSERT INTO user_state (user_id,data,updated_at) VALUES (?,?,?)').bind(userId,JSON.stringify({projects:[]}),Date.now()).run();}
      const token=randomString();await env.DB.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').bind(await digest(token),userId,Date.now()+SESSION_DAYS*86400000).run();
      return redirect(`${siteUrl}/?auth_success=1`,[sessionCookie(token),clearOauthStateCookie()]);
    }catch(error){console.error('Google OAuth error',error);return redirect(`${siteUrl}/?auth_error=google_server_error`,[clearOauthStateCookie()]);}
  }
  if(url.pathname==='/api/me'&&request.method==='GET'){const user=await currentUser(request,env);return json({user:user||null},200,request);}
  if(url.pathname==='/api/logout'&&request.method==='POST'){const token=parseCookies(request).pp_session;if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(token)).run();return json({ok:true},200,request,{'Set-Cookie':clearSessionCookie()});}
  if(url.pathname==='/api/signup'&&request.method==='POST'){
    const body=await requestBody(request),name=String(body?.name||'').trim(),email=String(body?.email||'').trim().toLowerCase(),password=String(body?.password||'');
    if(name.length<2||name.length>80)return json({error:'Enter a name between 2 and 80 characters.'},400,request);
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return json({error:'Enter a valid email address.'},400,request);
    if(password.length<8||password.length>128)return json({error:'Password must be 8 to 128 characters.'},400,request);
    if(await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first())return json({error:'An account with that email already exists.'},409,request);
    const userId=crypto.randomUUID(),salt=randomString(16),passwordHash=await hashPassword(password,salt);
    await env.DB.prepare('INSERT INTO users (id,email,name,password_hash,password_salt,created_at) VALUES (?,?,?,?,?,?)').bind(userId,email,name,passwordHash,salt,Date.now()).run();
    await env.DB.prepare('INSERT INTO user_state (user_id,data,updated_at) VALUES (?,?,?)').bind(userId,JSON.stringify({projects:[]}),Date.now()).run();
    return createSession(userId,env,request);
  }
  if(url.pathname==='/api/login'&&request.method==='POST'){
    const body=await requestBody(request),email=String(body?.email||'').trim().toLowerCase(),password=String(body?.password||''),user=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    if(!user||await hashPassword(password,user.password_salt)!==user.password_hash)return json({error:'Email or password is incorrect.'},401,request);
    return createSession(user.id,env,request);
  }
  return null;
}

export default {async fetch(request,env){
  if(request.method==='OPTIONS')return new Response(null,{status:204,headers:corsHeaders(request)});
  const url=new URL(request.url),authResponse=await authRoute(url,request,env);if(authResponse)return authResponse;
  if(url.pathname==='/load'||url.pathname==='/sync'){
    const user=await currentUser(request,env);if(!user)return json({error:'Authentication required.'},401,request);
    if(url.pathname==='/load'&&request.method==='GET'){const row=await env.DB.prepare('SELECT data,updated_at FROM user_state WHERE user_id=?').bind(user.id).first();return json({data:row?JSON.parse(row.data):{projects:[]},updated_at:row?.updated_at||null},200,request);}
    if(url.pathname==='/sync'&&request.method==='POST'){
      const rawBody=await request.text();if(new TextEncoder().encode(rawBody).byteLength>MAX_STATE_BYTES)return json({error:'State payload is too large.'},413,request);let body;try{body=JSON.parse(rawBody);}catch{return json({error:'Invalid JSON.'},400,request);}
      if(!body.data||!Array.isArray(body.data.projects))return json({error:'Expected data.projects to be an array.'},400,request);const updatedAt=Number.isFinite(body.updated_at)?body.updated_at:Date.now();
      await env.DB.prepare(`INSERT INTO user_state (user_id,data,updated_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at`).bind(user.id,JSON.stringify(body.data),updatedAt).run();return json({ok:true,updated_at:updatedAt},200,request);
    }
    return json({error:'Method not allowed.'},405,request);
  }
  return env.ASSETS.fetch(request);
}};
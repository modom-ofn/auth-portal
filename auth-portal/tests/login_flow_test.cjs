// Run with: node tests/login_flow_test.cjs /path/to/auth-portal/static/login.js
const vm = require('node:vm');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[2], 'utf8');
const next = '/oidc/authorize?client_id=example&state=original';
function environment({ complete = false, mfa = false, blocked = false, fail = false, provider = 'plex' } = {}) {
  const events = {}, clicks = {}, calls = [], navigations = [];
  const storage = new Map(complete ? [['authportal.oauth.next',next]] : []);
  const btn = { dataset:{provider}, closest:()=>null, addEventListener:(n,f)=>clicks.signin=f };
  const cancel = {hidden:true, addEventListener:(n,f)=>clicks.cancel=f};
  const status = {};
  const popupNavigations = [], timers = new Map(); let timerId = 0;
  const popup = {closed:false, document:{body:{style:{}}}, location:{replace:u=>popupNavigations.push(u)},close(){this.closed=true}};
  let popupBlocked = blocked; let popupAttempts = 0;
  const context = {
    URL,URLSearchParams,console, setTimeout:f=>{timers.set(++timerId,f);return timerId},setInterval:f=>{timers.set(++timerId,f);return timerId},clearTimeout:i=>timers.delete(i),clearInterval:i=>timers.delete(i),
    open:()=>{popupAttempts++;return popupBlocked?null:popup},
    location:{origin:'https://auth.example',search:complete?'':'?next='+encodeURIComponent(next),assign:u=>navigations.push(u)},
    sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    document:{body:{dataset:complete?{authComplete:'1',authRedirect:mfa?'/mfa/challenge':'/home',authMfa:String(mfa)}:{}},getElementById:k=>({'auth-signin':btn,'auth-cancel':cancel,'auth-status':status}[k])},
    addEventListener:(n,f)=>events[n]=f,
    fetch:async (u,o)=>{calls.push([u,o]);return {ok:!fail,json:async()=>u.includes('cancel')?{redirect:'https://app.example/callback?error=access_denied&state=original'}:u.includes('poll')?{ok:true,redirect:'/home'}:{url:'https://app.plex.tv/auth#?code=example'}}}
  };
  vm.runInNewContext(source,context);
  return {context,btn,cancel,status,clicks,calls,navigations,storage,events,popup,popupNavigations,timers,popupAttempts:()=>popupAttempts,click:()=>clicks.signin({preventDefault(){}}),allowPopup:()=>popupBlocked=false};
}
const flush = ()=>new Promise(r=>setImmediate(r));
(async()=>{
 let e=environment(); await flush(); assert.equal(e.calls.length,0);assert.equal(e.popupAttempts(),0);assert.equal(e.status.textContent,undefined);assert.equal(e.cancel.hidden,false);e.click();await flush();assert.equal(e.calls.length,1);assert.equal(e.navigations.length,0);assert.equal(e.popupNavigations[0],'https://app.plex.tv/auth#?code=example');assert.equal(e.cancel.hidden,false);
 e=environment();await e.clicks.cancel();assert.equal(e.popupAttempts(),0);assert.match(e.navigations[0],/error=access_denied/);assert.equal(e.calls.length,1);
 e=environment({blocked:true});await flush();assert.equal(e.popupAttempts(),0);e.click();await flush();assert.equal(e.calls.length,0);assert.equal(e.navigations.length,0);assert.equal(e.btn.disabled,false);assert.match(e.status.textContent,/Allow popups/);e.allowPopup();e.clicks.signin({preventDefault(){}});await flush();assert.equal(e.popupNavigations.length,1);
 e=environment();e.click();await e.clicks.cancel();await flush();assert.equal(e.navigations.length,1);assert.match(e.navigations[0],/app.example/);assert.equal(e.popup.closed,true);assert.equal(e.timers.size,0);assert.equal(e.popupNavigations.length,0);
 e.events.message({origin:'https://auth.example',data:{ok:true,type:'plex-auth',redirect:'/home'}});assert.equal(e.navigations.length,1);
 e=environment();e.click();await flush();e.popup.closed=true;Array.from(e.timers.values())[1]();assert.equal(e.navigations.length,0);assert.equal(e.btn.disabled,false);assert.equal(e.timers.size,0);
 e=environment();e.click();await flush();await Array.from(e.timers.values())[0]();assert.equal(e.navigations[0],next);assert.equal(e.popup.closed,true);
 e=environment({complete:true});assert.equal(e.navigations[0],next);assert.equal(e.storage.size,0);
 e=environment({complete:true,mfa:true});const target=new URL(e.navigations[0],'https://auth.example');assert.equal(target.pathname,'/mfa/challenge');assert.equal(target.searchParams.get('next'),next);
 e=environment({fail:true});e.click();await flush();assert.equal(e.navigations.length,0);assert.equal(e.btn.disabled,false);assert.match(e.status.textContent,/try again/);
 assert.equal(e.popup.closed,true);
 for (const provider of ['emby', 'jellyfin']) {
  e=environment({provider});assert.equal(e.cancel.hidden,false);e.click();await flush();await e.clicks.cancel();assert.equal(e.popup.closed,true);assert.equal(e.timers.size,0);assert.match(e.navigations[0],/error=access_denied/);
  e=environment({provider});e.click();await e.clicks.cancel();await flush();assert.equal(e.popupNavigations.length,0);assert.equal(e.navigations.length,1);
  e=environment({provider});e.click();await flush();e.popup.closed=true;Array.from(e.timers.values())[0]();assert.equal(e.navigations.length,0);assert.match(e.status.textContent,/Sign in again/);
 }
 console.log('Passed: quiet page load, click-only popup, blocked click retry, cancellation race, late completion suppression, popup closure, polling completion, same-tab fallback callback, MFA, startup failure, Emby/Jellyfin cancellation and popup closure.');
})().catch(e=>{console.error(e);process.exitCode=1});

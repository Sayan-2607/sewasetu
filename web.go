package main

// All pages are plain HTML strings with a little vanilla JS. No build step, no framework, no CDN.

import (
	"fmt"
	"net/http"
	"strings"
)

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

const css = `<style>
:root{--bg:#0b1020;--card:#151c36;--line:#2a3560;--tx:#e8ecf8;--mut:#9fb0e8;--a:#ff9a3c;--b:#ff5e7e;--ok:#4ade80;--bad:#ff8a8a}
*{box-sizing:border-box}body{margin:0;font:17px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--tx)}
a{color:#ffb86b}nav{display:flex;gap:6px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line);background:#0e1430;position:sticky;top:0;z-index:5}
nav a{color:var(--tx);text-decoration:none;padding:6px 12px;border-radius:999px;font-size:15px}nav a:hover{background:var(--card)}nav b{margin-right:10px;color:var(--a)}
main{max-width:980px;margin:0 auto;padding:20px 16px 60px}h1{font-size:28px;margin:6px 0 10px}h2{font-size:20px;margin:26px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px;margin:14px 0}
input,select,textarea,button{font:inherit;width:100%;padding:13px;border-radius:10px;border:1px solid #3a4780;background:#0e1430;color:var(--tx);margin:6px 0}
button{background:linear-gradient(90deg,var(--a),var(--b));border:0;font-weight:700;cursor:pointer;color:#1a1020}button.sec{background:#243066;color:var(--tx)}button.big{font-size:20px;padding:18px}
button:disabled{opacity:.5}label{display:block;color:var(--mut);font-size:14px;margin-top:8px}.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.bad{color:var(--bad)}.good{color:var(--ok)}.mut{color:var(--mut)}code,pre{font:14px ui-monospace,Menlo,monospace;background:#0a0f24;border:1px solid var(--line);border-radius:8px}
pre{padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:6px 0}code{padding:2px 6px}.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1;min-width:140px}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:13px;background:#243066}.pill.p{background:#5a4a12}.pill.a,.pill.d{background:#14532d}.pill.r{background:#6b1d2b}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>`

const nav = `<nav><b>🌉 Sewa Setu</b><a href="/">Home</a><a href="/apply">Apply</a><a href="/status">Status</a><a href="/admin">Officer</a><a href="/inbox">SMS inbox</a><a href="/eval-dashboard">Eval dashboard</a></nav>`

func shell(title, body, script string) string {
	s := ""
	if script != "" {
		s = "<script>" + script + "</script>"
	}
	return `<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>` + esc(title) + ` · Sewa Setu</title>` + css + nav + `<main>` + body + `</main>` + s + `</html>`
}

// ---------------------------------------------------------------- landing
func (a *Server) landing(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b := baseURL()
	body := `<style>
#hero{position:relative;overflow:hidden;border-radius:22px;border:1px solid var(--line);padding:46px 24px;background:radial-gradient(1200px 400px at 20% -10%,#3b2a6b55,transparent),#10183a}
#hero canvas{position:absolute;inset:0;width:100%;height:100%;opacity:.55}#hero>div{position:relative}
#hero h1{font-size:clamp(30px,6vw,52px);line-height:1.1;margin:0 0 10px;background:linear-gradient(90deg,#ffd29a,#ff7a9a);-webkit-background-clip:text;background-clip:text;color:transparent}
.big{font-size:38px;font-weight:800}.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;text-align:center;transition:transform .3s}.stat.pulse{transform:scale(1.07);border-color:var(--a)}
#feed{height:230px;overflow:auto;font:14px ui-monospace,Menlo,monospace}#feed div{padding:5px 8px;border-bottom:1px solid #1d2650;animation:in .5s}@keyframes in{from{opacity:0;transform:translateX(-14px)}}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--ok);margin-right:6px;animation:pl 1.4s infinite}@keyframes pl{50%{opacity:.25}}
</style>
<div id=hero><canvas id=cv></canvas><div>
<span class=pill><span class=dot></span>LIVE · one portal, three doors</span>
<h1>An old person speaks.<br>The pension portal listens.</h1>
<p class=mut style="max-width:640px">Apply on the web form, through an AI assistant on a shared phone, or let the block officer's assistant clear the queue. All three doors lead to <b>one system of record</b> and <b>one rulebook</b>. Nothing an assistant does can get a result the counter would refuse.</p>
<div class=row style="max-width:520px"><button onclick="location='/apply'">Apply on the web</button><button class=sec onclick="location='/eval-dashboard'">▶ Run the live self-test</button></div>
</div></div>
<h2>Live from the portal <span class=mut style="font-size:14px">(updates the instant anything happens, over a single streaming connection)</span></h2>
<div class=grid id=stats></div>
<div class=card><div id=feed><div class=mut>connecting…</div></div></div>
<h2>Connect an assistant (two separate MCP servers)</h2>
<div class=card><p class=mut>Streamable HTTP, OAuth 2.1 with PKCE and dynamic client registration. The person signs in on the portal's own page; the assistant never sees an OTP or a password.</p>
<b>Citizen (older person, mobile OTP)</b><pre id=c1>claude mcp add --transport http sewasetu-citizen ` + b + `/mcp/citizen</pre><button class=sec onclick="cp('c1')">Copy</button>
<b>Block officer (password)</b><pre id=c2>claude mcp add --transport http sewasetu-officer ` + b + `/mcp/officer</pre><button class=sec onclick="cp('c2')">Copy</button>
<p class=mut>Then run <code>claude</code>, type <code>/mcp</code>, choose the server and sign in. Demo SMS (the OTP) appears at <a href="/inbox">/inbox</a>.</p></div>
<h2>Why it is safe to hand to an agent</h2>
<div class=grid>
<div class=card><b>🔒 Identity from the token</b><br><span class=mut>No tool accepts a mobile number or officer name. The token decides who you are.</span></div>
<div class=card><b>👁 Preview, then confirm</b><br><span class=mut>"Submitted" only after a one-time code is claimed and the person accepts the declaration.</span></div>
<div class=card><b>📋 Case receipt</b><br><span class=mut>An officer decision needs the receipt from opening that exact case. No bulk tool exists.</span></div>
<div class=card><b>⚡ One rulebook</b><br><span class=mut>Web, assistant and officer all call the same Go functions in <code>rules.go</code>.</span></div>
<div class=card><b>🚪 Sign-out is instant</b><br><span class=mut>Shared phones: the next tool call is refused the moment the session is revoked.</span></div>
<div class=card><b>🧪 Prove it</b><br><span class=mut>The self-test plays real citizens and officers through real OAuth and MCP, then checks the data.</span></div></div>
<script>
function cp(id){navigator.clipboard.writeText(document.getElementById(id).textContent)}
var names={PENDING:'Pending',APPROVED:'Approved',DEEMED_APPROVED:'Deemed approved',REJECTED:'Rejected',WITHDRAWN:'Withdrawn'};
function paint(c){var h='';for(var k in names){h+='<div class=stat id=s_'+k+'><div class=big data-v="'+(c[k]||0)+'">'+(c[k]||0)+'</div><div class=mut>'+names[k]+'</div></div>'}document.getElementById('stats').innerHTML=h}
function bump(c){for(var k in names){var e=document.getElementById('s_'+k);if(!e)continue;var d=e.firstChild,n=c[k]||0;if(+d.dataset.v!==n){d.textContent=n;d.dataset.v=n;e.classList.add('pulse');(function(x){setTimeout(function(){x.classList.remove('pulse')},600)})(e)}}}
paint({});
var es=new EventSource('/events');
es.onmessage=function(m){var j=JSON.parse(m.data);if(j.counts){if(!document.querySelector('#stats .big').dataset.v||j.kind==='hello')paint(j.counts);bump(j.counts)}
var f=document.getElementById('feed');if(f.firstChild&&f.firstChild.className==='mut')f.innerHTML='';var d=document.createElement('div');d.textContent=j.at+'  '+j.kind.toUpperCase()+'  '+j.text;f.insertBefore(d,f.firstChild)};
var cv=document.getElementById('cv'),x=cv.getContext('2d'),P=[];function rs(){cv.width=cv.offsetWidth;cv.height=cv.offsetHeight}rs();addEventListener('resize',rs);
for(var i=0;i<60;i++)P.push({x:Math.random()*cv.width,y:Math.random()*cv.height,vx:(Math.random()-.5)*.5,vy:(Math.random()-.5)*.5});
function tick(){x.clearRect(0,0,cv.width,cv.height);for(var i=0;i<P.length;i++){var p=P[i];p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>cv.width)p.vx*=-1;if(p.y<0||p.y>cv.height)p.vy*=-1;x.fillStyle='#ffb86b';x.fillRect(p.x,p.y,2,2);
for(var j=i+1;j<P.length;j++){var q=P[j],d=Math.hypot(p.x-q.x,p.y-q.y);if(d<110){x.strokeStyle='rgba(255,140,120,'+(1-d/110)*.35+')';x.beginPath();x.moveTo(p.x,p.y);x.lineTo(q.x,q.y);x.stroke()}}}requestAnimationFrame(tick)}tick();
</script>`
	serve(w, "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Sewa Setu</title>"+css+nav+"<main>"+body+"</main></html>")
}

// ---------------------------------------------------------------- apply (web door)
func applyPage() string {
	opts := ""
	for _, b := range Blocks {
		opts += "<option>" + b + "</option>"
	}
	return shell("Apply", fmt.Sprintf(`<h1>Apply for the Old Age Pension</h1><p class=mut>₹%d every month, age %d or older. The same rules apply here, at the counter and through an assistant.</p>
<div class=card><form id=f>
<label>Mobile number</label><div class=row><input name=mobile id=m inputmode=numeric maxlength=10 placeholder="10 digits"><button type=button class=sec id=so>Send OTP</button></div>
<label>OTP (demo: read it at <a href="/inbox" target=_blank>/inbox</a>)</label><input name=otp inputmode=numeric maxlength=6>
<label>Full name (as on the age proof)</label><input name=name>
<label>Date of birth (DD/MM/YYYY)</label><input name=dob placeholder="DD/MM/YYYY">
<div class=row><div><label>Gender (optional)</label><select name=gender><option value="">—</option><option>Male</option><option>Female</option><option>Other</option></select></div>
<div><label>Marital status (optional)</label><select name=marital><option value="">—</option><option>Married</option><option>Unmarried</option><option>Widowed</option></select></div></div>
<label>Late husband's name (widows only, optional)</label><input name=husband>
<div class=row><div><label>Village</label><input name=village></div><div><label>Block</label><select name=block>%s</select></div></div>
<div class=row><div><label>Bank account number</label><input name=account inputmode=numeric></div><div><label>IFSC (optional)</label><input name=ifsc placeholder="SBIN0003077"></div></div>
<label>Age proof (birth certificate, school leaving certificate or Voter ID · JPG/PNG/PDF · 5 MB)</label><input type=file name=file accept="image/*,application/pdf">
<p class=mut style="font-size:14px">%s</p>
<button class=big id=go>Submit application</button></form><div id=out></div></div>`, MonthlyAmount, MinAge, opts, esc(declaration)+" By pressing Submit I accept this declaration."),
		`var $=function(i){return document.getElementById(i)};
$('so').onclick=function(){fetch('/api/otp',{method:'POST',body:JSON.stringify({mobile:$('m').value})}).then(function(r){return r.json()}).then(function(j){$('out').innerHTML=j.sent?'<p class=good>OTP sent. Open the SMS inbox to read it.</p>':'<p class=bad>'+(j.error||'failed')+'</p>'})};
$('f').onsubmit=function(e){e.preventDefault();$('go').disabled=true;fetch('/api/apply',{method:'POST',body:new FormData($('f'))}).then(function(r){return r.json()}).then(function(j){$('go').disabled=false;
if(j.result==='created'){$('out').innerHTML='<h2 class=good>✅ Submitted</h2><p>Your application number is <b style="font-size:24px">'+j.application_no+'</b>. Write it down. Track it on the <a href="/status">status page</a> with your mobile number and date of birth.</p>'}
else{$('out').innerHTML='<p class=bad><b>Not submitted:</b></p><ul class=bad>'+(j.errors||['error']).map(function(x){return '<li>'+x.replace(/</g,'&lt;')+'</li>'}).join('')+'</ul>'}})};`)
}

// ---------------------------------------------------------------- status
func statusPage() string {
	return shell("Status", `<h1>Check your application</h1><div class=card>
<label>Mobile number</label><input id=m inputmode=numeric maxlength=10><label>Date of birth (DDMMYYYY)</label><input id=d inputmode=numeric maxlength=10>
<button class=big id=go>Check</button><div id=out></div></div>`,
		`var $=function(i){return document.getElementById(i)};
$('go').onclick=function(){fetch('/api/status',{method:'POST',body:JSON.stringify({mobile:$('m').value,dob:$('d').value})}).then(function(r){return r.json()}).then(function(j){
if(j.error){$('out').innerHTML='<p class=bad>'+j.error+'</p>';return}
if(!j.applications.length){$('out').innerHTML='<p class=bad>No application found for that mobile number and date of birth.</p>';return}
$('out').innerHTML=j.applications.map(function(a){return '<div class=card><b>'+a.application_no+'</b> <span class="pill '+a.status[0].toLowerCase()+'">'+a.status+'</span><br>Block '+a.block+' · submitted '+a.submitted_at+(a.auto_on?'':'')+(a.auto_approval_on?'<br>Approved automatically on '+a.auto_approval_on+' if nobody decides.':'')+(a.reason?'<br>Reason: '+a.reason.replace(/</g,'&lt;'):'')+'</div>'}).join('')})};`)
}

// ---------------------------------------------------------------- SMS inbox (demo gateway)
func inboxPage() string {
	return shell("SMS inbox", `<h1>Demo SMS inbox</h1><p class=mut>In production this is a real SMS gateway. Here every message the portal "sends" appears, newest first. Filter by mobile number:</p>
<input id=to placeholder="mobile number (optional)" inputmode=numeric><div class=card id=list>loading…</div>`,
		`var $=function(i){return document.getElementById(i)};
function load(){fetch('/api/inbox?to='+encodeURIComponent($('to').value)).then(function(r){return r.json()}).then(function(l){$('list').innerHTML=(l||[]).map(function(m){return '<div style="padding:8px 0;border-bottom:1px solid #1d2650"><span class=mut>'+m.at.slice(11,19)+' → '+m.to+'</span><br>'+m.text.replace(/</g,'&lt;')+'</div>'}).join('')||'<span class=mut>no messages</span>'})}
load();setInterval(load,2000);`)
}

// ---------------------------------------------------------------- officer console
func adminPage() string {
	return shell("Officer", `<h1>Block officer console</h1>
<div id=login class=card><label>Username</label><input id=u value=admin><label>Password</label><input id=p type=password><button id=in class=big>Sign in</button><p id=le class=bad></p></div>
<div id=app style="display:none"><div class=row><button class=sec id=run>Run the 15-day deemed-approval job now</button><button class=sec id=out>Sign out</button></div><div id=cnt class=mut></div><div id=q></div></div>`,
		`var $=function(i){return document.getElementById(i)};
function post(u,b){return fetch(u,{method:'POST',body:JSON.stringify(b||{})}).then(function(r){return r.json().then(function(j){j._s=r.status;return j})})}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function load(){fetch('/api/admin/queue').then(function(r){if(r.status===401){$('login').style.display='';$('app').style.display='none';return null}return r.json()}).then(function(j){if(!j)return;$('login').style.display='none';$('app').style.display='';
$('cnt').textContent=Object.keys(j.counts).map(function(k){return k+': '+j.counts[k]}).join('  ·  ');
$('q').innerHTML=j.pending.map(function(a){var fl=a.flags.map(function(f){return '<span class="pill '+(f.blocking?'r':'p')+'" title="'+esc(f.detail)+'">'+f.code+'</span>'}).join(' ');
return '<div class=card><b>'+a.no+'</b> · '+a.days_waiting+' days waiting · auto-approves '+a.auto_on+'<br>'+fl+'<p><b>'+esc(a.name)+'</b>, born '+a.dob+' (age '+a.age_at_submission+' when applied)<br>'+esc(a.village)+', '+a.block+' · A/c '+a.account+(a.ifsc?' · '+a.ifsc:' · no IFSC')+' · via '+esc(a.via)+'</p>'
+(a.has_proof?'<a target=_blank href="/api/admin/proof?no='+a.no+'">View age proof</a>':'<span class=bad>No age proof on file</span>')
+'<input id=r_'+a.no+' placeholder="Your reason (8 to 400 characters)"><div class=row><button onclick="dec(\''+a.no+'\',\'APPROVED\')">Approve</button><button class=sec onclick="dec(\''+a.no+'\',\'REJECTED\')">Reject</button></div><div id=m_'+a.no+'></div></div>'}).join('')||'<p class=mut>The queue is empty.</p>'})}
function dec(no,d){post('/api/admin/decide',{no:no,decision:d,reason:$('r_'+no).value}).then(function(j){if(j.result==='recorded')load();else $('m_'+no).innerHTML='<p class=bad>'+esc(j.message||j.error)+'</p>'})}
$('in').onclick=function(){post('/api/admin/login',{username:$('u').value,password:$('p').value}).then(function(j){if(j.ok)load();else $('le').textContent=j.error})};
$('out').onclick=function(){post('/api/admin/logout').then(load)};
$('run').onclick=function(){post('/api/admin/deemed').then(function(j){alert('Deemed approved: '+j.deemed_approved+'. Held (under 60 on the day): '+j.held_under_60);load()})};
load();var es=new EventSource('/events');es.onmessage=function(m){if($('app').style.display!=='none')load()};`)
}

// ---------------------------------------------------------------- eval dashboard
func evalPage() string {
	return shell("Eval dashboard", `<h1>🧪 Eval dashboard</h1>
<p class=mut>The self-test plays <b>scripted</b> citizens and officers through the real OAuth flow and the real MCP endpoints of this running server, then reads the results back from the data. These are deterministic scripted agents, <b>not</b> a language model; they test the guardrails that a model must not be able to get around. Every run is recorded.</p>
<div class=row><button class=big id=go>▶ Run all checks now</button></div><div id=sum class=card></div><div id=runs></div>`,
		`var $=function(i){return document.getElementById(i)};
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function render(d){var r=d.runs||[];if(!r.length){$('sum').innerHTML='<span class=mut>No run yet. Press the button.</span>';$('runs').innerHTML='';return}
var l=r[r.length-1];$('sum').innerHTML='<div class=big style="font-size:44px;font-weight:800" class="'+(l.passed===l.total?'good':'bad')+'">'+l.passed+' / '+l.total+' checks passed</div><span class=mut>latest run '+l.at+' · '+l.duration_ms+' ms · history: '+r.map(function(x){return x.passed+'/'+x.total}).join(', ')+'</span>'+(d.running?'<br>⏳ a run is in progress…':'');
$('runs').innerHTML='<div class=card>'+l.checks.map(function(c){return '<div style="padding:7px 0;border-bottom:1px solid #1d2650"><span class="'+(c.pass?'good':'bad')+'">'+(c.pass?'✔':'✘')+'</span> <b>'+esc(c.group)+'</b> · '+esc(c.name)+' <span class=mut>('+c.ms+' ms)</span>'+(c.detail?'<br><span class=mut style="font-size:14px">'+esc(c.detail)+'</span>':'')+'</div>'}).join('')+'</div>'}
function load(){fetch('/api/evals').then(function(r){return r.json()}).then(render)}
$('go').onclick=function(){$('go').disabled=true;fetch('/api/evals/run',{method:'POST'}).then(function(r){return r.json()}).then(function(j){if(j.error)alert(j.error);setTimeout(function(){$('go').disabled=false},3000)})};
load();var es=new EventSource('/events');es.onmessage=function(m){var j=JSON.parse(m.data);if(j.kind==='eval')load()};setInterval(load,4000);`)
}

var _ = http.StatusOK

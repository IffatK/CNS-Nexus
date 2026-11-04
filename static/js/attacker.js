(() => {
 const $=id=>document.getElementById(id);
 document.querySelector("#event-rows")?.closest("table")?.classList.add("event-stream-table");
 // Keep the console navigation marker aligned with the section in view.
 const navLinks=[...document.querySelectorAll('.sidebar a[href^="#"]')];
 const navTargets=navLinks.map(link=>({link,target:$(link.getAttribute("href").slice(1))})).filter(item=>item.target);
 function setActiveNav(link){
  navLinks.forEach(item=>{const active=item===link;item.classList.toggle("active",active);if(active)item.setAttribute("aria-current","location");else item.removeAttribute("aria-current");});
 }
 navLinks.forEach(link=>link.addEventListener("click",()=>setActiveNav(link)));
 setActiveNav(navTargets.find(item=>item.target.id===location.hash.slice(1))?.link||navTargets[0]?.link);
 if("IntersectionObserver" in window){
  const navObserver=new IntersectionObserver(entries=>{
   const visible=entries.filter(entry=>entry.isIntersecting).sort((a,b)=>b.intersectionRatio-a.intersectionRatio)[0];
   if(visible)setActiveNav(navTargets.find(item=>item.target===visible.target)?.link);
  },{rootMargin:"-12% 0px -72% 0px",threshold:[0,.15,.35]});
  navTargets.forEach(({target})=>navObserver.observe(target));
 }
 const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
 function tag(value, cls=""){return `<span class="tag ${cls}">${esc(value)}</span>`}
 const themeColor=(name,fallback)=>getComputedStyle(document.documentElement).getPropertyValue(name).trim()||fallback;
 const palette=()=>document.documentElement.dataset.theme==="dark"? ["#55F39A","#2CBF75","#F0CB78","#A8D7B5","#F0918E"]:["#B52A32","#8F2029",themeColor("--green","#557A5C"),themeColor("--amber","#C28A2C"),themeColor("--error","#9B252C")];
 function plot(id, values, mode){
  const canvas=$(id),ctx=canvas?.getContext("2d");if(!ctx)return;
  const w=Math.max(320,canvas.clientWidth||320),h=180,dpr=window.devicePixelRatio||1;canvas.width=w*dpr;canvas.height=h*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,w,h);
  if(mode==="donut"){
   const colors=palette(),total=values.reduce((n,x)=>n+x.value,0),cx=w/2,cy=h/2,r=55;let a=-Math.PI/2;
   if(total===0){ctx.fillStyle=themeColor("--muted","#82746D");ctx.textAlign="center";ctx.fillText("No message outcomes yet",cx,cy);return;}
   values.forEach((x,i)=>{if(!x.value)return;const e=a+x.value/total*Math.PI*2;ctx.beginPath();ctx.arc(cx,cy,r,a,e);ctx.strokeStyle=colors[i%colors.length];ctx.lineWidth=22;ctx.stroke();a=e;});
   ctx.fillStyle=document.documentElement.dataset.theme==="dark"?"#E8F2EA":themeColor("--cream","#F7F0E7");ctx.textAlign="center";ctx.fillText(String(total),cx,cy+4);return;
  }
  const max=Math.max(1,...values.flatMap(x=>x.values.map(y=>y.value)));
  const colors=palette();
  if(!values.some(s=>s.values.some(p=>Number(p.value)>0))){
   ctx.fillStyle=themeColor("--muted","#82746D");ctx.textAlign="center";ctx.font="12px system-ui";
   ctx.fillText("No records in this range",w/2,h/2-5);ctx.font="10px system-ui";
   ctx.fillText("Run a lab action to create real data",w/2,h/2+14);ctx.textAlign="left";return;
  }
  if(mode==="line"){
   values.forEach((s,si)=>{ctx.beginPath();ctx.strokeStyle=colors[si%colors.length];ctx.lineWidth=2;s.values.forEach((p,i)=>{const x=18+i*(w-36)/Math.max(1,s.values.length-1),y=h-22-p.value/max*(h-42);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.stroke();});
  }else{
   const count=values[0]?.values.length||0,group=(w-30)/Math.max(1,count),bw=Math.max(3,Math.min(20,group/values.length*.7));
   values.forEach((s,si)=>s.values.forEach((p,i)=>{const x=15+i*group+si*group/values.length;const bh=p.value/max*(h-38);ctx.fillStyle=colors[si%colors.length];ctx.fillRect(x,h-20-bh,bw,bh);}));
  }
  ctx.fillStyle=themeColor("--muted","#82746D");ctx.font="10px system-ui";ctx.fillText(values[0]?.values?.[0]?.label||"",8,h-4);ctx.textAlign="right";ctx.fillText(values[0]?.values?.at(-1)?.label||"",w-8,h-4);ctx.textAlign="left";
 }
 async function loadDiagnostics(){
  try{
   const days=$("diagnostic-days")?.value||"7";
   const r=await fetch(`/api/attacker/diagnostics?days=${encodeURIComponent(days)}`,{credentials:"same-origin",cache:"no-store"});
   if(!r.ok)throw new Error(`HTTP ${r.status}`);const d=await r.json();
   plot("attack-timeline",[{values:d.timeline.map(x=>({label:x.label.slice(5),value:x.attempts}))},{values:d.timeline.map(x=>({label:x.label.slice(5),value:x.blocked}))}],"line");
   plot("attack-types",["successful","blocked"].map(key=>({values:Object.entries(d.attack_types).map(([label,x])=>({label,value:x[key]}))})),"bar");
   plot("message-outcomes",Object.entries(d.outcomes).map(([label,value])=>({label,value})),"donut");
   plot("signature-results",Object.entries(d.signature_results).map(([label,value])=>({label,value})),"donut");
   const simRows=Object.entries(d.simulation_types||{});
   plot("simulation-types",["successful","blocked","failed"].map(key=>({values:simRows.map(([label,x])=>({label,value:x[key]}))})),"bar");
   $("attack-timeline-summary").textContent=`Attempts: ${d.timeline.reduce((n,x)=>n+x.attempts,0)} · blocked by policy: ${d.timeline.reduce((n,x)=>n+x.blocked,0)}`;
   $("attack-types-summary").textContent=Object.entries(d.attack_types).map(([k,v])=>`${k}: ${v.successful} successful, ${v.blocked} blocked`).join(" · ");
   $("message-outcomes-summary").textContent=Object.entries(d.outcomes).map(([k,v])=>`${k}: ${v}`).join(" · ");
   $("signature-results-summary").textContent=Object.entries(d.signature_results).map(([k,v])=>`${k}: ${v}`).join(" · ");
   $("simulation-types-summary").textContent=simRows.length?simRows.map(([k,v])=>`${k}: ${v.successful} successful, ${v.blocked} blocked, ${v.failed} failed`).join(" · "):"No simulation runs in this time range.";
   $("protection-policy").textContent=`${d.protection.enabled_accounts} of ${d.protection.configured_accounts} accounts have protection enabled. ${d.protection.enforcement}`;
   if($("protection-summary"))$("protection-summary").textContent=`${d.protection.enabled_accounts} / ${d.protection.configured_accounts} accounts protected`;
   $("integrity-rows").innerHTML=d.integrity.length?d.integrity.map(m=>`<tr><td>#${esc(m.id)} · ${esc(m.time)}</td><td>${esc(m.sender)} → ${esc(m.recipient)}</td><td>${esc(m.protection)}</td><td>${tag(m.verification,m.verification==="verified"?"ok":m.verification==="unprotected"?"warning":"critical")}</td></tr>`).join(""):'<tr><td colspan="4" class="empty">No delivered messages to verify.</td></tr>';
  }catch(e){if($("protection-policy"))$("protection-policy").textContent=`Diagnostics unavailable: ${e.message}`;}
 }
 async function refresh(){
  try{
   const r=await fetch("/api/attacker/events",{credentials:"same-origin",cache:"no-store"});
   if(!r.ok)throw new Error("HTTP "+r.status);
   const d=await r.json(); $("connection").textContent="Connected";
   const feed=$("activity-feed"), feedCount=$("activity-count");
   if(feed&&feedCount){
    const recent=(d.events||[]).slice(0,8);
    feedCount.textContent=`${d.events?.length||0} saved event${d.events?.length===1?"":"s"}`;
    feed.innerHTML=recent.length?recent.map(e=>`<article class="activity-item ${esc(e.severity)}"><span class="activity-marker" aria-hidden="true"></span><div class="activity-copy"><b>${esc(e.type.replaceAll("_"," "))}</b><span>${esc(e.detail||"Recorded lab security event")}</span><small>${esc(e.time)} · ${esc(e.username)} · ${esc(e.source)}</small></div><span class="tag ${e.severity==="critical"?"critical":e.severity==="warning"?"warning":""}">${esc(e.severity)}</span></article>`).join(""):'<div class="empty">No recorded lab events yet. Send a message through the client portal or run a controlled simulation.</div>';
   }
   const picker=$("simulation-message"), previous=picker?.value||"";
   if(picker){picker.innerHTML='<option value="">Use a synthetic fixture / latest message</option>'+d.messages.map(m=>`<option value="msg:${esc(m.id)}">Message #${esc(m.id)} · ${esc(m.sender)} → ${esc(m.recipient)} · ${esc(m.protection)}</option>`).join("")+d.pending.map(m=>`<option value="queue:${esc(m.id)}">Pending relay #${esc(m.id)} · ${esc(m.sender)} → ${esc(m.recipient)}</option>`).join("");if([...picker.options].some(o=>o.value===previous))picker.value=previous;}
   const pendingCount=$("pending-count"); if(pendingCount) pendingCount.textContent=d.stats.pending ?? d.pending.length;
   if($("queue-summary"))$("queue-summary").textContent=`${d.stats.pending} pending · ${d.stats.forwarded} forwarded · ${d.stats.dropped} dropped`;
   $("users").textContent=d.stats.users;$("messages").textContent=d.stats.messages;$("events-count").textContent=d.stats.events;$("failed").textContent=d.stats.failed_logins;$("plaintext").textContent=d.stats.plaintext;
   $("captures").textContent=d.stats.captures;$("forwarded").textContent=d.stats.forwarded;$("dropped").textContent=d.stats.dropped;$("attack-attempts").textContent=d.stats.attack_attempts;$("simulation-successes").textContent=d.stats.simulation_successes;$("blocked-attacks").textContent=d.stats.blocked_attacks;
   const queue=$("intercept-queue"), queueKey=JSON.stringify(d.pending.map(m=>[m.id,m.body,m.time,m.source]));
   // Polling must not replace an actively edited textarea every two seconds.
   // Rebuild only when the queue contents change, preserving drafts otherwise.
   if(queue.dataset.queueKey!==queueKey){
    const edits=new Map([...queue.querySelectorAll(".intercept-item")].map(card=>[card.dataset.id,card.querySelector(".edited-body")?.value]));
    queue.innerHTML=d.pending.length?d.pending.map(m=>`<article class="intercept-item" data-id="${esc(m.id)}"><div class="intercept-head"><div><b>#${esc(m.id)} · ${esc(m.sender)} → ${esc(m.recipient)}</b><div class="muted">${esc(m.time)} · source ${esc(m.source)}</div></div><span class="pending-label">HELD / PLAINTEXT</span></div><label>Intercepted original message (read-only)</label><textarea readonly>${esc(m.body)}</textarea><label>Edited copy (optional)</label><textarea class="edited-body">${esc(edits.get(String(m.id)) ?? m.body)}</textarea><div class="intercept-actions"><button class="forward-original">Forward original unchanged</button><button class="forward-edited">Forward edited copy</button><button class="drop">Drop message</button></div><div class="muted relay-status" aria-live="polite"></div></article>`).join(""):'<div class="empty">No pending messages. Send from an unprotected sender account to create a readable relay item.</div>';
    queue.dataset.queueKey=queueKey;
    async function relay(button, action, body){
     const card=button.closest(".intercept-item"), id=card.dataset.id, status=card.querySelector(".relay-status");
     card.querySelectorAll("button").forEach(b=>b.disabled=true);status.textContent="Processing relay action…";
     try{const r=await window.cnsPostJSON(`/api/attacker/relay/${id}`,{action,...(body===undefined?{}:{body})});const result=await r.json();if(!r.ok)throw new Error(result.error||"Relay action failed");status.textContent=result.message;refresh();}
     catch(e){status.textContent=e.message;card.querySelectorAll("button").forEach(b=>b.disabled=false);}
    }
    queue.querySelectorAll(".forward-original").forEach(button=>button.addEventListener("click",()=>relay(button,"forward_original")));
    queue.querySelectorAll(".forward-edited").forEach(button=>button.addEventListener("click",()=>relay(button,"forward_edited",button.closest(".intercept-item").querySelector(".edited-body").value)));
    queue.querySelectorAll(".drop").forEach(button=>button.addEventListener("click",()=>{
     if(!confirm("Drop this intercepted message? The recipient will not receive it."))return;
     relay(button,"drop");
    }));
   }
   $("capture-rows").innerHTML=d.captures.length?d.captures.map(c=>{
    const protectedMode=c.protection==="protected";
    const payload=protectedMode?`<div class="content">${esc(c.wire_preview)}</div><small class="muted">Message content unavailable in observer view</small>`:`<div class="content">${esc(c.content)}</div>`;
    const statusClass=c.status.includes("intercept")?"warning":c.status.includes("drop")?"critical":c.status.includes("tamper")?"critical":"ok";
    return `<tr><td>${esc(c.time)}<br>#${esc(c.message_id??"queued")}</td><td>${esc(c.username)} → ${esc(c.recipient)}</td><td>${esc(c.size_bytes??"—")}</td><td>${tag(protectedMode?"PROTECTED":"PLAINTEXT",protectedMode?"protected":"plaintext")}<br>${tag(c.verification,c.verification==="verified"?"ok":c.verification==="pending"?"warning":"critical")}</td><td class="cell-wrap">${payload}</td><td>${tag(c.status,statusClass)}</td></tr>`;
   }).join(""):'<tr><td colspan="6" class="empty">No message captures yet. Send a message from the user portal.</td></tr>';
   $("event-rows").innerHTML=d.events.length?d.events.map(e=>`<tr><td>${esc(e.time)}</td><td>${tag(e.severity,e.severity==="critical"?"critical":e.severity==="warning"?"warning":"")}</td><td><b>${esc(e.type)}</b><br>${esc(e.username)}</td><td>${esc(e.source)}</td><td class="cell-wrap">${esc(e.detail)}</td></tr>`).join(""):'<tr><td colspan="5" class="empty">No events yet.</td></tr>';
   $("attempt-rows").innerHTML=d.attempts.length?d.attempts.map(a=>`<tr><td>${esc(a.time)}</td><td>${esc(a.username)}</td><td>${esc(a.source)}</td><td>${tag(a.result,a.result==="SUCCESS"?"ok":"critical")}</td></tr>`).join(""):'<tr><td colspan="4" class="empty">No attempts yet.</td></tr>';
  }catch(e){$("connection").textContent="Disconnected";$("event-rows").innerHTML=`<tr><td colspan="5">${esc(e.message)}</td></tr>`;}
 }
 async function loadSystemDiagnostics(){
  const overview=$("diagnostic-overview"), rows=$("diagnostic-rows"), summary=$("diagnostic-summary");
  if(!overview||!rows||!summary)return;
  try{
   const response=await fetch("/api/diagnostics",{credentials:"same-origin",cache:"no-store"});
   if(!response.ok)throw new Error(`HTTP ${response.status}`);
   const data=await response.json(), components=data.components||[];
   const healthy=components.filter(x=>x.status==="HEALTHY").length;
   const attention=components.filter(x=>["DEGRADED","UNAVAILABLE","FAILED"].includes(x.status)).length;
   const optional=components.filter(x=>x.status==="NOT CONFIGURED").length;
   overview.textContent=`${healthy} healthy · ${attention} need attention · ${optional} not configured. These checks cover application services; message delivery is monitored separately below.`;
   summary.replaceChildren(...components.map(component=>{
    const item=document.createElement("div"), name=document.createElement("b"), status=document.createElement("span");
    const state=component.status==="HEALTHY"?"ok":["DEGRADED"].includes(component.status)?"warning":["UNAVAILABLE","FAILED"].includes(component.status)?"critical":"neutral";
    item.className="diagnostic-chip";name.textContent=component.name;status.className=`tag ${state}`;status.textContent=component.status;item.append(name,status);return item;
   }));
   rows.innerHTML=components.map(component=>{
    const state=component.status==="HEALTHY"?"ok":component.status==="DEGRADED"?"warning":["UNAVAILABLE","FAILED"].includes(component.status)?"critical":"neutral";
    return `<tr><td>${esc(component.name)}</td><td>${tag(component.status,state)}</td><td class="cell-wrap">${esc(component.detail)}<br><small class="muted">Checked ${esc(component.checked_at||"")}</small></td></tr>`;
   }).join("")||'<tr><td colspan="3" class="empty">No diagnostic components were returned.</td></tr>';
  }catch(error){
   overview.textContent=`System diagnostics unavailable: ${error.message}`;
   summary.replaceChildren();rows.innerHTML=`<tr><td colspan="3" class="empty">Could not retrieve diagnostics (${esc(error.message)}).</td></tr>`;
  }
 }
 $("tamper").addEventListener("click",async()=>{
  const b=$("tamper");b.disabled=true;
  try{const r=await window.cnsPostJSON("/api/attacker/tamper-demo",{});const d=await r.json();const box=$("tamper-result");box.classList.add("visible");box.innerHTML=`<b>${esc(d.title||"Tamper test")}: ${esc(d.result||r.status)}</b><p>${esc(d.detail||d.error||"")}</p>`;refresh();}
  catch(e){alert("Test failed: "+e.message)}finally{b.disabled=false;}
 });
 document.querySelectorAll("[data-simulation]").forEach(button=>button.addEventListener("click",async()=>{
  const kind=button.dataset.simulation,box=$("result-"+kind),choice=$("simulation-message")?.value||"";
  const [scope,id]=choice.split(":");
  if(kind==="dropping"&&scope&&scope!=="queue"){box.className="simulation-result error";box.textContent="Select a pending relay item, not a delivered message.";return;}
  if(["replay","unauthorized_access"].includes(kind)&&scope==="queue"){box.className="simulation-result error";box.textContent="Select a delivered message or use the synthetic/latest message fixture.";return;}
  const payload={};if(scope==="msg")payload.message_id=Number(id);if(scope==="queue")payload.queue_id=Number(id);
  button.disabled=true;box.className="simulation-result";box.textContent="Running test…";
  try{
   const response=await window.cnsPostJSON(`/api/attacker/simulations/${encodeURIComponent(kind)}`,payload);
   const result=await response.json();if(!response.ok)throw new Error(result.error||result.explanation||`HTTP ${response.status}`);
   box.classList.add("complete");box.textContent=`${result.status.toUpperCase()} · ${result.outcome}\n${result.explanation||""}\nEvidence: ${JSON.stringify(result.evidence||{})}\nRun ID: ${result.run_id}`;
   const link=document.createElement("a");link.href=`/api/attacker/reports/${encodeURIComponent(result.run_id)}`;link.textContent=" Download run report";link.setAttribute("download",`lab-run-${result.run_id}.json`);box.appendChild(link);
   refresh();
  }catch(error){box.classList.add("error");box.textContent=`FAILED · ${error.message}`;}
  finally{button.disabled=false;}
 }));
 refresh();setInterval(refresh,2000);loadSystemDiagnostics();setInterval(loadSystemDiagnostics,30000);
 $("diagnostic-days")?.addEventListener("change",loadDiagnostics);window.addEventListener("cns-theme-change",loadDiagnostics);loadDiagnostics();setInterval(loadDiagnostics,10000);
})();

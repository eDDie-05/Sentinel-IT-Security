import { useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

const defaultPolicy = { antivirus_required: true, firewall_required: true, backup_required: true };

function token() { return localStorage.getItem("token"); }
async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const t = token();
  if (t) headers.Authorization = `Bearer ${t}`;
  const res = await fetch(`${API}${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) throw new Error(data.error || "Session expired");
    throw new Error(data.error || "Request failed");
  }
  return data;
}
function decodeToken(t) {
  try { return JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); }
  catch { return null; }
}
function bool(v) { return v === true || v === "true" || v === 1 || v === "1"; }
function secure(d, p) {
  return (!p.antivirus_required || bool(d.antivirus)) &&
         (!p.firewall_required || bool(d.firewall)) &&
         (!p.backup_required || bool(d.backup));
}
function problems(d, p) {
  const a=[];
  if (p.antivirus_required && !bool(d.antivirus)) a.push("Antivirus");
  if (p.firewall_required && !bool(d.firewall)) a.push("Firewall");
  if (p.backup_required && !bool(d.backup)) a.push("Backup");
  if (!bool(d.online)) a.push("Offline");
  return a;
}
function initials(name="User") { return name.split(/\s+/).map(x=>x[0]).slice(0,2).join("").toUpperCase(); }
function fmtDate(v) { return v ? new Date(v).toLocaleString([], {dateStyle:"medium",timeStyle:"short"}) : "—"; }

function Login({ onLogin }) {
  const [email,setEmail]=useState("admin@company.com"), [password,setPassword]=useState("Admin123456");
  const [loading,setLoading]=useState(false), [error,setError]=useState("");
  async function submit(e) {
    e.preventDefault(); setError(""); setLoading(true);
    try { const data=await api("/login",{method:"POST",body:JSON.stringify({email,password})}); localStorage.setItem("token",data.token); onLogin(decodeToken(data.token)); }
    catch(e){setError(e.message)} finally{setLoading(false)}
  }
  return <div className="login-shell">
    <div className="login-visual">
      <div className="brand-mark">e</div><div className="brand-name">eDDie</div>
      <h1>Company IT<br/><span>Security Center</span></h1>
      <p>Centralized visibility, policy enforcement and security operations for company endpoints.</p>
      <div className="security-points"><span>✓ Endpoint monitoring</span><span>✓ Policy compliance</span><span>✓ Audit accountability</span></div>
    </div>
    <form className="login-card" onSubmit={submit}>
      <div className="eyebrow">SECURE ADMIN PORTAL</div><h2>Welcome back</h2><p className="muted">Sign in to manage your organization's security.</p>
      {error && <div className="error-box">{error}</div>}
      <label>Email address<input type="email" value={email} onChange={e=>setEmail(e.target.value)} required /></label>
      <label>Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} required /></label>
      <button className="primary wide" disabled={loading}>{loading ? "Signing in…" : "Sign in securely →"}</button>
      <div className="login-note"><span>🔒</span> Protected session · Role-based access control</div>
    </form>
  </div>
}

function Sidebar({page,setPage,user,onLogout}) {
  const admin=user.role==="Administrator", manager=admin||user.role==="IT Manager";
  const nav=[["dashboard","⌂","Overview"],["devices","▣","Devices"],["alerts","⚠","Security Alerts"]];
  return <aside className="sidebar">
    <div className="side-brand"><div className="brand-mark small">e</div><div><b>eDDie</b><small>IT SECURITY</small></div></div>
    <div className="side-label">WORKSPACE</div>
    {nav.map(([id,ic,label])=><button key={id} className={page===id?"nav active":"nav"} onClick={()=>setPage(id)}><span>{ic}</span>{label}{id==="alerts"&&<span className="nav-dot"/>}</button>)}
    <div className="side-label">ADMINISTRATION</div>
    {admin&&<button className={page==="users"?"nav active":"nav"} onClick={()=>setPage("users")}><span>♙</span>Users</button>}
    {manager&&<button className={page==="settings"?"nav active":"nav"} onClick={()=>setPage("settings")}><span>⚙</span>Security Policy</button>}
    {admin&&<button className={page==="activity"?"nav active":"nav"} onClick={()=>setPage("activity")}><span>◷</span>Activity Log</button>}
    <div className="side-bottom">
      <div className="user-mini"><div className="avatar">{initials(user.name)}</div><div><b>{user.name}</b><small>{user.role}</small></div></div>
      <button className="logout" onClick={onLogout}>↪ Sign out</button>
    </div>
  </aside>
}

function Header({title,subtitle,user,onRefresh,loading}) {
  return <header className="topbar"><div><div className="crumb">SECURITY CENTER / <span>{title.toUpperCase()}</span></div><h1>{title}</h1>{subtitle&&<p>{subtitle}</p>}</div>
    <div className="top-actions"><button className="icon-btn" title="Refresh" onClick={onRefresh}>{loading?"…":"↻"}</button><div className="top-user"><div className="avatar">{initials(user.name)}</div><span>{user.name}</span></div></div>
  </header>
}

function Stat({icon,label,value,detail,tone="neutral"}) { return <div className="stat-card"><div className={`stat-icon ${tone}`}>{icon}</div><div className="stat-body"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div></div> }

function Dashboard({devices,policy,setPage}) {
  const total=devices.length, online=devices.filter(d=>bool(d.online)).length, safe=devices.filter(d=>secure(d,policy)).length, risk=total-safe;
  const rate=total?Math.round(safe/total*100):0;
  const alerts=devices.reduce((n,d)=>n+problems(d,policy).length,0);
  const departments=[...new Set(devices.map(d=>d.department).filter(Boolean))];
  return <div>
    <div className="hero-strip"><div><span className="pill green">● SYSTEM OPERATIONAL</span><h2>Security posture at a glance</h2><p>Monitor endpoints, enforce policies and respond to security issues.</p></div><button className="primary" onClick={()=>setPage("devices")}>Manage devices →</button></div>
    <div className="stats-grid">
      <Stat icon="▣" label="Total devices" value={total} detail="Registered endpoints" tone="blue"/>
      <Stat icon="✓" label="Secure devices" value={safe} detail={`${rate}% of fleet compliant`} tone="green"/>
      <Stat icon="!" label="At risk" value={risk} detail={risk?"Needs attention":"No critical exposure"} tone="red"/>
      <Stat icon="●" label="Online now" value={online} detail={`${total?Math.round(online/total*100):0}% reachable`} tone="purple"/>
    </div>
    <div className="content-grid">
      <section className="panel posture"><div className="panel-head"><div><h3>Security posture</h3><p>Current compliance against your active policy</p></div><b className="big-rate">{rate}%</b></div>
        <div className="progress"><span style={{width:`${rate}%`}}/></div><div className="legend"><span><i className="dot green-bg"/>Compliant <b>{safe}</b></span><span><i className="dot red-bg"/>At risk <b>{risk}</b></span><span><i className="dot gray-bg"/>Total <b>{total}</b></span></div>
        <div className="policy-mini"><b>Active controls</b><span>Antivirus {policy.antivirus_required?"Required":"Optional"}</span><span>Firewall {policy.firewall_required?"Required":"Optional"}</span><span>Backup {policy.backup_required?"Required":"Optional"}</span></div>
      </section>
      <section className="panel"><div className="panel-head"><div><h3>Attention required</h3><p>Endpoints with security findings</p></div><button className="text-btn" onClick={()=>setPage("alerts")}>View all</button></div>
        {devices.filter(d=>!secure(d,policy)).slice(0,4).map(d=><div className="issue-row" key={d.id}><div className="device-avatar">▣</div><div><b>{d.name}</b><small>{problems(d,policy).join(" · ")}</small></div><span className="badge risk">At risk</span></div>)}
        {!risk&&<div className="empty small">✓ All registered devices meet the active policy.</div>}
      </section>
    </div>
    <div className="content-grid lower">
      <section className="panel"><div className="panel-head"><div><h3>Fleet by department</h3><p>Device distribution</p></div></div>
        {departments.length?departments.map(dep=>{const n=devices.filter(d=>d.department===dep).length;return <div className="bar-row" key={dep}><span>{dep}</span><div className="bar"><i style={{width:`${total?n/total*100:0}%`}}/></div><b>{n}</b></div>}):<div className="empty">No departments yet.</div>}
      </section>
      <section className="panel"><div className="panel-head"><div><h3>Security events</h3><p>Live summary</p></div></div>
        <div className="event-stat"><span>⚠</span><div><b>{alerts}</b><small>Open security findings</small></div></div>
        <div className="event-stat"><span>●</span><div><b>{online}</b><small>Devices currently online</small></div></div>
        <div className="event-stat"><span>✓</span><div><b>{safe}</b><small>Devices meeting policy</small></div></div>
      </section>
    </div>
  </div>
}

const emptyDevice={name:"",operatingSystem:"Windows 11",employee:"",department:"",ipAddress:"",antivirus:true,firewall:true,backup:true,online:true};
function DeviceModal({device,onClose,onSaved}) {
  const [form,setForm]=useState(device?{...device}:emptyDevice),[saving,setSaving]=useState(false),[error,setError]=useState("");
  const change=(k,v)=>setForm(f=>({...f,[k]:v}));
  async function save(e){e.preventDefault();setError("");setSaving(true);try{const data=await api(device?`/devices/${device.id}`:"/devices",{method:device?"PUT":"POST",body:JSON.stringify(form)});onSaved(data)}catch(e){setError(e.message)}finally{setSaving(false)}}
  return <div className="modal-backdrop"><form className="modal large" onSubmit={save}><div className="modal-head"><div><span className="eyebrow">{device?"EDIT ENDPOINT":"REGISTER ENDPOINT"}</span><h2>{device?"Update device":"Add a company device"}</h2></div><button type="button" className="close" onClick={onClose}>×</button></div>
    {error&&<div className="error-box">{error}</div>}
    <div className="form-grid"><label>Device name<input value={form.name} onChange={e=>change("name",e.target.value)} required placeholder="e.g. Finance-Laptop-01"/></label><label>Operating system<select value={form.operatingSystem} onChange={e=>change("operatingSystem",e.target.value)}><option>Windows 11</option><option>Windows 10</option><option>macOS</option><option>Ubuntu Linux</option><option>Other</option></select></label><label>Assigned employee<input value={form.employee} onChange={e=>change("employee",e.target.value)} required placeholder="Employee name"/></label><label>Department<input value={form.department} onChange={e=>change("department",e.target.value)} required placeholder="e.g. Finance"/></label><label>IP address<input value={form.ipAddress} onChange={e=>change("ipAddress",e.target.value)} required placeholder="192.168.1.20"/></label></div>
    <div className="control-box"><b>Security controls</b><p>Set the current state reported by this endpoint.</p><div className="toggle-grid">{[["antivirus","Antivirus","Malware protection"],["firewall","Firewall","Network protection"],["backup","Backup","Data recovery"],["online","Online","Endpoint reachable"]].map(([k,l,d])=><button type="button" className={`toggle-card ${bool(form[k])?"on":""}`} key={k} onClick={()=>change(k,!bool(form[k]))}><span className="toggle-check">{bool(form[k])?"✓":"×"}</span><span><b>{l}</b><small>{d}</small></span><strong>{bool(form[k])?"Enabled":"Disabled"}</strong></button>)}</div></div>
    <div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={saving}>{saving?"Saving…":device?"Save changes":"Register device"}</button></div>
  </form></div>
}

function Devices({devices,setDevices,policy,user,setPage}) {
  const [query,setQuery]=useState(""),[filter,setFilter]=useState("all"),[department,setDepartment]=useState("all"),[modal,setModal]=useState(null),[error,setError]=useState("");
  const canManage=user.role!=="IT Staff";
  const deps=[...new Set(devices.map(d=>d.department).filter(Boolean))];
  const rows=useMemo(()=>devices.filter(d=>{
    const q=query.toLowerCase(); const match=!q||[d.name,d.employee,d.department,d.operating_system,d.ip_address].some(x=>String(x||"").toLowerCase().includes(q));
    const f=filter==="all"||filter==="online"&&bool(d.online)||filter==="offline"&&!bool(d.online)||filter==="secure"&&secure(d,policy)||filter==="risk"&&!secure(d,policy);
    return match&&f&&(department==="all"||d.department===department);
  }),[devices,query,filter,department,policy]);
  async function remove(d){if(!confirm(`Remove ${d.name} from the system?`))return;try{await api(`/devices/${d.id}`,{method:"DELETE"});setDevices(x=>x.filter(v=>v.id!==d.id))}catch(e){setError(e.message)}}
  function saved(d){setDevices(x=>{const exists=x.some(v=>v.id===d.id);return exists?x.map(v=>v.id===d.id?d:v):[d,...x]});setModal(null)}
  return <div>
    <div className="toolbar"><div className="search"><span>⌕</span><input placeholder="Search devices, employees, departments…" value={query} onChange={e=>setQuery(e.target.value)}/></div>{canManage&&<button className="primary" onClick={()=>setModal("add")}>＋ Add device</button>}</div>
    {error&&<div className="error-box">{error}</div>}
    <div className="filter-row"><div className="tabs">{[["all","All"],["online","Online"],["offline","Offline"],["secure","Secure"],["risk","At risk"]].map(([v,l])=><button className={filter===v?"selected":""} onClick={()=>setFilter(v)} key={v}>{l}<span>{v==="all"?devices.length:v==="online"?devices.filter(d=>bool(d.online)).length:v==="offline"?devices.filter(d=>!bool(d.online)).length:v==="secure"?devices.filter(d=>secure(d,policy)).length:devices.filter(d=>!secure(d,policy)).length}</span></button>)}</div><select className="compact-select" value={department} onChange={e=>setDepartment(e.target.value)}><option value="all">All departments</option>{deps.map(d=><option key={d}>{d}</option>)}</select></div>
    <section className="panel table-panel"><div className="panel-head"><div><h3>Company endpoints</h3><p>{rows.length} of {devices.length} devices shown</p></div><span className="live-indicator">● Live data</span></div>
      <div className="table-wrap"><table><thead><tr><th>DEVICE</th><th>ASSIGNED TO</th><th>OS</th><th>CONNECTION</th><th>PROTECTION</th><th>STATUS</th><th>ACTIONS</th></tr></thead><tbody>
      {rows.map(d=><tr key={d.id}><td><div className="device-cell"><div className="device-avatar">▣</div><div><b>{d.name}</b><small>{d.ip_address}</small></div></div></td><td><b className="normal">{d.employee}</b><small>{d.department}</small></td><td><span className="os-chip">{d.operating_system}</span></td><td><span className={`connection ${bool(d.online)?"online":"offline"}`}><i/> {bool(d.online)?"Online":"Offline"}</span></td><td><div className="control-chips"><span className={bool(d.antivirus)?"good":"bad"}>AV</span><span className={bool(d.firewall)?"good":"bad"}>FW</span><span className={bool(d.backup)?"good":"bad"}>BK</span></div></td><td><span className={`badge ${secure(d,policy)?"secure":"risk"}`}>{secure(d,policy)?"✓ Secure":"! At risk"}</span>{!secure(d,policy)&&<small className="reason">{problems(d,policy).join(", ")}</small>}</td><td><div className="actions"><button title="Edit" onClick={()=>setModal(d)} disabled={!canManage}>✎</button><button title="Delete" onClick={()=>remove(d)} disabled={!canManage}>⌫</button></div></td></tr>)}
      </tbody></table>{!rows.length&&<div className="empty">No devices match your filters.</div>}</div>
    </section>
    {modal&&<DeviceModal device={modal==="add"?null:modal} onClose={()=>setModal(null)} onSaved={saved}/>}
  </div>
}

function Alerts({devices,policy,setPage}) {
  const findings=devices.flatMap(d=>problems(d,policy).map(type=>({device:d,type,level:type==="Offline"?"warning":"critical"})));
  return <div><div className="hero-strip compact"><div><span className="pill red">● {findings.length} OPEN FINDINGS</span><h2>Security alerts</h2><p>Issues are calculated directly from endpoint state and the active security policy.</p></div><button className="secondary" onClick={()=>setPage("devices")}>Review devices</button></div>
    <section className="panel table-panel"><div className="panel-head"><div><h3>Open findings</h3><p>Resolve the underlying endpoint condition to clear an alert.</p></div></div>
      {findings.length?<div className="alert-list">{findings.map((f,i)=><div className="alert-row" key={`${f.device.id}-${f.type}-${i}`}><div className={`alert-icon ${f.level}`}>{f.type==="Offline"?"◌":"!"}</div><div className="alert-main"><b>{f.type} disabled</b><span>{f.device.name} · {f.device.employee} · {f.device.department}</span><small>IP {f.device.ip_address} · Detected from current endpoint state</small></div><span className={`badge ${f.level==="critical"?"risk":"warning"}`}>{f.level==="critical"?"Critical":"Warning"}</span></div>)}</div>:<div className="empty success-empty"><div>✓</div><b>No open security findings</b><span>All devices currently comply with the active controls.</span></div>}
    </section>
  </div>
}

function Settings({policy,setPolicy}) {
  const [draft,setDraft]=useState(policy),[saving,setSaving]=useState(false),[msg,setMsg]=useState(""),[error,setError]=useState("");
  useEffect(()=>setDraft(policy),[policy]);
  async function save(){setSaving(true);setMsg("");setError("");try{const d=await api("/security-policy",{method:"PUT",body:JSON.stringify(draft)});setPolicy(d);setMsg("Security policy saved successfully.")}catch(e){setError(e.message)}finally{setSaving(false)}}
  const item=(key,title,desc,icon)=><div className="setting-row"><div className="setting-icon">{icon}</div><div className="setting-copy"><b>{title}</b><span>{desc}</span></div><button className={`switch ${draft[key]?"on":""}`} onClick={()=>setDraft(x=>({...x,[key]:!x[key]}))}><i/>{draft[key]?"Required":"Optional"}</button></div>;
  return <div><div className="hero-strip compact"><div><span className="pill blue">POLICY CONTROL</span><h2>Endpoint security policy</h2><p>Define which controls are mandatory for a device to be considered secure.</p></div></div>
    {error&&<div className="error-box">{error}</div>}{msg&&<div className="success-box">✓ {msg}</div>}
    <section className="panel settings-panel"><div className="panel-head"><div><h3>Required controls</h3><p>Changes apply immediately to compliance calculations.</p></div></div>
      {item("antivirus_required","Antivirus protection","Every managed endpoint must have antivirus protection enabled.","◈")}
      {item("firewall_required","Firewall protection","Every managed endpoint must have its host firewall enabled.","◉")}
      {item("backup_required","Data backup","Every managed endpoint must have backup protection enabled.","◫")}
      <div className="save-strip"><div><b>Policy status</b><span>{Object.values(draft).filter(Boolean).length} of 3 controls required</span></div><button className="primary" onClick={save} disabled={saving}>{saving?"Saving…":"Save policy"}</button></div>
    </section>
    <section className="panel info-panel"><h3>How compliance works</h3><p>A device is marked <b>Secure</b> only when every control marked Required above is enabled on that device. Optional controls do not affect the Secure/At risk calculation.</p></section>
  </div>
}

function Users({user}) {
  const [users,setUsers]=useState([]),[open,setOpen]=useState(false),[form,setForm]=useState({name:"",email:"",password:"",role:"IT Staff"}),[error,setError]=useState(""),[saving,setSaving]=useState(false);
  async function load(){try{setUsers(await api("/users"))}catch(e){setError(e.message)}} useEffect(()=>{load()},[]);
  async function add(e){e.preventDefault();setSaving(true);setError("");try{const u=await api("/users",{method:"POST",body:JSON.stringify(form)});setUsers(x=>[u,...x]);setOpen(false);setForm({name:"",email:"",password:"",role:"IT Staff"})}catch(e){setError(e.message)}finally{setSaving(false)}}
  async function del(u){if(u.id===user.id)return alert("You cannot delete your own active account.");if(!confirm(`Delete ${u.name}'s account?`))return;try{await api(`/users/${u.id}`,{method:"DELETE"});setUsers(x=>x.filter(v=>v.id!==u.id))}catch(e){setError(e.message)}}
  return <div><div className="toolbar"><div><h2 className="page-title">User access</h2><p className="muted">Manage people who can access the security center.</p></div><button className="primary" onClick={()=>setOpen(true)}>＋ Add user</button></div>{error&&<div className="error-box">{error}</div>}
    <section className="panel table-panel"><div className="panel-head"><div><h3>Authorized users</h3><p>{users.length} accounts</p></div></div><div className="table-wrap"><table><thead><tr><th>USER</th><th>EMAIL</th><th>ROLE</th><th>ACTIONS</th></tr></thead><tbody>{users.map(u=><tr key={u.id}><td><div className="device-cell"><div className="avatar">{initials(u.name)}</div><div><b>{u.name}</b><small>ID #{u.id}</small></div></div></td><td className="normal">{u.email}</td><td><span className="role-chip">{u.role}</span></td><td><button className="danger-link" disabled={u.id===user.id} onClick={()=>del(u)}>Delete</button></td></tr>)}</tbody></table></div></section>
    {open&&<div className="modal-backdrop"><form className="modal" onSubmit={add}><div className="modal-head"><div><span className="eyebrow">NEW ACCOUNT</span><h2>Create user</h2></div><button type="button" className="close" onClick={()=>setOpen(false)}>×</button></div><label>Full name<input required value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/></label><label>Email<input required type="email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})}/></label><label>Temporary password<input required minLength="8" type="password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})}/></label><label>Role<select value={form.role} onChange={e=>setForm({...form,role:e.target.value})}><option>Administrator</option><option>IT Manager</option><option>IT Staff</option></select></label><div className="modal-actions"><button type="button" className="secondary" onClick={()=>setOpen(false)}>Cancel</button><button className="primary">{saving?"Creating…":"Create account"}</button></div></form></div>}
  </div>
}

function Activity() {
  const [logs,setLogs]=useState([]),[error,setError]=useState(""); useEffect(()=>{api("/audit-logs").then(setLogs).catch(e=>setError(e.message))},[]);
  return <div><div className="page-title-wrap"><h2 className="page-title">Activity log</h2><p className="muted">A chronological record of important security administration actions.</p></div>{error&&<div className="error-box">{error}</div>}
    <section className="panel"><div className="panel-head"><div><h3>Audit trail</h3><p>Latest 200 recorded events</p></div><span className="live-indicator">● Audited</span></div><div className="timeline">{logs.map(l=><div className="timeline-row" key={l.id}><div className="timeline-dot"/><div><b>{l.action}</b><span>{l.details||"—"}</span><small>{l.user_name||"System"} · {fmtDate(l.created_at)}</small></div></div>)}{!logs.length&&<div className="empty">No activity has been recorded yet.</div>}</div></section>
  </div>
}

export default function App(){
  const [user,setUser]=useState(null),[page,setPage]=useState("dashboard"),[devices,setDevices]=useState([]),[policy,setPolicy]=useState(defaultPolicy),[loading,setLoading]=useState(false),[error,setError]=useState("");
  useEffect(()=>{const t=token(),p=t&&decodeToken(t);if(p&&(!p.exp||p.exp*1000>Date.now()))setUser(p);else localStorage.removeItem("token")},[]);
  async function load(){if(!user)return;setLoading(true);setError("");try{const [d,p]=await Promise.all([api("/devices"),api("/security-policy")]);setDevices(d);setPolicy({...defaultPolicy,...p})}catch(e){setError(e.message)}finally{setLoading(false)}}
  useEffect(()=>{load()},[user]);
  function logout(){localStorage.removeItem("token");setUser(null);setDevices([]);setPage("dashboard")}
  if(!user)return <Login onLogin={setUser}/>;
  const titles={dashboard:["Dashboard","Organization-wide endpoint security overview"],devices:["Devices","Manage and monitor company endpoints"],alerts:["Security Alerts","Identify and respond to security findings"],users:["Users","Control access to the security center"],settings:["Security Policy","Configure mandatory endpoint controls"],activity:["Activity Log","Review security administration events"]};
  const [title,sub]=titles[page]||titles.dashboard;
  return <div className="app-shell"><Sidebar page={page} setPage={setPage} user={user} onLogout={logout}/><main className="main"><Header title={title} subtitle={sub} user={user} onRefresh={load} loading={loading}/>{error&&<div className="error-box global-error">{error}<button onClick={()=>setError("")}>×</button></div>}
    {page==="dashboard"&&<Dashboard devices={devices} policy={policy} setPage={setPage}/>}
    {page==="devices"&&<Devices devices={devices} setDevices={setDevices} policy={policy} user={user} setPage={setPage}/>}
    {page==="alerts"&&<Alerts devices={devices} policy={policy} setPage={setPage}/>}
    {page==="settings"&&<Settings policy={policy} setPolicy={setPolicy}/>}
    {page==="users"&&<Users user={user}/>}
    {page==="activity"&&<Activity/>}
  </main></div>
}

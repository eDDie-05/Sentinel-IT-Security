const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_IN_PRODUCTION_TO_A_LONG_RANDOM_SECRET";

app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

function auth(req,res,next){
  const header=req.headers.authorization||"";
  const t=header.startsWith("Bearer ")?header.slice(7):null;
  if(!t) return res.status(401).json({error:"Authentication required"});
  try{req.user=jwt.verify(t,JWT_SECRET);next()}catch{return res.status(401).json({error:"Invalid or expired session"})}
}
function roles(...allowed){return (req,res,next)=>allowed.includes(req.user?.role)?next():res.status(403).json({error:"You do not have permission for this action"})}
function clean(v){return typeof v==="string"?v.trim():v}
function bool(v, fallback=false){if(v===undefined||v===null)return fallback;return v===true||v==="true"||v===1||v==="1"}
async function audit(user,action,details){
  try{await pool.query(`INSERT INTO audit_logs(user_id,user_name,action,details) VALUES($1,$2,$3,$4)`,[user?.id||null,user?.name||"System",action,details||null])}
  catch(e){console.error("Audit log:",e.message)}
}

async function ensureDatabase(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(150) NOT NULL UNIQUE,
      role VARCHAR(50) NOT NULL CHECK(role IN ('Administrator','IT Manager','IT Staff')),
      password_hash VARCHAR(255)
    );
    CREATE TABLE IF NOT EXISTS devices(
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      operating_system VARCHAR(100) NOT NULL,
      employee VARCHAR(100) NOT NULL,
      department VARCHAR(100) NOT NULL,
      ip_address VARCHAR(50) NOT NULL,
      antivirus BOOLEAN NOT NULL DEFAULT TRUE,
      firewall BOOLEAN NOT NULL DEFAULT TRUE,
      backup BOOLEAN NOT NULL DEFAULT TRUE,
      online BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS security_policy(
      id SERIAL PRIMARY KEY,
      antivirus_required BOOLEAN NOT NULL DEFAULT TRUE,
      firewall_required BOOLEAN NOT NULL DEFAULT TRUE,
      backup_required BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      user_name VARCHAR(100),
      action VARCHAR(100) NOT NULL,
      details TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    ALTER TABLE devices ADD COLUMN IF NOT EXISTS online BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
  `);
  const policy=await pool.query("SELECT id FROM security_policy LIMIT 1");
  if(!policy.rowCount) await pool.query("INSERT INTO security_policy(antivirus_required,firewall_required,backup_required) VALUES(TRUE,TRUE,TRUE)");
  const admin=await pool.query("SELECT id FROM users WHERE email=$1",["admin@company.com"]);
  if(!admin.rowCount){
    const hash=await bcrypt.hash("Admin123456",10);
    await pool.query("INSERT INTO users(name,email,role,password_hash) VALUES($1,$2,$3,$4)",["System Administrator","admin@company.com","Administrator",hash]);
    console.log("Default administrator created: admin@company.com / Admin123456");
  }
}

app.get("/",(req,res)=>res.json({service:"Sentinel IT Security API",status:"operational",version:"2.0.0",time:new Date().toISOString()}));
app.get("/api/health",async(req,res)=>{
  try{await pool.query("SELECT 1");res.json({status:"healthy",database:"connected",time:new Date().toISOString()})}
  catch(e){res.status(503).json({status:"degraded",database:"disconnected"})}
});

app.post("/api/login",async(req,res)=>{
  try{
    const email=clean(req.body.email)?.toLowerCase(), password=req.body.password;
    if(!email||!password)return res.status(400).json({error:"Email and password are required"});
    const r=await pool.query("SELECT id,name,email,role,password_hash FROM users WHERE LOWER(email)=LOWER($1)",[email]);
    const u=r.rows[0];
    if(!u||!u.password_hash||!(await bcrypt.compare(password,u.password_hash))){
      return res.status(401).json({error:"Invalid email or password"});
    }
    const payload={id:u.id,name:u.name,email:u.email,role:u.role};
    const t=jwt.sign(payload,JWT_SECRET,{expiresIn:"2h"});
    await audit(payload,"LOGIN","Successful sign-in");
    res.json({token:t,user:payload,expiresIn:"2h"});
  }catch(e){console.error(e);res.status(500).json({error:"Unable to sign in"})}
});

app.get("/api/devices",auth,async(req,res)=>{
  try{const r=await pool.query("SELECT * FROM devices ORDER BY id DESC");res.json(r.rows)}
  catch(e){console.error(e);res.status(500).json({error:"Unable to load devices"})}
});
app.post("/api/devices",auth,roles("Administrator","IT Manager"),async(req,res)=>{
  try{
    const b=req.body; if(!clean(b.name)||!clean(b.operatingSystem)||!clean(b.employee)||!clean(b.department)||!clean(b.ipAddress))return res.status(400).json({error:"All device identity fields are required"});
    const r=await pool.query(`INSERT INTO devices(name,operating_system,employee,department,ip_address,antivirus,firewall,backup,online) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [clean(b.name),clean(b.operatingSystem),clean(b.employee),clean(b.department),clean(b.ipAddress),bool(b.antivirus,true),bool(b.firewall,true),bool(b.backup,true),bool(b.online,true)]);
    const d=r.rows[0]; await audit(req.user,"DEVICE ADDED",`${d.name} · ${d.employee}`);res.status(201).json(d);
  }catch(e){console.error(e);res.status(500).json({error:"Unable to add device"})}
});
app.put("/api/devices/:id",auth,roles("Administrator","IT Manager"),async(req,res)=>{
  try{
    const old=(await pool.query("SELECT * FROM devices WHERE id=$1",[req.params.id])).rows[0];
    if(!old)return res.status(404).json({error:"Device not found"});
    const b=req.body;
    const r=await pool.query(`UPDATE devices SET name=$1,operating_system=$2,employee=$3,department=$4,ip_address=$5,antivirus=$6,firewall=$7,backup=$8,online=$9 WHERE id=$10 RETURNING *`,
      [clean(b.name??old.name),clean(b.operatingSystem??old.operating_system),clean(b.employee??old.employee),clean(b.department??old.department),clean(b.ipAddress??old.ip_address),bool(b.antivirus,old.antivirus),bool(b.firewall,old.firewall),bool(b.backup,old.backup),bool(b.online,old.online),req.params.id]);
    const d=r.rows[0];await audit(req.user,"DEVICE UPDATED",`${d.name} · security controls/status changed`);res.json(d);
  }catch(e){console.error(e);res.status(500).json({error:"Unable to update device"})}
});
app.delete("/api/devices/:id",auth,roles("Administrator","IT Manager"),async(req,res)=>{
  try{
    const r=await pool.query("DELETE FROM devices WHERE id=$1 RETURNING *",[req.params.id]);
    if(!r.rowCount)return res.status(404).json({error:"Device not found"});
    await audit(req.user,"DEVICE REMOVED",`${r.rows[0].name} · ${r.rows[0].employee}`);res.json({message:"Device removed",device:r.rows[0]});
  }catch(e){console.error(e);res.status(500).json({error:"Unable to remove device"})}
});

app.get("/api/users",auth,roles("Administrator"),async(req,res)=>{
  try{const r=await pool.query("SELECT id,name,email,role FROM users ORDER BY id DESC");res.json(r.rows)}
  catch(e){res.status(500).json({error:"Unable to load users"})}
});
app.post("/api/users",auth,roles("Administrator"),async(req,res)=>{
  try{
    const {name,email,password,role}=req.body;
    if(!clean(name)||!clean(email)||!password||!role)return res.status(400).json({error:"Name, email, password and role are required"});
    if(password.length<8)return res.status(400).json({error:"Password must be at least 8 characters"});
    if(!["Administrator","IT Manager","IT Staff"].includes(role))return res.status(400).json({error:"Invalid role"});
    const hash=await bcrypt.hash(password,10);
    const r=await pool.query("INSERT INTO users(name,email,role,password_hash) VALUES($1,$2,$3,$4) RETURNING id,name,email,role",[clean(name),clean(email).toLowerCase(),role,hash]);
    await audit(req.user,"USER CREATED",`${r.rows[0].name} · ${r.rows[0].email} · ${r.rows[0].role}`);res.status(201).json(r.rows[0]);
  }catch(e){if(e.code==="23505")return res.status(409).json({error:"That email address is already registered"});console.error(e);res.status(500).json({error:"Unable to create user"})}
});
app.delete("/api/users/:id",auth,roles("Administrator"),async(req,res)=>{
  try{
    if(Number(req.params.id)===Number(req.user.id))return res.status(400).json({error:"You cannot delete your own active account"});
    const r=await pool.query("DELETE FROM users WHERE id=$1 RETURNING id,name,email,role",[req.params.id]);
    if(!r.rowCount)return res.status(404).json({error:"User not found"});
    await audit(req.user,"USER DELETED",`${r.rows[0].name} · ${r.rows[0].email}`);res.json({message:"User deleted"});
  }catch(e){console.error(e);res.status(500).json({error:"Unable to delete user"})}
});

app.get("/api/security-policy",auth,async(req,res)=>{
  try{const r=await pool.query("SELECT * FROM security_policy ORDER BY id DESC LIMIT 1");res.json(r.rows[0]||{...DEFAULT_POLICY})}
  catch(e){res.status(500).json({error:"Unable to load security policy"})}
});
const DEFAULT_POLICY={antivirus_required:true,firewall_required:true,backup_required:true};
app.put("/api/security-policy",auth,roles("Administrator","IT Manager"),async(req,res)=>{
  try{
    const a=bool(req.body.antivirus_required,true),f=bool(req.body.firewall_required,true),b=bool(req.body.backup_required,true);
    let r=await pool.query("UPDATE security_policy SET antivirus_required=$1,firewall_required=$2,backup_required=$3 WHERE id=(SELECT id FROM security_policy ORDER BY id DESC LIMIT 1) RETURNING *",[a,f,b]);
    if(!r.rowCount)r=await pool.query("INSERT INTO security_policy(antivirus_required,firewall_required,backup_required) VALUES($1,$2,$3) RETURNING *",[a,f,b]);
    await audit(req.user,"POLICY UPDATED",`Antivirus ${a?"required":"optional"} · Firewall ${f?"required":"optional"} · Backup ${b?"required":"optional"}`);
    res.json(r.rows[0]);
  }catch(e){console.error(e);res.status(500).json({error:"Unable to save security policy"})}
});
app.get("/api/audit-logs",auth,roles("Administrator"),async(req,res)=>{
  try{const r=await pool.query("SELECT id,user_id,user_name,action,details,created_at FROM audit_logs ORDER BY created_at DESC,id DESC LIMIT 200");res.json(r.rows)}
  catch(e){res.status(500).json({error:"Unable to load audit logs"})}
});

ensureDatabase().then(()=>app.listen(PORT,()=>console.log(`Sentinel API running on http://localhost:${PORT}`))).catch(e=>{console.error("Database startup failed:",e);process.exit(1)});

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "development-secret-change-me";

const uploadDir = path.join(__dirname, "uploads");
const backupDir = path.join(__dirname, "backups");
fs.mkdirSync(uploadDir, { recursive: true });
fs.mkdirSync(backupDir, { recursive: true });

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 150 * 1024 * 1024 }
});

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(uploadDir));
app.use(express.static(path.join(__dirname, "public")));

// Supabase PostgreSQL Pool Configuration
const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.error("CRITICAL ERROR: DATABASE_URL environment variable is not defined!");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function db(sql, params = []) {
  return pool.query(sql, params);
}

async function initDb() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(80) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE,
      password_hash TEXT,
      role VARCHAR(20) NOT NULL DEFAULT 'customer',
      avatar_url TEXT,
      wallet NUMERIC(12,2) NOT NULL DEFAULT 0,
      referral_bonus NUMERIC(12,2) NOT NULL DEFAULT 0,
      total_referrals INTEGER NOT NULL DEFAULT 0,
      referred_volume NUMERIC(12,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name VARCHAR(180) NOT NULL,
      description TEXT DEFAULT '',
      category VARCHAR(100) DEFAULT 'General',
      customer_price NUMERIC(12,2) NOT NULL DEFAULT 0,
      reseller_price NUMERIC(12,2) NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      thumbnail_url TEXT,
      video_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS product_buttons (
      id SERIAL PRIMARY KEY,
      product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
      label VARCHAR(80) NOT NULL,
      url TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS plans (
      id SERIAL PRIMARY KEY,
      product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
      name VARCHAR(120) NOT NULL,
      duration_hours INTEGER NOT NULL DEFAULT 1,
      customer_price NUMERIC(12,2) NOT NULL DEFAULT 0,
      reseller_price NUMERIC(12,2) NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS deposits (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL,
      screenshot_url TEXT,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
      plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL,
      amount NUMERIC(12,2) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'completed',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS custom_prices (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
      price NUMERIC(12,2) NOT NULL,
      UNIQUE(user_id, product_id)
    );
    CREATE TABLE IF NOT EXISTS settings (
      key VARCHAR(100) PRIMARY KEY,
      value TEXT NOT NULL DEFAULT ''
    );
  `);

  const admin = await db("SELECT id FROM users WHERE username=$1", [process.env.ADMIN_USERNAME || "admin"]);
  if (!admin.rowCount) {
    const username = process.env.ADMIN_USERNAME || "admin";
    const password = process.env.ADMIN_PASSWORD || "ChangeMe123!";
    const hash = await bcrypt.hash(password, 12);
    await db(
      "INSERT INTO users(username,email,password_hash,role) VALUES($1,$2,$3,'admin')",
      [username, `${username}@local.invalid`, hash]
    );
    console.log(`Admin created: ${username} / ${password}`);
  }
}

function sign(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired session" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  next();
}

function fileUrl(req, file) {
  return file ? `/uploads/${path.basename(file.path)}` : null;
}

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !password || password.length < 6)
      return res.status(400).json({ error: "Username and a 6+ character password are required" });
    const hash = await bcrypt.hash(password, 12);
    const r = await db(
      "INSERT INTO users(username,email,password_hash) VALUES($1,$2,$3) RETURNING id,username,email,role",
      [username.trim(), email?.trim() || null, hash]
    );
    const user = r.rows[0];
    res.json({ token: sign(user), user });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Username or email already exists" });
    console.error(e);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    const r = await db(
      "SELECT * FROM users WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($1) LIMIT 1",
      [identifier || ""]
    );
    if (!r.rowCount || !r.rows[0].password_hash)
      return res.status(401).json({ error: "Invalid username/email or password" });
    const user = r.rows[0];
    if (!(await bcrypt.compare(password || "", user.password_hash)))
      return res.status(401).json({ error: "Invalid username/email or password" });
    const safe = { id:user.id, username:user.username, email:user.email, role:user.role };
    res.json({ token: sign(safe), user: safe });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/me", auth, async (req,res) => {
  const r = await db("SELECT id,username,email,role,avatar_url,wallet,referral_bonus,total_referrals,referred_volume,created_at FROM users WHERE id=$1",[req.user.id]);
  res.json(r.rows[0]);
});

app.get("/api/products", auth, async (req,res) => {
  const r = await db(`
    SELECT p.*,
      COALESCE(json_agg(json_build_object('id',b.id,'label',b.label,'url',b.url,'sort_order',b.sort_order)
      ORDER BY b.sort_order) FILTER (WHERE b.id IS NOT NULL),'[]') AS buttons,
      COALESCE((SELECT json_agg(pl ORDER BY pl.duration_hours)
                FROM plans pl WHERE pl.product_id=p.id),'[]') AS plans
    FROM products p
    LEFT JOIN product_buttons b ON b.product_id=p.id
    WHERE p.active=true
    GROUP BY p.id
    ORDER BY p.created_at DESC
  `);
  res.json(r.rows);
});

app.get("/api/admin/stats", auth, adminOnly, async (req,res) => {
  const [u,p,d,o,w] = await Promise.all([
    db("SELECT COUNT(*)::int AS n FROM users WHERE role<>'admin'"),
    db("SELECT COUNT(*)::int AS n FROM products"),
    db("SELECT COUNT(*)::int AS n FROM deposits WHERE status='pending'"),
    db("SELECT COUNT(*)::int AS n FROM orders"),
    db("SELECT COALESCE(SUM(wallet),0) AS n FROM users")
  ]);
  res.json({
    customers:u.rows[0].n, products:p.rows[0].n, pendingDeposits:d.rows[0].n,
    orders:o.rows[0].n, walletTotal:w.rows[0].n
  });
});

app.get("/api/admin/users", auth, adminOnly, async (req,res) => {
  const r = await db("SELECT id,username,email,role,wallet,referral_bonus,total_referrals,referred_volume,created_at FROM users ORDER BY created_at DESC");
  res.json(r.rows);
});

app.patch("/api/admin/users/:id", auth, adminOnly, async (req,res) => {
  const { role, wallet } = req.body;
  const r = await db(
    "UPDATE users SET role=COALESCE($1,role), wallet=COALESCE($2,wallet) WHERE id=$3 RETURNING id,username,email,role,wallet",
    [role ?? null, wallet ?? null, req.params.id]
  );
  res.json(r.rows[0]);
});

app.get("/api/admin/products", auth, adminOnly, async (req,res) => {
  const r = await db(`
    SELECT p.*,
      COALESCE(json_agg(json_build_object('id',b.id,'label',b.label,'url',b.url,'sort_order',b.sort_order)
      ORDER BY b.sort_order) FILTER (WHERE b.id IS NOT NULL),'[]') AS buttons,
      COALESCE((SELECT json_agg(pl ORDER BY pl.duration_hours)
                FROM plans pl WHERE pl.product_id=p.id),'[]') AS plans
    FROM products p
    LEFT JOIN product_buttons b ON b.product_id=p.id
    GROUP BY p.id ORDER BY p.created_at DESC
  `);
  res.json(r.rows);
});

app.post("/api/admin/products", auth, adminOnly, upload.fields([
  {name:"thumbnail",maxCount:1},{name:"video",maxCount:1}
]), async (req,res) => {
  try {
    const {
      name, description="", category="General",
      customer_price=0, reseller_price=0, active="true",
      plans="[]", buttons="[]"
    } = req.body;
    if (!name) return res.status(400).json({error:"Product name is required"});
    const thumbnail = fileUrl(req, req.files?.thumbnail?.[0]);
    const video = fileUrl(req, req.files?.video?.[0]);
    const p = await db(
      `INSERT INTO products(name,description,category,customer_price,reseller_price,active,thumbnail_url,video_url)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [name,description,category,customer_price,reseller_price,active==="true" || active===true,thumbnail,video]
    );
    const product = p.rows[0];
    let planList=[]; let buttonList=[];
    try { planList=JSON.parse(plans); } catch {}
    try { buttonList=JSON.parse(buttons); } catch {}
    for (const x of planList) {
      await db(
        "INSERT INTO plans(product_id,name,duration_hours,customer_price,reseller_price,active) VALUES($1,$2,$3,$4,$5,$6)",
        [product.id,x.name || `${x.duration_hours||1} Hours`,x.duration_hours||1,x.customer_price||0,x.reseller_price||0,x.active!==false]
      );
    }
    for (let i=0;i<buttonList.length;i++) {
      const x=buttonList[i];
      if (x.label && x.url) await db(
        "INSERT INTO product_buttons(product_id,label,url,sort_order) VALUES($1,$2,$3,$4)",
        [product.id,x.label,x.url,i]
      );
    }
    res.json({ok:true,product});
  } catch(e) {
    console.error(e); res.status(500).json({error:"Could not create product"});
  }
});

app.patch("/api/admin/products/:id", auth, adminOnly, async (req,res) => {
  const {name,description,category,customer_price,reseller_price,active} = req.body;
  const r=await db(
    `UPDATE products SET name=COALESCE($1,name),description=COALESCE($2,description),
     category=COALESCE($3,category),customer_price=COALESCE($4,customer_price),
     reseller_price=COALESCE($5,reseller_price),active=COALESCE($6,active)
     WHERE id=$7 RETURNING *`,
    [name??null,description??null,category??null,customer_price??null,reseller_price??null,
     active??null,req.params.id]
  );
  res.json(r.rows[0]);
});

app.delete("/api/admin/products/:id", auth, adminOnly, async (req,res) => {
  await db("DELETE FROM products WHERE id=$1",[req.params.id]);
  res.json({ok:true});
});

app.post("/api/deposits", auth, upload.single("screenshot"), async (req,res) => {
  const amount=Number(req.body.amount);
  if (!amount || amount<=0) return res.status(400).json({error:"Enter a valid amount"});
  const r=await db(
    "INSERT INTO deposits(user_id,amount,screenshot_url) VALUES($1,$2,$3) RETURNING *",
    [req.user.id,amount,fileUrl(req,req.file)]
  );
  res.json(r.rows[0]);
});

app.get("/api/admin/deposits", auth, adminOnly, async (req,res) => {
  const r=await db(`
    SELECT d.*,u.username,u.email
    FROM deposits d JOIN users u ON u.id=d.user_id
    ORDER BY d.created_at DESC
  `);
  res.json(r.rows);
});

app.patch("/api/admin/deposits/:id", auth, adminOnly, async (req,res) => {
  const status=req.body.status;
  if (!["approved","rejected"].includes(status))
    return res.status(400).json({error:"Invalid status"});
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    const d=await client.query("SELECT * FROM deposits WHERE id=$1 FOR UPDATE",[req.params.id]);
    if(!d.rowCount) throw new Error("Deposit not found");
    if(d.rows[0].status!=="pending") throw new Error("Deposit already reviewed");
    await client.query("UPDATE deposits SET status=$1,reviewed_at=NOW() WHERE id=$2",[status,req.params.id]);
    if(status==="approved")
      await client.query("UPDATE users SET wallet=wallet+$1 WHERE id=$2",[d.rows[0].amount,d.rows[0].user_id]);
    await client.query("COMMIT");
    res.json({ok:true});
  } catch(e) {
    await client.query("ROLLBACK");
    res.status(400).json({error:e.message});
  } finally { client.release(); }
});

app.post("/api/admin/backup", auth, adminOnly, async (req,res) => {
  const tables=["users","products","product_buttons","plans","deposits","orders","custom_prices","settings"];
  const out={created_at:new Date().toISOString(),tables:{}};
  for(const t of tables) out.tables[t]=(await db(`SELECT * FROM ${t}`)).rows;
  const name=`backup-${Date.now()}.json`;
  fs.writeFileSync(path.join(backupDir,name),JSON.stringify(out,null,2));
  res.json({name,download:`/api/admin/backups/${name}`});
});

app.get("/api/admin/backups", auth, adminOnly, async (req,res) => {
  const names=fs.readdirSync(backupDir).filter(x=>x.endsWith(".json")).sort().reverse();
  res.json(names.map(name=>({name,url:`/api/admin/backups/${name}`})));
});

app.get("/api/admin/backups/:name", auth, adminOnly, (req,res) => {
  const safe=path.basename(req.params.name);
  const file=path.join(backupDir,safe);
  if(!fs.existsSync(file)) return res.status(404).send("Backup not found");
  res.download(file);
});

app.get("/api/admin/export", auth, adminOnly, async (req,res) => {
  const data={
    users:(await db("SELECT id,username,email,role,wallet,referral_bonus,total_referrals,referred_volume,created_at FROM users")).rows,
    products:(await db("SELECT * FROM products")).rows,
    plans:(await db("SELECT * FROM plans")).rows,
    deposits:(await db("SELECT * FROM deposits")).rows,
    orders:(await db("SELECT * FROM orders")).rows
  };
  res.setHeader("Content-Disposition","attachment; filename=kp-panel-export.json");
  res.json(data);
});

app.post("/api/admin/settings", auth, adminOnly, async (req,res) => {
  for(const [key,value] of Object.entries(req.body||{}))
    await db(`INSERT INTO settings(key,value) VALUES($1,$2)
              ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,[key,String(value)]);
  res.json({ok:true});
});

app.get("/api/settings", auth, async (req,res) => {
  const r=await db("SELECT key,value FROM settings");
  res.json(Object.fromEntries(r.rows.map(x=>[x.key,x.value])));
});

app.post("/api/orders", auth, async (req,res) => {
  const {product_id,plan_id}=req.body;
  const p=await db("SELECT * FROM products WHERE id=$1 AND active=true",[product_id]);
  const pl=await db("SELECT * FROM plans WHERE id=$1 AND product_id=$2 AND active=true",[plan_id,product_id]);
  if(!p.rowCount || !pl.rowCount) return res.status(404).json({error:"Product or plan unavailable"});
  const user=await db("SELECT * FROM users WHERE id=$1 FOR UPDATE",[req.user.id]);
  const price=Number(user.rows[0].role==="reseller"?pl.rows[0].reseller_price:pl.rows[0].customer_price);
  if(Number(user.rows[0].wallet)<price) return res.status(400).json({error:"Insufficient wallet balance"});
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("UPDATE users SET wallet=wallet-$1 WHERE id=$2",[price,req.user.id]);
    const o=await client.query(
      "INSERT INTO orders(user_id,product_id,plan_id,amount) VALUES($1,$2,$3,$4) RETURNING *",
      [req.user.id,product_id,plan_id,price]
    );
    await client.query("COMMIT");
    res.json(o.rows[0]);
  } catch(e) {
    await client.query("ROLLBACK"); res.status(500).json({error:"Purchase failed"});
  } finally { client.release(); }
});

app.get("/api/orders", auth, async (req,res) => {
  const r=await db(`
    SELECT o.*,p.name product_name,pl.name plan_name
    FROM orders o
    LEFT JOIN products p ON p.id=o.product_id
    LEFT JOIN plans pl ON pl.id=o.plan_id
    WHERE o.user_id=$1 ORDER BY o.created_at DESC`,[req.user.id]);
  res.json(r.rows);
});

app.get("*",(req,res)=>{
  res.sendFile(path.join(__dirname,"public","index.html"));
});

initDb().then(()=>{
  app.listen(PORT,()=>console.log(`KP PANEL SHOP running on port ${PORT}`));
}).catch(e=>{
  console.error("Database initialization failed:",e);
  process.exit(1);
});

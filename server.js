// ─────────────────────────────────────────────────────────────────────────────
//  Saker Baptist College — Teacher Account Server
// ─────────────────────────────────────────────────────────────────────────────
//  A small standalone server that creates and deletes teacher login accounts.
//  This exists separately from the main app because creating a login for
//  someone else requires Supabase's `service_role` key, which must NEVER be
//  placed in the React app (anyone could read it from the browser and gain
//  full control of the database). This server holds that key privately as
//  an environment variable, the same way the main app holds its Supabase URL
//  and anon key — set once in Render's dashboard, never visible in the code.
//
//  Deployed to Render exactly like the main site: push to GitHub, Render
//  builds and runs it automatically. No command-line tools needed.
// ─────────────────────────────────────────────────────────────────────────────

import express from "express";
import { createClient } from "@supabase/supabase-js";

const app = express();

// Explicit CORS handling — the default cors() package settings can behave
// inconsistently behind Render's proxy layer, sometimes answering the
// preflight OPTIONS request with an empty 200 that never reaches Express's
// route handlers. Setting headers directly removes that ambiguity.
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json());

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // set in Render dashboard — never in code
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

// Admin client — the only place the service_role key is ever used
const adminClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

// Verifies the request came from a logged-in admin. Returns the caller's
// user id if valid, or null if not — every endpoint below checks this first.
// Logs the specific reason for any failure to Render's Logs tab, since the
// user-facing error is intentionally generic (doesn't leak which check failed).
async function requireAdmin(req) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) { console.log("[requireAdmin] no token in Authorization header"); return null; }

  if (!SUPABASE_URL || !ANON_KEY || !SERVICE_ROLE_KEY) {
    console.log("[requireAdmin] missing env var — URL:", !!SUPABASE_URL, "ANON_KEY:", !!ANON_KEY, "SERVICE_ROLE_KEY:", !!SERVICE_ROLE_KEY);
    return null;
  }

  const callerClient = createClient(SUPABASE_URL, ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
  const { data: { user }, error } = await callerClient.auth.getUser();
  if (error || !user) { console.log("[requireAdmin] getUser failed:", error?.message || "no user returned"); return null; }
  console.log("[requireAdmin] token verified for user:", user.id, user.email);

  const { data: row, error: roleErr } = await adminClient
    .from("users").select("role").eq("id", user.id).single();
  if (roleErr) { console.log("[requireAdmin] users table lookup error:", roleErr.message); return null; }
  console.log("[requireAdmin] role found:", row?.role);
  if (row?.role !== "admin") { console.log("[requireAdmin] role is not admin, rejecting"); return null; }

  return user.id;
}

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "saker-teacher-server" });
});

// ─── Create a teacher account ───────────────────────────────────────────────
app.post("/create-teacher", async (req, res) => {
  console.log("[create-teacher] request received");
  try {
    const callerId = await requireAdmin(req);
    if (!callerId) { console.log("[create-teacher] rejected — not admin"); return res.status(403).json({ error: "Only admins can create teacher accounts." }); }
    console.log("[create-teacher] admin verified, caller:", callerId);

    const { name, email, password, subjects, forms } = req.body || {};
    if (!name?.trim() || !email?.trim() || !password || password.length < 6) {
      console.log("[create-teacher] validation failed — missing/short fields");
      return res.status(400).json({ error: "Name, email, and a password of at least 6 characters are required." });
    }

    console.log("[create-teacher] creating auth user for", email);
    const { data: newUser, error: createErr } = await adminClient.auth.admin.createUser({
      email: email.trim(),
      password,
      email_confirm: true,
    });
    if (createErr) { console.log("[create-teacher] createUser failed:", createErr.message); return res.status(400).json({ error: "Could not create login: " + createErr.message }); }
    const newUserId = newUser.user.id;
    console.log("[create-teacher] auth user created:", newUserId);

    const { error: userRowErr } = await adminClient.from("users").insert({
      id: newUserId, email: email.trim(), name: name.trim(), role: "teacher",
    });
    if (userRowErr) {
      console.log("[create-teacher] users insert failed:", userRowErr.message);
      await adminClient.auth.admin.deleteUser(newUserId);
      return res.status(400).json({ error: "Could not save role: " + userRowErr.message });
    }
    console.log("[create-teacher] users row inserted");

    const teacherId = "TCH" + Date.now().toString().slice(-6);
    const { error: teacherRowErr } = await adminClient.from("teachers").insert({
      id: teacherId, user_id: newUserId, name: name.trim(), email: email.trim(),
      subjects: subjects||[], forms: forms||[], active: true, joined: new Date().toISOString().slice(0,10),
    });
    if (teacherRowErr) {
      console.log("[create-teacher] teachers insert failed:", teacherRowErr.message);
      await adminClient.auth.admin.deleteUser(newUserId);
      await adminClient.from("users").delete().eq("id", newUserId);
      return res.status(400).json({ error: "Could not save teacher profile: " + teacherRowErr.message });
    }
    console.log("[create-teacher] teachers row inserted — success, sending response");

    return res.status(200).json({ success: true, teacherId, userId: newUserId });
  } catch(e) {
    console.log("[create-teacher] CAUGHT EXCEPTION:", e?.message || e);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Unexpected error: " + (e?.message || String(e)) });
    }
  }
});

// ─── Delete a teacher account ───────────────────────────────────────────────
app.post("/delete-teacher", async (req, res) => {
  const callerId = await requireAdmin(req);
  if (!callerId) return res.status(403).json({ error: "Only admins can delete teacher accounts." });

  const { teacherId, userId } = req.body || {};
  if (!teacherId) return res.status(400).json({ error: "teacherId is required." });

  try {
    await adminClient.from("teachers").delete().eq("id", teacherId);
    if (userId) {
      await adminClient.from("users").delete().eq("id", userId);
      await adminClient.auth.admin.deleteUser(userId);
    }
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: "Unexpected error: " + e.message });
  }
});

// Safety net: if any route throws something not already caught, this
// guarantees the client still gets valid, readable JSON back — never an
// empty or malformed body that fails to parse.
app.use((err, req, res, next) => {
  console.error("[unhandled error]", err);
  if (!res.headersSent) {
    res.status(500).json({ error: "Unexpected server error: " + (err?.message || String(err)) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Teacher server running on port ${PORT}`));
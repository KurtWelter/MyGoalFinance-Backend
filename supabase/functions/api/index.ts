// supabase/functions/api/index.ts
// API unificada para MyGoalFinance (auth, profile, transactions, goals, news,
// recommendations, chat con GROQ y push).

import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/* ───────────────────────────── Tipos y helpers base ───────────────────────────── */

type UserLike = {
  id: string;
  email?: string | null;
  user_metadata?: Record<string, unknown> | null;
} | null;

type Ctx = {
  sb: SupabaseClient;      // cliente con token del usuario (RLS activo)
  admin: SupabaseClient;   // service-role (sin RLS). ¡Usar con filtros!
  user: UserLike;
  profileId: number | null;
};

// 🔗 Deep link de confirmación de email
const EMAIL_REDIRECT_TO =
  Deno.env.get("EMAIL_REDIRECT_TO") ?? "mygoalfinance://auth/callback";

// CORS helpers
function withCORS(res: Response) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Headers", "authorization, x-client-info, apikey, content-type");
  h.set("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,DELETE,OPTIONS");
  return new Response(res.body, { status: res.status, headers: h });
}

function jsonOK(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
function jsonErr(detail: string, status = 400) {
  return jsonOK({ detail }, status);
}

async function readJson(req: Request): Promise<Record<string, unknown>> {
  try {
    const txt = await req.text();
    return txt ? (JSON.parse(txt) as any) : {};
  } catch {
    return {};
  }
}

/** "YYYY-MM" → {from: "YYYY-MM-01", to: "YYYY-MM-<last>"} */
function monthToRange(ym?: string) {
  if (!ym) {
    const d = new Date();
    ym = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
  }
  const [y, m] = ym.split("-").map(Number);
  const from = `${y}-${String(m).padStart(2, "0")}-01`;
  const last = new Date(y, m, 0).getDate();
  const to = `${y}-${String(m).padStart(2, "0")}-${String(last).padStart(2, "0")}`;
  return { from, to };
}

/** Asegura/obtiene el id de user_profile del usuario autenticado */
async function ensureProfileId(ctx: Ctx): Promise<number> {
  if (!ctx.user) throw new Error("Unauthenticated");
  if (ctx.profileId) return ctx.profileId;

  // Intentar obtener el perfil más reciente por id (tolerante a duplicados)
  const { data: row, error } = await ctx.admin
    .from("user_profile")
    .select("id")
    .eq("id_supabase", ctx.user.id)
    .order("id", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) {
    console.log("ensureProfileId select warn:", error.message || error);
  }

  if (row && (row as any).id) {
    ctx.profileId = (row as any).id;
    return (row as any).id;
  }

  // ⚠️ La tabla exige "name" NOT NULL → construir un valor por defecto seguro
  const meta = (ctx.user?.user_metadata || {}) as Record<string, unknown>;
  const metaName = typeof meta.name === "string" ? meta.name.trim() : "";
  const fallbackFromEmail =
    (ctx.user?.email && String(ctx.user.email).split("@")[0]) || "";
  const safeName = metaName || fallbackFromEmail || "Usuario";

  // Crear perfil mínimo
  const { data: created, error: e2 } = await ctx.admin
    .from("user_profile")
    .insert({
      id_supabase: ctx.user.id,
      email: ctx.user.email ?? null,
      name: safeName, // ⬅️ evita error NOT NULL
    })
    .select("id")
    .single();

  if (e2) throw new Error(e2.message || "No se pudo crear el perfil");
  ctx.profileId = created.id;
  return created.id;
}

/* ─────────────────────────────────── AUTH ─────────────────────────────────── */

async function authLogin(req: Request, ctx: Ctx) {
  const body = await readJson(req);
  const email = String(body?.email || "");
  const password = String(body?.password || "");
  if (!email || !password) return jsonErr("Faltan credenciales", 400);

  const { data, error } = await ctx.sb.auth.signInWithPassword({ email, password });
  if (error) return jsonErr(error.message || "Login inválido", 400);

  return jsonOK({
    access_token: data.session?.access_token || "",
    user: data.user || null,
  });
}

async function authRegister(req: Request, ctx: Ctx) {
  const body = await readJson(req);
  const email = String(body?.email || "");
  const password = String(body?.password || "");
  const name = String(body?.name || "");

  if (!email || !password) return jsonErr("Faltan email/password", 400);

  const { data, error } = await ctx.sb.auth.signUp({
    email,
    password,
    options: {
      data: { name },
      // 🔗 clave para abrir tu app tras confirmar el correo
      emailRedirectTo: EMAIL_REDIRECT_TO,
    },
  });
  if (error) return jsonErr(error.message || "No se pudo registrar", 400);

  return jsonOK(
    {
      id: data.user?.id || "",
      email: data.user?.email || email,
      requires_confirmation: true,
    },
    201
  );
}

async function authMe(_req: Request, ctx: Ctx) {
  if (!ctx.user) return jsonErr("No autenticado", 401);
  const pid = await ensureProfileId(ctx);
  const { data: profile } = await ctx.admin.from("user_profile").select("*").eq("id", pid).single();
  return jsonOK({ user: ctx.user, profile });
}

/* ───────────────────────────────── PROFILE ───────────────────────────────── */

async function getProfile(_req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const { data, error } = await ctx.admin.from("user_profile").select("*").eq("id", pid).single();
  if (error) return jsonErr(error.message, 400);
  return jsonOK(data);
}

async function updateProfile(req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const body = await readJson(req);

  // Si envían name vacío, no lo sobrescribas a null en tablas NOT NULL
  if (typeof body.name === "string" && body.name.trim() === "") {
    delete (body as any).name;
  }

  const { data, error } = await ctx.admin
    .from("user_profile")
    .update(body)
    .eq("id", pid)
    .select()
    .single();
  if (error) return jsonErr(error.message, 400);
  return jsonOK(data);
}

// ───────────────────────────── PROFILE: subir avatar ─────────────────────────────
async function uploadAvatar(req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);

  const ctype = req.headers.get("content-type") || "";
  if (!ctype.toLowerCase().includes("multipart/form-data")) {
    return jsonErr('Se espera multipart/form-data con campo "file"', 400);
  }

  const form = await req.formData();
  const file = form.get("file");
  if (!(file instanceof File)) return jsonErr('Falta el archivo en el campo "file"', 400);

  const buf = new Uint8Array(await file.arrayBuffer());
  const mime = file.type || "image/jpeg";

  // Extensión simple por mime
  const ext =
    mime.includes("png") ? "png" :
    mime.includes("webp") ? "webp" :
    "jpg";

  // Ruta destino en el bucket
  const path = `avatars/${pid}/${Date.now()}.${ext}`;

  // Subir al bucket "avatars" (debe existir)
  const { error: upErr } = await ctx.admin.storage
    .from("avatars")
    .upload(path, buf, { contentType: mime, upsert: true });

  if (upErr) return jsonErr(upErr.message, 400);

  // URL pública (si el bucket es público)
  const pub = ctx.admin.storage.from("avatars").getPublicUrl(path);
  const publicUrl = pub?.data?.publicUrl || "";

  // Guardar en el perfil
  await ctx.admin.from("user_profile")
    .update({ avatar_url: publicUrl })
    .eq("id", pid);

  return jsonOK({ url: publicUrl });
}

/* ────────────────────────────── TRANSACTIONS ────────────────────────────── */

async function listTransactions(req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const url = new URL(req.url);

  let from = url.searchParams.get("from") || undefined;
  let to = url.searchParams.get("to") || undefined;
  const month = url.searchParams.get("month") || undefined;

  if (!from && !to && month) {
    const r = monthToRange(month);
    from = r.from;
    to = r.to;
  }

  let q = ctx.admin
    .from("transaction")
    .select("*")
    .eq("user_id", pid)
    .order("occurred_at", { ascending: false });

  if (from) q = q.gte("occurred_at", from);
  if (to) q = q.lte("occurred_at", to);

  const { data, error } = await q;
  if (error) return jsonErr(error.message, 400);
  return jsonOK(data || []);
}

async function createTransaction(req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const body = await readJson(req);

  const type = body?.type === "expense" ? "expense" : "income";
  const rawAmount = Number(body?.amount || 0);
  const amount = type === "expense" ? -Math.abs(rawAmount) : Math.abs(rawAmount);
  if (!(Math.abs(amount) > 0)) return jsonErr("amount inválido", 400);

  const description = (body?.description ? String(body.description) : "").trim() || null;

  // Acepta "occurred_at" (correcto) o "date" (compatibilidad)
  const occurred_at =
    String((body as any)?.occurred_at || (body as any)?.date || "").trim() ||
    new Date().toISOString().slice(0, 10);

  const payload = { user_id: pid, type, amount, description, occurred_at };

  const { data, error } = await ctx.admin
    .from("transaction")
    .insert(payload)
    .select()
    .single();

  if (error) return jsonErr(error.message, 400);
  return jsonOK({ id: data.id }, 201);
}

async function summaryMonth(req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const url = new URL(req.url);
  const month = url.searchParams.get("month") || undefined;
  const range = monthToRange(month);

  const { data, error } = await ctx.admin
    .from("transaction")
    .select("amount")
    .eq("user_id", pid)
    .gte("occurred_at", range.from)
    .lte("occurred_at", range.to);

  if (error) return jsonErr(error.message, 400);

  let inc = 0, exp = 0;
  for (const t of data || []) {
    const v = Number((t as any).amount || 0);
    if (v >= 0) inc += v;
    else exp += Math.abs(v);
  }
  const net = inc - exp; // cuánto te queda
  return jsonOK({ month: month || "", inc, exp, net, from: range.from, to: range.to });
}

/* ────────────────────────────────── GOALS ───────────────────────────────── */

async function listGoals(_req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const { data, error } = await ctx.admin
    .from("financial_goal")
    .select("*")
    .eq("user_id", pid)
    .order("created_at", { ascending: false });
  if (error) return jsonErr(error.message, 400);
  return jsonOK(data || []);
}

async function createGoal(req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const body = await readJson(req);

  const title = String(body?.title || "").trim();
  const target_amount = Number(body?.target_amount || 0);
  if (title.length < 2) return jsonErr("Título demasiado corto", 400);
  if (!(target_amount > 0)) return jsonErr("target_amount debe ser > 0", 400);

  const description =
    body?.description == null || String(body.description).trim() === ""
      ? undefined
      : String(body.description).trim();
  const deadline =
    body?.deadline == null || String(body.deadline).trim() === ""
      ? undefined
      : String(body.deadline).trim(); // "YYYY-MM-DD"

  const payload = {
    user_id: pid,
    title,
    target_amount,
    current_amount: 0,
    description,
    deadline,
  };

  const { data, error } = await ctx.admin
    .from("financial_goal")
    .insert(payload)
    .select()
    .single();

  if (error) return jsonErr(error.message, 400);
  return jsonOK({ id: data.id }, 201);
}

async function updateGoal(req: Request, ctx: Ctx, goalId: number) {
  const pid = await ensureProfileId(ctx);
  const body = await readJson(req);

  const { data, error } = await ctx.admin
    .from("financial_goal")
    .update(body)
    .eq("id", goalId)
    .eq("user_id", pid)
    .select()
    .single();

  if (error) return jsonErr(error.message, 400);
  return jsonOK(data);
}

async function deleteGoal(_req: Request, ctx: Ctx, goalId: number) {
  const pid = await ensureProfileId(ctx);
  const { error } = await ctx.admin
    .from("financial_goal")
    .delete()
    .eq("id", goalId)
    .eq("user_id", pid);
  if (error) return jsonErr(error.message, 400);
  return jsonOK({ ok: true });
}

// POST /goals/:id/contribute
async function contributeGoal(req: Request, ctx: Ctx, goalId: number) {
  const pid = await ensureProfileId(ctx);
  const body = await readJson(req);
  const amount = Number(body?.amount || 0);
  const note = body?.note ? String(body.note) : null;
  if (!(amount > 0)) return jsonErr("amount debe ser > 0", 400);

  // 1) Confirmar que la meta es del usuario
  const { data: g, error: e0 } = await ctx.admin
    .from("financial_goal")
    .select("user_id,current_amount")
    .eq("id", goalId)
    .single();
  if (e0) return jsonErr(e0.message, 400);
  if (!g || Number((g as any).user_id) !== pid) return jsonErr("Meta no encontrada", 404);

  // 2) Insertar contribución (si tienes tabla goal_contribution)
  await ctx.admin.from("goal_contribution").insert({ goal_id: goalId, amount, note });

  // 3) Actualizar current_amount de la meta
  const next = Number((g as any).current_amount || 0) + amount;
  const { data: updated, error: e2 } = await ctx.admin
    .from("financial_goal")
    .update({ current_amount: next })
    .eq("id", goalId)
    .eq("user_id", pid)
    .select()
    .single();
  if (e2) return jsonErr(e2.message, 400);

  return jsonOK(updated);
}

// GET /goals/contributions/:goalId
async function listContributions(_req: Request, ctx: Ctx, goalId: number) {
  const pid = await ensureProfileId(ctx);

  // validar ownership
  const { data: g, error: e0 } = await ctx.admin
    .from("financial_goal")
    .select("user_id")
    .eq("id", goalId)
    .single();
  if (e0) return jsonErr(e0.message, 400);
  if (!g || Number((g as any).user_id) !== pid) return jsonErr("Meta no encontrada", 404);

  const { data, error } = await ctx.admin
    .from("goal_contribution")
    .select("*")
    .eq("goal_id", goalId)
    .order("created_at", { ascending: false });

  if (error) return jsonErr(error.message, 400);
  return jsonOK(data || []);
}

/* ─────────────────────────────────── NEWS ─────────────────────────────────── */

async function newsRates(_req: Request, ctx: Ctx) {
  const { data, error } = await ctx.admin
    .from("fx_snapshot")
    .select("base, usd, eur, uf, taken_at")
    .order("taken_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) return jsonErr(error.message, 400);
  const r = (data || {}) as any;
  return jsonOK({
    base: String(r.base || "CLP"),
    usd: Number(r.usd) || 0,
    eur: Number(r.eur) || 0,
    uf: Number(r.uf) || 0,
    updatedAt: r.taken_at || new Date().toISOString(),
  });
}

async function newsFeed(_req: Request, ctx: Ctx) {
  const { data, error } = await ctx.admin
    .from("news_seen")
    .select("article_id,title,url,source,published_at")
    .order("published_at", { ascending: false })
    .limit(20);
  if (error) return jsonErr(error.message, 400);

  const items = (data || []).map((r: any) => ({
    id: r.article_id,
    title: r.title,
    url: r.url,
    source: r.source,
    published_at: r.published_at,
  }));
  return jsonOK(items);
}

/* ───────────────────────────── RECOMMENDATIONS ───────────────────────────── */

async function listRecommendations(_req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const { data, error } = await ctx.admin
    .from("recommendation")
    .select("*")
    .eq("user_id", pid)
    .order("created_at", { ascending: false });
  if (error) return jsonErr(error.message, 400);
  return jsonOK(data || []);
}

/* ─────────────────────────────────── PUSH ─────────────────────────────────── */

async function pushRegister(req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const body = await readJson(req);
  const token = String(body?.token || "").trim();
  const platform = String(body?.platform || "").trim(); // 'ios' | 'android' | 'web'
  if (!token) return jsonErr("token requerido", 400);

  const { error } = await ctx.admin
    .from("push_token")
    .upsert({ user_id: pid, token, platform }, { onConflict: "token" })
    .select();

  if (error) return jsonErr(error.message, 400);
  return jsonOK({ ok: true });
}

/* ─────────────────────────────────── CHAT ─────────────────────────────────── */

async function chatHistory(_req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const { data, error } = await ctx.admin
    .from("chat_message")
    .select("id,user_id,sender,message,timestamp")
    .eq("user_id", pid)
    .order("timestamp", { ascending: true })
    .limit(200);
  if (error) return jsonErr(error.message, 400);
  return jsonOK(data || []);
}

async function chatSend(req: Request, ctx: Ctx) {
  const pid = await ensureProfileId(ctx);
  const body = await readJson(req);
  const message = String(body?.message || "").trim();
  if (!message) return jsonErr("message requerido", 400);

  // 1) guardar mensaje del usuario
  const { data: userMsg, error: e1 } = await ctx.admin
    .from("chat_message")
    .insert({ user_id: pid, sender: "user", message }) // timestamp: default now()
    .select()
    .single();
  if (e1) return jsonErr(e1.message, 400);

  // 2) llamar a GROQ
  const GROQ_API_KEY = Deno.env.get("GROQ_API_KEY") ?? "";
  const GROQ_MODEL = Deno.env.get("GROQ_MODEL") ?? "llama-3.1-8b-instant";
  if (!GROQ_API_KEY) return jsonErr("Falta GROQ_API_KEY en variables de entorno", 500);

  // contexto breve a partir del historial reciente
  const { data: lastMsgs } = await ctx.admin
    .from("chat_message")
    .select("sender,message")
    .eq("user_id", pid)
    .order("timestamp", { ascending: false })
    .limit(12);

  const msgs = (lastMsgs || [])
    .reverse()
    .map((m: any) => ({ role: m.sender === "user" ? "user" : "assistant", content: String(m.message || "") }));

  msgs.push({ role: "user", content: message });

  let botText = "Entendido.";
  try {
    const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${GROQ_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages: msgs,
        temperature: 0.3,
      }),
    });

    const out: any = await resp.json().catch(() => ({}));
    botText =
      out?.choices?.[0]?.message?.content?.trim?.() ||
      out?.choices?.[0]?.message?.content ||
      "🤖";
  } catch (_e) {
    botText = "Tuve un problema para generar la respuesta, intenta de nuevo.";
  }

  // 3) guardar respuesta del bot
  const { data: botMsg, error: e2 } = await ctx.admin
    .from("chat_message")
    .insert({ user_id: pid, sender: "bot", message: botText })
    .select()
    .single();
  if (e2) return jsonErr(e2.message, 400);

  // 4) compat con tu front { user, bot }
  return jsonOK({ user: userMsg, bot: botMsg });
}

/* ────────────────────────────────── ROUTER ───────────────────────────────── */

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return withCORS(jsonOK("ok"));

  // Vars de entorno necesarias
  const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
  const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  if (!SUPABASE_URL || !ANON_KEY || !SERVICE_ROLE) {
    return withCORS(jsonErr("Faltan variables de entorno de Supabase", 500));
  }

  // Normalizar path (la función se llama "api")
  const url = new URL(req.url);
  let path = url.pathname;
  path = path.replace(/^\/functions\/v1/, ""); // en local
  if (!path.startsWith("/api")) path = "/api" + path; // asegurar prefijo /api
  const p = path.replace(/^\/api/, "") || "/";

  // Log
  console.log(`[api] ${req.method} ${p}`);

  // Healthcheck público
  if (p === "/health" && (req.method === "GET" || req.method === "HEAD")) {
    return withCORS(jsonOK({ ok: true, time: new Date().toISOString() }));
  }

  // Clients
  const sb = createClient(SUPABASE_URL, ANON_KEY, {
    global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
  });
  const admin = createClient(SUPABASE_URL, SERVICE_ROLE);

  // User actual (si hay bearer)
  const { data: auth } = await sb.auth.getUser();
  const user: UserLike = auth?.user ?? null;
  const ctx: Ctx = { sb, admin, user, profileId: null };

  try {
    // ─── AUTH
    if (p === "/auth/login" && req.method === "POST") return withCORS(await authLogin(req, ctx));
    if (p === "/auth/register" && req.method === "POST") return withCORS(await authRegister(req, ctx));
    if (p === "/auth/me" && req.method === "GET") return withCORS(await authMe(req, ctx));
    if (p === "/auth/logout" && req.method === "POST") return withCORS(jsonOK({ ok: true }));

    // ─── PROFILE
    if (p === "/profile" && req.method === "GET") return withCORS(await getProfile(req, ctx));
    if (p === "/profile" && req.method === "PUT") return withCORS(await updateProfile(req, ctx));
    if (p === "/profile/avatar" && req.method === "POST") return withCORS(await uploadAvatar(req, ctx)); // ⬅️ NUEVO

    // ─── TRANSACTIONS
    if (p === "/transactions" && req.method === "GET") return withCORS(await listTransactions(req, ctx));
    if (p === "/transactions" && req.method === "POST") return withCORS(await createTransaction(req, ctx));
    if (p.startsWith("/transactions/summary/month") && req.method === "GET")
      return withCORS(await summaryMonth(req, ctx));

    // ─── GOALS
    if (p === "/goals" && req.method === "GET") return withCORS(await listGoals(req, ctx));
    if (p === "/goals" && req.method === "POST") return withCORS(await createGoal(req, ctx));

    const mGoal = p.match(/^\/goals\/(\d+)$/);
    if (mGoal && req.method === "PATCH") return withCORS(await updateGoal(req, ctx, Number(mGoal[1])));
    if (mGoal && req.method === "DELETE") return withCORS(await deleteGoal(req, ctx, Number(mGoal[1])));

    const mContrib = p.match(/^\/goals\/(\d+)\/contribute$/);
    if (mContrib && req.method === "POST")
      return withCORS(await contributeGoal(req, ctx, Number(mContrib[1])));

    const mListContrib = p.match(/^\/goals\/contributions\/(\d+)$/);
    if (mListContrib && req.method === "GET") {
      return withCORS(await listContributions(req, ctx, Number(mListContrib[1])));
    }

    // ─── NEWS
    if (p === "/news/rates" && req.method === "GET") return withCORS(await newsRates(req, ctx));
    if (p === "/news/feed" && req.method === "GET") return withCORS(await newsFeed(req, ctx));

    // ─── RECOMMENDATIONS
    if (p === "/recommendations" && req.method === "GET")
      return withCORS(await listRecommendations(req, ctx));

    // ─── PUSH TOKENS
    if (p === "/push/register" && req.method === "POST")
      return withCORS(await pushRegister(req, ctx));

    // ─── CHAT
    if (p === "/chat" && req.method === "GET") return withCORS(await chatHistory(req, ctx));
    if ((p === "/chat/message" || p === "/chat") && req.method === "POST")
      return withCORS(await chatSend(req, ctx));

    return withCORS(jsonErr(`Not Found: ${p}`, 404));
  } catch (e: unknown) {
    const msg = (e && typeof e === "object" && "message" in e) ? String((e as any).message) : "Internal error";
    console.log("[api][error]", msg);
    return withCORS(jsonErr(msg, 400));
  }
});

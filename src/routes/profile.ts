// src/routes/profile.ts
import { Router } from 'express';
import multer from 'multer';
import mime from 'mime-types';

import { supabaseAdmin } from '../supabase';
import { profileUpdateSchema } from '../utils/validators';
import { getAuthUserFromRequest } from '../utils/auth-helpers';

const router = Router();

/** Carga en memoria (hasta 5MB) */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

/** Columnas que EXISTEN en tu tabla */
const PROFILE_COLUMNS = [
  'email',
  'name',
  'fecnac',
  'age_range',
  'experience',
  'monthly_income',
  'finance_goal',
  'current_situation',
  'avatar_url',            // ⬅️ NUEVO
] as const;

type ProfileCol = (typeof PROFILE_COLUMNS)[number];

type ProfileDB = {
  email: string | null;
  name: string | null;
  fecnac: string | null;
  age_range: string | null;
  experience: 'beginner' | 'intermediate' | 'advanced' | null;
  monthly_income: number | null;
  finance_goal: string | null;
  current_situation: string | null;
  avatar_url: string | null;   // ⬅️ NUEVO
};

/** GET /api/profile */
router.get('/', async (req, res) => {
  const { user } = await getAuthUserFromRequest(req);
  if (!user) return res.status(401).json({ detail: 'No autenticado' });

  const { data: row, error } = await supabaseAdmin
    .from('user_profile')
    .select(PROFILE_COLUMNS.join(','))
    .eq('id_supabase', user.id)
    .maybeSingle();

  if (error && (error as any).code !== 'PGRST116') {
    return res.status(400).json({ detail: error.message });
  }

  const d = (row ?? {}) as Partial<ProfileDB>;

  return res.json({
    id: user.id,
    email: d.email ?? user.email,
    name: d.name ?? (user.user_metadata?.name as string | undefined) ?? null,
    fecnac: d.fecnac ?? null,
    age_range: d.age_range ?? null,
    experience: d.experience ?? null,
    monthly_income: d.monthly_income ?? null,
    finance_goal: d.finance_goal ?? null,
    current_situation: d.current_situation ?? null,
    avatar_url: d.avatar_url ?? null, // ⬅️ NUEVO
  });
});

/** PUT /api/profile */
router.put('/', async (req, res) => {
  const { user } = await getAuthUserFromRequest(req);
  if (!user) return res.status(401).json({ detail: 'No autenticado' });

  const parsed = profileUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json(parsed.error.flatten());
  }

  // Toma solo campos válidos que existen en la tabla
  const input = parsed.data as Record<string, any>;
  const toSet: Partial<Record<ProfileCol, any>> = {};
  for (const k of PROFILE_COLUMNS) {
    if (k in input && input[k] !== undefined) {
      toSet[k] = input[k];
    }
  }

  // ¿Existe perfil?
  const { data: existingRow, error: exErr } = await supabaseAdmin
    .from('user_profile')
    .select(PROFILE_COLUMNS.join(','))
    .eq('id_supabase', user.id)
    .maybeSingle();

  if (exErr) {
    return res.status(400).json({ detail: exErr.message });
  }

  if (existingRow) {
    const { data: updatedRow, error: updErr } = await supabaseAdmin
      .from('user_profile')
      .update(toSet)
      .eq('id_supabase', user.id)
      .select(PROFILE_COLUMNS.join(','))
      .single();

    if (updErr) return res.status(400).json({ detail: updErr.message });

    const d = (updatedRow ?? {}) as Partial<ProfileDB>;
    return res.json({
      id: user.id,
      email: d.email ?? user.email,
      name: d.name ?? (user.user_metadata?.name as string | undefined) ?? null,
      fecnac: d.fecnac ?? null,
      age_range: d.age_range ?? null,
      experience: d.experience ?? null,
      monthly_income: d.monthly_income ?? null,
      finance_goal: d.finance_goal ?? null,
      current_situation: d.current_situation ?? null,
      avatar_url: d.avatar_url ?? null, // ⬅️ NUEVO
    });
  } else {
    const fallbackName =
      (toSet.name as string | undefined) ||
      (user.user_metadata?.name as string | undefined) ||
      (user.email?.split('@')[0] ?? 'Usuario');

    const insertPayload: { id_supabase: string } & Partial<ProfileDB> = {
      id_supabase: user.id,
      email: user.email!,
      name: fallbackName,
      ...toSet,
    };

    const { data: insertedRow, error: insErr } = await supabaseAdmin
      .from('user_profile')
      .insert(insertPayload)
      .select(PROFILE_COLUMNS.join(','))
      .single();

    if (insErr) return res.status(400).json({ detail: insErr.message });

    const d = (insertedRow ?? {}) as Partial<ProfileDB>;
    return res.json({
      id: user.id,
      email: d.email ?? user.email,
      name: d.name ?? (user.user_metadata?.name as string | undefined) ?? null,
      fecnac: d.fecnac ?? null,
      age_range: d.age_range ?? null,
      experience: d.experience ?? null,
      monthly_income: d.monthly_income ?? null,
      finance_goal: d.finance_goal ?? null,
      current_situation: d.current_situation ?? null,
      avatar_url: d.avatar_url ?? null, // ⬅️ NUEVO
    });
  }
});

/**
 * POST /api/profile/avatar
 * multipart/form-data con campo "file"
 * Guarda en bucket "avatars" y actualiza user_profile.avatar_url
 */
router.post('/avatar', upload.single('file'), async (req, res) => {
  const { user } = await getAuthUserFromRequest(req);
  if (!user) return res.status(401).json({ detail: 'No autenticado' });

  if (!req.file) return res.status(400).json({ detail: 'Falta archivo' });
  if (!req.file.mimetype?.startsWith('image/')) {
    return res.status(400).json({ detail: 'Solo se permiten imágenes' });
  }

  const ext = mime.extension(req.file.mimetype || '') || 'jpg';
  const path = `u/${user.id}/${Date.now()}.${ext}`;

  // Sube a Storage (bucket público "avatars")
  const up = await supabaseAdmin.storage
    .from('avatars')
    .upload(path, req.file.buffer, {
      contentType: req.file.mimetype,
      upsert: true,
    });

  if (up.error) return res.status(400).json({ detail: up.error.message });

  // URL pública
  const pub = supabaseAdmin.storage.from('avatars').getPublicUrl(path);
  const url = pub.data.publicUrl;

  // Persiste en perfil
  const upd = await supabaseAdmin
    .from('user_profile')
    .update({ avatar_url: url })
    .eq('id_supabase', user.id)
    .select('avatar_url')
    .single();

  if (upd.error) return res.status(400).json({ detail: upd.error.message });

  res.json({ url });
});

export default router;

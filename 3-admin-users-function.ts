// @ts-nocheck
// Touch Designs Operations: password-reset function for Supabase.
//
// HOW TO INSTALL (about 2 minutes, once):
//   Supabase -> Edge Functions -> "Deploy a new function" -> "Via Editor"
//   Name:  admin-users        (exactly this name)
//   Delete the sample code, paste ALL of this file, click Deploy. Leave "Verify JWT" switched on.
//
// WHAT IT DOES: when an owner, director, secretary or project manager clicks "Reset password" in
// Team & access, this function (which runs inside Supabase and holds the secret key safely) gives that
// person a new temporary password. They must choose their own at next sign-in.
// The secret key is never placed in the website.
import { createClient } from 'jsr:@supabase/supabase-js@2'

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
// who may be reset by whom (the project manager is limited to the roles it is allowed to add)
const PM_CAN_RESET = ['site_manager', 'procurement', 'designer', 'workforce', 'client', 'marketing_manager', 'salesperson', 'hr', 'pending']
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...CORS, 'Content-Type': 'application/json' } })
const makePassword = () => {
  const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789', b = new Uint8Array(12)
  crypto.getRandomValues(b)
  return [...b].map((x) => a[x % a.length]).join('')
}

async function handler(req, make) {
  try {
    if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS })
    if (req.method !== 'POST') return json({ error: 'Use POST.' }, 405)
    const admin = make(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'), { auth: { persistSession: false, autoRefreshToken: false } })

    // 1. who is calling?
    const jwt = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '')
    if (!jwt) return json({ error: 'You are not signed in.' }, 401)
    const { data: u, error: ue } = await admin.auth.getUser(jwt)
    if (ue || !u || !u.user) return json({ error: 'Your session has expired. Please sign in again.' }, 401)
    const { data: me } = await admin.from('profiles').select('id,role,active,full_name').eq('id', u.user.id).single()
    if (!me || !me.active || !['owner', 'director', 'secretary', 'project_manager'].includes(me.role)) return json({ error: 'You are not allowed to reset passwords.' }, 403)

    // 2. what do they want?
    let body
    try { body = await req.json() } catch (_) { return json({ error: 'Bad request.' }, 400) }
    if (!body || body.action !== 'reset_password' || !body.user_id) return json({ error: 'Bad request.' }, 400)
    if (body.user_id === me.id) return json({ error: 'Use the Password button to change your own password.' }, 400)
    const { data: t } = await admin.from('profiles').select('id,email,full_name,role').eq('id', body.user_id).single()
    if (!t) return json({ error: 'That person was not found.' }, 404)

    // 3. are they allowed to reset THIS person?
    const ok = me.role === 'owner'
      || (['director', 'secretary'].includes(me.role) && t.role !== 'owner')
      || (me.role === 'project_manager' && PM_CAN_RESET.includes(t.role))
    if (!ok) return json({ error: "You are not allowed to reset this person's password." }, 403)

    // 4. do it
    const password = makePassword()
    const { error: pe } = await admin.auth.admin.updateUserById(t.id, { password })
    if (pe) return json({ error: 'Could not reset the password: ' + pe.message }, 500)
    await admin.from('profiles').update({ must_change: true }).eq('id', t.id)
    await admin.from('audit_log').insert({ user_id: me.id, op: 'RESET_PASSWORD', tab: 'profiles', row_id: t.id, new_data: { by_role: me.role } })
    return json({ ok: true, password, name: t.full_name, login: String(t.email).endsWith('@staff.touchdesigns.app') ? t.full_name : t.email })
  } catch (e) {
    return json({ error: 'Something went wrong: ' + (e && e.message ? e.message : e) }, 500)
  }
}

Deno.serve((req) => handler(req, createClient))

# Touch Designs Operations: setup guide

Two folders. **Upload only `1-upload-to-github` to GitHub. Never upload `2-run-in-supabase`.**

## Who can add people
- **Owner, Director, Secretary:** add anyone (any role) and choose what they see.
- **Project Manager:** adds site managers, procurement, designers, workforce, clients, marketing managers, salespeople and HR, and can give them only the projects the project manager is on. A project manager cannot add or touch directors, secretaries, other project managers or the owner.
- Nobody else can add people. There is no self-registration page.
Everything is done inside the app: **Team & access -> Add user** (one person) or **Add several people** (paste a list), and **Reset password** for forgotten passwords. No code.

## 1. Create the database (about 10 minutes, free)
1. supabase.com -> create an account -> **New project**. Choose a strong database password and the region closest to you.
2. **Authentication -> Sign In / Providers -> Email**: keep it enabled, **switch OFF "Confirm email"**, set minimum password length to 8. Leave "Allow new users to sign up" ON (the app needs it when you add people; the private company code stops outsiders from getting any access).
3. **SQL Editor**: run all of `1-setup.sql`, then `2-team.sql`.
4. **Authentication -> Users -> Add user**: create the owner (`mutitikaevans4@gmail.com`) with a very long password, tick auto-confirm. This is the only person you create in Supabase.
5. **Project Settings -> API**: copy the **Project URL** and the **anon public** key into `1-upload-to-github/config.js`. Never use the `service_role` key.
6. **Authentication -> URL Configuration**: set **Site URL** to your GitHub link (step 7).

## 2. Install the password-reset function (about 2 minutes, once)
This lets the owner, director, secretary or project manager press **Reset password** in the app when someone forgets theirs. It runs inside Supabase and keeps Supabase's secret key safe (the key is never in the website).
1. In Supabase open **Edge Functions** (left menu), click **Deploy a new function**, and choose **Via Editor**. A code editor opens with a sample.
2. Select **all** the sample code in the editor and delete it.
3. Paste the whole function. You can copy it from the file `2-run-in-supabase/3-admin-users-function.ts`, **or from the end of this README (section "Function code")**, so you do not need the file.
4. Type the name `admin-users` (exactly, small letters) in the name box at the bottom of the editor and click **Deploy function**. Leave every other setting as it is.
Until you do this, the Reset password button shows a message saying the function is not installed; everything else works.

## 3. Put the site on GitHub
7. github.com -> **New repository** (Public) -> **Add file -> Upload files**: `index.html` and `config.js` only -> commit. **Settings -> Pages** -> branch `main`, folder `/ (root)`, Save. The site is at `https://YOUR-NAME.github.io/REPO-NAME/`.

## 4. Add your people (inside the app)
8. Open the site and sign in as the **owner** (email + password).
9. **Team & access -> Add several people**, paste one person per line as `name, role` (add an email after the role only for people who sign in with email). For example:
```
Dennis Ngatia, director
Charity Wanjiru, secretary
Evans Mwaniki, project manager, his-daily-email@gmail.com
Isaiah Noel, site manager
Peter Muungani, site manager
Julius Munyao, marketing manager
Peter Kiko, salesperson
```
10. The app shows each person's **sign-in name and a temporary password** once. Send these privately (for example by WhatsApp). On first sign-in each person must choose their own password.
11. For site managers, designers, workforce, clients (and project managers) click **assigned** and tick the projects they may see. Add workforce one by one with **Add user** to tick their projects at the same time.
12. Everyone signs in with their **name** (capitals do not matter) or email, plus password. Their **Password** button changes it any time.

## Keeping data fresh
The app reloads the latest data whenever you come back to its tab. To refresh at any moment, press **Sync now** (top right): it first saves anything you were still typing, then loads the newest data and any change to your own role or access. If the connection is down it tells you and keeps what is on your screen.

## Switching someone off or changing access
Team & access: set **Active** to No, or change their **Role** or **assigned** projects. Every change is written to the audit log.

## Forgotten password
In **Team & access** press **Reset password** next to the person. A new temporary password is shown once; send it privately. The old password stops working, and they must choose their own at next sign-in. Owner and director can reset anyone except the owner; the project manager can reset the roles it is allowed to add. Everyone changes their own password with the **Password** button.

## Emergency owner account
The `owner` bypasses every access rule and cannot be demoted, deactivated or deleted from the app. Use a separate email and a very long password in a password manager, only in emergencies. If locked out: Supabase -> Authentication -> Users -> reset that password.

## Updating later
Replace only `index.html` on GitHub (`config.js` stays). When an update says to re-run the SQL, run the new `1-setup.sql`; it keeps your data.

## Who sees what
| Role | Access |
|---|---|
| owner | everything, always |
| director, secretary | everything, plus Team & access |
| project_manager | assigned projects, finance, jobs, materials, schedule, quotations; adds site, procurement, design, workforce, client, marketing, sales and HR staff |
| site_manager | assigned projects (read), jobs, materials, production, schedule, stock, attendance |
| marketing_manager | clients, meetings, artwork, quotations, schedule (read), approvals (read) |
| salesperson | clients, meetings, quotations |
| procurement | materials, stock, procurement |
| designer | artwork on assigned projects |
| hr | attendance |
| workforce | jobs and approved artwork on assigned projects, schedule, own attendance |
| client | own project, invoices, designs and quotations sent to them, approvals |

Change a role's access later in Supabase -> Table Editor -> `role_perms`.


## Function code
Paste this into the Supabase function editor (step 2 above).

```ts
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
```

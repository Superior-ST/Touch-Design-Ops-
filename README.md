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
1. Supabase -> **Edge Functions** -> **Deploy a new function** -> **Via Editor**.
2. Name it exactly `admin-users`.
3. Delete the sample code, paste everything from `2-run-in-supabase/3-admin-users-function.ts`, and click **Deploy**. Leave "Verify JWT" switched on.
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

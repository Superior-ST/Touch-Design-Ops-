-- Touch Design Ops: foundation schema (logins, roles, row-level security, audit trail).
-- Run ONCE in Supabase -> SQL Editor. Safe to re-run.

create table if not exists public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  email text, full_name text default '',
  role text not null default 'pending' check (role in ('pending','director','project_manager','site_manager','procurement','designer','hr','owner','workforce','client','secretary','marketing_manager','salesperson')),
  active boolean not null default false,
  created_at timestamptz not null default now());
create table if not exists public.invites(
  email text primary key, full_name text default '',
  role text not null default 'pending' check (role in ('pending','director','project_manager','site_manager','procurement','designer','hr','workforce','client','owner','secretary','marketing_manager','salesperson')),
  active boolean not null default true);
alter table public.profiles add column if not exists must_change boolean not null default false;
create table if not exists public.app_settings(key text primary key, value text not null);
insert into public.app_settings(key,value) values('join_code', upper(substr(md5(gen_random_uuid()::text),1,6))) on conflict (key) do nothing;
create table if not exists public.role_perms(
  role text not null, tab text not null,
  can_read boolean not null default false, can_write boolean not null default false,
  primary key(role,tab));
create table if not exists public.project_members(
  project_id text not null, user_id uuid not null references public.profiles(id) on delete cascade,
  primary key(project_id,user_id));
create table if not exists public.records(
  id text primary key, tab text not null, project_id text,
  data jsonb not null default '{}'::jsonb,
  created_by uuid default auth.uid(), created_at timestamptz not null default now(),
  updated_by uuid, updated_at timestamptz not null default now());
create index if not exists records_tab_idx on public.records(tab);
create index if not exists records_project_idx on public.records(project_id);
create table if not exists public.audit_log(
  id bigserial primary key, at timestamptz not null default now(), user_id uuid,
  op text, tab text, row_id text, old_data jsonb, new_data jsonb);

-- allow the procurement role on installs created from an earlier version of this file
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('pending','director','project_manager','site_manager','procurement','designer','hr','owner','workforce','client','secretary','marketing_manager','salesperson'));

-- helpers (security definer so they can read profiles without recursion)
create or replace function public.my_role() returns text language sql stable security definer set search_path=public as
$$ select role from public.profiles where id=auth.uid() and active $$;
create or replace function public.can_do(p_tab text, p_write boolean) returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from public.role_perms rp where rp.role=public.my_role() and rp.tab=p_tab
   and (case when p_write then rp.can_write else rp.can_read end)) $$;
create or replace function public.in_scope(p_tab text, p_project text) returns boolean language sql stable security definer set search_path=public as
$$ select case
     when public.my_role() in ('director','hr','owner','secretary','marketing_manager') then true
     when p_tab in ('projects','co','finance','production','assessments','jobs','designs','approvals') or (p_tab='quotes' and public.my_role()='client')
       then p_project is not null and exists(select 1 from public.project_members m where m.project_id=p_project and m.user_id=auth.uid())
     else true end $$;
-- one place for the permission + project + own-attendance checks
create or replace function public.row_ok(p_tab text, p_project text, p_data jsonb, p_write boolean) returns boolean language sql stable security definer set search_path=public as
$$ select public.my_role()='owner' or (public.can_do(p_tab,p_write) and public.in_scope(p_tab,p_project)
   and not (public.my_role()='workforce' and p_tab='attendance' and coalesce(p_data->>'user_id','')<>auth.uid()::text)) $$;

-- projects the signed-in person is assigned to (security definer avoids policy recursion)
create or replace function public.my_projects() returns setof text language sql stable security definer set search_path=public as
$$ select project_id from public.project_members where user_id=auth.uid() $$;

-- row-level security
alter table public.profiles enable row level security;
alter table public.role_perms enable row level security;
alter table public.project_members enable row level security;
alter table public.records enable row level security;
alter table public.audit_log enable row level security;
alter table public.app_settings enable row level security;
revoke all on public.app_settings from anon;
grant select, update on public.app_settings to authenticated;
drop policy if exists as_select on public.app_settings;
create policy as_select on public.app_settings for select to authenticated using (public.my_role() in ('director','secretary','owner','project_manager'));
drop policy if exists as_update on public.app_settings;
create policy as_update on public.app_settings for update to authenticated using (public.my_role() in ('director','secretary','owner')) with check (public.my_role() in ('director','secretary','owner'));
alter table public.invites enable row level security;   -- no policies: only the SQL editor and the sign-up trigger can read or write it
revoke all on public.invites from anon, authenticated;
revoke all on public.profiles, public.role_perms, public.project_members, public.records, public.audit_log from anon;
grant select, insert, update, delete on public.profiles, public.role_perms, public.project_members, public.records to authenticated;
grant select on public.audit_log to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- who can see and manage people: owner, director, secretary (everyone except the owner row) and the project manager (site managers, procurement, designers, workforce, clients, marketing, sales and HR; never directors, secretaries, project managers or the owner)
drop policy if exists prof_select on public.profiles;
create policy prof_select on public.profiles for select to authenticated using (id=auth.uid() or public.my_role() in ('director','secretary','owner')
  or (public.my_role()='project_manager' and role in ('site_manager','procurement','designer','workforce','client','marketing_manager','salesperson','hr','pending')));
drop policy if exists prof_update on public.profiles;
create policy prof_update on public.profiles for update to authenticated
  using (public.my_role()='owner' or (public.my_role() in ('director','secretary') and role<>'owner')
         or (public.my_role()='project_manager' and role in ('site_manager','procurement','designer','workforce','client','marketing_manager','salesperson','hr','pending')))
  with check (public.my_role()='owner' or (public.my_role() in ('director','secretary') and role<>'owner')
         or (public.my_role()='project_manager' and role in ('site_manager','procurement','designer','workforce','client','marketing_manager','salesperson','hr','pending')));
drop policy if exists rp_select on public.role_perms;  create policy rp_select on public.role_perms for select to authenticated using (true);
drop policy if exists rp_write on public.role_perms;   create policy rp_write on public.role_perms for all to authenticated using (public.my_role() in ('director','secretary','owner')) with check (public.my_role() in ('director','secretary','owner'));
drop policy if exists pm_select on public.project_members;
create policy pm_select on public.project_members for select to authenticated using (user_id=auth.uid() or public.my_role() in ('director','secretary','owner')
  or (public.my_role()='project_manager' and project_id in (select public.my_projects())));
drop policy if exists pm_write on public.project_members;
create policy pm_write on public.project_members for all to authenticated
  using (public.my_role() in ('director','secretary','owner') or (public.my_role()='project_manager' and project_id in (select public.my_projects())))
  with check (public.my_role() in ('director','secretary','owner') or (public.my_role()='project_manager' and project_id in (select public.my_projects())));
drop policy if exists audit_select on public.audit_log; create policy audit_select on public.audit_log for select to authenticated using (public.my_role() in ('director','secretary','owner'));

drop policy if exists rec_select on public.records;
create policy rec_select on public.records for select to authenticated using (
  public.row_ok(tab,project_id,data,false)
  and not (public.my_role()='client' and tab='finance' and coalesce(data->>'type','')<>'Invoice')
  and not (public.my_role()='client' and tab='designs' and coalesce(data->>'status','') not in ('Sent to client','Approved','Changes requested','Final'))
  and not (public.my_role()='client' and tab='quotes' and coalesce(data->>'status','') not in ('Sent','Accepted','Declined','Invoiced'))
  and not (public.my_role()='workforce' and tab='designs' and coalesce(data->>'status','') not in ('Approved','Final')));
drop policy if exists rec_insert on public.records;
create policy rec_insert on public.records for insert to authenticated with check (
  public.row_ok(tab,project_id,data,true)
  or (tab='projects' and public.my_role()='project_manager' and public.can_do('projects',true)));
drop policy if exists rec_update on public.records;
create policy rec_update on public.records for update to authenticated
  using (public.row_ok(tab,project_id,data,true) and not (public.my_role()='client' and tab='approvals'))
  with check (public.row_ok(tab,project_id,data,true) and not (public.my_role()='client' and tab='approvals'));
drop policy if exists rec_delete on public.records;
create policy rec_delete on public.records for delete to authenticated
  using (public.row_ok(tab,project_id,data,true) and not (public.my_role()='client' and tab='approvals'));

-- who may see / change which tab (adjust later in Table Editor -> role_perms; re-running this file keeps your changes)
insert into public.role_perms(role,tab,can_read,can_write)
select role,tab,true,w from (
  select 'director'::text role, unnest(array['projects','co','schedule','clients','production','inventory','finance','procurement','capacity','trend','activity','assessments','attendance','jobs','materials','tax','meetings','designs','quotes','approvals','reminders']) tab, true w
  union all select 'project_manager', unnest(array['projects','co','schedule','clients','production','inventory','finance','procurement','capacity','trend','activity','assessments','attendance','jobs','materials','meetings','designs','quotes','reminders']), true
  union all select 'project_manager', unnest(array['tax','approvals']), false
  union all select 'site_manager', unnest(array['schedule','production','inventory','procurement','capacity','activity','assessments','attendance','jobs','materials','meetings','reminders']), true
  union all select 'site_manager', unnest(array['projects','co','designs']), false
  union all select 'procurement', unnest(array['materials','inventory','procurement','reminders']), true
  union all select 'secretary', unnest(array['projects','co','schedule','clients','production','inventory','finance','procurement','capacity','trend','activity','assessments','attendance','jobs','materials','tax','meetings','designs','quotes','approvals','reminders']), true
  union all select 'marketing_manager', unnest(array['clients','meetings','designs','quotes','reminders']), true
  union all select 'marketing_manager', unnest(array['schedule','approvals']), false
  union all select 'salesperson', unnest(array['clients','meetings','quotes','reminders']), true
  union all select 'owner', unnest(array['projects','co','schedule','clients','production','inventory','finance','procurement','capacity','trend','activity','assessments','attendance','jobs','materials','tax','meetings','designs','quotes','approvals','reminders']), true
  union all select 'designer', unnest(array['designs']), true
  union all select 'designer', unnest(array['jobs']), false
  union all select 'hr', unnest(array['attendance']), true
  union all select 'workforce', unnest(array['attendance']), true
  union all select 'workforce', unnest(array['production','schedule','jobs','designs']), false
  union all select 'client', unnest(array['projects','co','finance','designs','quotes']), false
  union all select 'client', unnest(array['approvals']), true
) x
on conflict (role,tab) do nothing;

-- names only (no emails) so everyone can see WHO entered a record; project names only for roles that handle materials
create or replace view public.directory as
  select id, coalesce(nullif(full_name,''), split_part(email,'@',1)) as name, role from public.profiles where active;
create or replace view public.project_names as
  select r.id, r.data->>'code' as code, r.data->>'name' as name from public.records r where r.tab='projects' and (
    (public.my_role() in ('director','hr','procurement','owner','secretary','marketing_manager','salesperson')
       and (public.can_do('materials',false) or public.can_do('attendance',false) or public.can_do('quotes',false) or public.can_do('designs',false) or public.my_role() in ('owner','secretary','director')))
    or (exists(select 1 from public.project_members m where m.project_id=r.id and m.user_id=auth.uid())
        and (public.can_do('attendance',false) or public.can_do('designs',false) or public.can_do('jobs',false))));
revoke all on public.directory, public.project_names from anon;
grant select on public.directory, public.project_names to authenticated;

-- private storage for design files and build instructions (images / PDF, 15 MB max), folder = project id
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('designs','designs',false,15728640,array['image/png','image/jpeg','image/webp','application/pdf'])
on conflict (id) do update set public=false, file_size_limit=excluded.file_size_limit, allowed_mime_types=excluded.allowed_mime_types;
-- file path = <tab>/<project id>/<file>; (older uploads used <project id>/<file> and still work)
drop policy if exists designs_read on storage.objects;
create policy designs_read on storage.objects for select to authenticated using (bucket_id='designs' and (public.my_role()='owner' or
  ((storage.foldername(name))[1] in ('jobs','designs') and public.can_do((storage.foldername(name))[1],false) and public.in_scope((storage.foldername(name))[1],(storage.foldername(name))[2]))
  or (array_length(storage.foldername(name),1)=1 and public.can_do('jobs',false) and public.in_scope('jobs',(storage.foldername(name))[1]))));
drop policy if exists designs_insert on storage.objects;
create policy designs_insert on storage.objects for insert to authenticated with check (bucket_id='designs' and (public.my_role()='owner' or
  ((storage.foldername(name))[1] in ('jobs','designs') and public.can_do((storage.foldername(name))[1],true) and public.in_scope((storage.foldername(name))[1],(storage.foldername(name))[2]))
  or (array_length(storage.foldername(name),1)=1 and public.can_do('jobs',true) and public.in_scope('jobs',(storage.foldername(name))[1]))));
drop policy if exists designs_delete on storage.objects;
create policy designs_delete on storage.objects for delete to authenticated using (bucket_id='designs' and (public.my_role()='owner' or
  ((storage.foldername(name))[1] in ('jobs','designs') and public.can_do((storage.foldername(name))[1],true) and public.in_scope((storage.foldername(name))[1],(storage.foldername(name))[2]))
  or (array_length(storage.foldername(name),1)=1 and public.can_do('jobs',true) and public.in_scope('jobs',(storage.foldername(name))[1]))));

-- merge the old "Material needs" list into the single Materials list (needs become type 'Needed'); safe to re-run
update public.records set tab='materials',
  data = (data - 'status' - 'needby') || jsonb_build_object('move', case when data->>'status'='Cancelled' then 'Cancelled' else 'Needed' end)
        || case when coalesce(data->>'needby','')<>'' then jsonb_build_object('date', data->>'needby') else '{}'::jsonb end
where tab='requirements';

-- the owner (emergency) account is protected: nobody can demote, deactivate or delete it from the app
create or replace function public.protect_owner() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if auth.uid() is null then return coalesce(new,old); end if;  -- SQL editor / dashboard
  if tg_op='DELETE' then if old.role='owner' then raise exception 'The owner account is protected'; end if; return old; end if;
  if new.role='owner' and old.role<>'owner' then raise exception 'The owner role can only be assigned in the SQL editor'; end if;
  if old.role='owner' and (new.role<>'owner' or new.active is not true) then raise exception 'The owner account cannot be demoted or deactivated here'; end if;
  return new; end $$;
drop trigger if exists profiles_protect_owner on public.profiles;
create trigger profiles_protect_owner before update or delete on public.profiles for each row execute function public.protect_owner();

-- triggers: auto-create a profile for every new login (no access until the director activates it)
-- people who sign in with just a name get a behind-the-scenes address ending @staff.touchdesigns.app
-- they need the company code to register, and always wait for approval (Active = No) before they see anything
create or replace function public.check_join_code() returns trigger language plpgsql security definer set search_path=public as
$$ declare c text; begin
  if new.email like '%@staff.touchdesigns.app' then
    select value into c from public.app_settings where key='join_code';
    if c is null or coalesce(new.raw_user_meta_data->>'join_code','')<>c then raise exception 'Invalid company code'; end if;
  end if; return new; end $$;
drop trigger if exists auth_check_join_code on auth.users;
create trigger auth_check_join_code before insert on auth.users for each row execute function public.check_join_code();

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  insert into public.profiles(id,email,full_name,role,active)
  select new.id,new.email,coalesce(nullif(i.full_name,''),coalesce(new.raw_user_meta_data->>'full_name','')),coalesce(i.role,'pending'),
         coalesce(i.active,false) and new.email not like '%@staff.touchdesigns.app'
  from (select 1) x left join public.invites i on lower(i.email)=lower(new.email) on conflict do nothing;
  return new; end $$;
-- applies the names / roles in "invites" to people who already have a login (name-only accounts keep their own Active setting)
create or replace function public.apply_invites() returns integer language sql security definer set search_path=public as
$$ with u as (update public.profiles p set role=i.role, full_name=coalesce(nullif(i.full_name,''),p.full_name),
                active=case when p.email like '%@staff.touchdesigns.app' then p.active else i.active end
              from public.invites i where lower(p.email)=lower(i.email)
              and (p.email not like '%@staff.touchdesigns.app' or not p.active) returning 1) select count(*)::int from u $$;
revoke execute on function public.apply_invites() from public, anon, authenticated;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
insert into public.profiles(id,email) select id,email from auth.users on conflict do nothing;

-- "entered by" cannot be forged: the server stamps who created a row and who last changed it
create or replace function public.stamp_row() returns trigger language plpgsql as
$$ begin new.created_by=auth.uid(); new.created_at=now(); return new; end $$;
drop trigger if exists records_stamp on public.records;
create trigger records_stamp before insert on public.records for each row execute function public.stamp_row();
create or replace function public.touch_row() returns trigger language plpgsql as
$$ begin new.created_by=old.created_by; new.created_at=old.created_at; new.updated_at=now(); new.updated_by=auth.uid(); return new; end $$;
drop trigger if exists records_touch on public.records;
create trigger records_touch before update on public.records for each row execute function public.touch_row();

-- every change to people and access is written to the audit log (who gave whom what)
create or replace function public.audit_admin() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  if tg_table_name='profiles' then
    if new.role is distinct from old.role or new.active is distinct from old.active or new.full_name is distinct from old.full_name then
      insert into public.audit_log(user_id,op,tab,row_id,old_data,new_data) values(auth.uid(),'UPDATE','profiles',new.id::text,
        jsonb_build_object('role',old.role,'active',old.active,'name',old.full_name),jsonb_build_object('role',new.role,'active',new.active,'name',new.full_name));
    end if;
  else
    insert into public.audit_log(user_id,op,tab,row_id,old_data,new_data) values(auth.uid(),tg_op,'project_members',coalesce(new.user_id,old.user_id)::text,
      case when tg_op='DELETE' then jsonb_build_object('project',old.project_id) end, case when tg_op='INSERT' then jsonb_build_object('project',new.project_id) end);
  end if; return null; end $$;
drop trigger if exists profiles_audit on public.profiles;
create trigger profiles_audit after update on public.profiles for each row execute function public.audit_admin();
drop trigger if exists members_audit on public.project_members;
create trigger members_audit after insert or delete on public.project_members for each row execute function public.audit_admin();

-- people added by a manager must choose their own password at first sign-in
create or replace function public.clear_must_change() returns void language sql security definer set search_path=public as
$$ update public.profiles set must_change=false where id=auth.uid() $$;
grant execute on function public.clear_must_change() to authenticated;

-- a project manager who creates a project is automatically assigned to it
create or replace function public.auto_member() returns trigger language plpgsql security definer set search_path=public as
$$ begin if new.tab='projects' and auth.uid() is not null and exists(select 1 from public.profiles where id=auth.uid() and role='project_manager') then
   insert into public.project_members(project_id,user_id) values(new.id,auth.uid()) on conflict do nothing; end if; return null; end $$;
drop trigger if exists records_automember on public.records;
create trigger records_automember after insert on public.records for each row execute function public.auto_member();

create or replace function public.audit_row() returns trigger language plpgsql security definer set search_path=public as
$$ begin insert into public.audit_log(user_id,op,tab,row_id,old_data,new_data)
   values(auth.uid(),TG_OP,coalesce(new.tab,old.tab),coalesce(new.id,old.id),
          case when TG_OP<>'INSERT' then old.data end, case when TG_OP<>'DELETE' then new.data end);
   return null; end $$;
drop trigger if exists records_audit on public.records;
create trigger records_audit after insert or update or delete on public.records for each row execute function public.audit_row();

-- NOTE: re-running this whole file after an update is safe; it keeps your data and any role_perms changes.

-- STEP 2b: EMERGENCY / OWNER ACCOUNT (bypasses every access rule; keep its password secret, in a password manager, never shared)
--   1. Supabase -> Authentication -> Users -> Add user: a separate login with a LONG unique passphrase, auto-confirm ticked.
--   2. Run (SQL Editor):  update public.profiles set role='owner', active=true, full_name='Owner' where email='owner@yourdomain.com';
--   3. If you are ever locked out: Supabase -> Authentication -> Users -> reset that password, or re-run step 2 for the account.
--
-- STEP 2 (after you create your own login in Authentication -> Users), make yourself director:
--   update public.profiles set role='director', active=true, full_name='Your Name' where email='you@company.com';

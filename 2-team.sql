-- Touch Designs Operations: first-time team setup. Run this AFTER 1-setup.sql.
-- DO NOT upload this file to GitHub.
--
-- Only the OWNER needs to be listed here. You create the owner's login once in Supabase
-- (Authentication -> Users -> Add user). Everyone else is added inside the app, by the owner, a director,
-- a secretary or a project manager, from Team & access -> Add user. No more SQL needed.

insert into public.invites(email, full_name, role) values
  ('mutitikaevans4@gmail.com', 'Evans Mwaniki (owner)', 'owner')
on conflict (email) do update set full_name = excluded.full_name, role = excluded.role, active = true;

select public.apply_invites();

-- The company code the app uses behind the scenes when people are added. Keep it private.
select value as company_code from public.app_settings where key = 'join_code';

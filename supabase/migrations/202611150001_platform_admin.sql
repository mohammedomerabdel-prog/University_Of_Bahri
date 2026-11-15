-- University Platform: isolated administration backend
-- This migration is intentionally separate from the existing results system.
-- Apply only to the NEW Supabase project: University Platform.

create extension if not exists pgcrypto;

create table if not exists public.platform_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  role text not null default 'editor'
    check (role in ('super_admin', 'manager', 'editor')),
  permissions jsonb not null default '{"content": true, "admins": false, "analytics": true}'::jsonb,
  is_active boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.platform_content (
  id uuid primary key default gen_random_uuid(),
  content_type text not null
    check (content_type in ('lecture','specialty','course','announcement','exam','assignment','notification','timetable','suggestion')),
  title text not null,
  body text not null default '',
  specialty text,
  course text,
  file_path text,
  external_url text,
  status text not null default 'draft' check (status in ('draft','published','archived')),
  published_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  updated_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists platform_content_type_status_idx
  on public.platform_content(content_type, status, created_at desc);

create table if not exists public.platform_audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null,
  table_name text not null,
  record_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists platform_audit_logs_created_idx
  on public.platform_audit_logs(created_at desc);

create or replace function public.is_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.platform_admins a
    where a.user_id = auth.uid()
      and a.is_active = true
      and a.role in ('super_admin','manager','editor')
  );
$$;

create or replace function public.is_platform_super_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.platform_admins a
    where a.user_id = auth.uid()
      and a.is_active = true
      and a.role = 'super_admin'
  );
$$;

create or replace function public.can_manage_platform_content()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.platform_admins a
    where a.user_id = auth.uid()
      and a.is_active = true
      and (
        a.role in ('super_admin','manager')
        or coalesce((a.permissions ->> 'content')::boolean, false)
      )
  );
$$;

create or replace function public.set_platform_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  if auth.uid() is not null then
    new.updated_by = auth.uid();
  end if;
  return new;
end;
$$;

drop trigger if exists platform_content_updated_at on public.platform_content;
create trigger platform_content_updated_at
before update on public.platform_content
for each row execute function public.set_platform_updated_at();

create or replace function public.log_platform_content_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  rid text;
  act text;
begin
  if tg_op = 'DELETE' then
    rid := old.id::text;
    act := 'delete';
  elsif tg_op = 'INSERT' then
    rid := new.id::text;
    act := 'insert';
  else
    rid := new.id::text;
    act := 'update';
  end if;

  insert into public.platform_audit_logs(actor_id, action, table_name, record_id, details)
  values (
    auth.uid(),
    act,
    tg_table_name,
    rid,
    jsonb_build_object('content_type', coalesce(new.content_type, old.content_type),
                       'title', coalesce(new.title, old.title))
  );

  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;

drop trigger if exists platform_content_audit on public.platform_content;
create trigger platform_content_audit
after insert or update or delete on public.platform_content
for each row execute function public.log_platform_content_change();

alter table public.platform_admins enable row level security;
alter table public.platform_content enable row level security;
alter table public.platform_audit_logs enable row level security;

drop policy if exists "admins read own profile or super admins read all" on public.platform_admins;
create policy "admins read own profile or super admins read all"
on public.platform_admins for select to authenticated
using (user_id = auth.uid() or public.is_platform_super_admin());

drop policy if exists "super admins create admin accounts" on public.platform_admins;
create policy "super admins create admin accounts"
on public.platform_admins for insert to authenticated
with check (public.is_platform_super_admin());

drop policy if exists "super admins update admin accounts" on public.platform_admins;
create policy "super admins update admin accounts"
on public.platform_admins for update to authenticated
using (public.is_platform_super_admin())
with check (public.is_platform_super_admin());

drop policy if exists "super admins delete admin accounts" on public.platform_admins;
create policy "super admins delete admin accounts"
on public.platform_admins for delete to authenticated
using (public.is_platform_super_admin());

drop policy if exists "public reads published platform content" on public.platform_content;
create policy "public reads published platform content"
on public.platform_content for select to anon, authenticated
using (status = 'published');

drop policy if exists "admins read all platform content" on public.platform_content;
create policy "admins read all platform content"
on public.platform_content for select to authenticated
using (public.is_platform_admin());

drop policy if exists "authorized admins create platform content" on public.platform_content;
create policy "authorized admins create platform content"
on public.platform_content for insert to authenticated
with check (public.can_manage_platform_content());

drop policy if exists "authorized admins update platform content" on public.platform_content;
create policy "authorized admins update platform content"
on public.platform_content for update to authenticated
using (public.can_manage_platform_content())
with check (public.can_manage_platform_content());

drop policy if exists "authorized admins delete platform content" on public.platform_content;
create policy "authorized admins delete platform content"
on public.platform_content for delete to authenticated
using (public.can_manage_platform_content());

drop policy if exists "super admins read audit logs" on public.platform_audit_logs;
create policy "super admins read audit logs"
on public.platform_audit_logs for select to authenticated
using (public.is_platform_super_admin());

-- Private bucket for lecture files and attachments. Files are never public by default.
insert into storage.buckets (id, name, public)
values ('platform-files', 'platform-files', false)
on conflict (id) do update set public = false;

drop policy if exists "admins read platform files" on storage.objects;
create policy "admins read platform files"
on storage.objects for select to authenticated
using (bucket_id = 'platform-files' and public.can_manage_platform_content());

drop policy if exists "admins upload platform files" on storage.objects;
create policy "admins upload platform files"
on storage.objects for insert to authenticated
with check (bucket_id = 'platform-files' and public.can_manage_platform_content());

drop policy if exists "admins update platform files" on storage.objects;
create policy "admins update platform files"
on storage.objects for update to authenticated
using (bucket_id = 'platform-files' and public.can_manage_platform_content())
with check (bucket_id = 'platform-files' and public.can_manage_platform_content());

drop policy if exists "admins delete platform files" on storage.objects;
create policy "admins delete platform files"
on storage.objects for delete to authenticated
using (bucket_id = 'platform-files' and public.can_manage_platform_content());

-- IMPORTANT: after creating the first Auth user in the NEW project, run this
-- once in the SQL editor, replacing the UUID with that user's Auth ID:
-- insert into public.platform_admins(user_id, display_name, role, permissions)
-- values ('YOUR-AUTH-USER-UUID', 'مدير المنصة', 'super_admin',
--         '{"content":true,"admins":true,"analytics":true}'::jsonb);

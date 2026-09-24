-- Modalità amministratore sicura per Max
-- Eseguire UNA VOLTA nel SQL Editor di Supabase.
-- Il PIN non viene mai salvato nel browser: nel database resta solo l'hash.
-- Dopo 5 PIN errati, l'accesso amministratore viene bloccato per 15 minuti.
-- Ogni attivazione vale 30 minuti ed è legata alla singola sessione Supabase.

create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;

grant usage on schema private to authenticated;

create table if not exists private.admin_security (
  user_id uuid primary key,
  pin_hash text not null,
  failed_attempts integer not null default 0,
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);

create table if not exists private.admin_sessions (
  user_id uuid not null,
  session_id text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  primary key (user_id, session_id)
);

revoke all on private.admin_security from public, anon, authenticated;
revoke all on private.admin_sessions from public, anon, authenticated;

-- =========================
-- FUNZIONI PRIVATE PROTETTE
-- =========================

create or replace function private.get_max_admin_status_impl()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_email text := auth.jwt() ->> 'email';
  v_session text := auth.jwt() ->> 'session_id';
  v_configured boolean := false;
  v_expires timestamptz;
  v_locked timestamptz;
begin
  if v_user is null or v_email <> 'maxsaabb@gmail.com' then
    return jsonb_build_object(
      'configured', false,
      'active', false,
      'expires_at', null,
      'locked_until', null
    );
  end if;

  select true, locked_until
    into v_configured, v_locked
  from private.admin_security
  where user_id = v_user;

  select expires_at
    into v_expires
  from private.admin_sessions
  where user_id = v_user
    and session_id = coalesce(v_session, '')
    and expires_at > now();

  return jsonb_build_object(
    'configured', coalesce(v_configured, false),
    'active', v_expires is not null,
    'expires_at', v_expires,
    'locked_until', v_locked
  );
end;
$$;

create or replace function private.setup_max_admin_pin_impl(p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_email text := auth.jwt() ->> 'email';
  v_session text := auth.jwt() ->> 'session_id';
  v_expires timestamptz := now() + interval '30 minutes';
begin
  if v_user is null or v_email <> 'maxsaabb@gmail.com' then
    return jsonb_build_object('ok', false, 'message', 'Utente non autorizzato.');
  end if;

  if v_session is null or v_session = '' then
    return jsonb_build_object('ok', false, 'message', 'Sessione non valida.');
  end if;

  if p_pin is null or p_pin !~ '^[0-9]{6}$' then
    return jsonb_build_object('ok', false, 'message', 'Il PIN deve contenere esattamente 6 cifre.');
  end if;

  if exists (select 1 from private.admin_security where user_id = v_user) then
    return jsonb_build_object('ok', false, 'message', 'PIN già configurato.');
  end if;

  insert into private.admin_security(user_id, pin_hash, failed_attempts, locked_until, updated_at)
  values (
    v_user,
    extensions.crypt(p_pin, extensions.gen_salt('bf', 10)),
    0,
    null,
    now()
  );

  insert into private.admin_sessions(user_id, session_id, expires_at, created_at)
  values (v_user, v_session, v_expires, now())
  on conflict (user_id, session_id)
  do update set expires_at = excluded.expires_at, created_at = now();

  return jsonb_build_object('ok', true, 'expires_at', v_expires);
end;
$$;

create or replace function private.enable_max_admin_impl(p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_email text := auth.jwt() ->> 'email';
  v_session text := auth.jwt() ->> 'session_id';
  v_pin_hash text;
  v_failed integer;
  v_locked timestamptz;
  v_new_failed integer;
  v_new_locked timestamptz;
  v_expires timestamptz := now() + interval '30 minutes';
begin
  if v_user is null or v_email <> 'maxsaabb@gmail.com' then
    return jsonb_build_object('ok', false, 'message', 'Utente non autorizzato.');
  end if;

  if v_session is null or v_session = '' then
    return jsonb_build_object('ok', false, 'message', 'Sessione non valida.');
  end if;

  select pin_hash, failed_attempts, locked_until
    into v_pin_hash, v_failed, v_locked
  from private.admin_security
  where user_id = v_user;

  if v_pin_hash is null then
    return jsonb_build_object('ok', false, 'message', 'PIN non ancora configurato.');
  end if;

  if v_locked is not null and v_locked > now() then
    return jsonb_build_object(
      'ok', false,
      'message', 'Accesso temporaneamente bloccato.',
      'locked_until', v_locked
    );
  end if;

  if extensions.crypt(coalesce(p_pin, ''), v_pin_hash) <> v_pin_hash then
    v_new_failed := coalesce(v_failed, 0) + 1;

    if v_new_failed >= 5 then
      v_new_locked := now() + interval '15 minutes';

      update private.admin_security
      set failed_attempts = 0,
          locked_until = v_new_locked,
          updated_at = now()
      where user_id = v_user;

      return jsonb_build_object(
        'ok', false,
        'message', 'Troppi tentativi errati.',
        'locked_until', v_new_locked
      );
    else
      update private.admin_security
      set failed_attempts = v_new_failed,
          locked_until = null,
          updated_at = now()
      where user_id = v_user;

      return jsonb_build_object(
        'ok', false,
        'message', 'PIN amministratore non corretto.'
      );
    end if;
  end if;

  update private.admin_security
  set failed_attempts = 0,
      locked_until = null,
      updated_at = now()
  where user_id = v_user;

  insert into private.admin_sessions(user_id, session_id, expires_at, created_at)
  values (v_user, v_session, v_expires, now())
  on conflict (user_id, session_id)
  do update set expires_at = excluded.expires_at, created_at = now();

  return jsonb_build_object('ok', true, 'expires_at', v_expires);
end;
$$;

create or replace function private.disable_max_admin_impl()
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_email text := auth.jwt() ->> 'email';
  v_session text := auth.jwt() ->> 'session_id';
begin
  if v_user is null or v_email <> 'maxsaabb@gmail.com' then
    return;
  end if;

  delete from private.admin_sessions
  where user_id = v_user
    and session_id = coalesce(v_session, '');
end;
$$;

create or replace function private.is_max_admin_active()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    auth.uid() is not null
    and (auth.jwt() ->> 'email') = 'maxsaabb@gmail.com'
    and exists (
      select 1
      from private.admin_sessions s
      where s.user_id = auth.uid()
        and s.session_id = coalesce(auth.jwt() ->> 'session_id', '')
        and s.expires_at > now()
    );
$$;

revoke all on function private.get_max_admin_status_impl() from public;
revoke all on function private.setup_max_admin_pin_impl(text) from public;
revoke all on function private.enable_max_admin_impl(text) from public;
revoke all on function private.disable_max_admin_impl() from public;
revoke all on function private.is_max_admin_active() from public;

grant execute on function private.get_max_admin_status_impl() to authenticated;
grant execute on function private.setup_max_admin_pin_impl(text) to authenticated;
grant execute on function private.enable_max_admin_impl(text) to authenticated;
grant execute on function private.disable_max_admin_impl() to authenticated;
grant execute on function private.is_max_admin_active() to authenticated;

-- ========================================
-- WRAPPER RPC PUBBLICI (SECURITY INVOKER)
-- ========================================

create or replace function public.get_max_admin_status()
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select private.get_max_admin_status_impl();
$$;

create or replace function public.setup_max_admin_pin(p_pin text)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select private.setup_max_admin_pin_impl(p_pin);
$$;

create or replace function public.enable_max_admin(p_pin text)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select private.enable_max_admin_impl(p_pin);
$$;

create or replace function public.disable_max_admin()
returns void
language sql
security invoker
set search_path = ''
as $$
  select private.disable_max_admin_impl();
$$;

revoke all on function public.get_max_admin_status() from public;
revoke all on function public.setup_max_admin_pin(text) from public;
revoke all on function public.enable_max_admin(text) from public;
revoke all on function public.disable_max_admin() from public;

grant execute on function public.get_max_admin_status() to authenticated;
grant execute on function public.setup_max_admin_pin(text) to authenticated;
grant execute on function public.enable_max_admin(text) to authenticated;
grant execute on function public.disable_max_admin() to authenticated;

-- =====================================================
-- RLS: MAX SCRIVE SOLO CON SESSIONE ADMIN TEMPORANEA
-- Le policy di Olga esistenti rimangono invariate.
-- =====================================================

drop policy if exists "max_admin_insert" on public.lessons;
drop policy if exists "max_admin_update" on public.lessons;
drop policy if exists "max_admin_delete" on public.lessons;

create policy "max_admin_insert"
on public.lessons
for insert
to authenticated
with check ((select private.is_max_admin_active()));

create policy "max_admin_update"
on public.lessons
for update
to authenticated
using ((select private.is_max_admin_active()))
with check ((select private.is_max_admin_active()));

create policy "max_admin_delete"
on public.lessons
for delete
to authenticated
using ((select private.is_max_admin_active()));

-- =====================================================================
-- ACEH PASS: skema PostgreSQL (pengganti Google Sheets di Code.gs)
-- Versi PostgreSQL 13 ke atas. Berjalan di PostgreSQL biasa maupun Supabase.
--
-- Isi:
--   1. Tabel: tiket, masukan (kritik/saran/kesan/pesan), log validasi,
--             akun staf, sesi login, pengaturan
--   2. Fungsi yang meniru aksi server di Code.gs:
--        register_ticket, ticket_status, submit_feedback, staff_login, staff_logout,
--        redeem_ticket (atomik), staff_snapshot, mark_feedback_read, mark_all_feedback_read,
--        delete_feedback, reset_all
--   3. Keamanan: RLS aktif, tabel tidak bisa diakses langsung, hanya lewat fungsi
--
-- CARA PAKAI:
--   1. Jalankan seluruh file ini sekali (psql -f aceh-pass.sql, atau SQL Editor Supabase).
--   2. WAJIB ganti sandi bawaan (bagian paling bawah file ini).
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- 1. TABEL
-- ---------------------------------------------------------------------

create table if not exists app_settings (
  key   text primary key,
  value text not null
);
insert into app_settings (key, value) values
  ('ticket_ttl_min', '30'),   -- masa berlaku tiket (menit), sama dengan aplikasi web
  ('session_hours',  '6')     -- lama sesi login staf (jam)
on conflict (key) do nothing;

create table if not exists tickets (
  ticket_number text primary key
    check (ticket_number ~ '^AP-[0-9]{4}-[0-9]{6}$'),
  visitor_id    text not null
    check (visitor_id ~ '^[0-9a-fA-F-]{8,40}$'),
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,            -- diisi otomatis oleh trigger
  status        text not null default 'ACTIVE'
    check (status in ('ACTIVE', 'USED')),
  checked_in_at timestamptz,
  officer       text,
  check ((status = 'USED') = (checked_in_at is not null))
);
create index if not exists tickets_created_idx on tickets (created_at);
create index if not exists tickets_status_idx  on tickets (status);

create table if not exists feedbacks (
  id            text primary key
    check (id ~ '^[A-Za-z0-9_-]{8,64}$'),
  type          text not null
    check (type in ('KRITIK', 'SARAN', 'KESAN', 'PESAN')),
  name          text not null default 'Anonim'
    check (char_length(name) between 1 and 50),
  rating        smallint check (rating between 1 and 5),
  message       text not null
    check (char_length(message) between 5 and 500),
  ticket_number text check (ticket_number ~ '^AP-[0-9]{4}-[0-9]{6}$'),
  created_at    timestamptz not null default now(),
  is_read       boolean not null default false
);
create index if not exists feedbacks_created_idx on feedbacks (created_at desc);

create table if not exists validation_logs (
  id            uuid primary key default gen_random_uuid(),
  ticket_number text not null,
  status_result text not null
    check (status_result in ('SUCCESS', 'ALREADY_USED', 'EXPIRED', 'INVALID')),
  scanned_at    timestamptz not null default now(),
  officer       text not null
);
create index if not exists logs_scanned_idx on validation_logs (scanned_at desc);

create table if not exists staff_users (
  username      text primary key check (username in ('admin', 'petugas')),
  role          text not null check (role in ('ADMIN', 'OFFICER')),
  password_hash text not null
);

create table if not exists staff_sessions (
  token_hash text primary key,
  role       text not null check (role in ('ADMIN', 'OFFICER')),
  name       text not null,
  expires_at timestamptz not null
);
create index if not exists sessions_exp_idx on staff_sessions (expires_at);

create table if not exists login_failures (
  id bigserial primary key,
  at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 2. FUNGSI BANTU (internal)
-- ---------------------------------------------------------------------

create or replace function _ttl() returns interval
language sql stable as $$
  select make_interval(mins => coalesce((select value::int from app_settings where key = 'ticket_ttl_min'), 30));
$$;

-- Format waktu ISO-8601 UTC, sama dengan toISOString() di JavaScript
create or replace function _iso(ts timestamptz) returns text
language sql immutable as $$
  select case when ts is null then null
         else to_char(ts at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') end;
$$;

-- Waktu dari perangkat tamu dibatasi: tidak boleh lebih dari 10 menit di masa depan atau 3 hari ke belakang
create or replace function _clamp_ts(ts timestamptz) returns timestamptz
language sql stable as $$
  select case when ts is null or ts > now() + interval '10 minutes' or ts < now() - interval '3 days'
         then now() else ts end;
$$;

create or replace function _tickets_set_expiry() returns trigger
language plpgsql as $$
begin
  new.expires_at := new.created_at + _ttl();
  return new;
end;
$$;
drop trigger if exists trg_tickets_expiry on tickets;
create trigger trg_tickets_expiry before insert on tickets
  for each row execute function _tickets_set_expiry();

-- Memeriksa token sesi staf; mengembalikan baris sesi atau NULL
create or replace function _session(p_token text) returns staff_sessions
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare s staff_sessions;
begin
  if p_token is null or p_token = '' then return null; end if;
  select * into s from staff_sessions
   where token_hash = encode(digest(p_token, 'sha256'), 'hex') and expires_at > now();
  if not found then return null; end if;
  return s;
end;
$$;

create or replace function _log(p_num text, p_status text, p_officer text) returns void
language sql as $$
  insert into validation_logs (ticket_number, status_result, officer)
  values (coalesce(nullif(left(p_num, 20), ''), 'UNKNOWN'), p_status, p_officer);
$$;

-- ---------------------------------------------------------------------
-- 3. AKSI PUBLIK (dari HP tamu)
-- ---------------------------------------------------------------------

create or replace function register_ticket(
  p_ticket_number text, p_visitor_id text, p_created_at timestamptz default now()
) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare num text := upper(btrim(coalesce(p_ticket_number, '')));
begin
  if num !~ '^AP-[0-9]{4}-[0-9]{6}$' or coalesce(p_visitor_id, '') !~ '^[0-9a-fA-F-]{8,40}$' then
    return jsonb_build_object('ok', false, 'error', 'INVALID');
  end if;
  -- pembatas laju: maksimal 600 tiket baru per menit
  if (select count(*) from tickets where created_at > now() - interval '1 minute') >= 600 then
    return jsonb_build_object('ok', false, 'error', 'RATE_LIMIT');
  end if;
  insert into tickets (ticket_number, visitor_id, created_at)
  values (num, p_visitor_id, _clamp_ts(p_created_at))
  on conflict (ticket_number) do nothing;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function ticket_status(p_ticket_number text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions, pg_temp as $$
declare t tickets; num text := upper(btrim(coalesce(p_ticket_number, '')));
begin
  select * into t from tickets where ticket_number = num;
  if not found then return jsonb_build_object('ok', true, 'status', 'UNKNOWN'); end if;
  if t.status = 'USED' then
    return jsonb_build_object('ok', true, 'status', 'USED', 'checked_in_at', _iso(t.checked_in_at));
  end if;
  return jsonb_build_object('ok', true, 'status', case when now() >= t.expires_at then 'EXPIRED' else 'ACTIVE' end);
end;
$$;

create or replace function submit_feedback(
  p_id text, p_type text, p_name text, p_rating int, p_message text,
  p_ticket_number text default null, p_created_at timestamptz default now()
) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  msg  text := btrim(coalesce(p_message, ''));
  nm   text := left(coalesce(nullif(btrim(coalesce(p_name, '')), ''), 'Anonim'), 50);
  tick text := case when coalesce(p_ticket_number, '') ~ '^AP-[0-9]{4}-[0-9]{6}$' then p_ticket_number else null end;
  rate smallint := case when p_rating between 1 and 5 then p_rating::smallint else null end;
begin
  if coalesce(p_id, '') !~ '^[A-Za-z0-9_-]{8,64}$'
     or p_type not in ('KRITIK', 'SARAN', 'KESAN', 'PESAN')
     or char_length(msg) not between 5 and 500 then
    return jsonb_build_object('ok', false, 'error', 'INVALID');
  end if;
  if (select count(*) from feedbacks where created_at > now() - interval '1 minute') >= 120 then
    return jsonb_build_object('ok', false, 'error', 'RATE_LIMIT');
  end if;
  insert into feedbacks (id, type, name, rating, message, ticket_number, created_at)
  values (p_id, p_type, nm, rate, msg, tick, _clamp_ts(p_created_at))
  on conflict (id) do nothing;
  return jsonb_build_object('ok', true);
end;
$$;

-- ---------------------------------------------------------------------
-- 4. LOGIN STAF
--    Nama pengguna "petugas" + sandi petugas  => OFFICER
--    Nama pengguna apa saja + sandi admin     => ADMIN (nama tampil = yang diketik)
-- ---------------------------------------------------------------------

create or replace function staff_login(p_username text, p_password text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  typed text := left(btrim(coalesce(p_username, '')), 30);
  u staff_users;
  r text; n text; tok text; hrs int;
begin
  delete from login_failures where at < now() - interval '1 minute';
  if (select count(*) from login_failures) >= 10 then
    return jsonb_build_object('ok', false, 'error', 'LOCKED', 'message', 'Terlalu banyak percobaan. Coba lagi 1 menit lagi.');
  end if;

  if lower(typed) = 'petugas' then
    select * into u from staff_users where username = 'petugas';
    if found and u.password_hash = crypt(coalesce(p_password, ''), u.password_hash) then
      r := 'OFFICER'; n := 'Petugas Gate';
    end if;
  else
    select * into u from staff_users where username = 'admin';
    if found and u.password_hash = crypt(coalesce(p_password, ''), u.password_hash) then
      r := 'ADMIN'; n := coalesce(nullif(typed, ''), 'Panitia');
    end if;
  end if;

  if r is null then
    insert into login_failures default values;
    return jsonb_build_object('ok', false, 'error', 'BAD_LOGIN', 'message', 'Nama pengguna atau kata sandi salah.');
  end if;

  delete from login_failures;
  delete from staff_sessions where expires_at < now();
  hrs := least(6, greatest(1, coalesce((select value::int from app_settings where key = 'session_hours'), 6)));
  tok := encode(gen_random_bytes(32), 'hex');
  insert into staff_sessions (token_hash, role, name, expires_at)
  values (encode(digest(tok, 'sha256'), 'hex'), r, n, now() + make_interval(hours => hrs));
  return jsonb_build_object('ok', true, 'token', tok, 'role', r, 'name', n);
end;
$$;

create or replace function staff_logout(p_token text) returns jsonb
language sql security definer set search_path = public, extensions, pg_temp as $$
  with d as (delete from staff_sessions where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex'))
  select jsonb_build_object('ok', true);
$$;

-- ---------------------------------------------------------------------
-- 5. AKSI STAF
-- ---------------------------------------------------------------------

-- Validasi + penandaan USED secara atomik. Baris tiket dikunci (FOR UPDATE), sehingga
-- dua petugas yang memindai tiket yang sama bersamaan tidak akan lolos dua kali.
create or replace function redeem_ticket(
  p_token text, p_ticket_number text, p_officer text default null,
  p_created_ms bigint default null, p_visitor_id text default null, p_manual boolean default false
) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  s staff_sessions := _session(p_token);
  t tickets;
  num text := upper(btrim(coalesce(p_ticket_number, '')));
  v_officer text;
  created timestamptz;
begin
  if s is null then return jsonb_build_object('ok', false, 'error', 'AUTH'); end if;
  v_officer := left(coalesce(nullif(p_officer, ''), s.name, 'PETUGAS'), 40);

  if num !~ '^AP-[0-9]{4}-[0-9]{6}$' then
    perform _log(num, 'INVALID', v_officer);
    return jsonb_build_object('ok', true, 'status', 'INVALID', 'ticket_number', coalesce(nullif(left(num, 20), ''), 'UNKNOWN'));
  end if;

  select * into t from tickets where ticket_number = num for update;
  if not found then
    -- Tiket sah (tanda tangan QR sudah dicek di aplikasi) yang belum sempat terkirim dari HP tamu
    if coalesce(p_manual, false) or p_created_ms is null or coalesce(p_visitor_id, '') !~ '^[0-9a-fA-F-]{8,40}$' then
      perform _log(num, 'INVALID', v_officer);
      return jsonb_build_object('ok', true, 'status', 'INVALID', 'ticket_number', num);
    end if;
    created := to_timestamp(p_created_ms / 1000.0);
    if created > now() + interval '10 minutes' or created < now() - interval '3 days' then
      perform _log(num, 'INVALID', v_officer);
      return jsonb_build_object('ok', true, 'status', 'INVALID', 'ticket_number', num);
    end if;
    insert into tickets (ticket_number, visitor_id, created_at) values (num, p_visitor_id, created)
    on conflict (ticket_number) do nothing;
    select * into t from tickets where ticket_number = num for update;   -- menunggu bila ada permintaan paralel
  end if;

  if t.status = 'USED' then
    perform _log(num, 'ALREADY_USED', v_officer);
    return jsonb_build_object('ok', true, 'status', 'ALREADY_USED', 'ticket_number', num,
      'visitor_id', t.visitor_id, 'checked_in_at', _iso(t.checked_in_at), 'expires_at', _iso(t.expires_at));
  end if;

  if now() >= t.expires_at then
    perform _log(num, 'EXPIRED', v_officer);
    return jsonb_build_object('ok', true, 'status', 'EXPIRED', 'ticket_number', num,
      'visitor_id', t.visitor_id, 'expires_at', _iso(t.expires_at));
  end if;

  update tickets set status = 'USED', checked_in_at = now(), officer = v_officer
   where ticket_number = num returning * into t;
  perform _log(num, 'SUCCESS', v_officer);
  return jsonb_build_object('ok', true, 'status', 'SUCCESS', 'ticket_number', num,
    'visitor_id', t.visitor_id, 'checked_in_at', _iso(t.checked_in_at), 'expires_at', _iso(t.expires_at));
end;
$$;

create or replace function staff_snapshot(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions, pg_temp as $$
declare s staff_sessions := _session(p_token);
begin
  if s is null then return jsonb_build_object('ok', false, 'error', 'AUTH'); end if;
  return jsonb_build_object(
    'ok', true,
    'tickets', coalesce((
      select jsonb_agg(jsonb_build_object(
        'ticket_number', ticket_number, 'visitor_id', visitor_id, 'created_at', _iso(created_at),
        'status', status, 'checked_in_at', _iso(checked_in_at), 'officer', officer) order by created_at)
      from tickets), '[]'::jsonb),
    'feedbacks', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', id, 'type', type, 'name', name, 'rating', rating, 'message', message,
        'ticket_number', ticket_number, 'created_at', _iso(created_at), 'is_read', is_read) order by created_at desc)
      from feedbacks), '[]'::jsonb),
    'logs', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', id, 'ticket_number', ticket_number, 'status_result', status_result,
        'scanned_at', _iso(scanned_at), 'officer_id', officer) order by scanned_at desc)
      from (select * from validation_logs order by scanned_at desc limit 300) l), '[]'::jsonb),
    'server_time', _iso(now())
  );
end;
$$;

create or replace function mark_feedback_read(p_token text, p_id text, p_read boolean default true) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
begin
  if _session(p_token) is null then return jsonb_build_object('ok', false, 'error', 'AUTH'); end if;
  update feedbacks set is_read = coalesce(p_read, true) where id = p_id;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function mark_all_feedback_read(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
begin
  if _session(p_token) is null then return jsonb_build_object('ok', false, 'error', 'AUTH'); end if;
  update feedbacks set is_read = true where not is_read;
  return jsonb_build_object('ok', true);
end;
$$;

-- Khusus ADMIN
create or replace function delete_feedback(p_token text, p_id text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare s staff_sessions := _session(p_token);
begin
  if s is null then return jsonb_build_object('ok', false, 'error', 'AUTH'); end if;
  if s.role <> 'ADMIN' then return jsonb_build_object('ok', false, 'error', 'FORBIDDEN'); end if;
  delete from feedbacks where id = p_id;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function reset_all(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare s staff_sessions := _session(p_token);
begin
  if s is null then return jsonb_build_object('ok', false, 'error', 'AUTH'); end if;
  if s.role <> 'ADMIN' then return jsonb_build_object('ok', false, 'error', 'FORBIDDEN'); end if;
  delete from validation_logs;
  delete from feedbacks;
  delete from tickets;
  return jsonb_build_object('ok', true);
end;
$$;

-- ---------------------------------------------------------------------
-- 6. KEAMANAN: tabel tertutup, hanya fungsi yang bisa dipanggil
-- ---------------------------------------------------------------------

alter table app_settings    enable row level security;
alter table tickets         enable row level security;
alter table feedbacks       enable row level security;
alter table validation_logs enable row level security;
alter table staff_users     enable row level security;
alter table staff_sessions  enable row level security;
alter table login_failures  enable row level security;

revoke all on all tables    in schema public from public;
revoke all on all sequences in schema public from public;
revoke execute on all functions in schema public from public;

-- Fungsi yang boleh dipanggil dari web (tanpa login):
--   register_ticket, ticket_status, submit_feedback, staff_login, staff_logout
-- Fungsi staf (redeem_ticket, staff_snapshot, dst.) tetap memeriksa token sendiri.
-- Pada Supabase, role pemanggil dari web adalah "anon":
--
-- grant execute on function
--   register_ticket(text, text, timestamptz),
--   ticket_status(text),
--   submit_feedback(text, text, text, int, text, text, timestamptz),
--   staff_login(text, text),
--   staff_logout(text),
--   redeem_ticket(text, text, text, bigint, text, boolean),
--   staff_snapshot(text),
--   mark_feedback_read(text, text, boolean),
--   mark_all_feedback_read(text),
--   delete_feedback(text, text),
--   reset_all(text)
-- to anon;

-- ---------------------------------------------------------------------
-- 7. SANDI STAF  (WAJIB DIGANTI sebelum acara)
-- ---------------------------------------------------------------------

create or replace function set_staff_password(p_username text, p_password text) returns void
language plpgsql as $$
begin
  if p_username not in ('admin', 'petugas') then raise exception 'Akun harus admin atau petugas'; end if;
  if char_length(coalesce(p_password, '')) < 8 then raise exception 'Sandi minimal 8 karakter'; end if;
  insert into staff_users (username, role, password_hash)
  values (p_username, case when p_username = 'admin' then 'ADMIN' else 'OFFICER' end,
          crypt(p_password, gen_salt('bf', 10)))
  on conflict (username) do update set password_hash = excluded.password_hash;
end;
$$;
revoke execute on function set_staff_password(text, text) from public;

-- Jalankan dua baris ini dengan sandi Anda sendiri (jangan simpan sandi di file):
-- select set_staff_password('admin',   'GANTI-SANDI-ADMIN-ANDA');
-- select set_staff_password('petugas', 'GANTI-SANDI-PETUGAS-ANDA');

-- Limit the "Send a test" button: one test notification per person per minute.
-- Only the send-reminders function (service role) can read or write this table.

create table public.push_test_log (
  user_id uuid primary key references auth.users(id) on delete cascade,
  last_test_at timestamptz not null default now()
);
alter table public.push_test_log enable row level security;   -- no policies: the public and logged-in keys get nothing
revoke all on public.push_test_log from anon, authenticated;

-- Returns true and records the time if this person may send a test now,
-- false if their last test was under a minute ago. One statement, so two
-- presses at the same moment can't both get through.
create function public.claim_push_test(uid uuid) returns boolean
language sql security definer set search_path = '' as $$
  with claimed as (
    insert into public.push_test_log as l (user_id, last_test_at) values (uid, pg_catalog.now())
    on conflict (user_id) do update set last_test_at = pg_catalog.now()
      where l.last_test_at < pg_catalog.now() - interval '1 minute'
    returning 1
  )
  select exists (select 1 from claimed);
$$;
revoke execute on function public.claim_push_test(uuid) from public, anon, authenticated;

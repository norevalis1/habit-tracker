# Secrets and paid services

This is a static site served from GitHub Pages. Anything in this repo, and
anything the page loads, can be read by anyone. So:

- Never put a secret key in this repo or in any file the site serves:
  no Supabase secret/service_role key, no Google, OpenAI, Anthropic, Stripe,
  GitHub, Cloudflare or AWS key. The Supabase publishable (anon) key is the
  only key allowed in the page; it is meant to be public.
- Don't read, create, print or copy `.env` files or other key files. If a
  task seems to need a secret, stop and ask the owner. Secrets live in
  Supabase function secrets or the provider's dashboard.
- Never call a paid API (AI models, maps, email, payments) straight from the
  browser. It goes through a server-side function holding the key, with a
  usage limit.
- Ask the owner before adding any paid service or new API key, and say which
  spending cap or quota will limit it.
- Before every commit, check the staged diff for anything shaped like a key
  (`sk-`, `sb_secret_`, `AIza`, `ghp_`, `AKIA`, `-----BEGIN ... PRIVATE KEY`).
  Never use `git add -A` / `git add .` without reviewing what it picked up.
- If a key is ever committed or published, tell the owner right away: the key
  must be revoked in the provider's dashboard. Deleting the file is not enough.

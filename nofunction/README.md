# nofunction deployment notes (Vercel + Netlify)

You are correct: redirect mode exposes your backend URL in the browser address bar.
This update switches back to **reverse proxy mode** so your Vercel/Netlify URL stays visible.

## What these files now do

- `vercel.json` uses catch-all `rewrites`.
- `netlify.toml` uses catch-all proxy redirect with `status = 200`.

Both keep the public URL as:

- `https://<your-site>.vercel.app/...`
- `https://<your-site>.netlify.app/...`

and proxy traffic to your backend in the background.

## Why you still saw Forbidden earlier

Your logs already showed route matching works:

- `[ROUTE] optional prefix matched prefix=tr/cl ...`

Then backend denied on CF checks:

- `[CF] missing headers ...`

That means path forwarding is correct, but backend validation expects Cloudflare-specific headers that may not exist when request comes through Vercel/Netlify proxy chain.

## Practical fix to apply in backend (`server.js` on Railway)

Keep proxy rewrite mode here, and relax the CF-header gate for trusted proxy traffic, e.g.:

- Accept `x-forwarded-for`/`x-real-ip` when `cf-connecting-ip` is missing.
- Make strict CF-header requirement optional via env flag.
- Apply strict CF checks only when request is actually from Cloudflare.

## Important: set backend host

Replace `https://YOUR_BACKEND_HOST` in both files with your real Railway/API host (no trailing slash).

## New default behavior for `REQUIRE_CF_HEADERS=true`

Backend now allows trusted Vercel/Netlify proxy requests even when Cloudflare headers are absent, as long as platform identity headers are present:

- Vercel: `x-vercel-id` or `x-vercel-proxy-signature`
- Netlify: `x-nf-request-id`
- plus forwarded IP (`x-forwarded-for` or `x-real-ip`)

Control this with:

- `ALLOW_NON_CF_PROXY_HEADERS=true` (default, supports legacy `REQUIRE_CF_HEADERS_ALLOW_PLATFORM_PROXY`)

Set it to `false` if you want hard Cloudflare-only enforcement in every environment.


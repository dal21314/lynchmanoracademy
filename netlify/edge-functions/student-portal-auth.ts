// Lynch Manor Academy — Student Portal authentication gate.
//
// Intercepts /students and /students/* . Renders a branded login form when
// there is no valid session, validates the family password server-side, sets
// an HttpOnly session cookie on success, and supports /students/logout.
//
// SETUP (for David):
//   Netlify dashboard → Site configuration → Environment variables
//     Key:   STUDENT_PORTAL_PASSWORD
//     Value: <a strong shared family password>
//   Then trigger a redeploy.
//
// Notes:
//   • Runs on Netlify Edge (Deno). Web Crypto (crypto.subtle) is built in.
//   • The cookie stores SHA-256(password + salt), never the password itself.
//   • Session lasts 7 days; cookie is HttpOnly, Secure, SameSite=Strict.

import type { Context } from "https://edge.netlify.com";

const COOKIE_NAME = "lma_portal";
const SESSION_DAYS = 7;
// Salt is combined with the secret password before hashing. Public by design —
// it only matters in combination with the env-var password.
const SALT = "lynch-manor-academy::scientia-virtus-lumen::v1";

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Constant-time string comparison to avoid leaking match progress via timing.
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export default async (request: Request, context: Context) => {
  const url = new URL(request.url);
  const password = Deno.env.get("STUDENT_PORTAL_PASSWORD") ?? "";
  const expectedToken = password ? await sha256Hex(password + SALT) : "";

  // ---- Logout ---------------------------------------------------------------
  if (url.pathname === "/students/logout") {
    const headers = new Headers();
    headers.append(
      "Set-Cookie",
      `${COOKIE_NAME}=; Path=/students; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
    );
    headers.set("Location", "/?signed_out=1");
    return new Response(null, { status: 302, headers });
  }

  // ---- Already authenticated? -----------------------------------------------
  const existing = context.cookies.get(COOKIE_NAME) ?? "";
  if (expectedToken && existing && safeEqual(existing, expectedToken)) {
    return context.next();
  }

  // ---- Login attempt (POST) -------------------------------------------------
  if (request.method === "POST") {
    let submitted = "";
    try {
      const form = await request.formData();
      submitted = String(form.get("password") ?? "");
    } catch {
      submitted = "";
    }

    if (
      expectedToken &&
      safeEqual(await sha256Hex(submitted + SALT), expectedToken)
    ) {
      const headers = new Headers();
      const maxAge = SESSION_DAYS * 24 * 60 * 60;
      headers.append(
        "Set-Cookie",
        `${COOKIE_NAME}=${expectedToken}; Path=/students; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`,
      );
      headers.set("Location", "/students");
      return new Response(null, { status: 302, headers });
    }

    return new Response(loginPage({ error: true }), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // ---- No session → show the login form -------------------------------------
  return new Response(loginPage({ error: false }), {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
};

export const config = { path: ["/students", "/students/*"] };

// -----------------------------------------------------------------------------
// Branded login page (matches the Lynch Manor Academy landing page).
// -----------------------------------------------------------------------------
function loginPage({ error }: { error: boolean }): string {
  const errorBlock = error
    ? `<p class="err" id="pw-error" role="alert">That password didn&rsquo;t match. Please try again.</p>`
    : "";
  const describedBy = error ? ` aria-describedby="pw-error"` : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Student Portal · Lynch Manor Academy</title>
<meta name="robots" content="noindex, nofollow">
<link rel="icon" type="image/png" sizes="any" href="/assets/favicon-32.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;500;600&family=Cormorant+Garamond:ital@0;1&family=Nunito:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{
    --navy:#18243f; --navy-2:#1f2a44; --navy-line:#2d3a5c;
    --accent:#e9b464; --accent-quiet:#af8543;
    --ink:#e9ecf2; --ink-dim:#a9b0be; --ink-quiet:#b0b6c2; --on-accent:#1a1300;
    --serif:'Cinzel','Times New Roman',serif;
    --serif-body:'Cormorant Garamond',Georgia,serif;
    --sans:'Nunito',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  }
  *{box-sizing:border-box;}
  html,body{margin:0;height:100%;}
  body{
    background:var(--navy); color:var(--ink); font-family:var(--sans);
    min-height:100%; display:flex; align-items:center; justify-content:center;
    padding:32px 20px; -webkit-font-smoothing:antialiased;
    background-image:
      radial-gradient(ellipse at 50% 0%, rgba(233,180,100,0.06) 0%, transparent 55%),
      radial-gradient(ellipse at 50% 100%, rgba(0,0,0,0.4) 0%, transparent 60%);
    background-attachment:fixed;
  }
  ::selection{background:var(--accent);color:var(--on-accent);}
  .card{
    width:100%; max-width:420px; background:linear-gradient(180deg,var(--navy-2),#1a253f);
    border:1px solid var(--navy-line); border-radius:6px; padding:48px 44px 40px;
    text-align:center; position:relative;
    box-shadow:0 30px 60px rgba(0,0,0,0.45);
  }
  .card::before{content:"";position:absolute;top:-1px;left:40px;right:40px;height:2px;background:var(--accent);opacity:0.85;}
  .crest{width:80px;height:80px;display:block;margin:0 auto 22px;filter:drop-shadow(0 12px 20px rgba(0,0,0,0.45));}
  .kicker{font-family:var(--serif);font-size:11px;letter-spacing:0.26em;text-transform:uppercase;color:var(--accent);font-weight:500;margin:0 0 10px;}
  h1{font-family:var(--serif);font-weight:500;font-size:27px;letter-spacing:0.05em;color:var(--ink);margin:0 0 14px;}
  .instruction{font-size:14px;color:var(--ink-dim);line-height:1.5;margin:0 0 26px;}
  form{display:flex;flex-direction:column;gap:14px;text-align:left;}
  label{font-family:var(--sans);font-size:11px;letter-spacing:0.18em;text-transform:uppercase;color:var(--ink-quiet);font-weight:600;}
  input[type=password]{
    width:100%; font-family:var(--sans); font-size:17px; color:var(--ink);
    background:rgba(13,20,36,0.7); border:1px solid var(--navy-line); border-radius:4px;
    padding:13px 15px; outline:none; transition:border-color 160ms ease, box-shadow 160ms ease;
  }
  input[type=password]:focus{border-color:var(--accent-quiet);box-shadow:0 0 0 3px rgba(233,180,100,0.16);}
  .err{color:#e6a07a;font-size:13.5px;margin:-4px 0 0;font-family:var(--serif-body);font-style:italic;font-size:15px;}
  button{
    margin-top:6px; font-family:var(--serif); font-weight:600; font-size:14px; letter-spacing:0.22em;
    text-transform:uppercase; color:var(--on-accent); background:var(--accent); border:0; border-radius:4px;
    padding:14px; cursor:pointer; transition:background 160ms ease, transform 120ms ease;
  }
  button:hover{background:#f0c178;}
  button:active{transform:translateY(1px);}
  button[disabled]{opacity:0.7;cursor:default;}
  .foot{margin-top:24px;font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--ink-quiet);line-height:1.7;}
  .foot .sep{color:var(--accent-quiet);}
  a.back{display:inline-block;margin-top:18px;font-size:12px;color:var(--ink-dim);text-decoration:none;border-bottom:1px solid var(--navy-line);padding-bottom:1px;}
  a.back:hover{color:var(--accent);border-color:var(--accent-quiet);}
</style>
</head>
<body>
  <main class="card">
    <img class="crest" src="/assets/lynch-manor-logo.png" alt="Lynch Manor Academy crest">
    <p class="kicker">Lynch Manor Academy</p>
    <h1>Student Portal</h1>
    <p class="instruction">Please enter the family password to continue.</p>
    <form method="POST" action="/students" novalidate>
      <label for="password">Family Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password"
             autofocus required${describedBy}>
      ${errorBlock}
      <button type="submit">Sign In</button>
    </form>
    <p class="foot">For Lynch family use only<br><span class="sep">Scientia &middot; Virtus &middot; Lumen</span></p>
    <a class="back" href="/">&larr; Return to the Academy</a>
  </main>
  <script>
    // Light touch: show a working state on submit so the wait reads as intentional.
    var f = document.querySelector('form');
    if (f) f.addEventListener('submit', function(){
      var b = f.querySelector('button');
      if (b){ b.disabled = true; b.textContent = 'Signing in\\u2026'; }
    });
  </script>
</body>
</html>`;
}

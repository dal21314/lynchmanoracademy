// Lynch Manor Academy — Student Portal authentication gate.
// TEMPORARY DIAGNOSTIC VERSION — shows debug info on the error page.

import type { Context } from "https://edge.netlify.com";

const COOKIE_NAME = "lma_portal";
const SESSION_DAYS = 7;
const SALT = "lynch-manor-academy::scientia-virtus-lumen::v1";

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

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

  if (url.pathname === "/students/logout") {
    const headers = new Headers();
    headers.append(
      "Set-Cookie",
      `${COOKIE_NAME}=; Path=/students; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
    );
    headers.set("Location", "/?signed_out=1");
    return new Response(null, { status: 302, headers });
  }

  const existing = context.cookies.get(COOKIE_NAME) ?? "";
  if (expectedToken && existing && safeEqual(existing, expectedToken)) {
    return context.next();
  }

  if (request.method === "POST") {
    let submitted = "";
    try {
      const form = await request.formData();
      submitted = String(form.get("password") ?? "");
    } catch {
      submitted = "";
    }

    const submittedHash = await sha256Hex(submitted + SALT);

    if (
      expectedToken &&
      safeEqual(submittedHash, expectedToken)
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

    const diag = {
      env_var_length: password.length,
      env_var_first_char_code: password.length > 0 ? password.charCodeAt(0) : null,
      env_var_last_char_code: password.length > 0 ? password.charCodeAt(password.length - 1) : null,
      submitted_length: submitted.length,
      submitted_first_char_code: submitted.length > 0 ? submitted.charCodeAt(0) : null,
      submitted_last_char_code: submitted.length > 0 ? submitted.charCodeAt(submitted.length - 1) : null,
      expected_token_length: expectedToken.length,
      submitted_hash_length: submittedHash.length,
      hashes_match: submittedHash === expectedToken,
    };

    return new Response(loginPage({ error: true, diag }), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  return new Response(loginPage({ error: false, diag: null }), {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
};

export const config = { path: ["/students", "/students/*"] };

function loginPage({ error, diag }: { error: boolean; diag: any }): string {
  const errorBlock = error
    ? `<p class="err" id="pw-error" role="alert">That password didn&rsquo;t match. Please try again.</p>`
    : "";
  const describedBy = error ? ` aria-describedby="pw-error"` : "";

  const diagBlock = diag
    ? `<pre style="background:#000;color:#0f0;padding:12px;margin:16px 0;font-size:11px;text-align:left;border-radius:4px;overflow:auto;font-family:monospace;">DIAG:
${JSON.stringify(diag, null, 2)}</pre>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Student Portal · Lynch Manor Academy</title>
<meta name="robots" content="noindex, nofollow">
<link rel="icon" type="image/png" sizes="any" href="/assets/favicon-32.png">
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;500;600&family=Nunito:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  body{background:#18243f;color:#e9ecf2;font-family:'Nunito',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px 20px;margin:0;}
  .card{width:100%;max-width:520px;background:#1f2a44;border:1px solid #2d3a5c;border-radius:6px;padding:48px 44px 40px;text-align:center;}
  .crest{width:80px;height:80px;display:block;margin:0 auto 22px;}
  .kicker{font-family:'Cinzel',serif;font-size:11px;letter-spacing:0.26em;text-transform:uppercase;color:#e9b464;margin:0 0 10px;}
  h1{font-family:'Cinzel',serif;font-size:27px;letter-spacing:0.05em;margin:0 0 14px;}
  .instruction{font-size:14px;color:#a9b0be;margin:0 0 26px;}
  form{display:flex;flex-direction:column;gap:14px;text-align:left;}
  label{font-size:11px;letter-spacing:0.18em;text-transform:uppercase;color:#b0b6c2;font-weight:600;}
  input[type=password]{width:100%;font-size:17px;color:#e9ecf2;background:rgba(13,20,36,0.7);border:1px solid #2d3a5c;border-radius:4px;padding:13px 15px;outline:none;}
  .err{color:#e6a07a;font-size:15px;margin:-4px 0 0;font-style:italic;}
  button{margin-top:6px;font-family:'Cinzel',serif;font-weight:600;font-size:14px;letter-spacing:0.22em;text-transform:uppercase;color:#1a1300;background:#e9b464;border:0;border-radius:4px;padding:14px;cursor:pointer;}
  .foot{margin-top:24px;font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:#b0b6c2;}
  a.back{display:inline-block;margin-top:18px;font-size:12px;color:#a9b0be;text-decoration:none;}
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
    ${diagBlock}
    <p class="foot">For Lynch family use only<br>Scientia &middot; Virtus &middot; Lumen</p>
    <a class="back" href="/">&larr; Return to the Academy</a>
  </main>
</body>
</html>`;
}

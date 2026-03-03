/**
 * server.js — TowelPlus Mockup Uploader (OAuth + App Proxy + File Upload)
 *
 * ✅ Goals (your exact situation):
 * 1) Shopify hits App URL: https://app.towelplus.ca/?shop=...&hmac=...
 *    → we AUTO-start OAuth if token not saved yet (so install actually completes)
 * 2) Token is PERSISTED to disk so you don't have to reinstall every time you restart node
 * 3) Upload endpoint works after install: POST /api/upload-mockup
 * 4) App proxy verification works: GET /proxy/mockup (and you can expand later)
 *
 * REQUIRED ENV VARS:
 *   SHOPIFY_API_KEY=xxxxx
 *   SHOPIFY_API_SECRET=xxxxx
 *
 * OPTIONAL:
 *   SHOPIFY_SCOPES=write_files,write_metaobjects,write_orders,read_products,write_products
 *   SHOPIFY_API_VERSION=2026-01
 *   PORT=3000
 *
 * Run:
 *   npm i express
 *   node server.js
 */

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json({ limit: "25mb" }));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.SHOPIFY_API_KEY;
const API_SECRET = process.env.SHOPIFY_API_SECRET;
const API_VERSION = process.env.SHOPIFY_API_VERSION || "2026-01";
const SCOPES =
  process.env.SHOPIFY_SCOPES ||
  "write_files,write_metaobjects,write_orders,read_products,write_products";

if (!API_KEY || !API_SECRET) {
  console.error("❌ Missing env vars. Set SHOPIFY_API_KEY and SHOPIFY_API_SECRET.");
}

/** ----------------------------------------------------------------
 * Persistent token store (FILE-BASED)
 * - Saves tokens to ./tokens.json (same folder as server.js)
 * - So you only need to install once, even after restarting node
 * ---------------------------------------------------------------*/
const TOKENS_FILE = path.join(__dirname, "tokens.json");
const TOKENS = new Map(); // shop -> accessToken

function loadTokensFromDisk() {
  try {
    if (!fs.existsSync(TOKENS_FILE)) return;
    const raw = fs.readFileSync(TOKENS_FILE, "utf8");
    const obj = JSON.parse(raw || "{}");
    Object.entries(obj).forEach(([shop, token]) => {
      if (typeof shop === "string" && typeof token === "string" && token.length > 10) {
        TOKENS.set(shop, token);
      }
    });
    console.log(`✅ Loaded ${TOKENS.size} token(s) from tokens.json`);
  } catch (e) {
    console.warn("⚠️ Could not load tokens.json:", String(e?.message || e));
  }
}

function saveTokensToDisk() {
  try {
    const obj = Object.fromEntries(TOKENS.entries());
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(obj, null, 2), "utf8");
  } catch (e) {
    console.warn("⚠️ Could not write tokens.json:", String(e?.message || e));
  }
}

loadTokensFromDisk();

/** ----------------------------------------------------------------
 * Tiny cookie helpers (no external deps)
 * ---------------------------------------------------------------*/
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  if (opts.secure !== false) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  parts.push(`Path=${opts.path || "/"}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function getCookies(req) {
  const header = req.headers.cookie || "";
  return header.split(";").reduce((acc, part) => {
    const [k, ...v] = part.trim().split("=");
    if (!k) return acc;
    acc[k] = decodeURIComponent(v.join("=") || "");
    return acc;
  }, {});
}

/** ----------------------------------------------------------------
 * Helpers: shop validation + HMAC verification (OAuth callback)
 * ---------------------------------------------------------------*/
function isValidShop(shop) {
  return typeof shop === "string" && /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i.test(shop);
}

function verifyShopifyHmac(query) {
  // OAuth callback params include hmac; we must validate it
  const { hmac, signature, ...rest } = query; // signature is for app proxy, not oauth
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${Array.isArray(rest[k]) ? rest[k].join(",") : rest[k]}`)
    .join("&");

  const digest = crypto.createHmac("sha256", API_SECRET).update(message).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(hmac, "utf8"));
  } catch {
    return false;
  }
}

/** ----------------------------------------------------------------
 * App Proxy verification (Shopify sends ?signature=...)
 * https://shopify.dev/docs/apps/online-store/app-proxies#verify-requests
 * ---------------------------------------------------------------*/
function verifyAppProxySignature(req) {
  const { signature, ...rest } = req.query;
  if (!signature) return false;

  // App proxy uses concatenated key=value with NO separators
  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${Array.isArray(rest[k]) ? rest[k].join(",") : rest[k]}`)
    .join("");

  const digest = crypto.createHmac("sha256", API_SECRET).update(message).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(signature, "utf8"));
  } catch {
    return false;
  }
}

function requireProxyAuth(req, res, next) {
  if (!verifyAppProxySignature(req)) {
    return res.status(401).send("Invalid proxy signature");
  }
  next();
}

/** ----------------------------------------------------------------
 * Routes: Health + Home
 * IMPORTANT: Shopify loads your App URL as "/?shop=...&hmac=..."
 * Shopify does NOT automatically call /auth
 * So we AUTO-redirect into /auth when needed.
 * ---------------------------------------------------------------*/
app.get("/health", (req, res) => res.status(200).send("ok"));

app.get("/", (req, res) => {
  const shop = req.query.shop;

  // ✅ Key fix: if Shopify is hitting "/" with ?shop= and we don't have a token yet
  // then start OAuth immediately.
  if (shop && isValidShop(shop) && !TOKENS.has(shop)) {
    return res.redirect(`/auth?shop=${encodeURIComponent(shop)}`);
  }

  // If already installed (token exists), show a friendly page
  const installedText =
    shop && isValidShop(shop) && TOKENS.has(shop)
      ? `\n\n✅ Token found for ${shop} (installed)`
      : "";

  res.status(200).send(
    `TowelPlus App is running ✅
Try /health

Install flow:
  /auth?shop=YOURSTORE.myshopify.com
${installedText}
`
  );
});

/** ----------------------------------------------------------------
 * OAuth: Start install
 * ---------------------------------------------------------------*/
app.get("/auth", (req, res) => {
  const shop = req.query.shop;
  if (!isValidShop(shop)) return res.status(400).send("Missing/invalid shop");

  // If already installed, don't re-auth unless you want to
  if (TOKENS.has(shop)) {
    return res.status(200).send(`✅ Already installed on ${shop}. You can close this tab.`);
  }

  const state = crypto.randomBytes(16).toString("hex");
  setCookie(res, "tp_oauth_state", state, { maxAge: 600, sameSite: "Lax" });

  // Use the redirect that exists in your app settings:
  const redirectUri = `https://app.towelplus.ca/auth/callback`;

  const authUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(API_KEY)}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(authUrl);
});

/** ----------------------------------------------------------------
 * OAuth: Callback (support both paths you registered)
 *   /auth/callback
 *   /api/auth/callback
 * ---------------------------------------------------------------*/
async function oauthCallbackHandler(req, res) {
  try {
    const { shop, code, state } = req.query;
    const cookies = getCookies(req);

    if (!isValidShop(shop)) return res.status(400).send("Invalid shop");
    if (!code) return res.status(400).send("Missing code");

    if (!state || !cookies.tp_oauth_state || state !== cookies.tp_oauth_state) {
      return res.status(400).send("Invalid state");
    }
    if (!verifyShopifyHmac(req.query)) {
      return res.status(400).send("Invalid HMAC");
    }

    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: API_KEY,
        client_secret: API_SECRET,
        code,
      }),
    });

    if (!tokenRes.ok) {
      const text = await tokenRes.text().catch(() => "");
      return res.status(500).send(`Token exchange failed: ${tokenRes.status} ${text}`);
    }

    const tokenJson = await tokenRes.json();
    const accessToken = tokenJson.access_token;
    if (!accessToken) return res.status(500).send("No access_token returned");

    TOKENS.set(shop, accessToken);
    saveTokensToDisk();

    console.log("✅ Installed on:", shop);
    console.log("✅ Token stored (first 10):", accessToken.slice(0, 10) + "...");

    // Send them somewhere safe after install
    return res.redirect(`https://${shop}/admin/apps`);
  } catch (err) {
    console.error("❌ OAuth callback error:", err);
    return res.status(500).send(String(err?.message || err));
  }
}

app.get("/auth/callback", oauthCallbackHandler);
app.get("/api/auth/callback", oauthCallbackHandler);

/** ----------------------------------------------------------------
 * Shopify GraphQL helper
 * ---------------------------------------------------------------*/
async function shopifyGraphQL(shop, accessToken, query, variables = {}) {
  const resp = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify({ query, variables }),
  });

  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(`GraphQL HTTP ${resp.status}: ${JSON.stringify(json)}`);
  }
  if (json.errors?.length) {
    throw new Error(`GraphQL errors: ${JSON.stringify(json.errors)}`);
  }
  return json.data;
}

/** ----------------------------------------------------------------
 * Upload mockup to Shopify Files (returns a public URL)
 * POST /api/upload-mockup
 * ---------------------------------------------------------------*/
app.post("/api/upload-mockup", async (req, res) => {
  try {
    const { shop, filename, contentType, base64 } = req.body || {};
    if (!isValidShop(shop)) return res.status(400).json({ ok: false, error: "Invalid shop" });

    const accessToken = TOKENS.get(shop);
    if (!accessToken) {
      return res.status(401).json({
        ok: false,
        error: "Token missing for this shop. Reinstall once: visit /auth?shop=YOURSHOP.myshopify.com",
      });
    }

    if (!base64) return res.status(400).json({ ok: false, error: "Missing base64" });

    const safeFilename = filename || `mockup-${Date.now()}.png`;
    const ct = contentType || "image/png";

    const raw = String(base64).includes("base64,")
      ? String(base64).split("base64,")[1]
      : String(base64);

    const fileBuffer = Buffer.from(raw, "base64");
    if (!fileBuffer.length) {
      return res.status(400).json({ ok: false, error: "Invalid base64 data" });
    }

    // 1) stagedUploadsCreate
    const staged = await shopifyGraphQL(
      shop,
      accessToken,
      `
        mutation stagedUploadsCreate($input: [StagedUploadInput!]!) {
          stagedUploadsCreate(input: $input) {
            stagedTargets {
              url
              resourceUrl
              parameters { name value }
            }
            userErrors { field message }
          }
        }
      `,
      {
        input: [
          {
            filename: safeFilename,
            mimeType: ct,
            resource: "FILE",
            httpMethod: "POST",
          },
        ],
      }
    );

    const userErrors = staged?.stagedUploadsCreate?.userErrors || [];
    if (userErrors.length) return res.status(400).json({ ok: false, error: userErrors });

    const target = staged?.stagedUploadsCreate?.stagedTargets?.[0];
    if (!target?.url || !target?.resourceUrl) {
      return res.status(500).json({ ok: false, error: "No staged target returned" });
    }

    // 2) Upload file bytes to staged target
    const form = new FormData();
    (target.parameters || []).forEach((p) => form.append(p.name, p.value));
    form.append("file", new Blob([fileBuffer], { type: ct }), safeFilename);

    const uploadResp = await fetch(target.url, { method: "POST", body: form });
    if (!uploadResp.ok) {
      const text = await uploadResp.text().catch(() => "");
      return res.status(500).json({
        ok: false,
        error: `Staged upload failed: ${uploadResp.status} ${text}`,
      });
    }

    // 3) fileCreate
    const created = await shopifyGraphQL(
      shop,
      accessToken,
      `
        mutation fileCreate($files: [FileCreateInput!]!) {
          fileCreate(files: $files) {
            files {
              ... on MediaImage {
                id
                image { url }
              }
              ... on GenericFile {
                id
                url
              }
            }
            userErrors { field message }
          }
        }
      `,
      {
        files: [
          {
            originalSource: target.resourceUrl,
            contentType: "IMAGE",
          },
        ],
      }
    );

    const createErrors = created?.fileCreate?.userErrors || [];
    if (createErrors.length) return res.status(400).json({ ok: false, error: createErrors });

    const file = created?.fileCreate?.files?.[0];
    const url = file?.image?.url || file?.url;

    if (!url) return res.status(500).json({ ok: false, error: "No URL returned from fileCreate" });

    return res.json({ ok: true, url });
  } catch (err) {
    console.error("❌ upload error:", err);
    return res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
});

/** ----------------------------------------------------------------
 * Debug helper (optional): see if token exists for a shop
 * GET /api/token-status?shop=xxx.myshopify.com
 * ---------------------------------------------------------------*/
app.get("/api/token-status", (req, res) => {
  const shop = req.query.shop;
  if (!isValidShop(shop)) return res.status(400).json({ ok: false, error: "Invalid shop" });
  return res.json({ ok: true, shop, hasToken: TOKENS.has(shop) });
});

/** ----------------------------------------------------------------
 * App Proxy endpoint
 * Proxy URL (from your dev app): https://mockup-uploader.towelplus.ca/proxy/mockup
 * Storefront calls: https://towelplus.ca/apps/mockup?... (Shopify forwards to proxy url)
 * ---------------------------------------------------------------*/
app.get("/proxy/mockup", requireProxyAuth, (req, res) => {
  res.json({
    ok: true,
    message: "App Proxy is working ✅",
    received: req.query,
  });
});

/** ----------------------------------------------------------------
 * Start server
 * ---------------------------------------------------------------*/
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server listening on port ${PORT}`);
});

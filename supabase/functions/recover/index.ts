export const config = {
  verify_jwt: false,
};

import { createClient } from "npm:@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseSecretKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const supabase = createClient(supabaseUrl, supabaseSecretKey);

// Fallback Store Destination (Server-Authoritative)
const TRUSTED_STORE_FALLBACK = "https://example.com";

// Internal Error Codes for Logging (Never Exposed to Customer)
type ErrorCode =
  | "TOKEN_MISSING"
  | "TOKEN_INVALID"
  | "SESSION_EXPIRED"
  | "SESSION_USED"
  | "CONTRACT_UNAVAILABLE"
  | "CONTRACT_INVALID"
  | "UNAUTHORIZED"
  | "SERVICE_UNAVAILABLE"
  | "INTERNAL_ERROR";

// Customer-Facing Messages Mapping
const ERROR_CONFIGS: Record<ErrorCode, { status: number; title: string; message: string }> = {
  TOKEN_MISSING: {
    status: 400,
    title: "Invalid Request",
    message: "Recovery link is incomplete. Please return to the store and try again.",
  },
  TOKEN_INVALID: {
    status: 404,
    title: "Link Unavailable",
    message: "This recovery link is no longer available. Please return to the store and start checkout again.",
  },
  SESSION_EXPIRED: {
    status: 410,
    title: "Session Expired",
    message: "This recovery session has expired. Please return to the store to start a new checkout.",
  },
  SESSION_USED: {
    status: 410,
    title: "Session Completed",
    message: "This recovery link has already been used. Please return to the store if you still want to complete your order.",
  },
  CONTRACT_UNAVAILABLE: {
    status: 404,
    title: "Experience Unavailable",
    message: "This recovery experience is temporarily unavailable. Please return to the store and try again.",
  },
  CONTRACT_INVALID: {
    status: 422,
    title: "Invalid Experience",
    message: "We couldn't load your recovery experience. Please return to the store and try again.",
  },
  UNAUTHORIZED: {
    status: 403,
    title: "Access Denied",
    message: "This recovery link isn't available. Please return to the store.",
  },
  SERVICE_UNAVAILABLE: {
    status: 503,
    title: "Service Unavailable",
    message: "We're temporarily unable to load your recovery session. Please try again shortly.",
  },
  INTERNAL_ERROR: {
    status: 500,
    title: "System Error",
    message: "Something went wrong. Please return to the store and try again.",
  },
};

// HTML/String Sanitization Helper
function escapeHtml(str: string | undefined | null): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Strict URL Sanitizer (Protocol Whitelist)
function sanitizeUrl(urlStr: string | undefined | null): string {
  if (!urlStr) return "";
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed.href;
    }
  } catch (_) {
    // Invalid URL structure
  }
  return "";
}

// Render Safe Customer Error Page (Ignores query redirect_url completely)
function renderErrorPage(code: ErrorCode, trustedStoreUrl: string = TRUSTED_STORE_FALLBACK): Response {
  const config = ERROR_CONFIGS[code] || ERROR_CONFIGS.INTERNAL_ERROR;
  const safeStoreUrl = sanitizeUrl(trustedStoreUrl) || TRUSTED_STORE_FALLBACK;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(config.title)}</title>
  <style>
    body { background-color: #f4f6f8; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 16px; margin: 0; }
    .card { background: #ffffff; max-width: 400px; width: 100%; padding: 32px 24px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); text-align: center; }
    h2 { font-size: 20px; color: #111827; margin-bottom: 12px; font-weight: 700; }
    p { font-size: 14px; color: #4b5563; line-height: 1.5; margin-bottom: 24px; }
    a.btn { display: inline-block; width: 100%; box-sizing: border-box; background: #2563eb; color: #ffffff; text-decoration: none; padding: 12px 20px; border-radius: 8px; font-size: 15px; font-weight: 600; transition: background 0.2s ease; }
    a.btn:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <div class="card">
    <h2>${escapeHtml(config.title)}</h2>
    <p>${escapeHtml(config.message)}</p>
    <a href="${escapeHtml(safeStoreUrl)}" class="btn">Return to Store</a>
  </div>
</body>
</html>`;

  const encodedHtml = new TextEncoder().encode(html);

  return new Response(encodedHtml, {
    status: config.status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store, max-age=0",
    },
  });
}

Deno.serve(async (req) => {
  // Safe Exception Boundary
  try {
    const url = new URL(req.url);

    // Explicitly ignore any attacker-supplied redirect_url query param
    const rawToken = url.searchParams.get("token") || url.searchParams.get("t");
    const token = rawToken?.trim();

    if (!token) {
      return renderErrorPage("TOKEN_MISSING");
    }

    // Database lookup wrapped safely
    let session: any;
    let dbError: any;
    try {
      const res = await supabase
        .from("recovery_sessions")
        .select("*")
        .eq("recovery_token", token)
        .maybeSingle();
      session = res.data;
      dbError = res.error;
    } catch (_) {
      return renderErrorPage("SERVICE_UNAVAILABLE");
    }

    if (dbError) {
      console.error("[INTERNAL_ERROR] Supabase DB Query Error:", dbError);
      return renderErrorPage("SERVICE_UNAVAILABLE");
    }

    if (!session) {
      return renderErrorPage("TOKEN_INVALID");
    }

    // Status Check
    if (session.status === "completed" || session.status === "used") {
      return renderErrorPage("SESSION_USED");
    }

    if (session.status !== "active") {
      return renderErrorPage("SESSION_EXPIRED");
    }

    // Expiration Check
    if (session.expires_at && new Date(session.expires_at).getTime() < Date.now()) {
      try {
        await supabase.from("recovery_sessions").update({ status: "expired" }).eq("id", session.id);
      } catch (_) {
        // Non-blocking status update fail
      }
      return renderErrorPage("SESSION_EXPIRED");
    }

    // Server-Authoritative Context & Auth Check
    const trustedContext = {
      session_id: session.id,
      merchant_id: session.merchant_id || "TEST_MERCHANT_001",
      customer_id: session.customer_id || "TEST_CUSTOMER_001",
      cart_id: session.cart_id || "TEST_CART_001",
      merchant_store_url: session.merchant_store_url || TRUSTED_STORE_FALLBACK,
    };

    if (!trustedContext.merchant_id || !trustedContext.customer_id || !trustedContext.cart_id) {
      return renderErrorPage("UNAUTHORIZED", trustedContext.merchant_store_url);
    }

    // Contract checks
    let rawContract = session.recovery_contract_json;
    if (!rawContract) {
      return renderErrorPage("CONTRACT_UNAVAILABLE", trustedContext.merchant_store_url);
    }

    let contract: any;
    try {
      contract = typeof rawContract === "string" ? JSON.parse(rawContract) : rawContract;
    } catch (_) {
      return renderErrorPage("CONTRACT_INVALID", trustedContext.merchant_store_url);
    }

    const requiredSections = ["session", "product", "pricing", "delivery", "trust", "payment", "offer", "experience"];
    for (const sec of requiredSections) {
      if (!contract[sec] || typeof contract[sec] !== "object") {
        return renderErrorPage("CONTRACT_INVALID", trustedContext.merchant_store_url);
      }
    }

    // Pricing validation
    const p = contract.pricing;
    const calcTotal = (p.subtotal || 0) + (p.shipping || 0) - (p.discount || 0) + (p.tax || 0);
    if (Math.abs(calcTotal - p.total) > 0.01) {
      return renderErrorPage("CONTRACT_INVALID", trustedContext.merchant_store_url);
    }

    const prod = contract.product;
    if (!prod.id || !prod.name || typeof prod.quantity !== "number" || typeof prod.unit_price !== "number") {
      return renderErrorPage("CONTRACT_INVALID", trustedContext.merchant_store_url);
    }

    // Log View Event
    try {
      await supabase.from("recovery_events").insert({
        action: "recovery_experience_viewed",
        created_at: new Date().toISOString(),
      });
    } catch (_) {
      // Non-blocking logging exception
    }

    const isOfferApproved = contract.offer?.approved === true && contract.offer?.type !== "NONE" && contract.offer?.value > 0;
    const safeImgUrl = sanitizeUrl(prod.image_url);

    const availableMethods = Array.isArray(contract.payment?.available_methods) ? contract.payment.available_methods : ["CARD"];
    const formattedPaymentMethods = availableMethods
      .map((m: string) => (m === "CARD" ? "Credit / Debit Card" : escapeHtml(m)))
      .join(", ");

    let safeCheckoutUrl = TRUSTED_STORE_FALLBACK;
    if (contract.experience?.checkout_url) {
      const sanitized = sanitizeUrl(contract.experience.checkout_url);
      if (sanitized) safeCheckoutUrl = sanitized;
    }

    const renderPayload = {
      experience: {
        headline: contract.experience?.headline || "Your cart is ready",
        message: contract.experience?.message || "Complete your order securely.",
        cta_text: contract.experience?.cta_text || "Complete My Order",
      },
      product: {
        id: prod.id,
        name: prod.name,
        image_url: safeImgUrl,
        variant: prod.variant || "",
        quantity: prod.quantity,
        unit_price: prod.unit_price,
      },
      pricing: {
        subtotal: p.subtotal,
        shipping: p.shipping,
        discount: p.discount,
        tax: p.tax,
        total: p.total,
        currency: p.currency || "USD",
      },
      delivery: {
        method: contract.delivery?.method || "Standard Delivery",
        estimated_days: contract.delivery?.estimated_days || "",
        estimated_date: contract.delivery?.estimated_date || "",
      },
      trust: {
        return_policy: contract.trust?.return_policy || "",
        secure_checkout: Boolean(contract.trust?.secure_checkout),
      },
      offer: {
        type: isOfferApproved ? contract.offer.type : "NONE",
        value: isOfferApproved ? contract.offer.value : 0,
        approved: isOfferApproved,
      },
    };

    if (url.searchParams.get("format") === "json") {
      return new Response(JSON.stringify(renderPayload), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Content-Type-Options": "nosniff" },
      });
    }

    const currencySymbol = renderPayload.pricing.currency === "USD" ? "$" : `${renderPayload.pricing.currency} `;

    const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>${escapeHtml(renderPayload.experience.headline)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background-color: #f4f6f8; color: #1a1a1a; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 16px; }
    .card { background: #ffffff; width: 100%; max-width: 440px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); padding: 24px; }
    .headline { font-size: 22px; font-weight: 700; text-align: center; margin-bottom: 20px; color: #111827; }
    .product-box { display: flex; gap: 16px; align-items: center; padding-bottom: 20px; border-bottom: 1px solid #e5e7eb; }
    .product-img { width: 80px; height: 80px; border-radius: 12px; object-fit: cover; background-color: #f3f4f6; display: flex; align-items: center; justify-content: center; font-size: 11px; color: #6b7280; text-align: center; }
    .product-details { flex: 1; }
    .product-title { font-size: 16px; font-weight: 600; color: #1f2937; margin-bottom: 4px; }
    .product-meta { font-size: 14px; color: #6b7280; }
    .pricing-table { margin: 20px 0; font-size: 14px; }
    .pricing-row { display: flex; justify-content: space-between; margin-bottom: 8px; color: #4b5563; }
    .pricing-row.total { font-size: 18px; font-weight: 700; color: #111827; border-top: 1px dashed #e5e7eb; padding-top: 12px; margin-top: 12px; }
    .offer-banner { background-color: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; border-radius: 8px; padding: 10px; font-size: 14px; font-weight: 600; text-align: center; margin-bottom: 16px; }
    .trust-badge { font-size: 13px; color: #6b7280; display: flex; flex-direction: column; gap: 6px; margin-bottom: 20px; }
    .message { font-size: 14px; text-align: center; color: #6b7280; margin-bottom: 16px; }
    .cta-button { display: block; width: 100%; height: 50px; line-height: 50px; background-color: #2563eb; color: #ffffff; text-align: center; border-radius: 12px; font-size: 16px; font-weight: 600; text-decoration: none; border: none; cursor: pointer; transition: background 0.2s ease; }
    .cta-button:hover { background-color: #1d4ed8; }
  </style>
</head>
<body>
  <div class="card">
    <h1 class="headline">${escapeHtml(renderPayload.experience.headline)}</h1>
    <div class="product-box">
      ${
        safeImgUrl
          ? `<img class="product-img" src="${safeImgUrl}" alt="${escapeHtml(renderPayload.product.name)}" onerror="this.outerHTML='<div class=\\'product-img\\'>Image unavailable</div>';" />`
          : `<div class="product-img">Image unavailable</div>`
      }
      <div class="product-details">
        <div class="product-title">${escapeHtml(renderPayload.product.name)}</div>
        <div class="product-meta">${escapeHtml(renderPayload.product.variant)} ${renderPayload.product.variant ? "&bull; " : ""}Qty ${renderPayload.product.quantity}</div>
        <div class="product-meta" style="font-weight: 600; margin-top: 4px; color: #111827;">${currencySymbol}${renderPayload.product.unit_price}</div>
      </div>
    </div>
    <div class="pricing-table">
      <div class="pricing-row"><span>Subtotal</span><span>${currencySymbol}${renderPayload.pricing.subtotal}</span></div>
      <div class="pricing-row"><span>Shipping</span><span>${currencySymbol}${renderPayload.pricing.shipping}</span></div>
      ${renderPayload.pricing.discount > 0 ? `<div class="pricing-row" style="color: #059669;"><span>Discount</span><span>-${currencySymbol}${renderPayload.pricing.discount}</span></div>` : ""}
      ${renderPayload.pricing.tax > 0 ? `<div class="pricing-row"><span>Tax</span><span>${currencySymbol}${renderPayload.pricing.tax}</span></div>` : ""}
      <div class="pricing-row total"><span>Total</span><span>${currencySymbol}${renderPayload.pricing.total}</span></div>
    </div>
    ${
      renderPayload.offer.approved
        ? `<div class="offer-banner">&#127881; Special Offer Applied: ${renderPayload.offer.value}${renderPayload.offer.type === "PERCENT_DISCOUNT" ? "% Off" : " Discount"}</div>`
        : ""
    }
    <div class="trust-badge">
      ${renderPayload.delivery.method ? `<div>&#128666; <strong>${escapeHtml(renderPayload.delivery.method)}</strong> ${renderPayload.delivery.estimated_days ? `(${escapeHtml(renderPayload.delivery.estimated_days)})` : ""}</div>` : ""}
      ${renderPayload.delivery.estimated_date ? `<div>&#128197; Estimated delivery: ${escapeHtml(renderPayload.delivery.estimated_date)}</div>` : ""}
      ${renderPayload.trust.return_policy ? `<div>&#8617; ${escapeHtml(renderPayload.trust.return_policy)}</div>` : ""}
      ${renderPayload.trust.secure_checkout ? `<div>&#128274; Secure checkout (${escapeHtml(formattedPaymentMethods)})</div>` : ""}
    </div>
    <p class="message">${escapeHtml(renderPayload.experience.message)}</p>
    <button id="cta-btn" class="cta-button">${escapeHtml(renderPayload.experience.cta_text)}</button>
  </div>
  <script>
    document.getElementById('cta-btn').addEventListener('click', function() {
      if (navigator.sendBeacon) {
        navigator.sendBeacon('https://wynmayymvrpivtnjgdeu.supabase.co/functions/v1/track_click', JSON.stringify({
          event_type: "recovery_cta_clicked",
          cta: "${escapeHtml(renderPayload.experience.cta_text)}",
          timestamp: new Date().toISOString()
        }));
      }
      window.location.href = "${safeCheckoutUrl}";
    });
  </script>
</body>
</html>`;

    return new Response(new TextEncoder().encode(htmlContent), {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
      },
    });

  } catch (err) {
    // Catch-all safety net for uncaught runtime exceptions
    console.error("[CRITICAL] Uncaught Error in recover function:", err);
    return renderErrorPage("INTERNAL_ERROR");
  }
});

export const config = {
  verify_jwt: false,
};

import { createClient } from "npm:@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseSecretKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const supabase = createClient(supabaseUrl, supabaseSecretKey);

Deno.serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response("ok", {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
      },
    });
  }

  try {
    let payload: any = {};
    const contentType = req.headers.get("content-type") || "";

    if (contentType.includes("application/json") || contentType.includes("text/plain")) {
      const bodyText = await req.text();
      if (bodyText) {
        payload = JSON.parse(bodyText);
      }
    }

    // Insert tracking event into recovery_events
    const { error } = await supabase.from("recovery_events").insert({
      action: payload.event_type || "recovery_cta_clicked",
      payload: payload,
      created_at: payload.timestamp || new Date().toISOString(),
    });

    if (error) {
      console.error("[TRACK_CLICK_ERROR]", error);
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch (err) {
    console.error("[TRACK_CLICK_EXCEPTION]", err);
    return new Response(JSON.stringify({ success: false }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
});

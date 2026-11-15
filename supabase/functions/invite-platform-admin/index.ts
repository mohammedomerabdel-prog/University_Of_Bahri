import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...cors, "Content-Type": "application/json" },
    });

  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return json({ error: "Unauthorized" }, 401);

  const token = authHeader.slice(7);
  const authClient = createClient(url, anon, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: userData, error: userError } = await authClient.auth.getUser(token);
  if (userError || !userData.user) return json({ error: "Invalid session" }, 401);

  const adminClient = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: actor, error: actorError } = await adminClient
    .from("platform_admins")
    .select("role,is_active")
    .eq("user_id", userData.user.id)
    .maybeSingle();
  if (actorError || !actor || !actor.is_active || actor.role !== "super_admin") {
    return json({ error: "Only an active super admin can invite administrators" }, 403);
  }

  let input: { email?: string; display_name?: string; role?: string; permissions?: Record<string, boolean> };
  try { input = await req.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  const email = input.email?.trim().toLowerCase();
  const displayName = input.display_name?.trim() || "";
  const role = input.role || "editor";
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "A valid email is required" }, 400);
  if (!["manager", "editor"].includes(role)) return json({ error: "Invalid role" }, 400);

  const { data: invited, error: inviteError } = await adminClient.auth.admin.inviteUserByEmail(email, {
    data: { display_name: displayName },
  });
  if (inviteError || !invited.user) return json({ error: inviteError?.message || "Invitation failed" }, 400);

  const { error: profileError } = await adminClient.from("platform_admins").insert({
    user_id: invited.user.id,
    display_name: displayName,
    role,
    permissions: input.permissions || { content: true, admins: false, analytics: true },
    is_active: true,
    created_by: userData.user.id,
  });
  if (profileError) {
    await adminClient.auth.admin.deleteUser(invited.user.id);
    return json({ error: "Could not create admin profile: " + profileError.message }, 500);
  }
  return json({ invited: true, email, role });
});

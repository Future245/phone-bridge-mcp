// phone-bridge-mcp  -  stage 1
// A small MCP server that lets Claude look at Phone 2's command system.
// It does NOT hold any command logic: it only calls the existing
// two-phone-command-server Worker through a service binding.
//
// Stage 1 has ONE read-only tool (receiver_status) and no login.
// Protection in this stage: only requests from Anthropic's published address
// range are answered. That range is shared by every Anthropic customer, so it
// is NOT a login. A real login (OAuth) comes before any tool can do anything.

import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";

// Anthropic's outbound range for connector calls
const DEFAULT_ALLOWED_CIDRS = ["160.79.104.0/21"];

function ipv4ToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function inCidr(ip, cidr) {
  const [base, bitsText] = cidr.split("/");
  const bits = Number(bitsText);
  const ipN = ipv4ToInt(ip);
  const baseN = ipv4ToInt(base);
  if (ipN === null || baseN === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false;
  }
  const size = 2 ** (32 - bits);
  return Math.floor(ipN / size) === Math.floor(baseN / size);
}

function ipAllowed(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const cidrs = env.ALLOWED_CIDRS
    ? env.ALLOWED_CIDRS.split(",").map((s) => s.trim()).filter(Boolean)
    : DEFAULT_ALLOWED_CIDRS;
  return cidrs.some((c) => inCidr(ip, c)); // anything unreadable (incl. IPv6) is refused
}

// Ask the existing command Worker (private service binding, never the public internet)
async function commandWorker(env, path) {
  if (!env.COMMAND_SECRET) {
    throw new Error("COMMAND_SECRET is not set on phone-bridge-mcp");
  }
  const res = await env.COMMAND.fetch(
    new Request(`https://command-worker.internal${path}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${env.COMMAND_SECRET}` },
    })
  );
  if (!res.ok) {
    throw new Error(`command Worker answered ${res.status}`);
  }
  return res.json();
}

function createServer(env) {
  const server = new McpServer({ name: "phone-bridge", version: "0.1.0" });

  server.registerTool(
    "receiver_status",
    {
      description:
        "Check whether Phone 2's receiver is online and polling, whether the emergency stop " +
        "is on, and how many commands ran in the last 24 hours. Read-only: it changes nothing " +
        "and sends no command to the phone.",
      annotations: { readOnlyHint: true },
    },
    async () => {
      try {
        const s = await commandWorker(env, "/status");
        const r = s.receiver || {};
        const lines = [
          r.online
            ? `Phone 2 receiver: ONLINE (last poll ${r.seconds_since_poll} s ago)`
            : r.last_poll_at
              ? `Phone 2 receiver: OFFLINE (last poll ${r.seconds_since_poll} s ago)`
              : "Phone 2 receiver: OFFLINE (it has never polled)",
          `Emergency stop: ${s.kill_switch ? "ON (no commands are handed out)" : "off"}`,
          `Command Worker version: ${s.version}`,
          "Commands in the last 24 h: " +
            (Object.entries(s.commands_last_24h || {})
              .map(([k, v]) => `${k}=${v}`)
              .join(", ") || "none"),
        ];
        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return {
          isError: true,
          content: [{ type: "text", text: `Could not read the status: ${error.message}` }],
        };
      }
    }
  );

  return server;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Harmless public page so you can check the deploy worked
    if (url.pathname === "/") {
      return new Response("phone-bridge-mcp stage 1 is deployed.\n", {
        headers: { "Content-Type": "text/plain" },
      });
    }

    if (!ipAllowed(request, env)) {
      return new Response("Forbidden", { status: 403 });
    }

    return createMcpHandler(() => createServer(env), { route: "/mcp" })(request, env, ctx);
  },
};

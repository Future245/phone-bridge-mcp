// phone-bridge-mcp  -  stage 2
// An MCP server that lets Claude look at and control Phone 2 through the existing
// two-phone-command-server. It holds no command logic of its own: every action is
// a command in the existing queue, and the answer comes back from Phone 2 itself.
//
// Protection, in this order:
//   1. only requests from Anthropic's published address range are answered
//   2. every request must carry the secret key (X-API-Key header, a name Claude's connector form approves)
//   3. the trade tool needs an explicit confirmation value
//   4. the command Worker enforces the emergency stop, a duplicate block and a trade cap
//   5. Phone 2 itself refuses trades unless armed.txt exists and the cooldown has passed

import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

const DEFAULT_ALLOWED_CIDRS = ["160.79.104.0/21"];

// ------------------------------------------------------------------ access

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

// Constant-time comparison (hash both sides, then compare every byte)
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// Fails closed: if BRIDGE_KEY is not set, nobody gets in
async function keyOk(request, env) {
  if (!env.BRIDGE_KEY) return false;
  return safeEqual(request.headers.get("X-API-Key") || "", env.BRIDGE_KEY);
}

// ------------------------------------------------------- command Worker access

async function api(env, path, { method = "GET", body } = {}) {
  if (!env.COMMAND_SECRET) {
    throw new Error("COMMAND_SECRET is not set on phone-bridge-mcp");
  }
  const res = await env.COMMAND.fetch(
    new Request(`https://command-worker.internal${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${env.COMMAND_SECRET}`,
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    })
  );
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { status: res.status, data };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const TERMINAL = new Set(["completed", "failed", "expired", "timeout", "unknown"]);
const POLL_MS = 2000;

// WAIT_SCALE exists only so the waits can be shortened when testing
function waitMs(env, ms) {
  const scale = Number(env.WAIT_SCALE);
  return scale > 0 ? ms * scale : ms;
}

async function waitForResult(env, id, maxMs) {
  const deadline = Date.now() + waitMs(env, maxMs);
  let last = null;
  while (true) {
    const r = await api(env, `/result?id=${id}`);
    if (r.status === 200 && r.data) {
      last = r.data;
      if (TERMINAL.has(last.status)) return last;
    }
    if (Date.now() + waitMs(env, POLL_MS) > deadline) return last;
    await sleep(waitMs(env, POLL_MS));
  }
}

// Turn a /result answer into plain words. Success is only ever claimed
// when Phone 2 itself confirmed it.
function describe(id, r, extraOk = "") {
  if (!r) {
    return `Command #${id}: no answer yet from the server. Check again with get_command_result.`;
  }
  if (!TERMINAL.has(r.status)) {
    return (
      `Command #${id} is still ${r.status}. It has NOT finished yet. ` +
      `Do not send it again. Check with get_command_result (id ${id}).`
    );
  }
  if (!r.confirmed_by_phone) {
    return (
      `Command #${id} ended as "${r.status}" and Phone 2 never confirmed it. ` +
      `The outcome is UNKNOWN. Do not assume it ran and do not re-send it automatically.`
    );
  }
  const verdict =
    r.ok === true ? "SUCCESS (Phone 2 confirmed)"
    : r.ok === false ? "FAILED (Phone 2 reported a failure)"
    : "finished (Phone 2 sent no success flag)";
  return `Command #${id}: ${verdict}\n${r.result || "(no output)"}${r.ok === true ? extraOk : ""}`;
}

function reply(text, isError = false) {
  return { content: [{ type: "text", text }], ...(isError ? { isError: true } : {}) };
}

// Send one command and wait for Phone 2's answer
async function sendAndWait(env, body, maxMs, extraOk = "") {
  const sent = await api(env, "/send", { method: "POST", body });
  if (sent.status === 423) {
    return reply("Refused: the emergency stop is ON. Nothing was sent.", true);
  }
  if (sent.status === 409) {
    const d = sent.data || {};
    return reply(
      `Not sent: the same command is already ${d.status || "pending or running"} ` +
      `(command #${d.command_id}). Check it with get_command_result instead.`,
      true
    );
  }
  if (sent.status === 429) {
    const t = sent.data && sent.data.trade_commands;
    return reply(
      "Not sent: a limit was reached." +
      (t ? ` Trade commands: ${t.last_hour}/${t.cap_per_hour} in the last hour, ` +
           `${t.last_24h}/${t.cap_per_day} in 24 h.` : ""),
      true
    );
  }
  if (sent.status !== 201 || !sent.data || !sent.data.command_id) {
    return reply(`Not sent: the command Worker answered ${sent.status}.`, true);
  }
  const id = sent.data.command_id;
  const result = await waitForResult(env, id, maxMs);
  return reply(describe(id, result, extraOk));
}

// ------------------------------------------------------------------- the tools

const BUY_CONFIRM = "PLACE_10_BUYS_REAL_MONEY";

function createServer(env) {
  const server = new McpServer({ name: "phone-bridge", version: "0.2.0" });

  const safe = (fn) => async (args) => {
    try {
      return await fn(args);
    } catch (error) {
      return reply(`Error: ${error.message}`, true);
    }
  };

  server.registerTool(
    "receiver_status",
    {
      description:
        "Check whether Phone 2's receiver is online and polling, whether the emergency stop " +
        "is on, how many commands ran in the last 24 hours, and how many trade commands have " +
        "been used against the hourly and daily caps. Read-only: sends nothing to the phone.",
      annotations: { readOnlyHint: true },
    },
    safe(async () => {
      const { status, data: s } = await api(env, "/status");
      if (status !== 200 || !s) return reply(`Could not read the status (answered ${status}).`, true);
      const r = s.receiver || {};
      const t = s.trade_commands || {};
      return reply([
        r.online
          ? `Phone 2 receiver: ONLINE (last poll ${r.seconds_since_poll} s ago)`
          : r.last_poll_at
            ? `Phone 2 receiver: OFFLINE (last poll ${r.seconds_since_poll} s ago)`
            : "Phone 2 receiver: OFFLINE (it has never polled)",
        `Emergency stop: ${s.kill_switch ? "ON (no commands are handed out)" : "off"}`,
        `Command Worker version: ${s.version}`,
        "Commands in the last 24 h: " +
          (Object.entries(s.commands_last_24h || {}).map(([k, v]) => `${k}=${v}`).join(", ") || "none"),
        `Trade commands used: ${t.last_hour ?? "?"}/${t.cap_per_hour ?? "?"} this hour, ` +
          `${t.last_24h ?? "?"}/${t.cap_per_day ?? "?"} in 24 h`,
      ].join("\n"));
    })
  );

  server.registerTool(
    "phone_status",
    {
      description:
        "Ask Phone 2 for its battery, free disk space, time and whether the Deriv bot is running. " +
        "Read-only. Waits up to about 25 seconds for Phone 2 to answer.",
      annotations: { readOnlyHint: true },
    },
    safe(() => sendAndWait(env, { action: "phone_status" }, 25000))
  );

  server.registerTool(
    "read_mt5_account",
    {
      description:
        "Open MetaTrader 5 on Phone 2 and read balance, equity and margin. Places no trade and " +
        "closes nothing, but it does bring MT5 to the front on Phone 2's screen. Waits up to about 55 seconds.",
    },
    safe(() => sendAndWait(env, { action: "open_mt5" }, 55000))
  );

  server.registerTool(
    "run_status_script",
    {
      description:
        "Run the read-only status.py diagnostic on Phone 2: battery, disk, memory, whether trading " +
        "is armed, time of the last trade command, bot state and whether MT5 is calibrated. " +
        "Changes nothing. Waits up to about 40 seconds.",
      annotations: { readOnlyHint: true },
    },
    safe(() => sendAndWait(env, { action: "run_script", script: "status.py" }, 40000))
  );

  server.registerTool(
    "bot_status",
    {
      description:
        "Check whether deriv_bot.py is running on Phone 2 and show its last few log lines. Read-only.",
      annotations: { readOnlyHint: true },
    },
    safe(() => sendAndWait(env, { action: "bot_status" }, 25000))
  );

  server.registerTool(
    "bot_stop",
    {
      description:
        "Stop the deriv_bot.py process on Phone 2 (a clean stop first, then a forced stop). " +
        "It only stops a bot that the receiver itself started. Use when the user asks to stop the bot.",
      annotations: { destructiveHint: true },
    },
    safe(() => sendAndWait(env, { action: "bot_stop" }, 30000))
  );

  server.registerTool(
    "get_command_result",
    {
      description:
        "Look up the current state and result of a command by its number. Use this after a tool " +
        "said a command is still running. Read-only.",
      inputSchema: z.object({ id: z.number().int().positive() }),
      annotations: { readOnlyHint: true },
    },
    safe(async ({ id }) => {
      const r = await api(env, `/result?id=${id}`);
      if (r.status === 404) return reply(`Command #${id} does not exist.`, true);
      if (r.status !== 200) return reply(`Could not read command #${id} (answered ${r.status}).`, true);
      return reply(describe(id, r.data));
    })
  );

  server.registerTool(
    "emergency_stop",
    {
      description:
        "Turn the EMERGENCY STOP on: the server stops accepting new commands and stops handing " +
        "commands to Phone 2. Use it if the user says stop, halt, or panic. It cannot be turned off " +
        "from here, only by the owner. A trade burst that Phone 2 is already running will finish by itself.",
      annotations: { destructiveHint: true },
    },
    safe(async () => {
      const r = await api(env, "/killswitch", { method: "POST", body: { on: true } });
      if (r.status !== 200) return reply(`Could not set the emergency stop (answered ${r.status}).`, true);
      return reply(
        "Emergency stop is ON. No new commands will be accepted or handed to Phone 2. " +
        "A trade burst already running on Phone 2 cannot be interrupted. " +
        "Only the owner can turn this off."
      );
    })
  );

  server.registerTool(
    "mt5_buy10",
    {
      description:
        "REAL MONEY. Places exactly 10 BUY market orders on Jump 10 Index at lot 1 in MetaTrader 5 " +
        "on Phone 2. The size, symbol and count are fixed and cannot be changed here. " +
        "ONLY call this when the user has clearly and explicitly asked, in this conversation, " +
        "to place these buys now. Never call it on your own initiative, never as a test, and never " +
        "to retry: if it times out, errors, or reports it is still running, do NOT send it again; " +
        "use get_command_result and read_mt5_account to find out what happened. " +
        "Phone 2 refuses unless trading is armed there, and refuses a second trade within 2 minutes. " +
        "A SUCCESS here only means the script finished and fired its taps: afterwards check with " +
        "read_mt5_account that margin is no longer 'none'. Waits up to about 55 seconds.",
      inputSchema: z.object({
        confirm: z
          .literal(BUY_CONFIRM)
          .describe(
            `Must be exactly ${BUY_CONFIRM}, and only after the user explicitly asked for these 10 buys.`
          ),
      }),
      annotations: { destructiveHint: true },
    },
    safe(async () => {
      // Pre-flight: never queue a trade for a dead receiver or during an emergency stop
      const st = await api(env, "/status");
      if (st.status !== 200 || !st.data) {
        return reply("Trade NOT sent: could not read the system status.", true);
      }
      if (st.data.kill_switch) {
        return reply("Trade NOT sent: the emergency stop is ON.", true);
      }
      const r = st.data.receiver || {};
      if (!r.online) {
        return reply(
          `Trade NOT sent: Phone 2's receiver is offline (last poll ${r.seconds_since_poll ?? "never"} s ago).`,
          true
        );
      }
      return sendAndWait(
        env,
        { action: "mt5_buy10" },
        55000,
        "\n\nNote: this means the buy taps were fired. Verify with read_mt5_account."
      );
    })
  );

  return server;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Harmless public page so you can check the deploy worked
    if (url.pathname === "/") {
      return new Response("phone-bridge-mcp stage 2 is deployed.\n", {
        headers: { "Content-Type": "text/plain" },
      });
    }

    if (!ipAllowed(request, env)) {
      return new Response("Forbidden", { status: 403 });
    }
    if (!(await keyOk(request, env))) {
      return new Response("Unauthorized", { status: 401 });
    }

    return createMcpHandler(() => createServer(env), { route: "/mcp" })(request, env, ctx);
  },
};

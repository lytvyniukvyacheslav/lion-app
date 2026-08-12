import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const REDIS_URL =
  process.env.KV_REST_API_URL ||
  process.env.STORAGE_REST_API_URL ||
  process.env.UPSTASH_REDIS_REST_URL ||
  '';
const REDIS_TOKEN =
  process.env.KV_REST_API_TOKEN ||
  process.env.STORAGE_REST_API_TOKEN ||
  process.env.UPSTASH_REDIS_REST_TOKEN ||
  '';

const CASE_COST = 30;
const TOPUPS = new Set([50, 100, 200, 500, 1000]);
const PRIZES = [
  { name: 'Heart', price: 15, chance: 20 },
  { name: 'Bear', price: 15, chance: 20 },
  { name: 'Rose', price: 25, chance: 10 },
  { name: 'Gift', price: 25, chance: 10 },
  { name: 'Rocket', price: 50, chance: 10 },
  { name: 'Cake', price: 50, chance: 10 },
  { name: 'Bouquet', price: 50, chance: 8 },
  { name: 'Ring', price: 100, chance: 4 },
  { name: 'Trophy', price: 100, chance: 3 },
  { name: 'Diamond', price: 100, chance: 4 },
  { name: 'Torch', price: 385, chance: 1 },
];

function reply(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { 'cache-control': 'no-store' },
  });
}

function safeHexEqual(a, b) {
  try {
    const aa = Buffer.from(String(a), 'hex');
    const bb = Buffer.from(String(b), 'hex');
    return aa.length === bb.length && timingSafeEqual(aa, bb);
  } catch {
    return false;
  }
}

function verifyInitData(raw) {
  if (!BOT_TOKEN || !raw) throw new Error('UNAUTHORIZED');

  const params = new URLSearchParams(raw);
  const receivedHash = params.get('hash');
  if (!receivedHash) throw new Error('UNAUTHORIZED');
  params.delete('hash');

  const authDate = Number(params.get('auth_date') || 0);
  const now = Math.floor(Date.now() / 1000);
  if (!authDate || Math.abs(now - authDate) > 24 * 60 * 60) {
    throw new Error('EXPIRED');
  }

  const dataCheckString = [...params.entries()]
    .map(([key, value]) => `${key}=${value}`)
    .sort()
    .join('\n');

  const secretKey = createHmac('sha256', 'WebAppData')
    .update(BOT_TOKEN)
    .digest();
  const calculatedHash = createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest('hex');

  if (!safeHexEqual(calculatedHash, receivedHash)) {
    throw new Error('UNAUTHORIZED');
  }

  const userRaw = params.get('user');
  if (!userRaw) throw new Error('NO_USER');
  const user = JSON.parse(userRaw);
  if (!user?.id) throw new Error('NO_USER');
  return user;
}

function authUser(request) {
  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('tma ')) throw new Error('UNAUTHORIZED');
  return verifyInitData(header.slice(4));
}

async function redis(command) {
  if (!REDIS_URL || !REDIS_TOKEN) throw new Error('REDIS_NOT_CONFIGURED');
  const response = await fetch(REDIS_URL, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${REDIS_TOKEN}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(command),
  });
  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(data.error || `Redis ${response.status}`);
  }
  return data.result;
}

async function telegram(method, body = {}) {
  if (!BOT_TOKEN) throw new Error('BOT_TOKEN_NOT_CONFIGURED');
  const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!data.ok) throw new Error(data.description || `Telegram ${method} failed`);
  return data.result;
}

function userKey(id) {
  return `lion:user:${id}`;
}

function webhookSecret() {
  return createHash('sha256').update(`lion-webhook:${BOT_TOKEN}`).digest('hex');
}

function productionOrigin(request) {
  const production = process.env.VERCEL_PROJECT_PRODUCTION_URL;
  if (production) return `https://${production}`;
  return new URL(request.url).origin;
}

async function ensureWebhook(request) {
  const origin = productionOrigin(request);
  const fingerprint = createHash('sha256').update(BOT_TOKEN).digest('hex').slice(0, 12);
  const marker = `lion:webhook:${fingerprint}:${origin}`;
  const existing = await redis(['GET', marker]);
  if (existing === '1') return;

  await telegram('setWebhook', {
    url: `${origin}/api/index?action=webhook`,
    secret_token: webhookSecret(),
    allowed_updates: ['message', 'pre_checkout_query'],
  });
  await redis(['SET', marker, '1', 'EX', 86400]);
}

function parsePayload(payload) {
  const match = /^lion:(\d+):(50|100|200|500|1000):([a-f0-9]{16})$/.exec(String(payload || ''));
  if (!match) return null;
  return {
    userId: Number(match[1]),
    amount: Number(match[2]),
    nonce: match[3],
  };
}

function pickPrize() {
  let r = Math.random() * 100;
  let sum = 0;
  for (const prize of PRIZES) {
    sum += prize.chance;
    if (r < sum) {
      return {
        id: randomBytes(8).toString('hex'),
        name: prize.name,
        price: prize.price,
      };
    }
  }
  const prize = PRIZES[PRIZES.length - 1];
  return { id: randomBytes(8).toString('hex'), name: prize.name, price: prize.price };
}

async function getState(userId) {
  const values = await redis([
    'HMGET',
    userKey(userId),
    'balance',
    'opened',
    'sold',
    'inventory',
    'pending',
  ]);
  const [balance, opened, sold, inventoryRaw, pendingRaw] = Array.isArray(values) ? values : [];
  let inventory = [];
  let pending = null;
  try { inventory = inventoryRaw ? JSON.parse(inventoryRaw) : []; } catch {}
  try { pending = pendingRaw ? JSON.parse(pendingRaw) : null; } catch {}
  return {
    balance: Number(balance || 0),
    opened: Number(opened || 0),
    sold: Number(sold || 0),
    inventory: Array.isArray(inventory) ? inventory : [],
    pending,
  };
}

async function creditSuccessfulPayment(payment, fromUserId) {
  if (!payment || payment.currency !== 'XTR') return false;
  const parsed = parsePayload(payment.invoice_payload);
  if (!parsed) return false;
  if (parsed.userId !== Number(fromUserId)) return false;
  if (parsed.amount !== Number(payment.total_amount)) return false;
  if (!TOPUPS.has(parsed.amount)) return false;

  const chargeId = String(payment.telegram_payment_charge_id || '');
  if (!chargeId) return false;

  const script = `
    if redis.call('EXISTS', KEYS[1]) == 1 then
      return -1
    end
    redis.call('SET', KEYS[1], '1')
    return redis.call('HINCRBY', KEYS[2], 'balance', ARGV[1])
  `;

  await redis([
    'EVAL', script, 2,
    `lion:payment:${chargeId}`,
    userKey(parsed.userId),
    parsed.amount,
  ]);
  return true;
}

async function handleWebhook(request) {
  const secret = request.headers.get('x-telegram-bot-api-secret-token') || '';
  if (secret !== webhookSecret()) return reply({ ok: false }, 403);

  const update = await request.json();

  if (update.pre_checkout_query) {
    const q = update.pre_checkout_query;
    const parsed = parsePayload(q.invoice_payload);
    const valid = Boolean(
      parsed &&
      q.currency === 'XTR' &&
      TOPUPS.has(Number(q.total_amount)) &&
      parsed.amount === Number(q.total_amount) &&
      parsed.userId === Number(q.from?.id)
    );

    await telegram('answerPreCheckoutQuery', valid
      ? { pre_checkout_query_id: q.id, ok: true }
      : {
          pre_checkout_query_id: q.id,
          ok: false,
          error_message: 'ÐÐµ ÑÐ´Ð°Ð»Ð¾ÑÑ Ð¿ÑÐ¾Ð²ÐµÑÐ¸ÑÑ Ð¿Ð»Ð°ÑÑÐ¶. ÐÐ¾Ð¿ÑÐ¾Ð±ÑÐ¹ÑÐµ ÑÐ½Ð¾Ð²Ð°.',
        }
    );
    return reply({ ok: true });
  }

  const payment = update.message?.successful_payment;
  if (payment) {
    await creditSuccessfulPayment(payment, update.message?.from?.id);
  }

  return reply({ ok: true });
}

async function handleAction(request, action) {
  const user = authUser(request);
  const userId = Number(user.id);

  if (action === 'state') {
    return reply(await getState(userId));
  }

  if (action === 'create-invoice') {
    const body = await request.json().catch(() => ({}));
    const amount = Number(body.amount);
    if (!TOPUPS.has(amount)) return reply({ error: 'BAD_AMOUNT' }, 400);

    await ensureWebhook(request);
    const nonce = randomBytes(8).toString('hex');
    const invoiceUrl = await telegram('createInvoiceLink', {
      title: `${amount} Stars for Lion`,
      description: `ÐÐ¾Ð¿Ð¾Ð»Ð½ÐµÐ½Ð¸Ðµ Ð²Ð½ÑÑÑÐµÐ½Ð½ÐµÐ³Ð¾ Ð±Ð°Ð»Ð°Ð½ÑÐ° Lion Ð½Ð° ${amount} â­`,
      payload: `lion:${userId}:${amount}:${nonce}`,
      provider_token: '',
      currency: 'XTR',
      prices: [{ label: `${amount} â­`, amount }],
    });
    return reply({ invoiceUrl });
  }

  if (action === 'open-case') {
    const prize = pickPrize();
    const prizeJson = JSON.stringify(prize);
    const script = `
      local bal = tonumber(redis.call('HGET', KEYS[1], 'balance') or '0')
      local pending = redis.call('HGET', KEYS[1], 'pending')
      if pending and pending ~= '' then return -2 end
      if bal < tonumber(ARGV[1]) then return -1 end
      redis.call('HINCRBY', KEYS[1], 'balance', -tonumber(ARGV[1]))
      redis.call('HINCRBY', KEYS[1], 'opened', 1)
      redis.call('HSET', KEYS[1], 'pending', ARGV[2])
      return bal - tonumber(ARGV[1])
    `;
    const result = Number(await redis(['EVAL', script, 1, userKey(userId), CASE_COST, prizeJson]));
    if (result === -1) return reply({ error: 'INSUFFICIENT_BALANCE', balance: (await getState(userId)).balance }, 402);
    if (result === -2) return reply({ error: 'PENDING_PRIZE' }, 409);
    return reply({ prize, balance: result });
  }

  if (action === 'keep') {
    const script = `
      local pending = redis.call('HGET', KEYS[1], 'pending')
      if not pending or pending == '' then return 0 end
      local invRaw = redis.call('HGET', KEYS[1], 'inventory') or '[]'
      local inv = cjson.decode(invRaw)
      table.insert(inv, cjson.decode(pending))
      redis.call('HSET', KEYS[1], 'inventory', cjson.encode(inv))
      redis.call('HDEL', KEYS[1], 'pending')
      return 1
    `;
    await redis(['EVAL', script, 1, userKey(userId)]);
    return reply(await getState(userId));
  }

  if (action === 'sell-pending') {
    const script = `
      local pending = redis.call('HGET', KEYS[1], 'pending')
      if not pending or pending == '' then return -1 end
      local prize = cjson.decode(pending)
      redis.call('HINCRBY', KEYS[1], 'balance', tonumber(prize.price))
      redis.call('HINCRBY', KEYS[1], 'sold', 1)
      redis.call('HDEL', KEYS[1], 'pending')
      return tonumber(prize.price)
    `;
    await redis(['EVAL', script, 1, userKey(userId)]);
    return reply(await getState(userId));
  }

  if (action === 'sell-inventory') {
    const body = await request.json().catch(() => ({}));
    const itemId = String(body.id || '');
    if (!/^[a-f0-9]{16}$/.test(itemId)) return reply({ error: 'BAD_ITEM' }, 400);

    const script = `
      local invRaw = redis.call('HGET', KEYS[1], 'inventory') or '[]'
      local inv = cjson.decode(invRaw)
      local found = nil
      local out = {}
      for i, item in ipairs(inv) do
        if not found and item.id == ARGV[1] then
          found = item
        else
          table.insert(out, item)
        end
      end
      if not found then return -1 end
      redis.call('HSET', KEYS[1], 'inventory', cjson.encode(out))
      redis.call('HINCRBY', KEYS[1], 'balance', tonumber(found.price))
      redis.call('HINCRBY', KEYS[1], 'sold', 1)
      return tonumber(found.price)
    `;
    const result = Number(await redis(['EVAL', script, 1, userKey(userId), itemId]));
    if (result < 0) return reply({ error: 'ITEM_NOT_FOUND' }, 404);
    return reply(await getState(userId));
  }

  return reply({ error: 'UNKNOWN_ACTION' }, 404);
}

export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const action = url.searchParams.get('action') || '';

      if (action === 'webhook') {
        if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
        return await handleWebhook(request);
      }

      if (!action) return reply({ ok: true, service: 'lion-api' });
      return await handleAction(request, action);
    } catch (error) {
      const code = String(error?.message || error);
      if (['UNAUTHORIZED', 'EXPIRED', 'NO_USER'].includes(code)) {
        return reply({ error: 'UNAUTHORIZED' }, 401);
      }
      console.error(error);
      return reply({ error: 'SERVER_ERROR' }, 500);
    }
  },
};

import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const ADMIN_TELEGRAM_ID = Number(process.env.ADMIN_TELEGRAM_ID || 1962010342);
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
const ROCKET_GROWTH = 0.18;
const MAX_ROCKET_BET = 10000;

// Exactly 100% total, as requested.
const PRIZES = [
  { slot: 0, key: 'none', name: 'Ничего', price: 0, chance: 16, emoji: 'ZERO' },
  { slot: 1, key: 'bear-1', name: 'Мишка', price: 15, chance: 20, emoji: '🧸' },
  { slot: 2, key: 'bear-2', name: 'Мишка', price: 15, chance: 20, emoji: '🧸' },
  { slot: 3, key: 'bear-3', name: 'Мишка', price: 15, chance: 21, emoji: '🧸' },
  { slot: 4, key: 'rose', name: 'Роза', price: 25, chance: 12, emoji: '🌹' },
  { slot: 5, key: 'cake', name: 'Торт', price: 50, chance: 5, emoji: '🎂' },
  { slot: 6, key: 'trophy', name: 'Кубок', price: 100, chance: 5, emoji: '🏆' },
  { slot: 7, key: 'torch', name: 'Факел', price: 385, chance: 1, emoji: '🔥' },
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

function withdrawalKey(id) {
  return `lion:withdrawal:${id}`;
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
  // v3 forces one fresh setWebhook after deploying this version.
  const marker = `lion:webhook:v3:${fingerprint}:${origin}`;
  const existing = await redis(['GET', marker]);
  if (existing === '1') return;

  await telegram('setWebhook', {
    url: `${origin}/api/index?action=webhook`,
    secret_token: webhookSecret(),
    allowed_updates: ['message', 'pre_checkout_query', 'callback_query'],
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

function secureRandom() {
  const buf = randomBytes(6);
  const n = buf.readUIntBE(0, 6);
  return n / 281474976710656; // 2^48
}

function pickPrize() {
  const r = secureRandom() * 100;
  let sum = 0;
  for (const prize of PRIZES) {
    sum += prize.chance;
    if (r < sum) {
      return {
        id: prize.price > 0 ? randomBytes(8).toString('hex') : null,
        slot: prize.slot,
        key: prize.key,
        name: prize.name,
        price: prize.price,
        emoji: prize.emoji,
        nothing: prize.price === 0,
      };
    }
  }
  return { id: null, slot: 0, key: 'none', name: 'Ничего', price: 0, emoji: 'ZERO', nothing: true };
}

function generateCrashAt() {
  const u = secureRandom();
  if (u < 0.08) return 1.0; // instant crash is possible
  const v = (u - 0.08) / 0.92;
  const raw = 0.97 / Math.max(0.000001, 1 - v);
  return Math.min(100, Math.max(1.01, Math.floor(raw * 100) / 100));
}

function currentRocketMultiplier(round, nowMs = Date.now()) {
  if (!round?.startedAt) return 1;
  const elapsed = Math.max(0, (nowMs - Number(round.startedAt)) / 1000);
  return Math.max(1, Math.exp(ROCKET_GROWTH * elapsed));
}

function safeRocket(round, nowMs = Date.now()) {
  if (!round) return null;
  const current = currentRocketMultiplier(round, nowMs);
  const status = round.status || 'running';
  const out = {
    id: round.id,
    bet: Number(round.bet || 0),
    status,
    startedAt: Number(round.startedAt || 0),
    current: Number((status === 'running' ? Math.min(current, Number(round.crashAt || current)) : Number(round.finalMultiplier || round.crashAt || current)).toFixed(2)),
  };
  if (status === 'crashed') out.crashAt = Number(round.crashAt || 1);
  if (status === 'cashedout') {
    out.cashoutMultiplier = Number(round.cashoutMultiplier || 1);
    out.payout = Number(round.payout || 0);
  }
  return out;
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
    'withdrawals',
    'rocket',
    'betHistory',
  ]);
  const [balance, opened, sold, inventoryRaw, pendingRaw, withdrawalsRaw, rocketRaw, betHistoryRaw] = Array.isArray(values) ? values : [];
  let inventory = [];
  let pending = null;
  let withdrawals = [];
  let rocket = null;
  let betHistory = [];
  try { inventory = inventoryRaw ? JSON.parse(inventoryRaw) : []; } catch {}
  try { pending = pendingRaw ? JSON.parse(pendingRaw) : null; } catch {}
  try { withdrawals = withdrawalsRaw ? JSON.parse(withdrawalsRaw) : []; } catch {}
  try { rocket = rocketRaw ? JSON.parse(rocketRaw) : null; } catch {}
  try { betHistory = betHistoryRaw ? JSON.parse(betHistoryRaw) : []; } catch {}
  return {
    balance: Number(balance || 0),
    opened: Number(opened || 0),
    sold: Number(sold || 0),
    inventory: Array.isArray(inventory) ? inventory : [],
    pending,
    withdrawals: Array.isArray(withdrawals) ? withdrawals : [],
    rocket: safeRocket(rocket),
    betHistory: Array.isArray(betHistory) ? betHistory : [],
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

async function updateWithdrawal(requestId, status) {
  const raw = await redis(['GET', withdrawalKey(requestId)]);
  if (!raw) return null;
  let req;
  try { req = JSON.parse(raw); } catch { return null; }
  if (req.status !== 'pending') return req;

  const script = `
    local reqRaw = redis.call('GET', KEYS[2])
    if not reqRaw then return '' end
    local req = cjson.decode(reqRaw)
    if req.status ~= 'pending' then return reqRaw end

    local listRaw = redis.call('HGET', KEYS[1], 'withdrawals') or '[]'
    local list = cjson.decode(listRaw)
    local invRaw = redis.call('HGET', KEYS[1], 'inventory') or '[]'
    local inv = cjson.decode(invRaw)

    for i, row in ipairs(list) do
      if row.id == ARGV[1] then
        row.status = ARGV[2]
        row.updatedAt = tonumber(ARGV[3])
        if ARGV[2] == 'rejected' and row.gift then
          table.insert(inv, row.gift)
        end
      end
    end

    req.status = ARGV[2]
    req.updatedAt = tonumber(ARGV[3])
    redis.call('HSET', KEYS[1], 'withdrawals', cjson.encode(list))
    if ARGV[2] == 'rejected' then
      redis.call('HSET', KEYS[1], 'inventory', cjson.encode(inv))
    end
    redis.call('SET', KEYS[2], cjson.encode(req))
    return cjson.encode(req)
  `;

  const result = await redis([
    'EVAL', script, 2,
    userKey(req.userId),
    withdrawalKey(requestId),
    requestId,
    status,
    Date.now(),
  ]);
  if (!result) return null;
  try { return JSON.parse(result); } catch { return req; }
}

async function handleAdminCallback(q) {
  if (Number(q.from?.id) !== ADMIN_TELEGRAM_ID) {
    await telegram('answerCallbackQuery', { callback_query_id: q.id, text: 'Нет доступа', show_alert: true });
    return;
  }

  const m = /^wd:(done|reject):([a-f0-9]{12})$/.exec(String(q.data || ''));
  if (!m) {
    await telegram('answerCallbackQuery', { callback_query_id: q.id, text: 'Неизвестная команда' });
    return;
  }

  const status = m[1] === 'done' ? 'done' : 'rejected';
  const requestId = m[2];
  const req = await updateWithdrawal(requestId, status);
  if (!req) {
    await telegram('answerCallbackQuery', { callback_query_id: q.id, text: 'Заявка не найдена', show_alert: true });
    return;
  }

  const statusText = status === 'done' ? '✅ ОТПРАВЛЕНО' : '❌ ОТКЛОНЕНО — подарок возвращён пользователю';
  await telegram('answerCallbackQuery', { callback_query_id: q.id, text: statusText });

  if (q.message?.chat?.id && q.message?.message_id) {
    const original = String(q.message.text || '').replace(/\n\nСтатус:[\s\S]*$/, '');
    await telegram('editMessageText', {
      chat_id: q.message.chat.id,
      message_id: q.message.message_id,
      text: `${original}\n\nСтатус: ${statusText}`,
      reply_markup: { inline_keyboard: [] },
    }).catch(() => {});
  }
}

async function handleWebhook(request) {
  const secret = request.headers.get('x-telegram-bot-api-secret-token') || '';
  if (secret !== webhookSecret()) return reply({ ok: false }, 403);

  const update = await request.json();

  if (update.callback_query) {
    await handleAdminCallback(update.callback_query);
    return reply({ ok: true });
  }

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
          error_message: 'Не удалось проверить платёж. Попробуйте снова.',
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

async function createWithdrawal(user, itemId, request) {
  await ensureWebhook(request);
  const userId = Number(user.id);
  const requestId = randomBytes(6).toString('hex');
  const createdAt = Date.now();
  const displayName = [user.first_name, user.last_name].filter(Boolean).join(' ') || 'Пользователь';
  const username = user.username ? `@${user.username}` : 'нет username';

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
    if not found then return '' end

    local listRaw = redis.call('HGET', KEYS[1], 'withdrawals') or '[]'
    local list = cjson.decode(listRaw)
    local req = {
      id = ARGV[2],
      userId = tonumber(ARGV[3]),
      username = ARGV[4],
      displayName = ARGV[5],
      gift = found,
      status = 'pending',
      createdAt = tonumber(ARGV[6])
    }
    table.insert(list, 1, req)
    redis.call('HSET', KEYS[1], 'inventory', cjson.encode(out))
    redis.call('HSET', KEYS[1], 'withdrawals', cjson.encode(list))
    redis.call('SET', KEYS[2], cjson.encode(req))
    return cjson.encode(req)
  `;

  const raw = await redis([
    'EVAL', script, 2,
    userKey(userId),
    withdrawalKey(requestId),
    itemId,
    requestId,
    userId,
    username,
    displayName,
    createdAt,
  ]);
  if (!raw) return null;
  const req = JSON.parse(raw);

  const text = [
    '🎁 НОВАЯ ЗАЯВКА НА ВЫВОД',
    '',
    `Пользователь: ${displayName}`,
    `Username: ${username}`,
    `Telegram ID: ${userId}`,
    `Подарок: ${req.gift?.emoji || '🎁'} ${req.gift?.name || 'Gift'}`,
    `Стоимость: ${Number(req.gift?.price || 0)} ⭐`,
    `ID заявки: #${requestId}`,
  ].join('\n');

  try {
    await telegram('sendMessage', {
      chat_id: ADMIN_TELEGRAM_ID,
      text,
      reply_markup: {
        inline_keyboard: [[
          { text: '✅ Отправлено', callback_data: `wd:done:${requestId}` },
          { text: '❌ Отклонить', callback_data: `wd:reject:${requestId}` },
        ]],
      },
    });
  } catch (error) {
    // Return gift if admin notification could not be delivered.
    await updateWithdrawal(requestId, 'rejected').catch(() => {});
    throw error;
  }

  return req;
}

async function rocketStart(userId, bet) {
  if (!Number.isInteger(bet) || bet < 1 || bet > MAX_ROCKET_BET) return { error: 'BAD_BET' };
  const round = {
    id: randomBytes(8).toString('hex'),
    bet,
    crashAt: generateCrashAt(),
    startedAt: Date.now(),
    status: 'running',
  };

  const script = `
    local bal = tonumber(redis.call('HGET', KEYS[1], 'balance') or '0')
    local oldRaw = redis.call('HGET', KEYS[1], 'rocket')
    if oldRaw and oldRaw ~= '' then
      local old = cjson.decode(oldRaw)
      if old.status == 'running' then
        local elapsed = math.max(0, (tonumber(ARGV[3]) - tonumber(old.startedAt)) / 1000)
        local current = math.exp(tonumber(ARGV[4]) * elapsed)
        if current >= tonumber(old.crashAt) then
          old.status = 'crashed'
          old.finalMultiplier = tonumber(old.crashAt)
          old.crashedAt = tonumber(ARGV[3])
          if not old.historyRecorded then
            local histRaw = redis.call('HGET', KEYS[1], 'betHistory') or '[]'
            local hist = cjson.decode(histRaw)
            table.insert(hist, 1, {
              game = 'rocket',
              outcome = 'loss',
              bet = tonumber(old.bet),
              multiplier = tonumber(old.crashAt),
              payout = 0,
              profit = -tonumber(old.bet),
              startedAt = tonumber(old.startedAt),
              finishedAt = tonumber(ARGV[3])
            })
            if #hist > 50 then table.remove(hist) end
            redis.call('HSET', KEYS[1], 'betHistory', cjson.encode(hist))
            old.historyRecorded = true
          end
          redis.call('HSET', KEYS[1], 'rocket', cjson.encode(old))
        else
          return -2
        end
      end
    end
    if bal < tonumber(ARGV[1]) then return -1 end
    redis.call('HINCRBY', KEYS[1], 'balance', -tonumber(ARGV[1]))
    redis.call('HSET', KEYS[1], 'rocket', ARGV[2])
    return bal - tonumber(ARGV[1])
  `;
  const balance = Number(await redis([
    'EVAL', script, 1, userKey(userId), bet, JSON.stringify(round), Date.now(), ROCKET_GROWTH,
  ]));
  if (balance === -1) return { error: 'INSUFFICIENT_BALANCE' };
  if (balance === -2) return { error: 'ROCKET_ALREADY_RUNNING' };
  return { balance, rocket: safeRocket(round) };
}

async function rocketStatus(userId) {
  const now = Date.now();
  const script = `
    local raw = redis.call('HGET', KEYS[1], 'rocket')
    if not raw or raw == '' then return '' end
    local round = cjson.decode(raw)
    local elapsed = math.max(0, (tonumber(ARGV[1]) - tonumber(round.startedAt)) / 1000)
    local current = math.exp(tonumber(ARGV[2]) * elapsed)
    if round.status == 'running' and current >= tonumber(round.crashAt) then
      round.status = 'crashed'
      round.finalMultiplier = tonumber(round.crashAt)
      round.crashedAt = tonumber(ARGV[1])
      if not round.historyRecorded then
        local histRaw = redis.call('HGET', KEYS[1], 'betHistory') or '[]'
        local hist = cjson.decode(histRaw)
        table.insert(hist, 1, {
          game = 'rocket',
          outcome = 'loss',
          bet = tonumber(round.bet),
          multiplier = tonumber(round.crashAt),
          payout = 0,
          profit = -tonumber(round.bet),
          startedAt = tonumber(round.startedAt),
          finishedAt = tonumber(ARGV[1])
        })
        if #hist > 50 then table.remove(hist) end
        redis.call('HSET', KEYS[1], 'betHistory', cjson.encode(hist))
        round.historyRecorded = true
      end
      redis.call('HSET', KEYS[1], 'rocket', cjson.encode(round))
    end
    return cjson.encode(round)
  `;
  const raw = await redis(['EVAL', script, 1, userKey(userId), now, ROCKET_GROWTH]);
  if (!raw) return null;
  const round = JSON.parse(raw);
  return safeRocket(round, now);
}

async function rocketCashout(userId, roundId) {
  const now = Date.now();
  const script = `
    local raw = redis.call('HGET', KEYS[1], 'rocket')
    if not raw or raw == '' then return cjson.encode({code='NO_ROUND'}) end
    local round = cjson.decode(raw)
    if round.id ~= ARGV[1] then return cjson.encode({code='ROUND_MISMATCH'}) end
    if round.status ~= 'running' then return cjson.encode({code='NOT_RUNNING', status=round.status, crashAt=round.crashAt}) end

    local elapsed = math.max(0, (tonumber(ARGV[2]) - tonumber(round.startedAt)) / 1000)
    local current = math.exp(tonumber(ARGV[3]) * elapsed)
    if current >= tonumber(round.crashAt) then
      round.status = 'crashed'
      round.finalMultiplier = tonumber(round.crashAt)
      round.crashedAt = tonumber(ARGV[2])
      redis.call('HSET', KEYS[1], 'rocket', cjson.encode(round))
      return cjson.encode({code='CRASHED', crashAt=round.crashAt})
    end

    local mult = math.floor(current * 100) / 100
    if mult < 1 then mult = 1 end
    local payout = math.floor(tonumber(round.bet) * mult)
    round.status = 'cashedout'
    round.cashoutMultiplier = mult
    round.finalMultiplier = mult
    round.payout = payout
    round.cashedOutAt = tonumber(ARGV[2])
    redis.call('HINCRBY', KEYS[1], 'balance', payout)
    if not round.historyRecorded then
      local histRaw = redis.call('HGET', KEYS[1], 'betHistory') or '[]'
      local hist = cjson.decode(histRaw)
      table.insert(hist, 1, {
        game = 'rocket',
        outcome = 'win',
        bet = tonumber(round.bet),
        multiplier = tonumber(mult),
        payout = tonumber(payout),
        profit = tonumber(payout) - tonumber(round.bet),
        startedAt = tonumber(round.startedAt),
        finishedAt = tonumber(ARGV[2])
      })
      if #hist > 50 then table.remove(hist) end
      redis.call('HSET', KEYS[1], 'betHistory', cjson.encode(hist))
      round.historyRecorded = true
    end
    redis.call('HSET', KEYS[1], 'rocket', cjson.encode(round))
    local bal = tonumber(redis.call('HGET', KEYS[1], 'balance') or '0')
    return cjson.encode({code='OK', payout=payout, multiplier=mult, balance=bal})
  `;
  const raw = await redis(['EVAL', script, 1, userKey(userId), roundId, now, ROCKET_GROWTH]);
  return JSON.parse(raw);
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
      title: `Пополнение Lion — ${amount} ⭐`,
      description: `Внутренний баланс Lion: +${amount} ⭐`,
      payload: `lion:${userId}:${amount}:${nonce}`,
      provider_token: '',
      currency: 'XTR',
      prices: [{ label: `${amount} ⭐`, amount }],
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
      if ARGV[3] == '1' then
        redis.call('HDEL', KEYS[1], 'pending')
      else
        redis.call('HSET', KEYS[1], 'pending', ARGV[2])
      end
      return bal - tonumber(ARGV[1])
    `;
    const result = Number(await redis([
      'EVAL', script, 1, userKey(userId), CASE_COST, prizeJson, prize.nothing ? '1' : '0',
    ]));
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

  if (action === 'withdraw-gift') {
    const body = await request.json().catch(() => ({}));
    const itemId = String(body.id || '');
    if (!/^[a-f0-9]{16}$/.test(itemId)) return reply({ error: 'BAD_ITEM' }, 400);
    const req = await createWithdrawal(user, itemId, request);
    if (!req) return reply({ error: 'ITEM_NOT_FOUND' }, 404);
    return reply(await getState(userId));
  }

  if (action === 'rocket-start') {
    const body = await request.json().catch(() => ({}));
    const result = await rocketStart(userId, Number(body.bet));
    if (result.error === 'BAD_BET') return reply({ error: result.error }, 400);
    if (result.error === 'INSUFFICIENT_BALANCE') return reply({ error: result.error }, 402);
    if (result.error) return reply({ error: result.error }, 409);
    return reply(result);
  }

  if (action === 'rocket-status') {
    return reply({ rocket: await rocketStatus(userId) });
  }

  if (action === 'rocket-cashout') {
    const body = await request.json().catch(() => ({}));
    const roundId = String(body.roundId || '');
    if (!/^[a-f0-9]{16}$/.test(roundId)) return reply({ error: 'BAD_ROUND' }, 400);
    const result = await rocketCashout(userId, roundId);
    if (result.code === 'OK') return reply(result);
    if (result.code === 'CRASHED') return reply({ error: 'ROCKET_CRASHED', crashAt: result.crashAt }, 409);
    return reply({ error: result.code || 'ROCKET_ERROR' }, 409);
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

      if (!action) return reply({ ok: true, service: 'lion-api-v2' });
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

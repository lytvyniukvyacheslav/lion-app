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
const DAILY_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const TOPUPS = new Set([10, 50, 100, 200, 500, 1000]);
const ROCKET_GROWTH = 0.18;
const MAX_ROCKET_BET = 10000;
const PREMIUM_ROULETTE_COST = 70;
const MINES_CELLS = 9;
const MAX_MINES_BET = 10000;

const PREMIUM_PRIZES = [
  { slot: 0, key: 'premium-cake', name: 'Торт', price: 50, chance: 22, emoji: '🎂' },
  { slot: 1, key: 'premium-champagne', name: 'Шампанское', price: 50, chance: 22, emoji: '🍾' },
  { slot: 2, key: 'premium-bouquet', name: 'Букет', price: 50, chance: 22, emoji: '💐' },
  { slot: 3, key: 'premium-zero', name: 'Ничего', price: 0, chance: 12, emoji: 'ZERO', nothing: true },
  { slot: 4, key: 'premium-diamond', name: 'Алмаз', price: 100, chance: 10, emoji: '💎' },
  { slot: 5, key: 'premium-trophy', name: 'Кубок', price: 100, chance: 10, emoji: '🏆' },
  { slot: 6, key: 'premium-nft', name: 'Random NFT', price: 0, chance: 2, emoji: '🖼️', withdrawOnly: true },
];

const TASK_REWARD = 5;
const SHARE_TASK_REWARD = 5;
const SHARE_TASK_COOLDOWN_MS = 12 * 60 * 60 * 1000;
const TASKS = {
  channel: { chatId: '@Liongiftsnews', field: 'task_channel' },
  chat: { chatId: '@Liongiftchat', field: 'task_chat' },
};

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

// Free daily case: always gives a reward; total = 100%.
const DAILY_PRIZES = [
  { key: 'daily-star-1', type: 'stars', name: '1 звезда', amount: 1, chance: 37.5, emoji: '⭐' },
  { key: 'daily-star-2', type: 'stars', name: '2 звезды', amount: 2, chance: 25, emoji: '⭐' },
  { key: 'daily-star-3', type: 'stars', name: '3 звезды', amount: 3, chance: 18.75, emoji: '⭐' },
  { key: 'daily-star-4', type: 'stars', name: '4 звезды', amount: 4, chance: 12.5, emoji: '⭐' },
  { key: 'daily-bear', type: 'gift', name: 'Мишка', price: 15, chance: 6.25, emoji: '🧸' },
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
  const match = /^lion:(\d+):(10|50|100|200|500|1000):([a-f0-9]{16})$/.exec(String(payload || ''));
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

function pickDailyPrize() {
  const r = secureRandom() * 100;
  let sum = 0;
  for (const reward of DAILY_PRIZES) {
    sum += reward.chance;
    if (r < sum) {
      if (reward.type === 'stars') {
        return {
          id: null,
          key: reward.key,
          type: 'stars',
          name: reward.name,
          price: reward.amount,
          dailyStars: reward.amount,
          emoji: reward.emoji,
          creditOnly: true,
          nothing: false,
        };
      }
      return {
        id: randomBytes(8).toString('hex'),
        key: reward.key,
        type: 'gift',
        name: reward.name,
        price: reward.price,
        emoji: reward.emoji,
        creditOnly: false,
        nothing: false,
      };
    }
  }
  return { id: null, key: 'daily-star-1', type: 'stars', name: '1 звезда', price: 1, dailyStars: 1, emoji: '⭐', creditOnly: true, nothing: false };
}


function pickPremiumPrize() {
  const r = secureRandom() * 100;
  let sum = 0;
  for (const prize of PREMIUM_PRIZES) {
    sum += prize.chance;
    if (r < sum) {
      return {
        id: prize.nothing ? null : randomBytes(8).toString('hex'),
        slot: prize.slot,
        key: prize.key,
        name: prize.name,
        price: Number(prize.price || 0),
        emoji: prize.emoji,
        nothing: Boolean(prize.nothing),
        withdrawOnly: Boolean(prize.withdrawOnly),
        source: 'premium-roulette',
      };
    }
  }
  return { id: null, slot: 3, key: 'premium-zero', name: 'Ничего', price: 0, emoji: 'ZERO', nothing: true, source: 'premium-roulette' };
}

function minesMultiplier(mineCount, openedCount) {
  mineCount = Number(mineCount);
  openedCount = Number(openedCount);
  if (!Number.isInteger(mineCount) || mineCount < 1 || mineCount > 8 || openedCount <= 0) return 1;
  let mult = 1;
  for (let i = 0; i < openedCount; i++) {
    mult *= (MINES_CELLS - i) / (MINES_CELLS - mineCount - i);
  }
  return Math.floor(mult * 100) / 100;
}

function generateMinePositions(mineCount) {
  const cells = Array.from({ length: MINES_CELLS }, (_, i) => i);
  for (let i = cells.length - 1; i > 0; i--) {
    const j = Math.floor(secureRandom() * (i + 1));
    [cells[i], cells[j]] = [cells[j], cells[i]];
  }
  return cells.slice(0, mineCount).sort((a, b) => a - b);
}

function safeMines(round) {
  if (!round) return null;
  const opened = Array.isArray(round.opened) ? round.opened.map(Number) : [];
  const out = {
    id: String(round.id || ''),
    bet: Number(round.bet || 0),
    mineCount: Number(round.mineCount || 1),
    opened,
    status: String(round.status || 'running'),
    multiplier: minesMultiplier(round.mineCount, opened.length),
  };
  if (out.status === 'lost') {
    out.hit = Number(round.hit);
    out.mines = Array.isArray(round.minePositions) ? round.minePositions.map(Number) : [];
  }
  if (out.status === 'cashedout') {
    out.payout = Number(round.payout || 0);
    out.cashoutMultiplier = Number(round.cashoutMultiplier || out.multiplier);
  }
  return out;
}

async function minesStart(userId, bet, mineCount) {
  bet = Number(bet);
  mineCount = Number(mineCount);
  if (!Number.isInteger(bet) || bet < 1 || bet > MAX_MINES_BET) return { error: 'BAD_BET' };

  const round = {
    id: randomBytes(8).toString('hex'),
    bet,
    mineCount,
    minePositions: generateMinePositions(mineCount),
    opened: [],
    status: 'running',
    startedAt: Date.now(),
  };

  const script = `
    local bal = tonumber(redis.call('HGET', KEYS[1], 'balance') or '0')
    local oldRaw = redis.call('HGET', KEYS[1], 'mines')
    if oldRaw and oldRaw ~= '' then
      local old = cjson.decode(oldRaw)
      if old.status == 'running' then return cjson.encode({code='ACTIVE'}) end
    end
    if bal < tonumber(ARGV[1]) then return cjson.encode({code='NO_BALANCE', balance=bal}) end
    redis.call('HINCRBY', KEYS[1], 'balance', -tonumber(ARGV[1]))
    redis.call('HSET', KEYS[1], 'mines', ARGV[2])
    return cjson.encode({code='OK', balance=bal-tonumber(ARGV[1])})
  `;
  const raw = await redis(['EVAL', script, 1, userKey(userId), bet, JSON.stringify(round)]);
  const result = JSON.parse(raw);
  if (result.code === 'ACTIVE') return { error: 'MINES_ACTIVE' };
  if (result.code === 'NO_BALANCE') return { error: 'INSUFFICIENT_BALANCE', balance: Number(result.balance || 0) };
  return { balance: Number(result.balance || 0), mines: safeMines(round) };
}

async function minesOpen(userId, roundId, cell) {
  cell = Number(cell);
  if (!/^[a-f0-9]{16}$/.test(String(roundId || ''))) return { error: 'BAD_ROUND' };
  if (!Number.isInteger(cell) || cell < 0 || cell >= MINES_CELLS) return { error: 'BAD_CELL' };
  const now = Date.now();

  const script = `
    local raw = redis.call('HGET', KEYS[1], 'mines')
    if not raw or raw == '' then return cjson.encode({code='NO_ROUND'}) end
    local r = cjson.decode(raw)
    if r.id ~= ARGV[1] then return cjson.encode({code='BAD_ROUND'}) end
    if r.status ~= 'running' then return cjson.encode({code='NOT_RUNNING', round=r}) end
    local cell = tonumber(ARGV[2])
    for _,v in ipairs(r.opened or {}) do
      if tonumber(v) == cell then return cjson.encode({code='ALREADY', round=r}) end
    end
    local isMine = false
    for _,v in ipairs(r.minePositions or {}) do
      if tonumber(v) == cell then isMine = true break end
    end
    if isMine then
      r.status = 'lost'
      r.hit = cell
      r.finishedAt = tonumber(ARGV[3])
      local histRaw = redis.call('HGET', KEYS[1], 'betHistory') or '[]'
      local hist = cjson.decode(histRaw)
      table.insert(hist, 1, {
        game='mines', outcome='loss', bet=tonumber(r.bet), mineCount=tonumber(r.mineCount),
        opened=#(r.opened or {}), multiplier=0, payout=0, profit=-tonumber(r.bet),
        startedAt=tonumber(r.startedAt), finishedAt=tonumber(ARGV[3])
      })
      if #hist > 50 then table.remove(hist) end
      redis.call('HSET', KEYS[1], 'betHistory', cjson.encode(hist))
    else
      table.insert(r.opened, cell)
    end
    redis.call('HSET', KEYS[1], 'mines', cjson.encode(r))
    return cjson.encode({code=isMine and 'MINE' or 'SAFE', round=r})
  `;
  const raw = await redis(['EVAL', script, 1, userKey(userId), roundId, cell, now]);
  const result = JSON.parse(raw);
  if (result.round) result.mines = safeMines(result.round);
  return result;
}

async function minesCashout(userId, roundId) {
  const now = Date.now();
  const script = `
    local raw = redis.call('HGET', KEYS[1], 'mines')
    if not raw or raw == '' then return cjson.encode({code='NO_ROUND'}) end
    local r = cjson.decode(raw)
    if r.id ~= ARGV[1] then return cjson.encode({code='BAD_ROUND'}) end
    if r.status ~= 'running' then return cjson.encode({code='NOT_RUNNING'}) end
    local opened = #(r.opened or {})
    if opened < 1 then return cjson.encode({code='OPEN_FIRST'}) end

    local mult = 1
    for i=0,opened-1 do
      mult = mult * ((9-i) / (9-tonumber(r.mineCount)-i))
    end
    mult = math.floor(mult * 100) / 100
    local payout = math.floor(tonumber(r.bet) * mult)
    redis.call('HINCRBY', KEYS[1], 'balance', payout)
    r.status = 'cashedout'
    r.cashoutMultiplier = mult
    r.payout = payout
    r.finishedAt = tonumber(ARGV[2])
    redis.call('HSET', KEYS[1], 'mines', cjson.encode(r))

    local histRaw = redis.call('HGET', KEYS[1], 'betHistory') or '[]'
    local hist = cjson.decode(histRaw)
    table.insert(hist, 1, {
      game='mines', outcome='win', bet=tonumber(r.bet), mineCount=tonumber(r.mineCount),
      opened=opened, multiplier=mult, payout=payout, profit=payout-tonumber(r.bet),
      startedAt=tonumber(r.startedAt), finishedAt=tonumber(ARGV[2])
    })
    if #hist > 50 then table.remove(hist) end
    redis.call('HSET', KEYS[1], 'betHistory', cjson.encode(hist))
    local bal = tonumber(redis.call('HGET', KEYS[1], 'balance') or '0')
    return cjson.encode({code='OK', balance=bal, multiplier=mult, payout=payout, round=r})
  `;
  const raw = await redis(['EVAL', script, 1, userKey(userId), roundId, now]);
  const result = JSON.parse(raw);
  if (result.round) result.mines = safeMines(result.round);
  delete result.round;
  return result;
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
    'dailyLastOpened',
    'task_channel',
    'task_chat',
    'shareLastClaimed',
    'mines',
  ]);
  const [balance, opened, sold, inventoryRaw, pendingRaw, withdrawalsRaw, rocketRaw, betHistoryRaw, dailyLastOpenedRaw, taskChannelRaw, taskChatRaw, shareLastClaimedRaw, minesRaw] = Array.isArray(values) ? values : [];
  let inventory = [];
  let pending = null;
  let withdrawals = [];
  let rocket = null;
  let betHistory = [];
  let mines = null;
  const dailyLastOpened = Number(dailyLastOpenedRaw || 0);
  const dailyNextAt = dailyLastOpened > 0 ? dailyLastOpened + DAILY_COOLDOWN_MS : 0;
  const shareLastClaimed = Number(shareLastClaimedRaw || 0);
  const shareNextAt = shareLastClaimed > 0 ? shareLastClaimed + SHARE_TASK_COOLDOWN_MS : 0;
  try { inventory = inventoryRaw ? JSON.parse(inventoryRaw) : []; } catch {}
  try { pending = pendingRaw ? JSON.parse(pendingRaw) : null; } catch {}
  try { withdrawals = withdrawalsRaw ? JSON.parse(withdrawalsRaw) : []; } catch {}
  try { rocket = rocketRaw ? JSON.parse(rocketRaw) : null; } catch {}
  try { betHistory = betHistoryRaw ? JSON.parse(betHistoryRaw) : []; } catch {}
  try { mines = minesRaw ? JSON.parse(minesRaw) : null; } catch {}
  return {
    balance: Number(balance || 0),
    opened: Number(opened || 0),
    sold: Number(sold || 0),
    inventory: Array.isArray(inventory) ? inventory : [],
    pending,
    withdrawals: Array.isArray(withdrawals) ? withdrawals : [],
    rocket: safeRocket(rocket),
    mines: safeMines(mines),
    betHistory: Array.isArray(betHistory) ? betHistory : [],
    dailyNextAt,
    dailyAvailable: !dailyNextAt || Date.now() >= dailyNextAt,
    shareNextAt,
    shareAvailable: !shareNextAt || Date.now() >= shareNextAt,
    isAdmin: Number(userId) === ADMIN_TELEGRAM_ID,
    tasks: {
      channel: String(taskChannelRaw || '') === '1',
      chat: String(taskChatRaw || '') === '1',
    },
  };
}

function isTelegramMember(member) {
  const status = String(member?.status || '');
  if (['creator', 'administrator', 'member'].includes(status)) return true;
  if (status === 'restricted') return member?.is_member !== false;
  return false;
}

async function claimTask(userId, taskId) {
  const task = TASKS[taskId];
  if (!task) return { error: 'BAD_TASK' };

  let member;
  try {
    member = await telegram('getChatMember', {
      chat_id: task.chatId,
      user_id: userId,
    });
  } catch (error) {
    console.error('Task membership check failed:', taskId, error);
    return { error: 'TASK_CHECK_FAILED' };
  }

  if (!isTelegramMember(member)) {
    return { error: 'NOT_SUBSCRIBED' };
  }

  const script = `
    local claimed = redis.call('HGET', KEYS[1], ARGV[1])
    if claimed == '1' then
      local bal = tonumber(redis.call('HGET', KEYS[1], 'balance') or '0')
      return cjson.encode({already=true, balance=bal})
    end
    redis.call('HSET', KEYS[1], ARGV[1], '1')
    local bal = tonumber(redis.call('HINCRBY', KEYS[1], 'balance', tonumber(ARGV[2])))
    return cjson.encode({already=false, balance=bal})
  `;
  const raw = await redis([
    'EVAL', script, 1,
    userKey(userId),
    task.field,
    TASK_REWARD,
  ]);
  return JSON.parse(raw);
}


async function prepareShareTaskMessage(userId) {
  const prepared = await telegram('savePreparedInlineMessage', {
    user_id: userId,
    result: {
      type: 'article',
      id: randomBytes(8).toString('hex'),
      title: 'Lion Gift',
      description: 'Открой Lion и получай подарки ⭐',
      input_message_content: {
        message_text: '🦁 Lion Gift\n🎁 Кейсы и игры в Telegram\n⭐ Открыть Lion: https://t.me/Lion_app_bot',
      },
    },
    allow_user_chats: true,
    allow_group_chats: true,
    allow_channel_chats: true,
  });
  if (!prepared?.id) throw new Error('SHARE_PREPARE_FAILED');
  return prepared;
}

async function claimShareTask(userId) {
  const now = Date.now();
  const script = `
    local now = tonumber(ARGV[1])
    local cooldown = tonumber(ARGV[2])
    local reward = tonumber(ARGV[3])
    local last = tonumber(redis.call('HGET', KEYS[1], 'shareLastClaimed') or '0')
    if last > 0 and (now - last) < cooldown then
      local bal = tonumber(redis.call('HGET', KEYS[1], 'balance') or '0')
      return cjson.encode({code='COOLDOWN', nextAt=last+cooldown, balance=bal})
    end
    redis.call('HSET', KEYS[1], 'shareLastClaimed', now)
    local bal = tonumber(redis.call('HINCRBY', KEYS[1], 'balance', reward))
    return cjson.encode({code='OK', nextAt=now+cooldown, balance=bal})
  `;
  const raw = await redis(['EVAL', script, 1, userKey(userId), now, SHARE_TASK_COOLDOWN_MS, SHARE_TASK_REWARD]);
  return JSON.parse(raw);
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


function normalizePromoCode(value) {
  return String(value || '').trim().toUpperCase();
}
function promoKey(code) {
  return `lion:promo:${code}`;
}
function promoUsersKey(code) {
  return `lion:promo:${code}:users`;
}
function assertAdmin(userId) {
  if (Number(userId) !== ADMIN_TELEGRAM_ID) throw new Error('FORBIDDEN');
}
async function getPromo(code) {
  const values = await redis(['HMGET', promoKey(code), 'reward', 'limit', 'used', 'expiresAt', 'active', 'createdAt']);
  if (!Array.isArray(values) || values.every(v => v === null || typeof v === 'undefined')) return null;
  const [reward, limit, used, expiresAt, active, createdAt] = values;
  return {
    code,
    reward: Number(reward || 0),
    limit: Number(limit || 0),
    used: Number(used || 0),
    expiresAt: Number(expiresAt || 0),
    active: String(active || '0') === '1',
    createdAt: Number(createdAt || 0),
  };
}
async function listPromos() {
  const codesRaw = await redis(['SMEMBERS', 'lion:promos']);
  const codes = Array.isArray(codesRaw) ? codesRaw.map(normalizePromoCode).filter(Boolean) : [];
  const promos = [];
  for (const code of codes) {
    const promo = await getPromo(code);
    if (promo) promos.push(promo);
  }
  return promos.sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
}
async function activatePromo(userId, rawCode) {
  const code = normalizePromoCode(rawCode);
  if (!/^[A-Z0-9_-]{3,24}$/.test(code)) return { error: 'BAD_PROMO_CODE' };
  const now = Date.now();
  const script = `
    local reward = tonumber(redis.call('HGET', KEYS[1], 'reward') or '0')
    if reward <= 0 then return cjson.encode({code='PROMO_NOT_FOUND'}) end
    local active = redis.call('HGET', KEYS[1], 'active') or '0'
    if active ~= '1' then return cjson.encode({code='PROMO_INACTIVE'}) end
    local expiresAt = tonumber(redis.call('HGET', KEYS[1], 'expiresAt') or '0')
    if expiresAt > 0 and tonumber(ARGV[2]) >= expiresAt then return cjson.encode({code='PROMO_EXPIRED'}) end
    local lim = tonumber(redis.call('HGET', KEYS[1], 'limit') or '0')
    local used = tonumber(redis.call('HGET', KEYS[1], 'used') or '0')
    if lim > 0 and used >= lim then return cjson.encode({code='PROMO_LIMIT'}) end
    if redis.call('SISMEMBER', KEYS[3], ARGV[1]) == 1 then return cjson.encode({code='PROMO_ALREADY_USED'}) end
    redis.call('SADD', KEYS[3], ARGV[1])
    redis.call('HINCRBY', KEYS[1], 'used', 1)
    local bal = redis.call('HINCRBY', KEYS[2], 'balance', reward)
    return cjson.encode({code='OK', reward=reward, balance=bal})
  `;
  const raw = await redis(['EVAL', script, 3, promoKey(code), userKey(userId), promoUsersKey(code), String(userId), now]);
  const result = JSON.parse(raw);
  if (result.code !== 'OK') return { error: result.code };
  return { code, reward: Number(result.reward || 0), balance: Number(result.balance || 0) };
}

async function handleAction(request, action) {
  const user = authUser(request);
  const userId = Number(user.id);

  if (action === 'state') {
    return reply(await getState(userId));
  }

  if (action === 'activate-promo') {
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const body = await request.json().catch(() => ({}));
    const result = await activatePromo(userId, body.code);
    if (result.error) {
      const status = result.error === 'BAD_PROMO_CODE' ? 400 : result.error === 'PROMO_NOT_FOUND' ? 404 : 409;
      return reply({ error: result.error }, status);
    }
    const state = await getState(userId);
    return reply({ ...state, promoCode: result.code, promoReward: result.reward });
  }

  if (action === 'admin-list-promos') {
    assertAdmin(userId);
    return reply({ promos: await listPromos() });
  }

  if (action === 'admin-create-promo') {
    assertAdmin(userId);
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const body = await request.json().catch(() => ({}));
    const code = normalizePromoCode(body.code);
    const reward = Math.floor(Number(body.reward));
    const limit = Math.floor(Number(body.limit || 0));
    const expiresAt = Math.floor(Number(body.expiresAt || 0));
    const now = Date.now();
    if (!/^[A-Z0-9_-]{3,24}$/.test(code)) return reply({ error: 'BAD_PROMO_CODE' }, 400);
    if (!Number.isInteger(reward) || reward < 1 || reward > 100000) return reply({ error: 'BAD_PROMO_REWARD' }, 400);
    if (!Number.isInteger(limit) || limit < 0 || limit > 1000000) return reply({ error: 'BAD_PROMO_LIMIT' }, 400);
    if (expiresAt && (!Number.isFinite(expiresAt) || expiresAt <= now)) return reply({ error: 'BAD_PROMO_EXPIRY' }, 400);
    const existing = await redis(['EXISTS', promoKey(code)]);
    if (Number(existing) === 1) return reply({ error: 'PROMO_EXISTS' }, 409);
    await redis(['HSET', promoKey(code), 'reward', reward, 'limit', limit, 'used', 0, 'expiresAt', expiresAt || 0, 'active', 1, 'createdAt', now, 'createdBy', userId]);
    await redis(['SADD', 'lion:promos', code]);
    return reply({ promo: await getPromo(code) });
  }

  if (action === 'admin-set-promo-active') {
    assertAdmin(userId);
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const body = await request.json().catch(() => ({}));
    const code = normalizePromoCode(body.code);
    if (!/^[A-Z0-9_-]{3,24}$/.test(code)) return reply({ error: 'BAD_PROMO_CODE' }, 400);
    const exists = await redis(['EXISTS', promoKey(code)]);
    if (Number(exists) !== 1) return reply({ error: 'PROMO_NOT_FOUND' }, 404);
    await redis(['HSET', promoKey(code), 'active', body.active ? 1 : 0]);
    return reply({ promo: await getPromo(code) });
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

  if (action === 'prepare-share-task') {
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const state = await getState(userId);
    if (!state.shareAvailable) {
      return reply({ error: 'SHARE_COOLDOWN', nextAt: Number(state.shareNextAt || 0), balance: Number(state.balance || 0) }, 409);
    }
    try {
      const prepared = await prepareShareTaskMessage(userId);
      return reply({ preparedMessageId: prepared.id, expirationDate: Number(prepared.expiration_date || 0) });
    } catch (error) {
      console.error('prepare share task failed:', error);
      return reply({ error: 'SHARE_PREPARE_FAILED' }, 502);
    }
  }

  if (action === 'claim-share-task') {
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const result = await claimShareTask(userId);
    if (result.code === 'COOLDOWN') return reply({ error: 'SHARE_COOLDOWN', nextAt: Number(result.nextAt || 0), balance: Number(result.balance || 0) }, 409);
    const state = await getState(userId);
    return reply({ ...state, rewarded: true, reward: SHARE_TASK_REWARD });
  }

  if (action === 'check-task') {
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const body = await request.json().catch(() => ({}));
    const taskId = String(body.task || '');
    const result = await claimTask(userId, taskId);

    if (result.error === 'BAD_TASK') return reply({ error: 'BAD_TASK' }, 400);
    if (result.error === 'NOT_SUBSCRIBED') return reply({ error: 'NOT_SUBSCRIBED' }, 409);
    if (result.error === 'TASK_CHECK_FAILED') return reply({ error: 'TASK_CHECK_FAILED' }, 502);

    const state = await getState(userId);
    return reply({ ...state, taskAlready: Boolean(result.already), task: taskId, reward: TASK_REWARD });
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

  if (action === 'daily-case') {
    const prize = pickDailyPrize();
    const prizeJson = JSON.stringify(prize);
    const now = Date.now();
    const rewardType = prize.type === 'stars' ? 'stars' : 'gift';
    const rewardAmount = Number(prize.dailyStars || 0);
    const script = `
      local now = tonumber(ARGV[1])
      local cooldown = tonumber(ARGV[2])
      local rewardType = ARGV[3]
      local rewardAmount = tonumber(ARGV[4]) or 0
      local prizeJson = ARGV[5]

      local last = tonumber(redis.call('HGET', KEYS[1], 'dailyLastOpened') or '0')
      if last > 0 and (now - last) < cooldown then
        return cjson.encode({code='COOLDOWN', nextAt=last+cooldown})
      end

      if rewardType == 'gift' then
        local pending = redis.call('HGET', KEYS[1], 'pending')
        if pending and pending ~= '' then
          return cjson.encode({code='PENDING_PRIZE'})
        end
      end

      redis.call('HSET', KEYS[1], 'dailyLastOpened', now)
      redis.call('HINCRBY', KEYS[1], 'opened', 1)

      if rewardType == 'stars' then
        redis.call('HINCRBY', KEYS[1], 'balance', rewardAmount)
      else
        redis.call('HSET', KEYS[1], 'pending', prizeJson)
      end

      local bal = tonumber(redis.call('HGET', KEYS[1], 'balance') or '0')
      return cjson.encode({code='OK', balance=bal, nextAt=now+cooldown})
    `;
    const raw = await redis([
      'EVAL', script, 1, userKey(userId), now, DAILY_COOLDOWN_MS, rewardType, rewardAmount, prizeJson,
    ]);
    const result = JSON.parse(raw);
    if (result.code === 'COOLDOWN') return reply({ error: 'DAILY_COOLDOWN', nextAt: Number(result.nextAt || 0) }, 409);
    if (result.code === 'PENDING_PRIZE') return reply({ error: 'PENDING_PRIZE' }, 409);
    return reply({ prize, balance: Number(result.balance || 0), nextAt: Number(result.nextAt || 0) });
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


  if (action === 'premium-roulette') {
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const prize = pickPremiumPrize();
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
      'EVAL', script, 1, userKey(userId), PREMIUM_ROULETTE_COST, prizeJson, prize.nothing ? '1' : '0',
    ]));
    if (result === -1) return reply({ error: 'INSUFFICIENT_BALANCE', balance: (await getState(userId)).balance }, 402);
    if (result === -2) return reply({ error: 'PENDING_PRIZE' }, 409);
    return reply({ prize, balance: result });
  }

  if (action === 'mines-start') {
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const body = await request.json().catch(() => ({}));
    const result = await minesStart(userId, Number(body.bet), 1);
    if (result.error === 'BAD_BET' || result.error === 'BAD_MINES') return reply({ error: result.error }, 400);
    if (result.error === 'INSUFFICIENT_BALANCE') return reply({ error: result.error, balance: result.balance }, 402);
    if (result.error) return reply({ error: result.error }, 409);
    return reply(result);
  }

  if (action === 'mines-open') {
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const body = await request.json().catch(() => ({}));
    const result = await minesOpen(userId, String(body.roundId || ''), Number(body.cell));
    if (result.error) return reply({ error: result.error }, 400);
    if (result.code === 'MINE') return reply({ code: 'MINE', mines: result.mines });
    if (result.code === 'SAFE' || result.code === 'ALREADY') return reply({ code: result.code, mines: result.mines });
    return reply({ error: result.code || 'MINES_ERROR' }, 409);
  }

  if (action === 'mines-cashout') {
    if (request.method !== 'POST') return reply({ error: 'METHOD' }, 405);
    const body = await request.json().catch(() => ({}));
    const result = await minesCashout(userId, String(body.roundId || ''));
    if (result.code === 'OK') return reply(result);
    return reply({ error: result.code || 'MINES_ERROR' }, 409);
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
      if (code === 'FORBIDDEN') return reply({ error: 'FORBIDDEN' }, 403);
      console.error(error);
      return reply({ error: 'SERVER_ERROR' }, 500);
    }
  },
};

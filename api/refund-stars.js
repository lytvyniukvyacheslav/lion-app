const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const REFUND_ADMIN_SECRET = process.env.REFUND_ADMIN_SECRET || '';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

function getSecret(request) {
  const auth = request.headers.get('authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();

  const headerSecret = request.headers.get('x-refund-admin-secret');
  if (headerSecret) return headerSecret.trim();

  return '';
}

export default async function handler(request) {
  if (request.method !== 'POST') {
    return json({ ok: false, error: 'METHOD_NOT_ALLOWED' }, 405);
  }

  if (!BOT_TOKEN) {
    return json({ ok: false, error: 'TELEGRAM_BOT_TOKEN_NOT_CONFIGURED' }, 500);
  }

  if (!REFUND_ADMIN_SECRET) {
    return json({ ok: false, error: 'REFUND_ADMIN_SECRET_NOT_CONFIGURED' }, 500);
  }

  const suppliedSecret = getSecret(request);
  if (!suppliedSecret || suppliedSecret !== REFUND_ADMIN_SECRET) {
    return json({ ok: false, error: 'UNAUTHORIZED' }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'INVALID_JSON' }, 400);
  }

  const userId = Number(body?.user_id);
  const chargeId = String(body?.telegram_payment_charge_id || '').trim();

  if (!Number.isSafeInteger(userId) || userId <= 0) {
    return json({ ok: false, error: 'INVALID_USER_ID' }, 400);
  }

  if (!chargeId) {
    return json({ ok: false, error: 'MISSING_TELEGRAM_PAYMENT_CHARGE_ID' }, 400);
  }

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${BOT_TOKEN}/refundStarPayment`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          telegram_payment_charge_id: chargeId,
        }),
      }
    );

    const result = await response.json();

    if (!response.ok || !result?.ok) {
      return json(
        {
          ok: false,
          error: 'TELEGRAM_REFUND_FAILED',
          telegram: result,
        },
        502
      );
    }

    return json({
      ok: true,
      refunded: true,
      user_id: userId,
      telegram_payment_charge_id: chargeId,
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error: 'REFUND_REQUEST_FAILED',
        message: error instanceof Error ? error.message : String(error),
      },
      500
    );
  }
}

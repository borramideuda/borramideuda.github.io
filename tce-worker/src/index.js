/**
 * ═══════════════════════════════════════════════════════════
 * BORRAMIDEUDA — Cloudflare Worker v2
 * Backend de confirmación de pagos para el checkout hosteado de Efipay
 *
 * VARIABLES DE ENTORNO (Cloudflare Dashboard → Settings → Variables,
 * o `wrangler secret put NOMBRE` desde tce-worker/):
 *   EFIPAY_WEBHOOK_TOKEN → token de firma de webhooks de tu comercio Efipay
 *                          (Efipay → tu comercio → Webhooks). OBLIGATORIO:
 *                          sin esto, /webhook rechaza todas las notificaciones.
 *   BREVO_API_KEY      → API key de brevo.com (gratis 300 emails/día)
 *   OWNER_EMAIL        → email que recibe el reporte diario
 *   SENDER_EMAIL       → tu email verificado en Brevo
 *
 * KV NAMESPACE:
 *   PAGOS → estado de transacciones + registro de ventas diarias
 *
 * RUTAS:
 *   POST /webhook        → recibe notificaciones firmadas de Efipay
 *   POST /verificar       → el frontend consulta si el pago fue aprobado
 *   POST /registrar-email → registra el email del cliente tras volver del checkout
 *   GET  /health          → health check
 *
 * CRON: 0 13 * * * → 8am Colombia (UTC-5) — envía reporte diario de ventas
 *
 * El checkout de pago (número de tarjeta, CVV, PSE, etc.) lo maneja
 * enteramente el checkout hosteado de Efipay (EFIPAY_LINK en el frontend).
 * Este worker nunca ve ni procesa datos de tarjeta — solo confirma el
 * resultado vía webhook firmado.
 * ═══════════════════════════════════════════════════════════
 */

const BREVO_URL   = 'https://api.brevo.com/v3/smtp/email';
const PRECIO_COP  = 29900; // precio de venta — única fuente de verdad para reportes

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// ── Verificación de firma del webhook (HMAC-SHA256) ─────────
// Efipay firma cada webhook con un header `Signature` = HMAC-SHA256(rawBody, EFIPAY_WEBHOOK_TOKEN).
// Sin esto, cualquiera podría falsear un POST a /webhook y marcar una compra como pagada gratis.
async function verificarFirmaEfipay(rawBody, signatureHeader, secret) {
  if (!secret || !signatureHeader) return false;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rawBody));
  const expected = [...new Uint8Array(sigBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');

  // Comparación en tiempo constante para evitar timing attacks
  const recibida = signatureHeader.trim().toLowerCase();
  const esperada = expected.toLowerCase();
  if (recibida.length !== esperada.length) return false;
  let diff = 0;
  for (let i = 0; i < esperada.length; i++) diff |= recibida.charCodeAt(i) ^ esperada.charCodeAt(i);
  return diff === 0;
}

// ── Email: cross-sell MultaCheck ────────────────────────────
async function enviarEmailCrossSell(env, emailCliente, nombreCliente) {
  if (!env.BREVO_API_KEY || !emailCliente) return false;
  const nombre = nombreCliente ? nombreCliente.split(' ')[0] : 'hola';
  const html = `
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:30px 0;">
    <tr><td align="center">
      <table width="580" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
        <tr><td style="background:#b71c1c;padding:28px 32px;">
          <p style="margin:0;color:#ffffff;font-size:22px;font-weight:bold;">BorraMiDeuda ✓</p>
          <p style="margin:4px 0 0;color:#ffcdd2;font-size:13px;">Cartas legales para DataCrédito</p>
        </td></tr>
        <tr><td style="padding:32px;">
          <p style="font-size:17px;color:#222;margin-top:0;">¡Hola, ${nombre}! 👋</p>
          <p style="font-size:15px;color:#444;line-height:1.6;">Tus cartas legales están listas. Recuerda enviarlas a DataCrédito según las instrucciones.</p>
          <p style="font-size:15px;color:#444;line-height:1.6;">Otra cosa que te puede servir: <strong>¿sabes si tu vehículo tiene multas de tránsito sin pagar?</strong> Las multas sin pagar generan intereses y pueden generar más reportes negativos.</p>
          <p style="font-size:15px;color:#444;line-height:1.6;"><strong>MultaCheck</strong> te permite consultar el historial de multas de cualquier placa en segundos — por solo <strong>$9.900 COP</strong>.</p>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
            <tr><td align="center">
              <a href="https://multacheckv1.netlify.app" style="background:#1a237e;color:#ffffff;text-decoration:none;font-size:16px;font-weight:bold;padding:14px 32px;border-radius:6px;display:inline-block;">
                Consultar multas →
              </a>
            </td></tr>
          </table>
          <p style="font-size:13px;color:#888;line-height:1.5;">Este es un servicio adicional. No estás obligado a nada.</p>
        </td></tr>
        <tr><td style="background:#f9f9f9;padding:16px 32px;border-top:1px solid #eeeeee;">
          <p style="margin:0;font-size:12px;color:#aaa;text-align:center;">BorraMiDeuda — Colombia · <a href="https://borramideuda.github.io" style="color:#aaa;">borramideuda.github.io</a></p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  try {
    const resp = await fetch(BREVO_URL, {
      method:  'POST',
      headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender:      { name: 'BorraMiDeuda', email: env.SENDER_EMAIL || 'notificaciones@borramideuda.co' },
        to:          [{ email: emailCliente }],
        subject:     '¿Tu vehículo tiene multas sin pagar?',
        htmlContent: html,
      }),
    });
    console.log('Email cross-sell enviado:', emailCliente, resp.status);
    return resp.ok;
  } catch (e) {
    console.error('Error enviando email cross-sell:', e.message);
    return false;
  }
}

// ── Reporte diario al dueño ─────────────────────────────────
async function enviarReporteDiario(env, fecha, datos) {
  if (!env.BREVO_API_KEY || !env.OWNER_EMAIL) return;
  const { ventas = 0, total = 0 } = datos;
  const totalFmt = new Intl.NumberFormat('es-CO', { style: 'currency', currency: 'COP', minimumFractionDigits: 0 }).format(total);
  const html = `
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:30px 0;">
  <table width="540" cellpadding="0" cellspacing="0" style="margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
    <tr><td style="background:#b71c1c;padding:24px 28px;">
      <p style="margin:0;color:#fff;font-size:20px;font-weight:bold;">📊 Reporte BorraMiDeuda</p>
      <p style="margin:4px 0 0;color:#ffcdd2;font-size:13px;">${fecha}</p>
    </td></tr>
    <tr><td style="padding:28px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="text-align:center;padding:20px;background:#ffebee;border-radius:8px;">
            <p style="margin:0;font-size:36px;font-weight:bold;color:#b71c1c;">${ventas}</p>
            <p style="margin:4px 0 0;color:#555;font-size:14px;">Ventas ayer</p>
          </td>
          <td width="20"></td>
          <td style="text-align:center;padding:20px;background:#e8f5e9;border-radius:8px;">
            <p style="margin:0;font-size:28px;font-weight:bold;color:#1b5e20;">${totalFmt}</p>
            <p style="margin:4px 0 0;color:#555;font-size:14px;">Ingresos ayer</p>
          </td>
        </tr>
      </table>
      <p style="margin-top:24px;font-size:14px;color:#666;">Meta mensual: <strong>$75.000.000 COP</strong> (2.509 ventas)</p>
      <p style="font-size:14px;color:#666;margin-bottom:0;">Para llegar a la meta: necesitas <strong>${Math.max(0, Math.ceil((75000000 - total) / PRECIO_COP))}</strong> ventas más este mes. 🚀</p>
    </td></tr>
    <tr><td style="background:#f9f9f9;padding:14px 28px;border-top:1px solid #eee;">
      <p style="margin:0;font-size:11px;color:#aaa;text-align:center;">Reporte automático de BorraMiDeuda — Generado a las 8am Colombia</p>
    </td></tr>
  </table>
</body>
</html>`;

  try {
    await fetch(BREVO_URL, {
      method:  'POST',
      headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender:      { name: 'BorraMiDeuda Reporte', email: env.SENDER_EMAIL || 'notificaciones@borramideuda.co' },
        to:          [{ email: env.OWNER_EMAIL }],
        subject:     `BorraMiDeuda — ${ventas} ventas ayer (${fecha})`,
        htmlContent: html,
      }),
    });
    console.log('Reporte diario enviado a', env.OWNER_EMAIL);
  } catch (e) {
    console.error('Error enviando reporte diario:', e.message);
  }
}

// ── Fecha Colombia (UTC-5) ─────────────────────────────────
function fechaColombia(ts = Date.now()) {
  return new Date(ts - 5 * 3600 * 1000).toISOString().slice(0, 10);
}

// ── Agrega las ventas de un día listando las claves venta:{fecha}:* ──
// Cada venta se guarda bajo su propia clave (ver /webhook), así que agregar
// aquí evita la condición de carrera de un contador compartido get→modify→put.
async function agregarVentasDelDia(env, fecha) {
  let ventas = 0, total = 0;
  let cursor;
  do {
    const page = await env.PAGOS.list({ prefix: `venta:${fecha}:`, cursor });
    for (const k of page.keys) {
      const raw = await env.PAGOS.get(k.name);
      if (!raw) continue;
      const v = JSON.parse(raw);
      ventas += 1;
      total  += v.monto || PRECIO_COP;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return { ventas, total };
}

export default {
  // ─────────────────────────────────────────────────────────
  // CRON TRIGGER — 8am Colombia todos los días
  // ─────────────────────────────────────────────────────────
  async scheduled(event, env, ctx) {
    const ayer = fechaColombia(Date.now() - 86400000);
    console.log('Cron BorraMiDeuda para fecha:', ayer);

    const datos = env.PAGOS ? await agregarVentasDelDia(env, ayer) : { ventas: 0, total: 0 };
    await enviarReporteDiario(env, ayer, datos);
  },

  // ─────────────────────────────────────────────────────────
  // FETCH — manejo de requests HTTP
  // ─────────────────────────────────────────────────────────
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    if (path === '/health' || path === '/') {
      return json({ ok: true, servicio: 'BorraMiDeuda Worker v2' });
    }

    // ── POST /webhook ─────────────────────────────────────────
    if (path === '/webhook' && request.method === 'POST') {
      try {
        const rawBody = await request.text();

        const firmaOk = await verificarFirmaEfipay(
          rawBody,
          request.headers.get('Signature'),
          env.EFIPAY_WEBHOOK_TOKEN
        );
        if (!firmaOk) {
          console.error('Webhook rechazado: firma inválida o EFIPAY_WEBHOOK_TOKEN no configurado');
          return json({ ok: false, error: 'Firma inválida' }, 401);
        }

        const body = JSON.parse(rawBody);
        console.log('Webhook Efipay:', rawBody.slice(0, 300));

        const tx          = body?.transaction || body;
        const transactionId = tx?.transaction_id || tx?.id || '';
        const status        = tx?.status || '';
        const referencia    = tx?.reference || tx?.external_reference || String(transactionId);
        const monto          = Number(tx?.amount ?? tx?.value_cop) || PRECIO_COP;

        const estadosAprobados = ['Aprobada', 'APPROVED', 'approved', 'success', 'SUCCESS', 'paid', 'PAID'];
        const aprobado = estadosAprobados.includes(status);

        if (env.PAGOS && referencia) {
          // Recuperar datos previos (incluyendo email)
          const prevRaw = await env.PAGOS.get(`pago:${referencia}`);
          const prev    = prevRaw ? JSON.parse(prevRaw) : {};
          // El checkout hosteado de Efipay pide el email en un campo propio
          // ("Formulario adicional") y lo devuelve en el webhook como reference_1 —
          // no depende de que el cliente vuelva al sitio. Si no viene ahí,
          // probamos los campos estándar que también documenta Efipay.
          const refEmail = (tx?.reference_1 && /@/.test(tx.reference_1)) ? tx.reference_1 : '';
          const email   = prev.email || refEmail || tx?.customer_payer?.email || tx?.transaction_details?.email || '';
          const nombre  = prev.nombre || tx?.customer_payer?.name || '';

          const datoActualizado = JSON.stringify({ referencia, transactionId, status, aprobado, email, nombre, timestamp: Date.now(), raw: body });

          await env.PAGOS.put(`pago:${referencia}`, datoActualizado, { expirationTtl: 86400 * 7 });
          if (transactionId && String(transactionId) !== referencia) {
            await env.PAGOS.put(`pago:${transactionId}`, datoActualizado, { expirationTtl: 86400 * 7 });
          }

          // Registrar venta del día (clave propia — sin condición de carrera) y
          // enviar email cross-sell si acaba de aprobarse
          if (aprobado && !prev.aprobado) {
            const hoy = fechaColombia();
            await env.PAGOS.put(
              `venta:${hoy}:${referencia}`,
              JSON.stringify({ referencia, monto, timestamp: Date.now() }),
              { expirationTtl: 86400 * 7 }
            );

            if (email) {
              const yaEnviado = await env.PAGOS.get(`email_sent:${referencia}`);
              if (!yaEnviado) {
                const ok = await enviarEmailCrossSell(env, email, nombre);
                if (ok) await env.PAGOS.put(`email_sent:${referencia}`, '1', { expirationTtl: 86400 * 3 });
              }
            }
          }
        }

        return json({ ok: true });
      } catch (err) {
        console.error('Error webhook:', err.message);
        return json({ ok: false }, 500);
      }
    }

    // ── POST /verificar ───────────────────────────────────────
    if (path === '/verificar' && request.method === 'POST') {
      try {
        const body = await request.json();
        const ref  = body.referencia || body.transaccionId || '';
        if (!ref) return json({ valido: false, error: 'Referencia requerida' }, 400);

        let datos = null;
        if (env.PAGOS) {
          const raw = await env.PAGOS.get(`pago:${ref}`);
          if (raw) datos = JSON.parse(raw);
        }

        if (!datos) return json({ valido: false, estado: 'PENDING', mensaje: 'Pago no registrado aún' });

        return json({ valido: datos.aprobado, estado: datos.status, transaccionId: datos.transactionId });
      } catch (err) {
        return json({ valido: false, error: err.message }, 500);
      }
    }

    // ── POST /registrar-email ─────────────────────────────────
    // El frontend llama esto en cuanto vuelve de Efipay con el transaction_id
    // real, porque el checkout hosteado de Efipay no pasa por el webhook con
    // el email del cliente ya asociado hasta que Efipay lo confirma.
    if (path === '/registrar-email' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { referencia, email, nombre } = body;
        if (!referencia || !email) return json({ ok: false, error: 'referencia y email requeridos' }, 400);

        if (env.PAGOS) {
          const prevRaw = await env.PAGOS.get(`pago:${referencia}`);
          const prev = prevRaw ? JSON.parse(prevRaw) : {};
          const actualizado = { ...prev, referencia, email, nombre: nombre || prev.nombre || '', timestamp: Date.now() };
          await env.PAGOS.put(`pago:${referencia}`, JSON.stringify(actualizado), { expirationTtl: 86400 * 7 });

          // Si el webhook ya había aprobado el pago antes de que llegara el email, enviar ahora
          if (prev.aprobado) {
            const yaEnviado = await env.PAGOS.get(`email_sent:${referencia}`);
            if (!yaEnviado) {
              const ok = await enviarEmailCrossSell(env, email, nombre);
              if (ok) await env.PAGOS.put(`email_sent:${referencia}`, '1', { expirationTtl: 86400 * 3 });
            }
          }
        }
        return json({ ok: true });
      } catch (err) {
        return json({ ok: false, error: err.message }, 500);
      }
    }

    return new Response('Not found', { status: 404, headers: CORS });
  },
};

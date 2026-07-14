import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
} from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import worker from "../src";

async function firmar(rawBody, secret) {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);
	const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
	return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function postWebhook(bodyObj, { secret = env.EFIPAY_WEBHOOK_TOKEN, signature } = {}) {
	const rawBody = JSON.stringify(bodyObj);
	const headers = { "Content-Type": "application/json" };
	if (signature !== null) {
		headers.Signature = signature ?? (await firmar(rawBody, secret));
	}
	const request = new Request("https://example.com/webhook", {
		method: "POST",
		headers,
		body: rawBody,
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

describe("GET /health", () => {
	it("responde ok con el nombre del servicio", async () => {
		const request = new Request("https://example.com/health");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toEqual({ ok: true, servicio: "BorraMiDeuda Worker v2" });
	});
});

describe("Rutas no existentes", () => {
	it("responde 404", async () => {
		const request = new Request("https://example.com/no-existe");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(404);
	});
});

describe("POST /webhook — verificación de firma", () => {
	it("rechaza el webhook si no trae header Signature", async () => {
		const response = await postWebhook(
			{ transaction: { transaction_id: "t1", reference: "ref1", status: "Aprobada" } },
			{ signature: null }
		);
		expect(response.status).toBe(401);
		const data = await response.json();
		expect(data.ok).toBe(false);
	});

	it("rechaza el webhook si la firma no coincide", async () => {
		const response = await postWebhook(
			{ transaction: { transaction_id: "t2", reference: "ref2", status: "Aprobada" } },
			{ signature: "0000000000000000000000000000000000000000000000000000000000000000" }
		);
		expect(response.status).toBe(401);
	});

	it("acepta el webhook cuando la firma es correcta y marca la referencia como aprobada", async () => {
		const referencia = "ref-aprobada-1";
		const response = await postWebhook({
			transaction: {
				transaction_id: "tx-1",
				reference: referencia,
				status: "Aprobada",
				amount: 29900,
				customer_payer: { email: "cliente@example.com", name: "Cliente Prueba" },
			},
		});
		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toEqual({ ok: true });

		// /verificar debe reflejar el pago aprobado
		const verReq = new Request("https://example.com/verificar", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ referencia }),
		});
		const ctx = createExecutionContext();
		const verResp = await worker.fetch(verReq, env, ctx);
		await waitOnExecutionContext(ctx);
		const verData = await verResp.json();
		expect(verData.valido).toBe(true);
	});
});

describe("POST /verificar", () => {
	it("requiere una referencia", async () => {
		const request = new Request("https://example.com/verificar", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(400);
	});

	it("responde PENDING para una referencia desconocida", async () => {
		const request = new Request("https://example.com/verificar", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ referencia: "no-existe-" + Date.now() }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		const data = await response.json();
		expect(data.valido).toBe(false);
		expect(data.estado).toBe("PENDING");
	});
});

describe("POST /registrar-email", () => {
	it("requiere referencia y email", async () => {
		const request = new Request("https://example.com/registrar-email", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ referencia: "x" }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(400);
	});
});

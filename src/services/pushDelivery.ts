import { buildApnsPayload, isInvalidTokenReason, sendApns } from "../apns";
import { auditEvent, findActiveRegistrations, isRegistrationCurrent, markRegistrationError, markRegistrationSuccess } from "../repository";
import type { AppEnv, ClientType, PushEventRequest, PushFailureSummary } from "../types";

export interface PushDeliveryResult {
	matched: number;
	delivered: number;
	failed: number;
	audit: Promise<void>;
}

export async function deliverPushEvent(env: AppEnv, input: PushEventRequest): Promise<PushDeliveryResult> {
	const registrations = await findActiveRegistrations(env.DB, input);
	let delivered = 0;
	let failed = 0;
	const failures = new Map<string, PushFailureSummary>();
	const registrationChanged = new Error("registration_changed");

	for (const registration of registrations) {
		const payload = buildApnsPayload({ ...input, locale: registration.locale });
		const result = await sendApns(env, registration, payload, async (endpoint, options) => {
			if (!await isRegistrationCurrent(env.DB, registration)) throw registrationChanged;
			return fetch(endpoint, options);
		}).catch((error: unknown) => {
			if (error === registrationChanged) return null;
			throw error;
		});
		if (!result) continue;
		if (result.ok) {
			delivered += 1;
			await markRegistrationSuccess(env.DB, registration);
		} else {
			failed += 1;
			incrementFailure(failures, registration.client_type, result.status, result.reason ?? `HTTP_${result.status}`);
			await markRegistrationError(
				env.DB,
				registration,
				result.reason ?? `HTTP_${result.status}`,
				isInvalidTokenReason(result.status, result.reason),
			);
		}
	}

	const audit = auditEvent(env.DB, {
		ha_install_id: input.ha_install_id,
		event_type: input.event_type,
		client_type: input.client_types?.length === 1 ? input.client_types[0] : undefined,
		target: delivered + failed,
		success: delivered,
		error: failed,
		failures: [...failures.values()],
	});

	return { matched: delivered + failed, delivered, failed, audit };
}

function incrementFailure(failures: Map<string, PushFailureSummary>, clientType: ClientType, status: number, reason: string): void {
	const key = `${clientType}:${status}:${reason}`;
	const existing = failures.get(key);
	if (existing) {
		existing.count += 1;
		return;
	}
	failures.set(key, { client_type: clientType, status, reason, count: 1 });
}

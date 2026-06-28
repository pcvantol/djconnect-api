import { buildApnsPayload, isInvalidTokenReason, sendApns } from "../apns";
import { auditEvent, findActiveRegistrations, markRegistrationError, markRegistrationSuccess } from "../repository";
import type { AppEnv, PushEventRequest } from "../types";

export interface PushDeliveryResult {
	matched: number;
	delivered: number;
	failed: number;
	audit: Promise<void>;
}

export async function deliverPushEvent(env: AppEnv, input: PushEventRequest): Promise<PushDeliveryResult> {
	const registrations = await findActiveRegistrations(env.DB, input);
	const payload = buildApnsPayload(input);
	let delivered = 0;
	let failed = 0;

	for (const registration of registrations) {
		const result = await sendApns(env, registration, payload);
		if (result.ok) {
			delivered += 1;
			await markRegistrationSuccess(env.DB, registration.id);
		} else {
			failed += 1;
			await markRegistrationError(
				env.DB,
				registration.id,
				result.reason ?? `HTTP_${result.status}`,
				isInvalidTokenReason(result.status, result.reason),
			);
		}
	}

	const audit = auditEvent(env.DB, {
		ha_install_id: input.ha_install_id,
		event_type: input.event_type,
		client_type: input.client_types?.length === 1 ? input.client_types[0] : undefined,
		target: registrations.length,
		success: delivered,
		error: failed,
	});

	return { matched: registrations.length, delivered, failed, audit };
}

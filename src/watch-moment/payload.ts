import { sha256Hex } from "../crypto";
import type { MomentEvent } from "./wire";

const copy = {
	en: ["New DJ Moment", "Your DJ has something new for you."],
	nl: ["Nieuw DJ Moment", "Je DJ heeft iets nieuws voor je."],
	de: ["Neuer DJ-Moment", "Dein DJ hat etwas Neues für dich."],
	fr: ["Nouveau Moment DJ", "Votre DJ a du nouveau pour vous."],
	es: ["Nuevo Momento DJ", "Tu DJ tiene algo nuevo para ti."],
} as const;

/** API proposes a structured internal destination, never a URL or an access grant. */
export async function buildMomentNotification(event: MomentEvent, recipientBinding: string, expiresAt: number) {
	const language = event.locale.toLowerCase().split(/[-_]/)[0] as keyof typeof copy;
	const [title, body] = copy[language] ?? copy.en;
	const collapse = await sha256Hex(JSON.stringify([recipientBinding, event.ha_install_id, event.session_id, event.moment_id]));
	const thread = await sha256Hex(JSON.stringify([recipientBinding, event.ha_install_id, event.session_id]));
	const payload = {
		aps: { alert: { title: `DJConnect · ${title}`, body }, sound: "default", category: "DJCONNECT_MOMENT_V1", "thread-id": thread },
		version: event.version, event_type: event.event_type, event_id: event.event_id,
		open_target: "dj_moment", session_id: event.session_id, moment_id: event.moment_id,
		transport_expires_at_ms: expiresAt,
	};
	return { payload, headers: { "apns-collapse-id": collapse, "apns-expiration": String(Math.floor(expiresAt / 1000)), "apns-priority": "10" } };
}

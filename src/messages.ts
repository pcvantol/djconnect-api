import type { EventType } from "./types";

export const SUPPORTED_LANGUAGES = ["en", "nl", "de", "fr", "es"] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

export const DEFAULT_LANGUAGE: SupportedLanguage = "en";

export type ApiMessageKey =
	| "admin_auth_required"
	| "auth_required"
	| "bootstrap_proof_expired"
	| "bootstrap_proof_used"
	| "bootstrap_rate_limited"
	| "install_auth_required"
	| "install_id_mismatch"
	| "install_token_scope_mismatch"
	| "internal_error"
	| "invalid_apns_environment"
	| "invalid_bootstrap_proof"
	| "invalid_client_type"
	| "invalid_disabled"
	| "invalid_event_type"
	| "invalid_ha_user_hash"
	| "invalid_invalid"
	| "invalid_json"
	| "invalid_label"
	| "invalid_pagination"
	| "invalid_reason"
	| "invalid_ttl_seconds"
	| "missing_apns_token"
	| "missing_bootstrap_proof"
	| "missing_device_id"
	| "missing_ha_install_id"
	| "missing_token_id"
	| "not_found"
	| "relay_secret_not_configured"
	| "unsafe_payload"
	| "unsupported_media_type";

export type ApnsMessageKey =
	| "apns.ask_dj_confirm.title"
	| "apns.ask_dj_confirm.body"
	| "apns.ask_dj_response.title"
	| "apns.ask_dj_response.body"
	| "apns.playback_change.title"
	| "apns.playback_change.body";

export type MessageKey = ApiMessageKey | ApnsMessageKey;

export const MESSAGES: Record<SupportedLanguage, Record<MessageKey, string>> = {
	en: {
		admin_auth_required: "Operator authorization is required.",
		auth_required: "Authorization is required.",
		bootstrap_proof_expired: "The bootstrap proof has expired.",
		bootstrap_proof_used: "The bootstrap proof was already used.",
		bootstrap_rate_limited: "Too many bootstrap attempts. Try again later.",
		install_auth_required: "Install authorization is required.",
		install_id_mismatch: "The install does not match the bootstrap proof.",
		install_token_scope_mismatch: "The install token does not match this install.",
		internal_error: "The request could not be completed.",
		invalid_apns_environment: "The APNs environment is invalid.",
		invalid_bootstrap_proof: "The bootstrap proof is invalid.",
		invalid_client_type: "The client type is invalid.",
		invalid_disabled: "The disabled filter is invalid.",
		invalid_event_type: "The event type is invalid.",
		invalid_ha_user_hash: "The user hash is invalid.",
		invalid_invalid: "The invalid filter is invalid.",
		invalid_json: "The request body must be valid JSON.",
		invalid_label: "The label is invalid.",
		invalid_pagination: "The pagination parameters are invalid.",
		invalid_reason: "The revoke reason is invalid.",
		invalid_ttl_seconds: "The time-to-live value is invalid.",
		missing_apns_token: "The APNs token is required.",
		missing_bootstrap_proof: "The bootstrap proof is required.",
		missing_device_id: "The device ID is required.",
		missing_ha_install_id: "The install ID is required.",
		missing_token_id: "The token ID is required.",
		not_found: "The requested endpoint was not found.",
		relay_secret_not_configured: "The relay secret is not configured.",
		unsafe_payload: "The request contains unsupported sensitive fields.",
		unsupported_media_type: "The request must use application/json.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ is waiting for your choice.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ has replied.",
		"apns.playback_change.title": "DJConnect",
		"apns.playback_change.body": "DJConnect has an update.",
	},
	nl: {
		admin_auth_required: "Operatorautorisatie is vereist.",
		auth_required: "Autorisatie is vereist.",
		bootstrap_proof_expired: "Het bootstrapbewijs is verlopen.",
		bootstrap_proof_used: "Het bootstrapbewijs is al gebruikt.",
		bootstrap_rate_limited: "Te veel bootstrappogingen. Probeer het later opnieuw.",
		install_auth_required: "Installatieautorisatie is vereist.",
		install_id_mismatch: "De installatie komt niet overeen met het bootstrapbewijs.",
		install_token_scope_mismatch: "Het installatietoken hoort niet bij deze installatie.",
		internal_error: "Het verzoek kon niet worden voltooid.",
		invalid_apns_environment: "De APNs-omgeving is ongeldig.",
		invalid_bootstrap_proof: "Het bootstrapbewijs is ongeldig.",
		invalid_client_type: "Het clienttype is ongeldig.",
		invalid_disabled: "Het disabled-filter is ongeldig.",
		invalid_event_type: "Het gebeurtenistype is ongeldig.",
		invalid_ha_user_hash: "De gebruikershash is ongeldig.",
		invalid_invalid: "Het invalid-filter is ongeldig.",
		invalid_json: "De request body moet geldige JSON zijn.",
		invalid_label: "Het label is ongeldig.",
		invalid_pagination: "De paginaparameters zijn ongeldig.",
		invalid_reason: "De intrekkingsreden is ongeldig.",
		invalid_ttl_seconds: "De geldigheidsduur is ongeldig.",
		missing_apns_token: "Het APNs-token is vereist.",
		missing_bootstrap_proof: "Het bootstrapbewijs is vereist.",
		missing_device_id: "De apparaat-ID is vereist.",
		missing_ha_install_id: "De installatie-ID is vereist.",
		missing_token_id: "De token-ID is vereist.",
		not_found: "Het gevraagde endpoint is niet gevonden.",
		relay_secret_not_configured: "Het relaygeheim is niet geconfigureerd.",
		unsafe_payload: "Het verzoek bevat niet-ondersteunde gevoelige velden.",
		unsupported_media_type: "Het verzoek moet application/json gebruiken.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ wacht op je keuze.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ heeft geantwoord.",
		"apns.playback_change.title": "DJConnect",
		"apns.playback_change.body": "DJConnect heeft een update.",
	},
	de: {
		admin_auth_required: "Operatorautorisierung ist erforderlich.",
		auth_required: "Autorisierung ist erforderlich.",
		bootstrap_proof_expired: "Der Bootstrap-Nachweis ist abgelaufen.",
		bootstrap_proof_used: "Der Bootstrap-Nachweis wurde bereits verwendet.",
		bootstrap_rate_limited: "Zu viele Bootstrap-Versuche. Bitte versuche es später erneut.",
		install_auth_required: "Installationsautorisierung ist erforderlich.",
		install_id_mismatch: "Die Installation passt nicht zum Bootstrap-Nachweis.",
		install_token_scope_mismatch: "Das Installationstoken passt nicht zu dieser Installation.",
		internal_error: "Die Anfrage konnte nicht abgeschlossen werden.",
		invalid_apns_environment: "Die APNs-Umgebung ist ungültig.",
		invalid_bootstrap_proof: "Der Bootstrap-Nachweis ist ungültig.",
		invalid_client_type: "Der Clienttyp ist ungültig.",
		invalid_disabled: "Der disabled-Filter ist ungültig.",
		invalid_event_type: "Der Ereignistyp ist ungültig.",
		invalid_ha_user_hash: "Der Benutzerhash ist ungültig.",
		invalid_invalid: "Der invalid-Filter ist ungültig.",
		invalid_json: "Der Request Body muss gültiges JSON sein.",
		invalid_label: "Das Label ist ungültig.",
		invalid_pagination: "Die Paginierungsparameter sind ungültig.",
		invalid_reason: "Der Widerrufsgrund ist ungültig.",
		invalid_ttl_seconds: "Die Gueltigkeitsdauer ist ungueltig.",
		missing_apns_token: "Das APNs-Token ist erforderlich.",
		missing_bootstrap_proof: "Der Bootstrap-Nachweis ist erforderlich.",
		missing_device_id: "Die Geraete-ID ist erforderlich.",
		missing_ha_install_id: "Die Installations-ID ist erforderlich.",
		missing_token_id: "Die Token-ID ist erforderlich.",
		not_found: "Der angeforderte Endpunkt wurde nicht gefunden.",
		relay_secret_not_configured: "Das Relay-Geheimnis ist nicht konfiguriert.",
		unsafe_payload: "Die Anfrage enthält nicht unterstützte sensible Felder.",
		unsupported_media_type: "Die Anfrage muss application/json verwenden.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ wartet auf deine Auswahl.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ hat geantwortet.",
		"apns.playback_change.title": "DJConnect",
		"apns.playback_change.body": "DJConnect hat ein Update.",
	},
	fr: {
		admin_auth_required: "L'autorisation operateur est requise.",
		auth_required: "Une autorisation est requise.",
		bootstrap_proof_expired: "La preuve de demarrage a expire.",
		bootstrap_proof_used: "La preuve de demarrage a deja ete utilisee.",
		bootstrap_rate_limited: "Trop de tentatives de demarrage. Reessayez plus tard.",
		install_auth_required: "L'autorisation de l'installation est requise.",
		install_id_mismatch: "L'installation ne correspond pas a la preuve de demarrage.",
		install_token_scope_mismatch: "Le jeton d'installation ne correspond pas a cette installation.",
		internal_error: "La requete n'a pas pu etre terminee.",
		invalid_apns_environment: "L'environnement APNs est invalide.",
		invalid_bootstrap_proof: "La preuve de demarrage est invalide.",
		invalid_client_type: "Le type de client est invalide.",
		invalid_disabled: "Le filtre disabled est invalide.",
		invalid_event_type: "Le type d'evenement est invalide.",
		invalid_ha_user_hash: "Le hash utilisateur est invalide.",
		invalid_invalid: "Le filtre invalid est invalide.",
		invalid_json: "Le corps de la requete doit etre du JSON valide.",
		invalid_label: "Le libelle est invalide.",
		invalid_pagination: "Les parametres de pagination sont invalides.",
		invalid_reason: "Le motif de revocation est invalide.",
		invalid_ttl_seconds: "La duree de validite est invalide.",
		missing_apns_token: "Le jeton APNs est requis.",
		missing_bootstrap_proof: "La preuve de demarrage est requise.",
		missing_device_id: "L'ID de l'appareil est requis.",
		missing_ha_install_id: "L'ID d'installation est requis.",
		missing_token_id: "L'ID du jeton est requis.",
		not_found: "Le point de terminaison demande est introuvable.",
		relay_secret_not_configured: "Le secret du relais n'est pas configure.",
		unsafe_payload: "La requete contient des champs sensibles non pris en charge.",
		unsupported_media_type: "La requete doit utiliser application/json.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ attend votre choix.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ a repondu.",
		"apns.playback_change.title": "DJConnect",
		"apns.playback_change.body": "DJConnect a une mise a jour.",
	},
	es: {
		admin_auth_required: "Se requiere autorizacion de operador.",
		auth_required: "Se requiere autorizacion.",
		bootstrap_proof_expired: "La prueba de arranque ha caducado.",
		bootstrap_proof_used: "La prueba de arranque ya se uso.",
		bootstrap_rate_limited: "Demasiados intentos de arranque. Intentalo de nuevo mas tarde.",
		install_auth_required: "Se requiere autorizacion de instalacion.",
		install_id_mismatch: "La instalacion no coincide con la prueba de arranque.",
		install_token_scope_mismatch: "El token de instalacion no coincide con esta instalacion.",
		internal_error: "No se pudo completar la solicitud.",
		invalid_apns_environment: "El entorno APNs no es valido.",
		invalid_bootstrap_proof: "La prueba de arranque no es valida.",
		invalid_client_type: "El tipo de cliente no es valido.",
		invalid_disabled: "El filtro disabled no es valido.",
		invalid_event_type: "El tipo de evento no es valido.",
		invalid_ha_user_hash: "El hash de usuario no es valido.",
		invalid_invalid: "El filtro invalid no es valido.",
		invalid_json: "El cuerpo de la solicitud debe ser JSON valido.",
		invalid_label: "La etiqueta no es valida.",
		invalid_pagination: "Los parametros de paginacion no son validos.",
		invalid_reason: "El motivo de revocacion no es valido.",
		invalid_ttl_seconds: "La duracion de validez no es valida.",
		missing_apns_token: "Se requiere el token APNs.",
		missing_bootstrap_proof: "Se requiere la prueba de arranque.",
		missing_device_id: "Se requiere el ID del dispositivo.",
		missing_ha_install_id: "Se requiere el ID de instalacion.",
		missing_token_id: "Se requiere el ID del token.",
		not_found: "No se encontro el endpoint solicitado.",
		relay_secret_not_configured: "El secreto del relay no esta configurado.",
		unsafe_payload: "La solicitud contiene campos sensibles no admitidos.",
		unsupported_media_type: "La solicitud debe usar application/json.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ espera tu eleccion.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ ha respondido.",
		"apns.playback_change.title": "DJConnect",
		"apns.playback_change.body": "DJConnect tiene una actualizacion.",
	},
};

const APNS_KEYS: Record<EventType, { title: ApnsMessageKey; body: ApnsMessageKey }> = {
	ask_dj_confirm: {
		title: "apns.ask_dj_confirm.title",
		body: "apns.ask_dj_confirm.body",
	},
	ask_dj_response: {
		title: "apns.ask_dj_response.title",
		body: "apns.ask_dj_response.body",
	},
	playback_change: {
		title: "apns.playback_change.title",
		body: "apns.playback_change.body",
	},
};

export function message(key: MessageKey, language: SupportedLanguage = DEFAULT_LANGUAGE): string {
	return MESSAGES[language][key] ?? MESSAGES[DEFAULT_LANGUAGE][key];
}

export function notificationText(eventType: EventType, language: SupportedLanguage = DEFAULT_LANGUAGE): { title: string; body: string } {
	const keys = APNS_KEYS[eventType];
	return {
		title: message(keys.title, language),
		body: message(keys.body, language),
	};
}

export function resolveSupportedLanguage(value: string | null | undefined): SupportedLanguage {
	if (!value) return DEFAULT_LANGUAGE;
	const normalized = value.toLowerCase().split("-")[0];
	return isSupportedLanguage(normalized) ? normalized : DEFAULT_LANGUAGE;
}

export function preferredResponseLanguage(request: Request): SupportedLanguage | undefined {
	const explicit = new URL(request.url).searchParams.get("lang");
	if (explicit) return resolveSupportedLanguage(explicit);
	const acceptLanguage = request.headers.get("accept-language");
	if (!acceptLanguage) return undefined;
	return resolveSupportedLanguage(parseAcceptLanguage(acceptLanguage));
}

export function assertCompleteTranslations(): void {
	const expected = Object.keys(MESSAGES[DEFAULT_LANGUAGE]).sort();
	for (const language of SUPPORTED_LANGUAGES) {
		const keys = Object.keys(MESSAGES[language]).sort();
		if (keys.join("\n") !== expected.join("\n")) {
			throw new Error(`Missing or extra message keys for ${language}`);
		}
		for (const key of keys) {
			if (MESSAGES[language][key as MessageKey].trim() === "") {
				throw new Error(`Empty message for ${language}.${key}`);
			}
		}
	}
}

function isSupportedLanguage(value: string): value is SupportedLanguage {
	return SUPPORTED_LANGUAGES.includes(value as SupportedLanguage);
}

function parseAcceptLanguage(header: string): string | undefined {
	return header
		.split(",")
		.map((part) => part.trim().split(";")[0]?.trim())
		.find(Boolean);
}

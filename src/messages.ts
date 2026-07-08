import type { EventType } from "./types";

export const SUPPORTED_LANGUAGES = ["en", "nl", "de", "fr", "es"] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

export const DEFAULT_LANGUAGE: SupportedLanguage = "en";

export type ApiMessageKey =
	| "admin_auth_required"
	| "auth_required"
	| "bootstrap_proof_unavailable"
	| "bootstrap_proof_expired"
	| "bootstrap_proof_used"
	| "bootstrap_rate_limited"
	| "install_auth_required"
	| "install_id_mismatch"
	| "install_token_scope_mismatch"
	| "internal_error"
	| "invalid_apns_environment"
	| "invalid_app_bundle_id"
	| "invalid_bootstrap_proof"
	| "invalid_client_type"
	| "invalid_disabled"
	| "invalid_event_type"
	| "invalid_ha_user_hash"
	| "invalid_invalid"
	| "invalid_json"
	| "invalid_push_environment"
	| "invalid_label"
	| "invalid_pagination"
	| "invalid_reason"
	| "invalid_ttl_seconds"
	| "missing_apns_token"
	| "missing_bootstrap_proof"
	| "missing_device_id"
	| "missing_ha_install_id"
	| "missing_pairing_session_id"
	| "missing_token_id"
	| "not_found"
	| "pairing_issuer_secret_not_configured"
	| "relay_secret_not_configured"
	| "unsafe_payload"
	| "unsupported_media_type";

export type ApnsMessageKey =
	| "apns.ask_dj_confirm.title"
	| "apns.ask_dj_confirm.body"
	| "apns.ask_dj_response.title"
	| "apns.ask_dj_response.body";

export type MessageKey = ApiMessageKey | ApnsMessageKey;

export const MESSAGES: Record<SupportedLanguage, Record<MessageKey, string>> = {
	en: {
		admin_auth_required: "Operator authorization is required.",
		auth_required: "Authorization is required.",
		bootstrap_proof_unavailable: "A bootstrap proof is not available for this pairing context.",
		bootstrap_proof_expired: "The bootstrap proof has expired.",
		bootstrap_proof_used: "The bootstrap proof was already used.",
		bootstrap_rate_limited: "Too many bootstrap attempts. Try again later.",
		install_auth_required: "Install authorization is required.",
		install_id_mismatch: "The install does not match the bootstrap proof.",
		install_token_scope_mismatch: "The install token does not match this install.",
		internal_error: "The request could not be completed.",
		invalid_apns_environment: "The APNs environment is invalid.",
		invalid_app_bundle_id: "The app bundle ID is invalid.",
		invalid_bootstrap_proof: "The bootstrap proof is invalid.",
		invalid_client_type: "The client type is invalid.",
		invalid_disabled: "The disabled filter is invalid.",
		invalid_event_type: "The event type is invalid.",
		invalid_ha_user_hash: "The user hash is invalid.",
		invalid_invalid: "The invalid filter is invalid.",
		invalid_json: "The request body must be valid JSON.",
		invalid_push_environment: "The push environment is invalid.",
		invalid_label: "The label is invalid.",
		invalid_pagination: "The pagination parameters are invalid.",
		invalid_reason: "The revoke reason is invalid.",
		invalid_ttl_seconds: "The time-to-live value is invalid.",
		missing_apns_token: "The APNs token is required.",
		missing_bootstrap_proof: "The bootstrap proof is required.",
		missing_device_id: "The device ID is required.",
		missing_ha_install_id: "The install ID is required.",
		missing_pairing_session_id: "The pairing session ID is required.",
		missing_token_id: "The token ID is required.",
		not_found: "The requested endpoint was not found.",
		pairing_issuer_secret_not_configured: "The pairing issuer secret is not configured.",
		relay_secret_not_configured: "The relay secret is not configured.",
		unsafe_payload: "The request contains unsupported sensitive fields.",
		unsupported_media_type: "The request must use application/json.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ is waiting for your choice.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ has replied.",
	},
	nl: {
		admin_auth_required: "Operatorautorisatie is vereist.",
		auth_required: "Autorisatie is vereist.",
		bootstrap_proof_unavailable: "Er is geen bootstrapbewijs beschikbaar voor deze koppelcontext.",
		bootstrap_proof_expired: "Het bootstrapbewijs is verlopen.",
		bootstrap_proof_used: "Het bootstrapbewijs is al gebruikt.",
		bootstrap_rate_limited: "Te veel bootstrappogingen. Probeer het later opnieuw.",
		install_auth_required: "Installatieautorisatie is vereist.",
		install_id_mismatch: "De installatie komt niet overeen met het bootstrapbewijs.",
		install_token_scope_mismatch: "Het installatietoken hoort niet bij deze installatie.",
		internal_error: "Het verzoek kon niet worden voltooid.",
		invalid_apns_environment: "De APNs-omgeving is ongeldig.",
		invalid_app_bundle_id: "De app bundle-ID is ongeldig.",
		invalid_bootstrap_proof: "Het bootstrapbewijs is ongeldig.",
		invalid_client_type: "Het clienttype is ongeldig.",
		invalid_disabled: "Het disabled-filter is ongeldig.",
		invalid_event_type: "Het gebeurtenistype is ongeldig.",
		invalid_ha_user_hash: "De gebruikershash is ongeldig.",
		invalid_invalid: "Het invalid-filter is ongeldig.",
		invalid_json: "De request body moet geldige JSON zijn.",
		invalid_push_environment: "De pushomgeving is ongeldig.",
		invalid_label: "Het label is ongeldig.",
		invalid_pagination: "De paginaparameters zijn ongeldig.",
		invalid_reason: "De intrekkingsreden is ongeldig.",
		invalid_ttl_seconds: "De geldigheidsduur is ongeldig.",
		missing_apns_token: "Het APNs-token is vereist.",
		missing_bootstrap_proof: "Het bootstrapbewijs is vereist.",
		missing_device_id: "De apparaat-ID is vereist.",
		missing_ha_install_id: "De installatie-ID is vereist.",
		missing_pairing_session_id: "De pairing session-ID is vereist.",
		missing_token_id: "De token-ID is vereist.",
		not_found: "Het gevraagde endpoint is niet gevonden.",
		pairing_issuer_secret_not_configured: "Het pairing-issuergeheim is niet geconfigureerd.",
		relay_secret_not_configured: "Het relaygeheim is niet geconfigureerd.",
		unsafe_payload: "Het verzoek bevat niet-ondersteunde gevoelige velden.",
		unsupported_media_type: "Het verzoek moet application/json gebruiken.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ wacht op je keuze.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ heeft geantwoord.",
	},
	de: {
		admin_auth_required: "Operatorautorisierung ist erforderlich.",
		auth_required: "Autorisierung ist erforderlich.",
		bootstrap_proof_unavailable: "Für diesen Pairing-Kontext ist kein Bootstrap-Nachweis verfügbar.",
		bootstrap_proof_expired: "Der Bootstrap-Nachweis ist abgelaufen.",
		bootstrap_proof_used: "Der Bootstrap-Nachweis wurde bereits verwendet.",
		bootstrap_rate_limited: "Zu viele Bootstrap-Versuche. Bitte versuche es später erneut.",
		install_auth_required: "Installationsautorisierung ist erforderlich.",
		install_id_mismatch: "Die Installation passt nicht zum Bootstrap-Nachweis.",
		install_token_scope_mismatch: "Das Installationstoken passt nicht zu dieser Installation.",
		internal_error: "Die Anfrage konnte nicht abgeschlossen werden.",
		invalid_apns_environment: "Die APNs-Umgebung ist ungültig.",
		invalid_app_bundle_id: "Die App-Bundle-ID ist ungültig.",
		invalid_bootstrap_proof: "Der Bootstrap-Nachweis ist ungültig.",
		invalid_client_type: "Der Clienttyp ist ungültig.",
		invalid_disabled: "Der disabled-Filter ist ungültig.",
		invalid_event_type: "Der Ereignistyp ist ungültig.",
		invalid_ha_user_hash: "Der Benutzerhash ist ungültig.",
		invalid_invalid: "Der invalid-Filter ist ungültig.",
		invalid_json: "Der Request Body muss gültiges JSON sein.",
		invalid_push_environment: "Die Push-Umgebung ist ungültig.",
		invalid_label: "Das Label ist ungültig.",
		invalid_pagination: "Die Paginierungsparameter sind ungültig.",
		invalid_reason: "Der Widerrufsgrund ist ungültig.",
		invalid_ttl_seconds: "Die Gültigkeitsdauer ist ungültig.",
		missing_apns_token: "Das APNs-Token ist erforderlich.",
		missing_bootstrap_proof: "Der Bootstrap-Nachweis ist erforderlich.",
		missing_device_id: "Die Geräte-ID ist erforderlich.",
		missing_ha_install_id: "Die Installations-ID ist erforderlich.",
		missing_pairing_session_id: "Die Pairing-Session-ID ist erforderlich.",
		missing_token_id: "Die Token-ID ist erforderlich.",
		not_found: "Der angeforderte Endpunkt wurde nicht gefunden.",
		pairing_issuer_secret_not_configured: "Das Pairing-Issuer-Geheimnis ist nicht konfiguriert.",
		relay_secret_not_configured: "Das Relay-Geheimnis ist nicht konfiguriert.",
		unsafe_payload: "Die Anfrage enthält nicht unterstützte sensible Felder.",
		unsupported_media_type: "Die Anfrage muss application/json verwenden.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ wartet auf deine Auswahl.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ hat geantwortet.",
	},
	fr: {
		admin_auth_required: "L'autorisation opérateur est requise.",
		auth_required: "Une autorisation est requise.",
		bootstrap_proof_unavailable: "Aucune preuve de démarrage n'est disponible pour ce contexte de jumelage.",
		bootstrap_proof_expired: "La preuve de démarrage a expiré.",
		bootstrap_proof_used: "La preuve de démarrage a déjà été utilisée.",
		bootstrap_rate_limited: "Trop de tentatives de démarrage. Réessayez plus tard.",
		install_auth_required: "L'autorisation de l'installation est requise.",
		install_id_mismatch: "L'installation ne correspond pas à la preuve de démarrage.",
		install_token_scope_mismatch: "Le jeton d'installation ne correspond pas à cette installation.",
		internal_error: "La requête n'a pas pu être terminée.",
		invalid_apns_environment: "L'environnement APNs est invalide.",
		invalid_app_bundle_id: "L'ID de bundle de l'app est invalide.",
		invalid_bootstrap_proof: "La preuve de démarrage est invalide.",
		invalid_client_type: "Le type de client est invalide.",
		invalid_disabled: "Le filtre disabled est invalide.",
		invalid_event_type: "Le type d'événement est invalide.",
		invalid_ha_user_hash: "Le hash utilisateur est invalide.",
		invalid_invalid: "Le filtre invalid est invalide.",
		invalid_json: "Le corps de la requête doit être du JSON valide.",
		invalid_push_environment: "L'environnement push est invalide.",
		invalid_label: "Le libellé est invalide.",
		invalid_pagination: "Les paramètres de pagination sont invalides.",
		invalid_reason: "Le motif de révocation est invalide.",
		invalid_ttl_seconds: "La durée de validité est invalide.",
		missing_apns_token: "Le jeton APNs est requis.",
		missing_bootstrap_proof: "La preuve de démarrage est requise.",
		missing_device_id: "L'ID de l'appareil est requis.",
		missing_ha_install_id: "L'ID d'installation est requis.",
		missing_pairing_session_id: "L'ID de session de jumelage est requis.",
		missing_token_id: "L'ID du jeton est requis.",
		not_found: "Le point de terminaison demandé est introuvable.",
		pairing_issuer_secret_not_configured: "Le secret de l'émetteur de jumelage n'est pas configuré.",
		relay_secret_not_configured: "Le secret du relais n'est pas configuré.",
		unsafe_payload: "La requête contient des champs sensibles non pris en charge.",
		unsupported_media_type: "La requête doit utiliser application/json.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ attend votre choix.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ a répondu.",
	},
	es: {
		admin_auth_required: "Se requiere autorización de operador.",
		auth_required: "Se requiere autorización.",
		bootstrap_proof_unavailable: "No hay una prueba de arranque disponible para este contexto de emparejamiento.",
		bootstrap_proof_expired: "La prueba de arranque ha caducado.",
		bootstrap_proof_used: "La prueba de arranque ya se usó.",
		bootstrap_rate_limited: "Demasiados intentos de arranque. Inténtalo de nuevo más tarde.",
		install_auth_required: "Se requiere autorización de instalación.",
		install_id_mismatch: "La instalación no coincide con la prueba de arranque.",
		install_token_scope_mismatch: "El token de instalación no coincide con esta instalación.",
		internal_error: "No se pudo completar la solicitud.",
		invalid_apns_environment: "El entorno APNs no es válido.",
		invalid_app_bundle_id: "El ID de paquete de la app no es válido.",
		invalid_bootstrap_proof: "La prueba de arranque no es válida.",
		invalid_client_type: "El tipo de cliente no es válido.",
		invalid_disabled: "El filtro disabled no es válido.",
		invalid_event_type: "El tipo de evento no es válido.",
		invalid_ha_user_hash: "El hash de usuario no es válido.",
		invalid_invalid: "El filtro invalid no es válido.",
		invalid_json: "El cuerpo de la solicitud debe ser JSON válido.",
		invalid_push_environment: "El entorno push no es válido.",
		invalid_label: "La etiqueta no es válida.",
		invalid_pagination: "Los parámetros de paginación no son válidos.",
		invalid_reason: "El motivo de revocación no es válido.",
		invalid_ttl_seconds: "La duración de validez no es válida.",
		missing_apns_token: "Se requiere el token APNs.",
		missing_bootstrap_proof: "Se requiere la prueba de arranque.",
		missing_device_id: "Se requiere el ID del dispositivo.",
		missing_ha_install_id: "Se requiere el ID de instalación.",
		missing_pairing_session_id: "Se requiere el ID de sesión de emparejamiento.",
		missing_token_id: "Se requiere el ID del token.",
		not_found: "No se encontró el endpoint solicitado.",
		pairing_issuer_secret_not_configured: "El secreto del emisor de emparejamiento no está configurado.",
		relay_secret_not_configured: "El secreto del relay no está configurado.",
		unsafe_payload: "La solicitud contiene campos sensibles no admitidos.",
		unsupported_media_type: "La solicitud debe usar application/json.",
		"apns.ask_dj_confirm.title": "Ask DJ",
		"apns.ask_dj_confirm.body": "Ask DJ espera tu elección.",
		"apns.ask_dj_response.title": "Ask DJ",
		"apns.ask_dj_response.body": "Ask DJ ha respondido.",
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
	return parseAcceptLanguages(acceptLanguage)
		.map((tag) => tag.toLowerCase().split("-")[0])
		.find(isSupportedLanguage) ?? DEFAULT_LANGUAGE;
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

function parseAcceptLanguages(header: string): string[] {
	return header
		.split(",")
		.map(parseLanguageRange)
		.filter((range): range is { tag: string; quality: number; index: number } => range !== undefined)
		.sort((left, right) => right.quality - left.quality || left.index - right.index)
		.map((range) => range.tag);
}

function parseLanguageRange(part: string, index: number): { tag: string; quality: number; index: number } | undefined {
	const [rawTag, ...params] = part.trim().split(";").map((value) => value.trim());
	if (!rawTag || rawTag === "*") return undefined;
	const qualityParam = params.find((param) => param.toLowerCase().startsWith("q="));
	const quality = qualityParam ? Number(qualityParam.slice(2)) : 1;
	if (!Number.isFinite(quality) || quality <= 0 || quality > 1) return undefined;
	return { tag: rawTag, quality, index };
}

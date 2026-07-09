export type ClientType = "ios" | "macos" | "watchos";
export type BootstrapClientType = ClientType;
export type ApnsEnvironment = "sandbox" | "production";
export type EventType = "ask_dj_response" | "ask_dj_confirm";
export type AnnouncementDelivery = "client_device" | "both" | "ha_speaker" | "text_only";
export type AnnouncementSpeakerDelivery = "attempted" | "none";

export interface AnnouncementHint {
	delivery?: AnnouncementDelivery;
	audio_available?: boolean;
	speaker_delivery?: AnnouncementSpeakerDelivery;
}

export interface AppEnv {
	DB: D1Database;
	APNS_TEAM_ID: string;
	APNS_KEY_ID: string;
	APNS_PRIVATE_KEY: string;
	APNS_TOPIC_IOS: string;
	APNS_TOPIC_MACOS: string;
	APNS_TOPIC_WATCHOS: string;
	APNS_ENVIRONMENT: ApnsEnvironment;
	APNS_TOKEN_ENCRYPTION_KEY: string;
	DJCONNECT_RELAY_SECRET: string;
	DJCONNECT_PAIRING_ISSUER_SECRET?: string;
	DJCONNECT_SMOKE_TEST_MODE?: string;
}

export interface InstallTokenRequest {
	ha_install_id: string;
	ha_user_hash?: string;
	label?: string;
	integration?: string;
	integration_version?: string;
	client_type?: BootstrapClientType;
	device_id?: string;
	bootstrap_proof?: string;
	pairing_session_id?: string;
}

export interface BootstrapProofRequest {
	ha_install_id?: string;
	integration?: string;
	integration_version?: string;
	client_type: BootstrapClientType;
	device_id: string;
	pairing_session_id?: string;
	app_bundle_id?: string;
	push_environment?: ApnsEnvironment;
	ttl_seconds?: number;
}

export interface RotateInstallTokenRequest {
	ha_install_id: string;
}

export interface RevokeInstallTokenRequest {
	ha_install_id: string;
	token_id: string;
	reason?: string;
}

export interface RegisterRequest {
	ha_install_id: string;
	ha_user_hash?: string;
	device_id: string;
	client_type: ClientType;
	apns_token: string;
	apns_environment?: ApnsEnvironment;
	app_bundle_id?: string;
	app_version?: string;
	locale?: string;
	categories?: string[];
}

export interface UnregisterRequest {
	ha_install_id: string;
	device_id: string;
	client_type?: ClientType;
	apns_token?: string;
}

export interface PushEventRequest {
	ha_install_id: string;
	ha_user_hash?: string;
	event_type: EventType;
	history_revision?: string | number;
	client_message_id?: string;
	open_target?: "ask_dj" | "history" | "playback";
	client_types?: ClientType[];
	announcement?: AnnouncementHint;
}

export interface AdminRegistrationsQuery {
	limit: number;
	offset: number;
	client_type?: ClientType;
	apns_environment?: ApnsEnvironment;
	disabled?: boolean;
	invalid?: boolean;
	ha_install_id?: string;
}

export interface AdminDiagnosticsQuery {
	since_hours: number;
}

export interface ApiDiagnosticSummary {
	window_hours: number;
	totals: {
		total: number;
		ok: number;
		client_error: number;
		server_error: number;
	};
	by_route: Array<{
		method: string;
		route: string;
		status: number;
		error_code: string | null;
		count: number;
	}>;
	by_error: Array<{
		error_code: string;
		status: number;
		count: number;
	}>;
}

export interface AdminDiagnostics {
	ok: true;
	generated_at: string;
	window_hours: number;
	registrations: {
		total: number;
		active: number;
		disabled: number;
		invalid: number;
		by_client: Array<{
			client_type: ClientType;
			apns_environment: ApnsEnvironment;
			disabled: boolean;
			invalid: boolean;
			count: number;
		}>;
	};
	registration_errors: Array<{ code: string; count: number }>;
	relay: {
		events: number;
		targeted: number;
		delivered: number;
		failed: number;
		by_event: Array<{
			event_type: string;
			client_type: ClientType | null;
			events: number;
			targeted: number;
			delivered: number;
			failed: number;
		}>;
	};
	apns_failures: Array<{
		reason: string;
		status: number;
		client_type: ClientType | null;
		count: number;
	}>;
	api: ApiDiagnosticSummary;
}

export interface AdminRegistration {
	id: string;
	ha_install_id_hash: string;
	ha_user_hash: string | null;
	device_id_hash: string;
	client_type: ClientType;
	apns_environment: ApnsEnvironment;
	topic: string;
	app_bundle_id: string | null;
	app_version: string | null;
	locale: string | null;
	categories: string[];
	disabled: boolean;
	invalid: boolean;
	created_at: string;
	updated_at: string;
	last_success_at: string | null;
	last_error_code: string | null;
	apns_token_hash_prefix: string | null;
}

export interface Registration {
	id: string;
	ha_install_id: string;
	ha_user_hash: string | null;
	device_id: string;
	client_type: ClientType;
	apns_token_hash: string;
	apns_token: string | null;
	apns_token_ciphertext: string | null;
	apns_token_nonce: string | null;
	apns_token_key_version: string | null;
	apns_environment: ApnsEnvironment;
	topic: string;
	app_bundle_id: string | null;
	app_version: string | null;
	locale: string | null;
	categories_json: string;
	disabled: number;
	invalid: number;
	created_at: string;
	updated_at: string;
	last_success_at: string | null;
	last_error_code: string | null;
}

export interface ApnsResult {
	ok: boolean;
	status: number;
	reason?: string;
	endpoint: string;
}

export interface PushFailureSummary {
	client_type: ClientType;
	status: number;
	reason: string;
	count: number;
}

export interface InstallTokenRecord {
	id: string;
	ha_install_id: string;
	ha_user_hash: string | null;
	token_hash: string;
	token_prefix: string;
	label: string | null;
	disabled: number;
	created_at: string;
	updated_at: string;
	last_used_at: string | null;
	rotated_at: string | null;
	revoked_at: string | null;
	revoke_reason: string | null;
}

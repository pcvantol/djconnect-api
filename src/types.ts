export type ClientType = "ios" | "macos" | "watchos";
export type ApnsEnvironment = "sandbox" | "production";
export type EventType = "ask_dj_response" | "ask_dj_confirm" | "playback_change";

export interface AppEnv {
	DB: D1Database;
	APNS_TEAM_ID: string;
	APNS_KEY_ID: string;
	APNS_PRIVATE_KEY: string;
	APNS_TOPIC_IOS: string;
	APNS_TOPIC_MACOS: string;
	APNS_TOPIC_WATCHOS: string;
	APNS_ENVIRONMENT: ApnsEnvironment;
	DJCONNECT_RELAY_SECRET: string;
}

export interface InstallTokenRequest {
	ha_install_id: string;
	ha_user_hash?: string;
	label?: string;
}

export interface RotateInstallTokenRequest {
	ha_install_id: string;
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
}

export interface Registration {
	id: string;
	ha_install_id: string;
	ha_user_hash: string | null;
	device_id: string;
	client_type: ClientType;
	apns_token_hash: string;
	apns_token: string;
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
}

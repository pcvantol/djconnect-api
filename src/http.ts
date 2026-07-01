import { message, preferredResponseLanguage, type ApiMessageKey } from "./messages";

export class HttpError extends Error {
	constructor(
		public readonly status: number,
		public readonly code: ApiMessageKey,
		message = code,
	) {
		super(message);
	}
}

export function json(data: unknown, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set("content-type", "application/json; charset=utf-8");
	return new Response(JSON.stringify(data), { ...init, headers });
}

export function errorJson(request: Request, code: ApiMessageKey, init: ResponseInit = {}): Response {
	const language = preferredResponseLanguage(request);
	return json(language ? { error: code, message: message(code, language) } : { error: code }, init);
}

export async function readJson<T>(request: Request): Promise<T> {
	const contentType = request.headers.get("content-type") ?? "";
	if (!contentType.includes("application/json")) {
		throw new HttpError(415, "unsupported_media_type");
	}

	try {
		return (await request.json()) as T;
	} catch {
		throw new HttpError(400, "invalid_json");
	}
}

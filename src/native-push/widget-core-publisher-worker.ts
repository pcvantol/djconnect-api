import { verifyWidgetCoreAccess, widgetCoreAccessClientId } from "./widget-core-access";
import { createWidgetCorePublisher } from "./widget-core-publisher";

interface Bindings {
	WIDGET_PUBLISHER_MODE?: string;
	WIDGET_PUBLISHER_ORIGIN?: string;
	WIDGET_PUBLISHER_ACCESS_ISSUER?: string;
	WIDGET_PUBLISHER_ACCESS_AUDIENCE?: string;
	WIDGET_PUBLISHER_ACCESS_CLIENT_ID?: string;
	WIDGET_PUBLISHER_EXPIRES_AT_MS?: string;
	WIDGET_CORE_ORIGIN?: string;
	WIDGET_CORE_ACCESS_AUDIENCE?: string;
	WIDGET_CORE_ACCESS_CLIENT_ID?: string;
	WIDGET_HA_DEV_DB?: D1Database;
}

export function createWidgetCorePublisherWorker(resolveKeys?: Parameters<typeof verifyWidgetCoreAccess>[7]) {
	return {
		fetch(request: Request, env: Bindings, ctx: ExecutionContext): Promise<Response> {
			const { WIDGET_PUBLISHER_MODE: mode, WIDGET_PUBLISHER_ORIGIN: origin,
				WIDGET_PUBLISHER_ACCESS_ISSUER: issuer, WIDGET_PUBLISHER_ACCESS_AUDIENCE: audience,
				WIDGET_PUBLISHER_ACCESS_CLIENT_ID: publisherId, WIDGET_PUBLISHER_EXPIRES_AT_MS: expiration,
				WIDGET_CORE_ORIGIN: coreOrigin, WIDGET_CORE_ACCESS_AUDIENCE: coreAudience,
				WIDGET_CORE_ACCESS_CLIENT_ID: coreId, WIDGET_HA_DEV_DB: db } = env;
			const expiresAt = Number(expiration);
			if (mode !== "publisher-v1" || !origin || !coreOrigin || origin === coreOrigin || !issuer ||
				!audience || !coreAudience || audience === coreAudience || !publisherId || !coreId ||
				!widgetCoreAccessClientId.test(publisherId) || !widgetCoreAccessClientId.test(coreId) ||
				publisherId === coreId || !db || !Number.isSafeInteger(expiresAt) ||
				String(expiresAt) !== expiration || Date.now() >= expiresAt) {
				return createWidgetCorePublisher()(request);
			}

			const configurationCurrent = () => env.WIDGET_PUBLISHER_MODE === mode &&
				env.WIDGET_PUBLISHER_ORIGIN === origin && env.WIDGET_PUBLISHER_ACCESS_ISSUER === issuer &&
				env.WIDGET_PUBLISHER_ACCESS_AUDIENCE === audience && env.WIDGET_PUBLISHER_ACCESS_CLIENT_ID === publisherId &&
				env.WIDGET_PUBLISHER_EXPIRES_AT_MS === expiration && env.WIDGET_CORE_ORIGIN === coreOrigin &&
				env.WIDGET_CORE_ACCESS_AUDIENCE === coreAudience && env.WIDGET_CORE_ACCESS_CLIENT_ID === coreId &&
				env.WIDGET_HA_DEV_DB === db;
			return createWidgetCorePublisher(db, origin, async publication => {
				const access = await verifyWidgetCoreAccess(publication, ctx, issuer, audience, publisherId,
					expiresAt, configurationCurrent, resolveKeys);
				return access && { ...access, clientId: coreId };
			})(request);
		},
	} satisfies ExportedHandler<Bindings>;
}

export default createWidgetCorePublisherWorker();

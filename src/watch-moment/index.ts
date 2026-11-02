/** Source-only transport library. No root Worker route, DB migration or default authority. */
export { createMomentTransport, type Admission, type MomentPorts, type MomentReceipt } from "./service";
export { existingRelaySender } from "./relay";
export { buildMomentNotification } from "./payload";
export { createMomentHttpHandler, type AuthenticatedPorts } from "./http";
export { VERSION, CATEGORY, MomentError, decodeEvent, readEvent, canonical } from "./wire";

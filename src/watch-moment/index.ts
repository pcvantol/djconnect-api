/** Source-only transport library. No root Worker route, DB migration or default authority. */
export { createMomentTransport, type Admission, type MomentPorts, type MomentReceipt } from "./service";
export { existingRelaySender } from "./relay";
export { buildMomentNotification } from "./payload";
export { VERSION, CATEGORY, decodeEvent, readEvent, canonical } from "./wire";

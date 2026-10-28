export {CoordinatorSourceState} from '../state';
export {SourceStateOutbound} from '../outbound';
// Test binding only; HTTP is always closed, even in the local fixture Worker.
export default {fetch(): Response { return new Response('source qualification only', {status:503}); }};

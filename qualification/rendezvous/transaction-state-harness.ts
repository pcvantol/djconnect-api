// TEMPORARY LOCAL QA ONLY: software initial enrollment must never be a product binding.
import {TransactionCoordinator,type TransactionEnv} from './transaction-state';
export {ReceiptKeyStore,AssertionKeyState,EnrollmentCoordinator,SoftwareEnrollmentCoordinator} from './enrollment-state-harness';
export {TransactionCoordinator};
interface SoftwareEnv extends TransactionEnv {SOFTWARE_TRANSACTIONS:DurableObjectNamespace;SOFTWARE_ENROLLMENT:TransactionEnv['ENROLLMENT_COORDINATOR']}
export class SoftwareTransactionCoordinator extends TransactionCoordinator {constructor(ctx:DurableObjectState,env:SoftwareEnv){super(ctx,env,env.SOFTWARE_TRANSACTIONS,env.SOFTWARE_ENROLLMENT);}}
export default {fetch(){return new Response(null,{status:503,headers:{'Cache-Control':'no-store'}});}};

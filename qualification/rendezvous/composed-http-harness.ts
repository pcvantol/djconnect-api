// QA-only software enrollment is a separately named constructor/binding, never wire input.
import {BudgetedTransactionCoordinator,type ComposedEnv} from './composed-http';
export {AllocationBudget,AllocationIndex,ReceiptKeyStore,AssertionKeyState,EnrollmentCoordinator,SoftwareEnrollmentCoordinator,TransactionCoordinator,SoftwareTransactionCoordinator} from './index-state-harness';
export {BudgetedTransactionCoordinator};
interface SoftwareEnv extends ComposedEnv {SOFTWARE_COMPOSED_TRANSACTIONS:ComposedEnv['COMPOSED_TRANSACTIONS'];SOFTWARE_ENROLLMENT:ComposedEnv['ENROLLMENT_COORDINATOR']}
export class SoftwareBudgetedTransactionCoordinator extends BudgetedTransactionCoordinator {
  constructor(ctx:DurableObjectState,env:SoftwareEnv){super(ctx,env,env.SOFTWARE_COMPOSED_TRANSACTIONS,env.SOFTWARE_ENROLLMENT);}
}
export default {fetch(){return new Response(null,{status:503,headers:{'Cache-Control':'no-store'}});}};

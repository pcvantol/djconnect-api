// TEMPORARY QA: not wired into the product Worker. Default transport is disabled.
import {createIngress} from './http-ingress';
export {AllocationBudget} from './allocation-budget';
export default {fetch:createIngress()};

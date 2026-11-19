// Private product RPC allowlists. Public rendezvous transport remains compiled unavailable.
import { DurableObject } from "cloudflare:workers";
import { RequestAdmission as RequestAdmissionEngine } from "../../qualification/rendezvous/request-admission";
import { AllocationBudget as AllocationBudgetEngine } from "../../qualification/rendezvous/allocation-budget";
import { AllocationIndex as AllocationIndexEngine } from "../../qualification/rendezvous/allocation-index";
import { EnrollmentCoordinator as EnrollmentCoordinatorEngine } from "../../qualification/rendezvous/enrollment-key-state";
import { BudgetedTransactionCoordinator as BudgetedTransactionCoordinatorEngine } from "../../qualification/rendezvous/composed-http";

export class RequestAdmission extends DurableObject<ConstructorParameters<typeof RequestAdmissionEngine>[1]> {
	#engine: RequestAdmissionEngine;
	constructor(ctx: DurableObjectState, env: ConstructorParameters<typeof RequestAdmissionEngine>[1]) {
		super(ctx, env);
		this.#engine = new RequestAdmissionEngine(ctx, env);
	}
	admit(...args: Parameters<RequestAdmissionEngine["admit"]>) {
		return this.#engine.admit(...args);
	}
	alarm(...args: Parameters<RequestAdmissionEngine["alarm"]>) {
		return this.#engine.alarm(...args);
	}
}

export class AllocationBudget extends DurableObject<ConstructorParameters<typeof AllocationBudgetEngine>[1]> {
	#engine: AllocationBudgetEngine;
	constructor(ctx: DurableObjectState, env: ConstructorParameters<typeof AllocationBudgetEngine>[1]) {
		super(ctx, env);
		this.#engine = new AllocationBudgetEngine(ctx, env);
	}
	admit(...args: Parameters<AllocationBudgetEngine["admit"]>) {
		return this.#engine.admit(...args);
	}
	admitKeyCall(...args: Parameters<AllocationBudgetEngine["admitKeyCall"]>) {
		return this.#engine.admitKeyCall(...args);
	}
	alarm(...args: Parameters<AllocationBudgetEngine["alarm"]>) {
		return this.#engine.alarm(...args);
	}
}

export class AllocationIndex extends DurableObject<ConstructorParameters<typeof AllocationIndexEngine>[1]> {
	#engine: AllocationIndexEngine;
	constructor(ctx: DurableObjectState, env: ConstructorParameters<typeof AllocationIndexEngine>[1]) {
		super(ctx, env);
		this.#engine = new AllocationIndexEngine(ctx, env);
	}
	allocate(...args: Parameters<AllocationIndexEngine["allocate"]>) {
		return this.#engine.allocate(...args);
	}
	lookup(...args: Parameters<AllocationIndexEngine["lookup"]>) {
		return this.#engine.lookup(...args);
	}
	alarm(...args: Parameters<AllocationIndexEngine["alarm"]>) {
		return this.#engine.alarm(...args);
	}
}

export class EnrollmentCoordinator extends DurableObject<ConstructorParameters<typeof EnrollmentCoordinatorEngine>[1]> {
	#engine: EnrollmentCoordinatorEngine;
	constructor(ctx: DurableObjectState, env: ConstructorParameters<typeof EnrollmentCoordinatorEngine>[1]) {
		super(ctx, env);
		this.#engine = new EnrollmentCoordinatorEngine(ctx, env);
	}
	issueEnrollment(...args: Parameters<EnrollmentCoordinatorEngine["issueEnrollment"]>) {
		return this.#engine.issueEnrollment(...args);
	}
	enroll(...args: Parameters<EnrollmentCoordinatorEngine["enroll"]>) {
		return this.#engine.enroll(...args);
	}
	issueAction(...args: Parameters<EnrollmentCoordinatorEngine["issueAction"]>) {
		return this.#engine.issueAction(...args);
	}
	authorize(...args: Parameters<EnrollmentCoordinatorEngine["authorize"]>) {
		return this.#engine.authorize(...args);
	}
	alarm(...args: Parameters<EnrollmentCoordinatorEngine["alarm"]>) {
		return this.#engine.alarm(...args);
	}
}

export class BudgetedTransactionCoordinator extends DurableObject<ConstructorParameters<typeof BudgetedTransactionCoordinatorEngine>[1]> {
	#engine: BudgetedTransactionCoordinatorEngine;
	constructor(ctx: DurableObjectState, env: ConstructorParameters<typeof BudgetedTransactionCoordinatorEngine>[1]) {
		super(ctx, env);
		this.#engine = new BudgetedTransactionCoordinatorEngine(ctx, env);
	}
	create(...args: Parameters<BudgetedTransactionCoordinatorEngine["create"]>) {
		return this.#engine.create(...args);
	}
	inspect(...args: Parameters<BudgetedTransactionCoordinatorEngine["inspect"]>) {
		return this.#engine.inspect(...args);
	}
	reserveSubmitChallenge(...args: Parameters<BudgetedTransactionCoordinatorEngine["reserveSubmitChallenge"]>) {
		return this.#engine.reserveSubmitChallenge(...args);
	}
	submit(...args: Parameters<BudgetedTransactionCoordinatorEngine["submit"]>) {
		return this.#engine.submit(...args);
	}
	poll(...args: Parameters<BudgetedTransactionCoordinatorEngine["poll"]>) {
		return this.#engine.poll(...args);
	}
	consume(...args: Parameters<BudgetedTransactionCoordinatorEngine["consume"]>) {
		return this.#engine.consume(...args);
	}
	cancel(...args: Parameters<BudgetedTransactionCoordinatorEngine["cancel"]>) {
		return this.#engine.cancel(...args);
	}
	alarm(...args: Parameters<BudgetedTransactionCoordinatorEngine["alarm"]>) {
		return this.#engine.alarm(...args);
	}
}

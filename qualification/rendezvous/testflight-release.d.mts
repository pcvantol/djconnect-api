export const TESTFLIGHT_POLICY: 'ios-testflight/1';
export const TESTFLIGHT_APP: 'ZEML4LPXH4.dev.djconnect.ios';
export interface TestFlightReleaseEnv {
  RENDEZVOUS_TESTFLIGHT_RELEASE_REVISION?: string;
  RENDEZVOUS_TESTFLIGHT_MIN_BUILD?: string;
  RENDEZVOUS_TESTFLIGHT_MAX_BUILD?: string;
}
export interface TestFlightRelease {
  readonly revision: number;
  readonly min: number;
  readonly max?: number;
}
export function testflightRelease(env: TestFlightReleaseEnv): TestFlightRelease | undefined;
export function testflightBuildAllowed(value: unknown, release?: TestFlightRelease): boolean;
export function testflightReleaseRevision(release?: TestFlightRelease): string | undefined;

export interface PublicTrialWindow {
  RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT?: string;
  ASSERTION_POLICY_EXPIRES_AT?: string;
}
export function publicTrialRequestOpen(env: PublicTrialWindow, now: number, creating: boolean): boolean;

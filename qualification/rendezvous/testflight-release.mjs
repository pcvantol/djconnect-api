export const TESTFLIGHT_POLICY = 'ios-testflight/1';
export const TESTFLIGHT_APP = 'ZEML4LPXH4.dev.djconnect.ios';

function buildNumber(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,14}$/.test(value)) return undefined;
  return Number(value);
}

/** These values come from the reviewed Worker configuration, never from a request. */
export function testflightRelease(env) {
  const revision = buildNumber(env.RENDEZVOUS_TESTFLIGHT_RELEASE_REVISION);
  const min = buildNumber(env.RENDEZVOUS_TESTFLIGHT_MIN_BUILD);
  const rawMax = env.RENDEZVOUS_TESTFLIGHT_MAX_BUILD;
  const max = rawMax === undefined ? undefined : buildNumber(rawMax);
  if (revision === undefined || min === undefined || (rawMax !== undefined && (max === undefined || max < min))) return undefined;
  return { revision, min, max };
}

export function testflightBuildAllowed(value, release) {
  const build = buildNumber(value);
  return build !== undefined && release !== undefined && build >= release.min
    && (release.max === undefined || build <= release.max);
}

export function testflightReleaseRevision(release) {
  return release === undefined ? undefined : `${release.revision}:${release.min}:${release.max ?? ''}`;
}

// Only an explicit production TestFlight policy can omit the release deadline.
export function alwaysOnTestflight(env) {
  return env.ASSERTION_POLICY_ENABLED === TESTFLIGHT_POLICY
    && env.ASSERTION_POLICY_EXPIRES_AT === 'always-on/1'
    && env.RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT === undefined;
}

export function assertionPolicyDeadline(env) {
  return alwaysOnTestflight(env) ? Number.MAX_SAFE_INTEGER : Number(env.ASSERTION_POLICY_EXPIRES_AT);
}

export function publicTrialRequestOpen(env, now, creating) {
  if (env.ASSERTION_POLICY_ENABLED !== TESTFLIGHT_POLICY || env.RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT === undefined) return true;
  const start = Number(env.RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT);
  const end = Number(env.ASSERTION_POLICY_EXPIRES_AT);
  return Number.isSafeInteger(start) && Number.isSafeInteger(end)
    && now >= start && now < end - (creating ? 120_000 : 0);
}

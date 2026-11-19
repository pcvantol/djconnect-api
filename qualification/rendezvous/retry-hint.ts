// Trusted denial metadata only; never a new retry, lifetime or authority.
export function readRetryHint(value:{retry_after_ms?:unknown}):number|undefined {
  const hint=value.retry_after_ms;
  if(hint===undefined)return undefined;
  if(typeof hint!=="number"||!Number.isSafeInteger(hint)||hint<1||hint>60000)throw new Error('retry_hint_rejected');
  return hint;
}
export const hintFields=(hint:number|undefined)=>hint===undefined?{}:{retry_after_ms:hint};

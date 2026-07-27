const SENSITIVE_QUERY_PARAMETER = /^(?:access_?token|auth|authorization|code|credential|jwt|otp|pass(?:word|code)?|reset(?:_?token)?|session(?:id)?|signature|sig|secret|token)$/i;

export function findSensitiveUrlParameters(input: string) {
  const candidates = input.match(/(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/gi) ?? [];
  const parameters = new Set<string>();

  for (const candidate of candidates) {
    const value = /^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`;
    try {
      const parsed = new URL(value.replace(/[),.;!?\]}>'"]+$/g, ""));
      for (const key of parsed.searchParams.keys()) {
        if (SENSITIVE_QUERY_PARAMETER.test(key)) parameters.add(key);
      }
    } catch {
      // The server performs authoritative URL validation.
    }
  }

  return [...parameters];
}

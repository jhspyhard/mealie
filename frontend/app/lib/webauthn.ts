/**
 * Glue between the server's WebAuthn options (JSON, binary fields as base64url) and the browser's
 * `navigator.credentials` API (ArrayBuffers).
 *
 * Browsers that have `PublicKeyCredential.parseCreationOptionsFromJSON()` and `credential.toJSON()` do this
 * themselves. Older ones (Safari before 18.4, for one) get the same conversion done by hand.
 */

type JSONObject = Record<string, unknown>;

export function base64UrlToBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToBase64Url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes = buffer instanceof ArrayBuffer
    ? new Uint8Array(buffer)
    : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** True when the browser can use passkeys at all. Needs a secure origin (https, or localhost). */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined"
    && window.isSecureContext
    && typeof window.PublicKeyCredential !== "undefined"
    && typeof navigator.credentials?.get === "function";
}

/** True when the browser can offer passkeys in the username field's autofill list. */
export async function conditionalMediationAvailable(): Promise<boolean> {
  if (!passkeysSupported()) {
    return false;
  }
  try {
    return await PublicKeyCredential.isConditionalMediationAvailable?.() === true;
  }
  catch {
    return false;
  }
}

function descriptorsFromJSON(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) {
    return undefined;
  }
  return list.map((item: JSONObject) => ({
    ...item,
    type: "public-key",
    id: base64UrlToBuffer(item.id as string),
  })) as PublicKeyCredentialDescriptor[];
}

export function parseCreationOptions(options: JSONObject): PublicKeyCredentialCreationOptions {
  if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
    return PublicKeyCredential.parseCreationOptionsFromJSON(options as unknown as PublicKeyCredentialCreationOptionsJSON);
  }

  const user = options.user as JSONObject;
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge as string),
    user: { ...user, id: base64UrlToBuffer(user.id as string) },
    excludeCredentials: descriptorsFromJSON(options.excludeCredentials),
  } as unknown as PublicKeyCredentialCreationOptions;
}

export function parseRequestOptions(options: JSONObject): PublicKeyCredentialRequestOptions {
  if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
    return PublicKeyCredential.parseRequestOptionsFromJSON(options as unknown as PublicKeyCredentialRequestOptionsJSON);
  }

  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge as string),
    allowCredentials: descriptorsFromJSON(options.allowCredentials),
  } as unknown as PublicKeyCredentialRequestOptions;
}

/** The credential as the server expects it: the shape `PublicKeyCredential.toJSON()` produces. */
export function credentialToJSON(credential: PublicKeyCredential): JSONObject {
  if (typeof credential.toJSON === "function") {
    try {
      return credential.toJSON() as unknown as JSONObject;
    }
    catch {
      // Some password-manager extensions wrap the credential and break toJSON(); fall through.
    }
  }

  const response = credential.response;
  const json: JSONObject = {
    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
  };

  if ("attestationObject" in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    json.attestationObject = bufferToBase64Url(attestation.attestationObject);
    json.transports = attestation.getTransports?.() ?? [];
  }
  else {
    const assertion = response as AuthenticatorAssertionResponse;
    json.authenticatorData = bufferToBase64Url(assertion.authenticatorData);
    json.signature = bufferToBase64Url(assertion.signature);
    json.userHandle = assertion.userHandle ? bufferToBase64Url(assertion.userHandle) : null;
  }

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
    response: json,
  };
}

/**
 * True for the errors a browser raises when the person backs out (closes the prompt, or it times out) or when
 * we abort a pending request ourselves. Neither is worth an error message.
 */
export function isPasskeyCancellation(error: unknown): boolean {
  return error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError");
}

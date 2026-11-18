/**
 * Converts between the WebAuthn options from the server (JSON, with binary fields as base64url) and the
 * `navigator.credentials` API of the browser (ArrayBuffers).
 *
 * Browsers with `PublicKeyCredential.parseCreationOptionsFromJSON()` and `credential.toJSON()` do this
 * conversion. For older browsers (for example Safari before 18.4), this module does the conversion.
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

/** True when the browser can use passkeys. Passkeys need a secure origin (https, or localhost). */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined"
    && window.isSecureContext
    && typeof window.PublicKeyCredential !== "undefined"
    && typeof navigator.credentials?.get === "function";
}

/** True when the browser can show passkeys in the autofill list of the username field. */
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

/** The credential in the format of `PublicKeyCredential.toJSON()`. The server expects this format. */
export function credentialToJSON(credential: PublicKeyCredential): JSONObject {
  if (typeof credential.toJSON === "function") {
    try {
      return credential.toJSON() as unknown as JSONObject;
    }
    catch {
      // Some password manager extensions wrap the credential, and toJSON() fails. Use the manual conversion.
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
 * True for the errors that a browser raises when the user closes the prompt, when the prompt times out, or
 * when the app stops the request. These errors do not need an error message.
 */
export function isPasskeyCancellation(error: unknown): boolean {
  return error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError");
}

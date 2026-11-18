import { afterEach, describe, expect, test, vi } from "vitest";
import {
  base64UrlToBuffer,
  bufferToBase64Url,
  credentialToJSON,
  isPasskeyCancellation,
  parseCreationOptions,
  parseRequestOptions,
} from "./webauthn";

function bytes(buffer: ArrayBuffer | BufferSource | undefined): number[] {
  return Array.from(new Uint8Array(buffer as ArrayBuffer));
}

/** Removes the JSON helpers from the browser, so the tests use the manual conversion */
function stubOldBrowser() {
  vi.stubGlobal("PublicKeyCredential", {});
}

afterEach(() => vi.unstubAllGlobals());

describe("base64url", () => {
  test("round-trips bytes that need the url-safe alphabet and no padding", () => {
    const input = new Uint8Array([0xFB, 0xFF, 0xBF, 0x00, 0x01]);
    const encoded = bufferToBase64Url(input);

    expect(encoded).toBe("-_-_AAE");
    expect(bytes(base64UrlToBuffer(encoded))).toEqual(Array.from(input));
  });

  test("encodes a view over part of a buffer, not the whole buffer", () => {
    const backing = new Uint8Array([9, 1, 2, 3, 9]);
    expect(bufferToBase64Url(backing.subarray(1, 4))).toBe(bufferToBase64Url(new Uint8Array([1, 2, 3])));
  });
});

describe("option parsing without browser support", () => {
  test("creation options decode the challenge, user id and excluded credentials", () => {
    stubOldBrowser();
    const parsed = parseCreationOptions({
      challenge: "AQID",
      rp: { id: "mealie.test", name: "Mealie" },
      user: { id: "BAUG", name: "user", displayName: "User" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ type: "public-key", id: "BwgJ", transports: ["internal"] }],
    });

    expect(bytes(parsed.challenge)).toEqual([1, 2, 3]);
    expect(bytes(parsed.user.id)).toEqual([4, 5, 6]);
    expect(parsed.user.name).toBe("user");
    expect(bytes(parsed.excludeCredentials![0]!.id)).toEqual([7, 8, 9]);
    expect(parsed.excludeCredentials![0]!.transports).toEqual(["internal"]);
  });

  test("request options with no allow list stay without one", () => {
    stubOldBrowser();
    const parsed = parseRequestOptions({ challenge: "AQID", rpId: "mealie.test", userVerification: "required" });

    expect(bytes(parsed.challenge)).toEqual([1, 2, 3]);
    expect(parsed.allowCredentials).toBeUndefined();
    expect(parsed.userVerification).toBe("required");
  });

  test("uses the browser's own parser when there is one", () => {
    const parseRequestOptionsFromJSON = vi.fn(() => ({ challenge: new ArrayBuffer(0) }));
    vi.stubGlobal("PublicKeyCredential", { parseRequestOptionsFromJSON });

    parseRequestOptions({ challenge: "AQID" });
    expect(parseRequestOptionsFromJSON).toHaveBeenCalledWith({ challenge: "AQID" });
  });
});

describe("credentialToJSON without toJSON()", () => {
  const raw = (values: number[]) => new Uint8Array(values).buffer;

  test("encodes an assertion the way toJSON() would", () => {
    const credential = {
      id: "AQI",
      rawId: raw([1, 2]),
      type: "public-key",
      authenticatorAttachment: "platform",
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: raw([3]),
        authenticatorData: raw([4]),
        signature: raw([5]),
        userHandle: raw([6]),
      },
    } as unknown as PublicKeyCredential;

    expect(credentialToJSON(credential)).toEqual({
      id: "AQI",
      rawId: "AQI",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: "Aw",
        authenticatorData: "BA",
        signature: "BQ",
        userHandle: "Bg",
      },
    });
  });

  test("encodes an attestation with its transports", () => {
    const credential = {
      id: "AQI",
      rawId: raw([1, 2]),
      type: "public-key",
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: raw([3]),
        attestationObject: raw([4]),
        getTransports: () => ["hybrid", "internal"],
      },
    } as unknown as PublicKeyCredential;

    expect(credentialToJSON(credential).response).toEqual({
      clientDataJSON: "Aw",
      attestationObject: "BA",
      transports: ["hybrid", "internal"],
    });
  });
});

test("only a dismissed or aborted prompt counts as cancelling", () => {
  expect(isPasskeyCancellation(new DOMException("closed", "NotAllowedError"))).toBe(true);
  expect(isPasskeyCancellation(new DOMException("aborted", "AbortError"))).toBe(true);
  expect(isPasskeyCancellation(new DOMException("exists", "InvalidStateError"))).toBe(false);
  expect(isPasskeyCancellation(new Error("network"))).toBe(false);
});

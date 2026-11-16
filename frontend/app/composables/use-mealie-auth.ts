import { ref, watch, computed } from "vue";
import { useAuthBackend } from "~/composables/use-auth-backend";
import type { PasskeyOptionsOut, UserOut } from "~/lib/api/types/user";
import { credentialToJSON, parseRequestOptions } from "~/lib/webauthn";

export const useMealieAuth = function () {
  const auth = useAuthBackend();
  const { $axios } = useNuxtApp();

  // User Management
  const lastUser = ref<UserOut | null>(null);
  const user = computed(() => lastUser.value);

  watch(
    () => auth.data.value,
    (val) => {
      if (val) {
        lastUser.value = val as UserOut;
      }
      else {
        lastUser.value = null;
      }
    },
    { immediate: true },
  );

  // Auth Status Management
  const lastAuthStatus = ref<string>(auth.status.value);
  const loggedIn = computed(() => lastAuthStatus.value === "authenticated");

  watch(
    () => auth.status.value,
    (val) => {
      if (val !== "loading") {
        lastAuthStatus.value = val;
      }
    },
    { immediate: true },
  );

  async function oauthSignIn() {
    const params = new URLSearchParams(window.location.search);
    const { data: token } = await $axios.get<{ access_token: string; token_type: "bearer" }>("/api/auth/oauth/callback", { params });
    auth.setToken(token.access_token);

    await auth.getSession();
    if (auth.status.value !== "authenticated") {
      throw new Error("OIDC sign-in succeeded but the session could not be established");
    }
  }

  async function reverseProxySignIn() {
    const { data: token } = await $axios.get<{ access_token: string; token_type: "bearer" }>("/api/auth/reverse-proxy");
    auth.setToken(token.access_token);
    await auth.getSession();
  }

  /**
   * Signs in with a passkey. Resolves false when there was nothing to sign in with: the person closed the
   * browser's prompt, or `signal` aborted it. Server rejections throw like `signIn` does.
   *
   * With `mediation: "conditional"` the browser waits for the person to pick a passkey from the username
   * field's autofill list instead of opening a prompt, so the promise can stay pending for as long as the
   * login page is open.
   *
   * Requests skip the interceptor's toasts; the login page reports failures itself, as it does for passwords.
   */
  async function passkeySignIn(options: { remember: boolean; mediation?: CredentialMediationRequirement; signal?: AbortSignal }) {
    const { data } = await $axios.post<PasskeyOptionsOut>("/api/auth/passkey/options", null, { suppressAlert: true });

    const credential = await navigator.credentials.get({
      publicKey: parseRequestOptions(data.options),
      mediation: options.mediation,
      signal: options.signal,
    }) as PublicKeyCredential | null;

    if (!credential) {
      return false;
    }

    const { data: token } = await $axios.post<{ access_token: string; token_type: "bearer" }>("/api/auth/passkey", {
      challengeId: data.challengeId,
      credential: credentialToJSON(credential),
      rememberMe: options.remember,
    }, { suppressAlert: true });
    auth.setToken(token.access_token);
    await auth.getSession();
    return true;
  }

  return {
    user,
    loggedIn,
    token: auth.token,
    signIn: auth.signIn,
    signOut: auth.signOut,
    getSession: auth.getSession,
    oauthSignIn,
    reverseProxySignIn,
    passkeySignIn,
  };
};

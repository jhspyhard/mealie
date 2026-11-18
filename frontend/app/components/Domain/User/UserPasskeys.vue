<template>
  <section v-if="visible">
    <BaseDialog
      v-model="addDialog"
      :title="$t('profile.passkeys.add-a-passkey')"
      :icon="$globals.icons.passkey"
      :submit-text="$t('general.next')"
      :submit-disabled="!addForm.name.trim() || !addForm.password"
      :loading="adding"
      can-submit
      keep-open
      @submit="addPasskey"
    >
      <v-card-text>
        <p class="mb-4">
          {{ $t('profile.passkeys.add-a-passkey-description') }}
        </p>
        <v-form @submit.prevent="addPasskey">
          <v-text-field
            v-model="addForm.name"
            :label="$t('profile.passkeys.passkey-name')"
            :hint="$t('profile.passkeys.passkey-name-hint')"
            persistent-hint
            maxlength="64"
            autofocus
            class="mb-4"
          />
          <v-text-field
            v-model="addForm.password"
            :label="$t('user.current-password')"
            :prepend-inner-icon="$globals.icons.lock"
            :append-inner-icon="passwordIcon"
            :type="inputType"
            autocomplete="current-password"
            @click:append-inner="togglePasswordShow"
          />
        </v-form>
      </v-card-text>
    </BaseDialog>

    <BaseDialog
      v-model="deleteDialog"
      :title="$t('profile.passkeys.remove-passkey')"
      color="error"
      :icon="$globals.icons.alertCircle"
      can-confirm
      @confirm="deletePasskey"
    >
      <v-card-text>
        {{ $t('profile.passkeys.remove-passkey-confirmation', { name: deleteTarget?.name ?? "" }) }}
      </v-card-text>
    </BaseDialog>

    <BaseCardSectionTitle
      class="mt-10"
      :title="$t('profile.passkeys.passkeys')"
    />
    <v-card
      tag="article"
      variant="outlined"
      style="border-color: lightgrey;"
    >
      <v-card-text class="pb-0">
        <p class="mb-2">
          {{ $t('profile.passkeys.description') }}
        </p>
        <v-alert
          v-if="unavailableReason"
          type="info"
          variant="tonal"
          density="compact"
          class="my-2"
        >
          {{ unavailableReason }}
        </v-alert>
        <v-progress-linear
          v-if="loading"
          indeterminate
          color="primary"
          class="my-4"
        />
        <p
          v-else-if="passkeys.length === 0"
          class="text-medium-emphasis my-2"
        >
          {{ $t('profile.passkeys.no-passkeys') }}
        </p>
        <v-list
          v-else
          density="comfortable"
        >
          <template
            v-for="(passkey, index) in passkeys"
            :key="passkey.id"
          >
            <v-divider v-if="index > 0" />
            <v-list-item
              class="px-0"
              :prepend-icon="$globals.icons.passkey"
            >
              <v-list-item-title>
                {{ passkey.name }}
                <v-chip
                  v-if="passkey.backedUp"
                  size="x-small"
                  class="ml-2"
                  label
                >
                  {{ $t('profile.passkeys.synced') }}
                </v-chip>
              </v-list-item-title>
              <v-list-item-subtitle>
                <span v-if="passkey.createdAt">{{ $t('general.created-on-date', [$d(new Date(passkey.createdAt))]) }} · </span>
                <span>
                  {{ passkey.lastUsedAt
                    ? $t('profile.passkeys.last-used-on-date', [$d(new Date(passkey.lastUsedAt))])
                    : $t('profile.passkeys.never-used') }}
                </span>
              </v-list-item-subtitle>
              <template #append>
                <BaseButton
                  delete
                  small
                  @click="confirmDelete(passkey)"
                />
              </template>
            </v-list-item>
          </template>
        </v-list>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <BaseButton
          v-if="canAdd"
          create
          :icon="$globals.icons.passkey"
          @click="openAddDialog"
        >
          {{ $t('profile.passkeys.add-a-passkey') }}
        </BaseButton>
      </v-card-actions>
    </v-card>
  </section>
</template>

<script setup lang="ts">
import { useUserApi } from "~/composables/api";
import { usePasswordField } from "~/composables/use-passwords";
import { alert } from "~/composables/use-toast";
import type { UserPasskeyOut } from "~/lib/api/types/user";
import { credentialToJSON, isPasskeyCancellation, parseCreationOptions, passkeysSupported } from "~/lib/webauthn";

const i18n = useI18n();
const auth = useMealieAuth();
const api = useUserApi();
const { $appInfo } = useNuxtApp();
const { passwordIcon, inputType, togglePasswordShow } = usePasswordField();

const passkeys = ref<UserPasskeyOut[]>([]);
const loading = ref(true);

// The component sets this after mount, because the server render cannot detect WebAuthn support in the browser
const browserSupported = ref(true);

const isMealieUser = computed(() => auth.user.value?.authMethod === "Mealie");

/**
 * Mealie-password users see this card when passkeys are on. When passkeys are off, the card shows only if the
 * user has passkeys. Thus the user can remove passkeys that do not work.
 */
const visible = computed(() => isMealieUser.value && ($appInfo.enablePasskeys || passkeys.value.length > 0));

/** The reason that the user cannot add a passkey, or null. The user can always remove passkeys. */
const unavailableReason = computed(() => {
  if (!$appInfo.enablePasskeys) {
    return i18n.t("profile.passkeys.disabled-on-this-server");
  }
  if (!browserSupported.value) {
    return i18n.t("profile.passkeys.browser-not-supported");
  }
  return null;
});
const canAdd = computed(() => unavailableReason.value === null);

async function refreshPasskeys() {
  const { data } = await api.users.getPasskeys();
  passkeys.value = data ?? [];
  loading.value = false;
}

onMounted(() => {
  browserSupported.value = passkeysSupported();
  if (isMealieUser.value) {
    refreshPasskeys();
  }
});

// ================================================================
// Passkey registration

const addDialog = ref(false);
const adding = ref(false);
const addForm = reactive({ name: "", password: "" });

function openAddDialog() {
  addForm.name = "";
  addForm.password = "";
  addDialog.value = true;
}

async function addPasskey() {
  if (adding.value || !addForm.name.trim() || !addForm.password) {
    return;
  }
  adding.value = true;

  try {
    // For a wrong password, the request layer shows the error
    const { data: options } = await api.users.getPasskeyRegistrationOptions({ currentPassword: addForm.password });
    if (!options) {
      return;
    }

    let credential: PublicKeyCredential | null;
    try {
      credential = await navigator.credentials.create({
        publicKey: parseCreationOptions(options.options),
      }) as PublicKeyCredential | null;
    }
    catch (error) {
      // InvalidStateError: this authenticator has a passkey for this account (from the exclude list)
      if (error instanceof DOMException && error.name === "InvalidStateError") {
        alert.error(i18n.t("profile.passkeys.already-registered"));
      }
      else if (!isPasskeyCancellation(error)) {
        console.error(error);
        alert.error(i18n.t("events.something-went-wrong"));
      }
      return;
    }

    if (!credential) {
      return;
    }

    const { data: created } = await api.users.createPasskey({
      challengeId: options.challengeId,
      name: addForm.name.trim(),
      credential: credentialToJSON(credential),
    });

    if (created) {
      alert.success(i18n.t("profile.passkeys.passkey-added"));
      addDialog.value = false;
      await refreshPasskeys();
    }
  }
  finally {
    adding.value = false;
  }
}

// ================================================================
// Passkey removal

const deleteDialog = ref(false);
const deleteTarget = ref<UserPasskeyOut | null>(null);

function confirmDelete(passkey: UserPasskeyOut) {
  deleteTarget.value = passkey;
  deleteDialog.value = true;
}

async function deletePasskey() {
  if (!deleteTarget.value) {
    return;
  }

  const { data } = await api.users.deletePasskey(deleteTarget.value.id);
  if (data) {
    alert.success(i18n.t("profile.passkeys.passkey-removed"));
  }
  deleteTarget.value = null;
  await refreshPasskeys();
}
</script>

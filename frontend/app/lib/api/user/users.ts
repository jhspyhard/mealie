import { BaseCRUDAPI } from "../base/base-clients";
import type {
  ChangePassword,
  DeleteTokenResponse,
  LongLiveTokenIn,
  LongLiveTokenOut,
  PasskeyOptionsOut,
  PasskeyRegistrationOptionsRequest,
  ResetPassword,
  UserBase,
  UserIn,
  UserOut,
  UserPasskeyCreate,
  UserPasskeyOut,
  UserRatingOut,
  UserRatingSummary,
} from "~/lib/api/types/user";

export interface UserRatingsSummaries {
  ratings: UserRatingSummary[];
}

export interface UserRatingsOut {
  ratings: UserRatingOut[];
}

const prefix = "/api";

const routes = {
  usersSelf: `${prefix}/users/self`,
  ratingsSelf: `${prefix}/users/self/ratings`,
  passwordReset: `${prefix}/users/reset-password`,
  passwordChange: `${prefix}/users/password`,
  users: `${prefix}/users`,

  usersIdImage: (id: string) => `${prefix}/users/${id}/image`,
  usersIdResetPassword: (id: string) => `${prefix}/users/${id}/reset-password`,
  usersId: (id: string) => `${prefix}/users/${id}`,
  usersIdFavorites: (id: string) => `${prefix}/users/${id}/favorites`,
  usersIdFavoritesSlug: (id: string, slug: string) => `${prefix}/users/${id}/favorites/${slug}`,
  usersIdRatings: (id: string) => `${prefix}/users/${id}/ratings`,
  usersIdRatingsSlug: (id: string, slug: string) => `${prefix}/users/${id}/ratings/${slug}`,
  usersSelfFavoritesId: (id: string) => `${prefix}/users/self/favorites/${id}`,
  usersSelfRatingsId: (id: string) => `${prefix}/users/self/ratings/${id}`,

  usersApiTokens: `${prefix}/users/api-tokens`,
  usersApiTokensTokenId: (token_id: string | number) => `${prefix}/users/api-tokens/${token_id}`,

  passkeysSelf: `${prefix}/users/self/passkeys`,
  passkeysSelfRegistrationOptions: `${prefix}/users/self/passkeys/registration-options`,
  passkeysSelfId: (id: string) => `${prefix}/users/self/passkeys/${id}`,
};

export class UserApi extends BaseCRUDAPI<UserIn, UserOut, UserBase> {
  baseRoute: string = routes.users;
  itemRoute = (itemid: string) => routes.usersId(itemid);

  async addFavorite(id: string, slug: string) {
    return await this.requests.post(routes.usersIdFavoritesSlug(id, slug), {});
  }

  async removeFavorite(id: string, slug: string) {
    return await this.requests.delete(routes.usersIdFavoritesSlug(id, slug));
  }

  async getFavorites(id: string) {
    return await this.requests.get<UserRatingsOut>(routes.usersIdFavorites(id));
  }

  async getSelfFavorites() {
    return await this.requests.get<UserRatingsSummaries>(routes.ratingsSelf);
  }

  async getRatings(id: string) {
    return await this.requests.get<UserRatingsOut>(routes.usersIdRatings(id));
  }

  async setRating(id: string, slug: string, rating: number | null, isFavorite: boolean | null) {
    return await this.requests.post(routes.usersIdRatingsSlug(id, slug), { rating, isFavorite });
  }

  async getSelfRatings() {
    return await this.requests.get<UserRatingsSummaries>(routes.ratingsSelf);
  }

  async changePassword(changePassword: ChangePassword) {
    return await this.requests.put(routes.passwordChange, changePassword);
  }

  async createAPIToken(tokenName: LongLiveTokenIn) {
    return await this.requests.post<LongLiveTokenOut>(routes.usersApiTokens, tokenName);
  }

  async deleteAPIToken(tokenId: number) {
    return await this.requests.delete<DeleteTokenResponse>(routes.usersApiTokensTokenId(tokenId));
  }

  async getPasskeys() {
    return await this.requests.get<UserPasskeyOut[]>(routes.passkeysSelf);
  }

  async getPasskeyRegistrationOptions(payload: PasskeyRegistrationOptionsRequest) {
    return await this.requests.post<PasskeyOptionsOut>(routes.passkeysSelfRegistrationOptions, payload);
  }

  async createPasskey(payload: UserPasskeyCreate) {
    return await this.requests.post<UserPasskeyOut>(routes.passkeysSelf, payload);
  }

  async deletePasskey(id: string) {
    return await this.requests.delete<UserPasskeyOut>(routes.passkeysSelfId(id));
  }

  userProfileImage(id: string) {
    if (!id || id === undefined) return;
    return `/api/users/${id}/image`;
  }

  async resetPassword(payload: ResetPassword) {
    return await this.requests.post(routes.passwordReset, payload);
  }
}

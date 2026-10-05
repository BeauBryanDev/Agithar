// Login and the current user. All auth network I/O lives here.

import { apiClient } from "./apiClient";

export interface CurrentUser {
  user_id: number;
  username: string;
  name: string;
  is_admin: boolean;
  is_active: boolean;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
}

export async function login(
  username: string,
  password: string
): Promise<string> {
  const { data } = await apiClient.post<TokenResponse>("/users/login", {
    username,
    password,
  });
  return data.access_token;
}

export async function fetchMe(): Promise<CurrentUser> {
  const { data } = await apiClient.get<CurrentUser>("/users/me");
  return data;
}

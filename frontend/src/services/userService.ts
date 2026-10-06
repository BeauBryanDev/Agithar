// The users API. All user network I/O lives here.

import { apiClient } from "./apiClient";
import type {
  NewUser,
  ProfileChanges,
  UserList,
  UserProfile,
} from "../types/user";

export async function fetchProfile(): Promise<UserProfile> {
  const { data } = await apiClient.get<UserProfile>("/users/me");
  return data;
}

export async function updateProfile(
  changes: ProfileChanges
): Promise<UserProfile> {
  const { data } = await apiClient.patch<UserProfile>("/users/me", changes);
  return data;
}

export async function changePassword(
  currentPassword: string,
  newPassword: string
): Promise<void> {
  await apiClient.put("/users/me/password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
}

/** Soft delete: the account is deactivated, not erased. */
export async function deactivateMe(): Promise<void> {
  await apiClient.delete("/users/me");
}

export async function listUsers(skip: number, limit: number): Promise<UserList> {
  const { data } = await apiClient.get<UserList>("/users", {
    params: { skip, limit },
  });
  return data;
}

export async function createUser(user: NewUser): Promise<UserProfile> {
  const { data } = await apiClient.post<UserProfile>("/users", user);
  return data;
}

export async function setUserActive(
  userId: number,
  isActive: boolean
): Promise<UserProfile> {
  const { data } = await apiClient.patch<UserProfile>(
    `/users/${userId}/active`,
    { is_active: isActive }
  );
  return data;
}

/** Erases an account that is already deactivated. Never your own. */
export async function deleteUserPermanently(userId: number): Promise<void> {
  await apiClient.delete(`/users/${userId}`, { params: { permanent: true } });
}

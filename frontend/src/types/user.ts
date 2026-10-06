// User contracts (api/routers/users.py).

export type Gender = "male" | "female" | "other";

export interface UserProfile {
  user_id: number;
  name: string;
  username: string;
  email: string;
  phone_number: string | null;
  address: string | null;
  country: string | null;
  city: string | null;
  gender: Gender | null;
  dob: string | null; // ISO 8601
  is_active: boolean;
  is_admin: boolean;
  created_at: string;
  updated_at: string;
}

/** What a user may change about themselves. */
export interface ProfileChanges {
  phone_number?: string | null;
  address?: string | null;
  country?: string | null;
  city?: string | null;
}

export interface NewUser {
  name: string;
  username: string;
  email: string;
  password: string;
  phone_number?: string | null;
  address?: string | null;
  country?: string | null;
  city?: string | null;
  gender?: Gender | null;
  dob?: string | null;
  is_admin?: boolean;
}

export interface UserList {
  items: UserProfile[];
  total: number;
  skip: number;
  limit: number;
}

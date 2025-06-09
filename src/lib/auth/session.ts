import { sha256 } from "@oslojs/crypto/sha2";
import {
  encodeBase32LowerCaseNoPadding,
  encodeHexLowerCase,
} from "@oslojs/encoding";
import { SESSION_EXPIRATION_MS } from "@repo/config";
import {
  mediaTable,
  sessionsTable,
  usersTable,
  walletsTable,
  type Session,
  type User,
  type UserProfile,
} from "@repo/db";
import { eq } from "drizzle-orm";
import { db } from "../lib/db";

export function generateSessionToken(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const token = encodeBase32LowerCaseNoPadding(bytes);
  return token;
}

export function generateSessionId(token: string): string {
  return encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
}

export const updateExpiryTime = (): Date =>
  new Date(Date.now() + SESSION_EXPIRATION_MS);

export async function createSession(userId: string): Promise<Session> {
  return (
    await db
      .insert(sessionsTable)
      .values({
        user_id: userId,
        expires_at: new Date(Date.now() + SESSION_EXPIRATION_MS),
        created_at: new Date(Date.now()),
      })
      .returning()
  )[0];
}

export async function validateSessionToken(
  token: string
): Promise<SessionValidationResult> {
  const result = await db
    .select({ user: usersTable, session: sessionsTable })
    .from(sessionsTable)
    .innerJoin(usersTable, eq(sessionsTable.user_id, usersTable.id))
    .where(eq(sessionsTable.id, token));

  if (result.length < 1) {
    return { session: null, user: null };
  }
  const { user, session } = result[0];
  if (Date.now() >= session.expires_at.getTime()) {
    await db.delete(sessionsTable).where(eq(sessionsTable.id, session.id));
    return { session: null, user: null };
  }

  const halfLife = SESSION_EXPIRATION_MS / 2;
  if (Date.now() >= session.expires_at.getTime() - halfLife) {
    session.expires_at = new Date(updateExpiryTime());
    await db
      .update(sessionsTable)
      .set({
        expires_at: session.expires_at,
      })
      .where(eq(sessionsTable.id, session.id));
  }
  return { session, user };
}

export async function invalidateSession(sessionId: string): Promise<void> {
  await db.delete(sessionsTable).where(eq(sessionsTable.id, sessionId));
}

export type SessionValidationResult =
  | { session: Session; user: User }
  | { session: null; user: null };

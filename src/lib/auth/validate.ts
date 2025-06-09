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

export const validate = publicProcedure
    .input(z.object({ session: z.string().optional() }))
    .query(async ({ input, ctx }) => {
      const sessionKey = SESSION_COOKIE as keyof typeof ctx.cookies;
      const sessionId = ctx.cookies[sessionKey] || "";
      if (!sessionId) return { session: null, user: null };

      return validateSessionToken(sessionId ?? input?.session);
    }),
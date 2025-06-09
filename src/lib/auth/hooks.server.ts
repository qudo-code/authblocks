import { trpc } from "$lib/trpc";
import { SESSION_COOKIE } from "@repo/config";
import type { User } from "@repo/db";
import type { Handle } from "@sveltejs/kit";
import { sequence } from "@sveltejs/kit/hooks";

// Redirect away from these route IDs if session not valid
const authorized = ["/(private)/test"];

const unauthorized = new Response(null, {
  status: 302,
  headers: { location: "/" },
});

const authHandle: Handle = async ({ event, resolve }) => {
  // Clear these to be repopulated if session is valid
  event.locals.user = null;
  event.locals.session = null;

  const sessionCookie = event.cookies.get(SESSION_COOKIE);
  const requiresAuth = authorized.includes(event.route.id || "");

  // Is public route
  if (!requiresAuth) return resolve(event);
  // Is private route, but no session
  if (!sessionCookie) return unauthorized;

  const { session, user } = await trpc.session.validate.query({
    session: sessionCookie,
  });

  // Invalid session
  if (!session || !user) return unauthorized;

  // Populate locals with session and user
  event.locals.user = user as User;
  event.locals.session = session?.id || "";

  return resolve(event);
};

export const handle: Handle = sequence(authHandle);

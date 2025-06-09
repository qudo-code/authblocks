import { createSession, invalidateSession } from "./session";
import { SESSION_COOKIE, SESSION_EXPIRATION_SECONDS } from "@repo/config";
import cookie from "cookie";

const validateAuthInput = () => {
  // ..validate input, return a user
}

export const login = async (request: Request) => {
  const cookies = cookie.parse(request.headers.get("Cookie") || "");
  const url = new URL(request.url);

  try {
    const user = await validateAuthInput(request)
    const session = createSession(user?.id);

    return new Response("Success", {
      headers: {
        "Content-Type": "text/plain",
        "Set-Cookie": cookie.serialize(SESSION_COOKIE, session.id, {
          httpOnly: true,
          maxAge: SESSION_EXPIRATION_SECONDS,
          secure: true,
          path: "/",
          sameSite: "lax",
        }),
        Location: `${UI_URL}/u/${session.user_id}`,
      },
      status: 302,
    });
  } catch (error) {
    return new Response("Unauthorized", {
      status: 302,
      headers: {
        "Content-Type": "text/plain",
        Location: `${UI_URL}/signin/?error=true`,
      },
    });
  }
};


export const handleLogout = async (request: Request) => {
  const url = new URL(request.url);
  const params = new URLSearchParams(url.search);
  const cookies = cookie.parse(request.headers.get("Cookie") || "");
  const sessionCookie = cookies[SESSION_COOKIE];

  if (!sessionCookie) {
    console.log("No session cookie found");

    return new Response("Unauthorized", {
      status: 302,
      headers: {
        "Content-Type": "text/plain",
        Location: `${UI_URL}/signin/?`,
      },
    });
  }

  try {
    await invalidateSession(sessionCookie);
    return new Response("Success", {
      headers: {
        "Content-Type": "text/plain",
        "Set-Cookie": cookie.serialize(SESSION_COOKIE, "", {
          httpOnly: true,
          maxAge: 0,
          secure: true,
          path: "/",
          sameSite: "lax",
        }),
        Location: `${UI_URL}/signin`,
      },
      status: 302,
    });
  } catch (error) {
    console.error(error);
    return new Response("Unauthorized", {
      status: 302,
      headers: {
        "Content-Type": "text/plain",
        Location: `${UI_URL}/signin/?error=true`,
      },
    });
  }
};

import {
  DISCORD_STATE_COOKIE,
  GITHUB_STATE_COOKIE,
  GOOGLE_CODE_VERIFIER_COOKIE,
  GOOGLE_STATE_COOKIE,
  SESSION_COOKIE,
  TWITTER_CODE_VERIFIER_COOKIE,
  TWITTER_STATE_COOKIE,
} from "@repo/config";
import { mediaTable, providersTable } from "@repo/db";
import {
  Discord,
  GitHub,
  Google,
  Twitter,
  generateCodeVerifier,
  generateState,
} from "arctic";
import cookie from "cookie";
import { and, eq } from "drizzle-orm";
import { db } from "./db";
import { validateSessionToken } from "./session";

const isDev =
  process?.env?.PUBLIC_UI_URL?.includes("localhost") ||
  process?.env?.PUBLIC_UI_URL?.includes("127.0.0.1");

const methodMap = {
  init: "requestAuth",
  callback: "verifyAuth",
  remove: "removeAuth",
} as const;

export const handleOauthInitAndCallback = async (request: Request) => {
  console.log("request", request.url);
  const url = request.url.split("/");
  const provider = url[5] as OauthClient;
  const type = url[6].split("?")[0] as "init" | "callback" | "remove";
  const oauth = clients[provider];
  if (!oauth) {
    return new Response("Not Found", { status: 404 });
  }
  try {
    return oauth[methodMap[type]](request);
  } catch (error) {
    console.log(error);
    return new Response("Internal Server Error", { status: 500 });
  }
};

export const oauth = {
  discord: () =>
    new Discord(
      process.env.DISCORD_CLIENT_ID || "",
      process.env.DISCORD_CLIENT_SECRET || "",
      `${process.env.PUBLIC_API_URL}/auth/link/discord/callback`
    ) as Discord,
  github: () =>
    new GitHub(
      process.env.GITHUB_CLIENT_ID || "",
      process.env.GITHUB_CLIENT_SECRET || "",
      `${process.env.PUBLIC_API_URL}/auth/link/github/callback`
    ),
  twitter: () =>
    new Twitter(
      process.env.TWITTER_CLIENT_ID || "",
      process.env.TWITTER_CLIENT_SECRET || "",
      `${process.env.PUBLIC_API_URL}/auth/link/twitter/callback`
    ),
  google: () =>
    new Google(
      process.env.GOOGLE_CLIENT_ID || "",
      process.env.GOOGLE_CLIENT_SECRET || "",
      `${process.env.PUBLIC_API_URL}/auth/link/google/callback`
    ),
};

export type OauthClient = keyof typeof oauth;

const errorResponse = (error: string) =>
  new Response("Error", {
    headers: {
      "Content-Type": "text/plain",
      Location: `${process.env.PUBLIC_UI_URL}/?error=${error}`,
    },
    status: 302,
  });

type User = {
  username?: string;
  email?: string;
  oauth_user_id?: string;
  avatar?: string;
};

type GetUserMethod = (input: any) => Promise<User>;
type RequestAuthMethod = (request: Request) => Promise<Response>;
type VerifyAuthMethod = (request: Request) => Promise<Response>;
type RemoveAuthMethod = (request: Request) => Promise<Response>;

type OauthInput = {
  client: OauthClient;
};

class Oauth {
  public readonly clientName: OauthClient;
  public readonly client: Discord | GitHub | Twitter | Google;
  public readonly requestAuth: RequestAuthMethod = async (request: Request) => {
    return new Response();
  };
  public readonly verifyAuth: VerifyAuthMethod = async (request: Request) => {
    return new Response();
  };
  public readonly removeAuth: RemoveAuthMethod = async (request: Request) => {
    return new Response();
  };
  public readonly getUser: GetUserMethod = async () => ({});

  constructor(input: OauthInput) {
    this.clientName = input.client;
    this.client = oauth[input.client]();
  }
}

class GoogleOauth extends Oauth {
  constructor(input: OauthInput) {
    super(input);
  }

  public readonly requestAuth = async (request: Request) => {
    const state = generateState();
    const scopes = ["openid", "profile", "email"];
    const codeVerifier = generateCodeVerifier();
    // @ts-ignore
    const url = this.client.createAuthorizationURL(state, codeVerifier, scopes);
    const requestUrl = new URL(request.url);
    const sessionId = requestUrl.searchParams.get(SESSION_COOKIE);

    const headers = new Headers();

    headers.append(
      "Set-Cookie",
      cookie.serialize(SESSION_COOKIE, sessionId || "", {
        httpOnly: true,
        secure: true,
        path: "/",
        sameSite: "lax",
      })
    );

    headers.append(
      "Set-Cookie",
      cookie.serialize(GOOGLE_STATE_COOKIE, state, {
        httpOnly: true,
        secure: true,
        path: "/",
        sameSite: "lax",
      })
    );
    headers.append(
      "Set-Cookie",
      cookie.serialize(GOOGLE_CODE_VERIFIER_COOKIE, codeVerifier, {
        httpOnly: true,
        secure: true,
        path: "/",
        sameSite: "lax",
      })
    );

    return new Response(null, {
      status: 302,
      headers: {
        ...Object.fromEntries(headers),
        Location: url.toString(),
      },
    });
  };

  public readonly verifyAuth = async (request: Request) => {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const cookies = cookie.parse(request.headers.get("Cookie") || "");
    const sessionId = cookies[SESSION_COOKIE];
    const codeVerifier = cookies[GOOGLE_CODE_VERIFIER_COOKIE];
    // If none of these exist, throw a 400 and redirect to /
    if (!state || !code || !codeVerifier) {
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
    try {
      if (!sessionId) {
        return Response.redirect(process.env.PUBLIC_UI_URL || "");
      }
      const { user } = await validateSessionToken(sessionId);
      if (!user) {
        return Response.redirect(process.env.PUBLIC_UI_URL || "");
      }
      const tokens = await this.client.validateAuthorizationCode(
        code,
        codeVerifier
      );
      if (!tokens.accessToken) {
        return Response.redirect(process.env.PUBLIC_UI_URL || "");
      }
      const response = await fetch(
        "https://openidconnect.googleapis.com/v1/userinfo",
        {
          headers: {
            Authorization: `Bearer ${tokens.accessToken()}`,
          },
        }
      );
      const googleUser = await response.json();
      const [existingLinkedProvider] = await db
        .select()
        .from(providersTable)
        .where(eq(providersTable.auth_id, googleUser.sub))
        .limit(1);

      if (existingLinkedProvider) {
        return Response.redirect(
          `${process.env.PUBLIC_UI_URL}/u/${existingLinkedProvider.id}`
        );
      }

      const [checkExistingImage] = await db
        .select()
        .from(mediaTable)
        .where(
          and(
            eq(mediaTable.user_id, user.id),
            eq(mediaTable.uri, googleUser.picture)
          )
        )
        .limit(1);
      if (checkExistingImage) {
        return Response.redirect(`${process.env.PUBLIC_UI_URL}/u/${user.id}`);
      }
      await db.insert(providersTable).values({
        provider: "google",
        auth_username: googleUser.name,
        auth_id: googleUser.sub,
        auth_profile_image: googleUser.picture,
        user_id: user.id,
      });
      await db.insert(mediaTable).values({
        user_id: user.id,
        type: "avatar",
        formatting: "url",
        uri: googleUser.picture,
      });
      // send back to the app after login
      return Response.redirect(`${process.env.PUBLIC_UI_URL}/u/${user.id}`);
    } catch (error) {
      console.error(error);
      // send back to the app after login
      // TODO: handle error better
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
  };

  public readonly removeAuth = async (request: Request) => {
    const url = new URL(request.url);
    const sessionId = url.searchParams.get("session_id");
    if (!sessionId) {
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
    const { user } = await validateSessionToken(sessionId);
    if (!user) {
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
    await db
      .delete(providersTable)
      .where(
        and(
          eq(providersTable.user_id, user.id),
          eq(providersTable.provider, this.clientName)
        )
      );
    return Response.redirect(`${process.env.PUBLIC_UI_URL}/u/${user.id}`);
  };

  // example/todo
  public readonly getUser = async () => ({});
}
class GithubOauth extends Oauth {
  constructor(input: OauthInput) {
    super(input);
  }

  public readonly requestAuth = async (request: Request) => {
    const state = generateState();
    const scopes = ["read:user", "user:email"];
    // @ts-ignore
    const url = this.client.createAuthorizationURL(state, scopes);
    const requestUrl = new URL(request.url);
    const sessionId = requestUrl.searchParams.get(SESSION_COOKIE);

    const headers = new Headers();

    headers.append(
      "Set-Cookie",
      cookie.serialize(SESSION_COOKIE, sessionId || "", {
        httpOnly: true,
        secure: true,
        path: "/",
        sameSite: "lax",
      })
    );

    headers.append(
      "Set-Cookie",
      cookie.serialize(GITHUB_STATE_COOKIE, state, {
        httpOnly: true,
        secure: true,
        path: "/",
        sameSite: "lax",
      })
    );

    return new Response(null, {
      status: 302,
      headers: {
        ...Object.fromEntries(headers),
        Location: url.toString(),
      },
    });
  };

  public readonly verifyAuth = async (request: Request) => {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const cookies = cookie.parse(request.headers.get("Cookie") || "");
    const sessionId = cookies[SESSION_COOKIE];
    const storedState = cookies[GITHUB_STATE_COOKIE];
    // Current session ID from cookie
    // If none of these exist, throw a 400 and redirect to /
    if (!state || !code || state !== storedState) {
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
    try {
      // @ts-ignore
      const tokens = await this.client.validateAuthorizationCode(code);
      const accessToken = tokens.accessToken();
      if (!accessToken) {
        return Response.redirect(process.env.PUBLIC_UI_URL || "");
      }
      const response = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      const oauthUser = await response.json();
      if (!oauthUser.id) {
        return Response.redirect(process.env.PUBLIC_UI_URL || "");
      }
      const [existingLinkedProvider] = await db
        .select()
        .from(providersTable)
        .where(eq(providersTable.auth_id, oauthUser.id))
        .limit(1);

      // Account is already linked, throw error
      if (existingLinkedProvider || !sessionId) {
        return Response.redirect(
          `${process.env.PUBLIC_UI_URL}/u/${existingLinkedProvider.id}`
        );
      }
      const { user } = await validateSessionToken(sessionId);
      if (!user) {
        return Response.redirect(process.env.PUBLIC_UI_URL || "");
      }
      const [checkExistingImage] = await db
        .select()
        .from(mediaTable)
        .where(
          and(
            eq(mediaTable.user_id, user.id),
            eq(
              mediaTable.uri,
              `https://avatars.githubusercontent.com/${oauthUser.login}`
            )
          )
        )
        .limit(1);
      if (checkExistingImage) {
        return Response.redirect(`${process.env.PUBLIC_UI_URL}/u/${user.id}`);
      }
      // Inserting the provider and avatar to media table //
      await db.insert(providersTable).values({
        provider: "github",
        auth_username: oauthUser.login,
        auth_id: oauthUser.id,
        auth_profile_image: `https://avatars.githubusercontent.com/${oauthUser.login}`,
        user_id: user.id,
      });
      await db.insert(mediaTable).values({
        user_id: user.id,
        type: "avatar",
        formatting: "url",
        uri: `https://avatars.githubusercontent.com/${oauthUser.login}`,
      });
      return Response.redirect(`${process.env.PUBLIC_UI_URL}/u/${user.id}`);
    } catch (error) {
      console.error(error);
      // send back to the app after login
      // TODO: handle error better
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
  };

  public readonly removeAuth = async (request: Request) => {
    const url = new URL(request.url);
    const sessionId = url.searchParams.get("session_id");
    if (!sessionId) {
      //
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
    const { user } = await validateSessionToken(sessionId);
    if (!user) {
      //
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
    await db
      .delete(providersTable)
      .where(
        and(
          eq(providersTable.user_id, user.id),
          eq(providersTable.provider, this.clientName)
        )
      );
    return Response.redirect(`${process.env.PUBLIC_UI_URL}/u/${user.id}`);
  };

  // example/todo
  public readonly getUser = async () => ({});
}

class DiscordOauth extends Oauth {
  constructor(input: OauthInput) {
    super(input);
  }

  public readonly requestAuth = async (request: Request) => {
    const state = generateState();
    const scopes = ["identify"];
    // @ts-ignore
    const url = this.client.createAuthorizationURL(state, scopes);
    const requestUrl = new URL(request.url);
    const sessionId = requestUrl.searchParams.get(SESSION_COOKIE);

    // Create response with cookies using the Web API approach
    const headers = new Headers();

    // Set cookies using the same approach as siws.ts
    headers.append(
      "Set-Cookie",
      cookie.serialize(SESSION_COOKIE, sessionId || "", {
        httpOnly: true,
        secure: true,
        path: "/",
        sameSite: "lax",
      })
    );

    headers.append(
      "Set-Cookie",
      cookie.serialize(DISCORD_STATE_COOKIE, state, {
        httpOnly: true,
        secure: true,
        path: "/",
        sameSite: "lax",
      })
    );

    return new Response(null, {
      status: 302,
      headers: {
        ...Object.fromEntries(headers),
        Location: url.toString(),
      },
    });
  };

  public readonly verifyAuth = async (request: Request) => {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const cookies = cookie.parse(request.headers.get("Cookie") || "");
    console.log("cookies", cookies);
    const sessionId = cookies[SESSION_COOKIE];
    const storedState = cookies[DISCORD_STATE_COOKIE];

    // If none of these exist, throw a 400 and redirect to /
    if (!state || !code || state !== storedState) {
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }

    try {
      console.log({ sessionId });
      if (!sessionId) {
        console.log("no session id");
        return Response.redirect(
          `${process.env.PUBLIC_UI_URL || ""}/?error=invalid-session`
        );
      }

      // @ts-ignore
      const tokens = await this.client.validateAuthorizationCode(code);
      if (!tokens.accessToken) {
        console.log("no access token");
        return Response.redirect(
          `${process.env.PUBLIC_UI_URL || ""}/?error=invalid-access-token`
        );
      }

      const response = await fetch("https://discord.com/api/users/@me", {
        headers: {
          Authorization: `Bearer ${tokens.accessToken()}`,
        },
      });

      const discordUser = await response.json();
      const { user } = await validateSessionToken(sessionId);

      if (!user) {
        console.log("no user");
        return Response.redirect(
          `${process.env.PUBLIC_UI_URL || ""}/?error=invalid-user`
        );
      }

      const [existingLinkedProvider] = await db
        .select()
        .from(providersTable)
        .where(eq(providersTable.auth_id, discordUser.id))
        .limit(1);

      if (existingLinkedProvider) {
        return Response.redirect(
          `${process.env.PUBLIC_UI_URL}/u/${user.id}?error=account-already-linked`
        );
      }
      await db.insert(providersTable).values({
        provider: "discord",
        auth_username: discordUser.username,
        auth_id: discordUser.id,
        auth_profile_image: `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`,
        user_id: user.id,
      });

      if (discordUser.banner) {
        const [checkExistingBanner] = await db
          .select()
          .from(mediaTable)
          .where(
            and(
              eq(mediaTable.user_id, user.id),
              eq(
                mediaTable.uri,
                `https://cdn.discordapp.com/banners/${discordUser.id}/${discordUser.banner}.png`
              )
            )
          )
          .limit(1);

        if (!checkExistingBanner) {
          await db.insert(mediaTable).values({
            user_id: user.id,
            type: "banner",
            formatting: "url",
            uri: `https://cdn.discordapp.com/banners/${discordUser.id}/${discordUser.banner}.png`,
          });
        }
      }

      const [checkExistingImage] = await db
        .select()
        .from(mediaTable)
        .where(
          and(
            eq(mediaTable.user_id, user.id),
            eq(
              mediaTable.uri,
              `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
            )
          )
        )
        .limit(1);

      if (!checkExistingImage) {
        await db.insert(mediaTable).values({
          user_id: user.id,
          type: "avatar",
          formatting: "url",
          uri: `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`,
        });
      }

      return new Response("Success", {
        headers: {
          "Content-Type": "text/plain",
          "Set-Cookie": cookie.serialize(DISCORD_STATE_COOKIE, "", {
            httpOnly: true,
            secure: isDev ? false : true,
            path: "/",
            expires: new Date(0),
            sameSite: "lax",
          }),
          Location: `${process.env.PUBLIC_UI_URL}/u/${user.id}?success=oauth-discord`,
        },
        status: 302,
      });
    } catch (error) {
      console.error(error);
      return Response.redirect(
        `${process.env.PUBLIC_UI_URL || ""}?error=oauth`
      );
    }
  };

  public readonly removeAuth = async (request: Request) => {
    const url = new URL(request.url);
    const sessionId = url.searchParams.get("session_id");
    if (!sessionId) {
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
    const { user } = await validateSessionToken(sessionId);
    if (!user) {
      return Response.redirect(process.env.PUBLIC_UI_URL || "");
    }
    await db
      .delete(providersTable)
      .where(
        and(
          eq(providersTable.user_id, user.id),
          eq(providersTable.provider, this.clientName)
        )
      );
    return Response.redirect(`${process.env.PUBLIC_UI_URL}/u/${user.id}`);
  };
  public readonly getUser = async () => ({});
  public readonly verifyUser = async () => ({});
}

class TwitterOauth extends Oauth {
  constructor(input: OauthInput) {
    super(input);
  }
  public readonly requestAuth = async (request: Request) => {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const scopes = ["users.read", "tweet.read"];
    // @ts-ignore
    const url = this.client.createAuthorizationURL(state, codeVerifier, scopes);
    console.log("TWITTER_VERIFICATION_URL", url);

    return new Response("Success", {
      headers: {
        "Content-Type": "text/plain",
        "Set-Cookie": [
          cookie.serialize(TWITTER_STATE_COOKIE, state, {
            httpOnly: true,
            secure: isDev ? false : true,
            maxAge: 60 * 10,
            path: "/",
            sameSite: "lax",
          }),
          cookie.serialize(TWITTER_CODE_VERIFIER_COOKIE, codeVerifier, {
            httpOnly: true,
            secure: isDev ? false : true,
            maxAge: 60 * 10,
            path: "/",
            sameSite: "lax",
          }),
        ].join("; "),
        Location: url.toString(),
      },
      status: 302,
    });
  };
  //@ts-ignore
  public readonly verifyAuth = async (request: Request) => {
    const url = new URL(request.url);
    const {
      twitter_state,
      twitter_code_verifier,
      [SESSION_COOKIE]: session,
    } = cookie.parse(request.headers.get("Cookie") || "");

    const params = url.searchParams;

    const code = params.get("code");
    const state = params.get("state");

    const stateCookie = twitter_state;
    const codeVerifier = twitter_code_verifier;

    // If none of these exist, throw a 400 and redirect to /
    if (
      !state ||
      !stateCookie ||
      !code ||
      stateCookie !== state ||
      !codeVerifier
    ) {
      console.log(
        "TWITTER_VERIFICATION_ERROR",
        !state,
        !stateCookie,
        !code,
        stateCookie !== state,
        !codeVerifier
      );

      return errorResponse("oauth-twitter-state");
    }
    try {
      if (!session) {
        return errorResponse("oauth-twitter-session");
      }
      const { user } = await validateSessionToken(session);
      if (!user) {
        return errorResponse("oauth-twitter-user");
      }
      const tokens = await this.client.validateAuthorizationCode(
        code,
        codeVerifier
      );
      if (!tokens.accessToken) {
        return errorResponse("oauth-twitter-token");
      }
      const response = await fetch("https://api.twitter.com/2/users/me", {
        headers: {
          Authorization: `Bearer ${tokens.accessToken()}`,
        },
      });
      const twitterUser = await response.json();
      console.log("twitterUser", twitterUser);
      const username = twitterUser.data.username;

      const [existingLinkedProvider] = await db
        .select()
        .from(providersTable)
        .where(eq(providersTable.auth_id, twitterUser.id))
        .limit(1);

      // Account is already linked, throw error
      if (existingLinkedProvider) {
        return errorResponse("oauth-twitter-linked");
      }
      await db.insert(providersTable).values({
        provider: "twitter",
        auth_username: username,
        auth_id: twitterUser.id,
        auth_profile_image: `https://x.com/${username}`,
        user_id: user.id,
      });

      await db.insert(mediaTable).values({
        user_id: user.id,
        type: "avatar",
        formatting: "url",
        uri: `https://x.com/${username}`,
      });

      return new Response("Success", {
        headers: {
          "Content-Type": "text/plain",
          // Clear cookie
          "Set-Cookie": cookie.serialize(TWITTER_STATE_COOKIE, "", {
            httpOnly: true,
            secure: isDev ? false : true,
            path: "/",
            expires: new Date(0),
            sameSite: "lax",
          }),
          Location: `${process.env.PUBLIC_UI_URL}/u/${user.id}?success=oauth-twitter`,
        },
        status: 302,
      });
    } catch (error) {
      console.error(error);
      return errorResponse("oauth-twitter");
    }
  };

  //@ts-ignore
  public readonly removeAuth = async (request: Request) => {
    const url = new URL(request.url);
    const session = url.searchParams.get("session_id");
    if (!session) {
      return errorResponse("oauth-twitter-state");
    }
    const { user } = await validateSessionToken(session);
    if (!user) {
      return errorResponse("oauth-twitter-session");
    }
    await db
      .delete(providersTable)
      .where(
        and(
          eq(providersTable.user_id, user.id),
          eq(providersTable.provider, this.clientName)
        )
      );
    return errorResponse("oauth-twitter-user");
  };
  public readonly getUser = async () => ({});
}

export const google = new GoogleOauth({ client: "google" });
export const discord = new DiscordOauth({ client: "discord" });
export const github = new GithubOauth({ client: "github" });
export const twitter = new TwitterOauth({ client: "twitter" });

export const clients: Partial<Record<OauthClient, Oauth>> = {
  google: google,
  discord: discord,
  github: github,
  twitter: twitter,
};

import {
  Discord,
  generateCodeVerifier,
  generateState,
  GitHub,
  Google,
  LinkedIn,
  OAuth2Tokens,
  Twitter,
} from "arctic";
import cookie from "cookie";

const STATE_COOKIE = "oauth_state";
const CODE_VERIFIER_COOKIE = "oauth_code_verifier";

type OauthConfig = {
  scopes: string[];
  api: string;
  transform: (response: any) => OauthUserDetails;
  useCodeVerifier?: boolean;
};

export type OauthUserDetails = {
  username?: string;
  email?: string;
  oauth_user_id?: string;
  avatar?: string;
};

type InitializeOauth = {
  provider: SupportedProvider;
  clientId: string;
  clientSecret: string;
  oauthRedirectUri: string;
  verifiedRedirectUri: string;
  stateCookie?: string;
  codeVerifierCookie?: string;
  scopes?: string[];
  onVerified?: (
    provider: SupportedProvider,
    user: OauthUserDetails,
    request: Request
  ) => Promise<void>;
  onError?: (provider: SupportedProvider, error: Error) => Promise<void>;
};

const supportedProviders = {
  google: Google,
  github: GitHub,
  discord: Discord,
  twitter: Twitter,
  linkedin: LinkedIn,
};

export type SupportedProvider = keyof typeof supportedProviders;
export type OauthClient = Google | GitHub | Discord | Twitter | LinkedIn;

// Default configs
const config: Record<SupportedProvider, OauthConfig> = {
  google: {
    useCodeVerifier: true,
    scopes: ["openid", "profile", "email"],
    api: "https://openidconnect.googleapis.com/v1/userinfo",
    transform: (response: any) => ({
      oauth_user_id: response?.sub,
      email: response?.email,
      username: response?.name,
      avatar: response?.picture,
    }),
  },
  discord: {
    useCodeVerifier: true,
    scopes: ["identify"],
    api: "https://discord.com/api/users/@me",
    transform: (response: any) => ({
      oauth_user_id: response?.id,
      email: response?.email,
      username: response?.username,
      avatar: response?.avatar,
    }),
  },
  twitter: {
    useCodeVerifier: true,
    scopes: ["users.read", "tweet.read"],
    api: "https://api.twitter.com/2/users/me",
    transform: (response: any) => ({
      oauth_user_id: response?.data?.id,
      email: response?.data?.email,
      username: response?.data?.name,
      avatar: response?.data?.profile_image_url,
    }),
  },
  github: {
    scopes: ["read:user"],
    api: "https://api.github.com/user",
    transform: (response: any) => ({
      oauth_user_id: String(response?.id) || "",
      username: response?.login || "",
      avatar: response?.avatar_url || "",
      email: "",
    }),
  },
  linkedin: {
    scopes: ["openid", "profile", "email"],
    api: "https://api.linkedin.com/v2/userinfo",
    transform: (response: any) => ({
      oauth_user_id: response?.sub,
      username: response?.name || "",
      avatar: response?.picture || "",
      email: response?.email || "",
    }),
  },
};

/**
 * OAuth class for handling authentication flows with various providers
 */
export class Oauth {
  public readonly config: OauthConfig;
  public readonly client: OauthClient;
  public readonly provider: SupportedProvider;
  public readonly oauthRedirectUri: string;
  public readonly verifiedRedirectUri: string;
  public readonly onVerified: (
    provider: SupportedProvider,
    user: OauthUserDetails,
    request: Request
  ) => Promise<void>;
  public readonly onError: (
    provider: SupportedProvider,
    error: Error
  ) => Promise<void>;

  /**
   * Creates an instance of the OAuth handler
   * @param {InitializeOauth} input - Configuration object containing clientId, clientSecret, etc.
   */
  constructor(input: InitializeOauth) {
    this.provider = input.provider;
    this.oauthRedirectUri = input.oauthRedirectUri;
    this.verifiedRedirectUri = input.verifiedRedirectUri;

    this.client = new supportedProviders[input.provider](
      input.clientId,
      input.clientSecret,
      input.oauthRedirectUri
    );

    this.config = {
      scopes: input.scopes || config[input.provider].scopes || [],
      api: config[input.provider].api,
      transform: config[input.provider].transform,
      useCodeVerifier: config[input.provider].useCodeVerifier || false,
    };

    this.onVerified =
      input.onVerified ||
      ((provider, user, request) =>
        new Promise((resolve) => {
          console.log("[verified user]", provider, user);

          resolve();
        }));

    this.onError =
      input.onError ||
      ((provider, error) => {
        console.error("[error oauth]", provider, error);

        return Promise.resolve();
      });
  }

  public readonly getUser = async (tokens: OAuth2Tokens) => {
    const response = await fetch(this.config.api, {
      headers: {
        Authorization: `Bearer ${
          typeof tokens.accessToken === "function"
            ? tokens.accessToken()
            : tokens.accessToken
        }`,
      },
    });

    const resolved = await response.json();

    console.log("[resolved]", resolved);

    return this.config.transform(resolved);
  };

  /**
   * Initiates OAuth flow by generating state and code verifier
   * @returns {Promise<Response>} Redirect response with auth cookies
   */
  public readonly requestAuth = async () => {
    try {
      const state = generateState();
      const scopes = this.config?.scopes || [];
      const codeVerifier = generateCodeVerifier();

      let url = "";
      if (this.config.useCodeVerifier) {
        // @ts-ignore
        url = this.client.createAuthorizationURL(state, codeVerifier, scopes);
      } else {
        // @ts-ignore
        url = this.client.createAuthorizationURL(state, scopes);
      }

      const response = new Response("Redirecting...", {
        status: 302,
      });

      response.headers.append(
        "Set-Cookie",
        cookie.serialize(STATE_COOKIE, state || "", {
          httpOnly: true,
          secure: true,
          path: "/",
          sameSite: "lax",
        })
      );

      response.headers.append(
        "Set-Cookie",
        cookie.serialize(CODE_VERIFIER_COOKIE, codeVerifier || "", {
          httpOnly: true,
          secure: true,
          path: "/",
          sameSite: "lax",
        })
      );

      response.headers.append("Location", url.toString());

      return response;
    } catch (error) {
      console.error("[error oauth]", error);

      await this.onError(this.provider, error as Error);

      return new Response("Internal Server Error", { status: 500 });
    }
  };

  /**
   * Verifies the OAuth callback request
   * @param {Request} request - Incoming request with auth code and state
   * @returns {Promise<Response>} Response indicating auth success/failure
   */
  public readonly verifyAuthCallback = async (request: Request) => {
    try {
      const url = new URL(request.url);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const cookies = cookie.parse(request.headers.get("Cookie") || "");
      const stateCookie = cookies[STATE_COOKIE];
      const codeVerifierCookie = cookies[CODE_VERIFIER_COOKIE];

      if (!state || !code) {
        return new Response("Unauthorized: Missing state or code", {
          status: 401,
        });
      }

      if (stateCookie !== state || !codeVerifierCookie) {
        return new Response("Unauthorized: Invalid state or code verifier", {
          status: 401,
        });
      }

      const tokens = await this.client.validateAuthorizationCode(
        code,
        codeVerifierCookie
      );

      if (!tokens.accessToken) {
        return new Response("Unauthorized: Invalid access token", {
          status: 401,
        });
      }

      const user = await this.getUser(tokens);

      await this.onVerified(this.provider, user, request);

      return new Response(JSON.stringify(user), {
        status: 302,
        headers: {
          Location: this.verifiedRedirectUri,
        },
      });
    } catch (error) {
      console.error("[error oauth]", error);

      await this.onError(this.provider, error as Error);

      return new Response("Internal Server Error", { status: 500 });
    }
  };
}
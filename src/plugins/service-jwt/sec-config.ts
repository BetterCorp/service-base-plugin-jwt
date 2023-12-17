import { BSBServiceConfig } from "@bettercorp/service-base";
import { z } from "zod";

export enum IEJWTPluginAuthType {
  JWTCERTS = "JWTCERTS",
  JWTSECRET = "JWTSECRET",
}
// https://github.com/auth0/node-jsonwebtoken#algorithms-supported
export type Algorithm =
  | "HS256"
  | "HS384"
  | "HS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "none";

export const secSchema = z
  .object({
    privateKey: z
      .string()
      .nullable()
      .default(null)
      .describe("Private signing key"),
    publicKey: z
      .string()
      .nullable()
      .default(null)
      .describe("Public signing key"),
    secretKey: z
      .string()
      .nullable()
      .default(null)
      .describe("Signing secret key"),
    keyUrl: z.string().nullable().default(null).describe("JWT Signing key url"),
    bearerStr: z
      .string()
      .default("Bearer")
      .describe("Changes auth header 'Bearer (token)' value"),
    authKey: z.string().nullable().default(null).describe("For using secret key signing"),
    queryKey: z
      .string()
      .default("token")
      .describe(
        "For WebServers to use query string auth instead of header auth"
      ),
    options: z
      .object({
        algorithms: z
          .array(
            z.enum([
              "HS256",
              "HS384",
              "HS512",
              "RS256",
              "RS384",
              "RS512",
              "ES256",
              "ES384",
              "ES512",
              "PS256",
              "PS384",
              "PS512",
              "none",
            ])
          )
          .optional(),
        audience: z
          .union([
            z.string(),
            z.instanceof(RegExp),
            z.array(z.union([z.string(), z.instanceof(RegExp)])),
          ])
          .optional(),
        clockTimestamp: z.number().optional(),
        clockTolerance: z.number().optional(),
        complete: z.boolean().optional(),
        issuer: z.union([z.string(), z.array(z.string())]).optional(),
        ignoreExpiration: z.boolean().optional(),
        ignoreNotBefore: z.boolean().optional(),
        jwtid: z.string().optional(),
        nonce: z.string().optional(),
        subject: z.string().optional(),
        maxAge: z.union([z.string(), z.number()]).optional(),
      })
      .describe("Signing options")
      .default({}),
    tokenLifespanMinutes: z
      .number()
      .nullable()
      .default(null)
      .describe("Token lifespan in minutes"),
    defaultTokenType: z
      .enum(["req", "reqOrQuery", "query"])
      .default("reqOrQuery")
      .describe("The default web server token validation type"),
    allowedTokenTypes: z
      .array(z.enum(["req", "reqOrQuery", "query"]))
      .default(["reqOrQuery"])
      .describe(
        "If clients should only use certain types of tokens (header/query etc...)"
      ),
  })
  .default({});

export class Config extends BSBServiceConfig<typeof secSchema> {
  validationSchema = secSchema;

  migrate(
    toVersion: string,
    fromVersion: string | null,
    fromConfig: any | null
  ) {
    return fromConfig;
  }
}

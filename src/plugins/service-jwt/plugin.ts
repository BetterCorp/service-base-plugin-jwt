import {
  BSBService,
  BSBServiceConstructor,
  BSBServiceTypes,
  ServiceEventsBase,
} from "@bettercorp/service-base";
import * as jsonwebtoken from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import { Config } from "./sec-config";
import { Tools } from "@bettercorp/tools";
import * as bcrypt from "bcrypt";
import type { SignOptions, VerifyOptions } from "jsonwebtoken";

export interface ServiceTypes extends BSBServiceTypes {
  onEvents: ServiceEventsBase;
  emitEvents: ServiceEventsBase;
  onReturnableEvents: {
    validateToken(
      token: string,
      overrideOptions?: VerifyOptions
    ): Promise<WJwtPayload>;
    signToken(
      tokenData: any,
      userId: string,
      overrideOptions?: SignOptions
    ): Promise<string>;
    getConfig(): Promise<{
      bearerStr: string;
      queryKey: string;
      //defaultTokenType: EJWTTokenType;
      //allowedTokenTypes: Array<EJWTTokenType>;
    }>;
  };
  emitReturnableEvents: ServiceEventsBase;
  onBroadcast: ServiceEventsBase;
  emitBroadcast: ServiceEventsBase;
  methods: {};
}
export interface WJwtPayload extends jsonwebtoken.JwtPayload {
  _from: string;
}

export class Plugin extends BSBService<Config, ServiceTypes> {
  private JWTClient: jwksClient.JwksClient | null = null;

  initBeforePlugins?: string[] | undefined;
  initAfterPlugins?: string[] | undefined;
  runBeforePlugins?: string[] | undefined;
  runAfterPlugins?: string[] | undefined;

  methods = {};
  dispose(): void {
    if (this.JWTClient !== null) this.JWTClient = null;
  }
  public run?(): void;

  constructor(config: BSBServiceConstructor) {
    super(config);
  }

  public async init(): Promise<void> {
    const jwtClientKeyUrl = this.config.keyUrl;
    if (Tools.isString(jwtClientKeyUrl))
      this.JWTClient = jwksClient({
        jwksUri: jwtClientKeyUrl,
      });

    const self = this;
    await this.events.onReturnableEvent(
      "validateToken",
      async (token: string, overrideOptions?: VerifyOptions) => {
        if (!Tools.isNull(self.JWTClient)) {
          return await self.validateToken(token, "", overrideOptions, true);
        }
        const secretKey = this.config.secretKey ?? this.config.privateKey;
        if (secretKey === null)
          throw "Unknown secret/private key to sign token";
        return await self.validateToken(
          token,
          secretKey,
          overrideOptions,
          false
        );
      }
    );
    await this.events.onReturnableEvent(
      "signToken",
      async (tokenData: any, userId: string, overrideOptions?: SignOptions) => {
        const secretKey = this.config.secretKey ?? this.config.privateKey;
        if (secretKey === null)
          throw "Unknown secret/private key to sign token";
        return await self.signToken(
          tokenData,
          userId,
          secretKey,
          overrideOptions
        );
      }
    );
    await this.events.onReturnableEvent("getConfig", async () => {
      return {
        bearerStr: this.config.bearerStr,
        queryKey: this.config.queryKey,
        defaultTokenType: this.config.defaultTokenType,
        allowedTokenTypes: this.config.allowedTokenTypes,
      };
    });
  }

  private getJWTKey(header: any, callback: Function) {
    if (Tools.isNull(this.JWTClient))
      throw "JWT CLIENT NOT AVAILABLE FOR PUBLIC EXTERNAL KEYS";
    this.JWTClient.getSigningKey(header.kid, function (err: any, key: any) {
      try {
        var signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
      } catch (exc) {
        callback(exc);
      }
    });
  }
  private async validateToken(
    data: string,
    secretKey: string,
    overrideOptions?: VerifyOptions,
    externalKey: boolean = false
  ): Promise<WJwtPayload> {
    const self = this;
    return new Promise(async (resolve: any, reject: any) => {
      const publicKey = this.config.publicKey;
      const safeOverrideOptions = overrideOptions ?? this.config.options;
      if (externalKey === true) {
        return jsonwebtoken.verify(
          data,
          Tools.isString(publicKey)
            ? publicKey
            : (a, b) => {
                self.getJWTKey(a, b);
              },
          safeOverrideOptions,
          async (err: any, decoded: any) => {
            if (err) {
              return reject(err);
            }
            if (Tools.isArray(safeOverrideOptions.issuer)) {
              if (
                safeOverrideOptions.issuer.indexOf(
                  (decoded as jsonwebtoken.JwtPayload).iss ??
                    bcrypt.genSaltSync(8)
                ) < 0
              )
                return reject("Issuer does not match Issuer");
            } else if (Tools.isString(safeOverrideOptions.issuer)) {
              if (
                (decoded as jsonwebtoken.JwtPayload).iss !==
                safeOverrideOptions.issuer
              )
                return reject("Issuer does not match Issuer");
            }
            resolve({
              ...decoded,
              _from: "token",
            });
          }
        );
      }
      try {
        let decoded = jsonwebtoken.verify(data, secretKey, safeOverrideOptions);
        if (Tools.isString(decoded)) throw "Invalid token";
        if (Tools.isArray(safeOverrideOptions.issuer)) {
          if (
            safeOverrideOptions.issuer.indexOf(
              (decoded as jsonwebtoken.JwtPayload).iss ?? bcrypt.genSaltSync(8)
            ) < 0
          )
            return reject("Issuer does not match Issuer");
        } else if (Tools.isString(safeOverrideOptions.issuer)) {
          if (
            (decoded as jsonwebtoken.JwtPayload).iss !==
            safeOverrideOptions.issuer
          )
            return reject("Issuer does not match Issuer");
        }
        resolve({
          ...(decoded as jsonwebtoken.JwtPayload),
          _from: "token",
        });
      } catch (xcc) {
        return reject(xcc);
      }
    });
  }

  private async signToken(
    tokenData: any,
    userId: string,
    signingKey: string,
    overrideOptions?: SignOptions
  ) {
    const tokenLifespanMinutes = this.config.tokenLifespanMinutes;
    return jsonwebtoken.sign(
      tokenData,
      signingKey,
      overrideOptions ?? {
        expiresIn:
          tokenLifespanMinutes === null ? undefined : 60 * tokenLifespanMinutes,
        issuer: (this.config.options.issuer || this.pluginName).toString(),
        subject: userId,
      }
    );
  }
}

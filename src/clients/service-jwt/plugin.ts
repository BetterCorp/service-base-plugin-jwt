import { BSBService, BSBServiceClient } from "@bettercorp/service-base";
import { ServiceTypes } from "../../plugins/service-jwt/plugin";
import { SignOptions, VerifyOptions } from "jsonwebtoken";

export class JWT extends BSBServiceClient<ServiceTypes> {
  public readonly pluginName = "service-jwt";
  public readonly initBeforePlugins?: string[] | undefined;
  public readonly initAfterPlugins?: string[] | undefined;
  public readonly runBeforePlugins?: string[] | undefined;
  public readonly runAfterPlugins?: string[] | undefined;
  dispose?(): void;
  init?(): Promise<void>;
  run?(): Promise<void>;
  public constructor(context: BSBService<any, any>) {
    super(context);
  }

  async validateToken(token: string): Promise<any>;
  async validateToken(
    token: string,
    overrideOptions: VerifyOptions
  ): Promise<any>;
  async validateToken(
    token: string,
    overrideOptions?: VerifyOptions
  ): Promise<any> {
    return await this.events.emitEventAndReturn(
      "validateToken",
      15,
      token,
      overrideOptions
    );
  }

  async validateTokenQuiet(token: string): Promise<any>;
  async validateTokenQuiet(
    token: string,
    overrideOptions: VerifyOptions
  ): Promise<any>;
  async validateTokenQuiet(
    token: string,
    overrideOptions?: VerifyOptions
  ): Promise<any> {
    const self = this;
    return new Promise(async (resolve) =>
      self.events
        .emitEventAndReturn("validateToken", 15, token, overrideOptions)
        .then(resolve)
        .catch(() => resolve(false))
    );
  }

  async signToken(tokenData: any, userId: string): Promise<string>;
  async signToken(
    tokenData: any,
    userId: string,
    overrideOptions: SignOptions
  ): Promise<string>;
  async signToken(
    tokenData: any,
    userId: string,
    overrideOptions?: SignOptions
  ): Promise<string> {
    return await this.events.emitEventAndReturn(
      "signToken",
      15,
      tokenData,
      userId,
      overrideOptions
    );
  }
}

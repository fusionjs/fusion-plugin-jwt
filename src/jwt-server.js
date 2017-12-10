// @flow
/* eslint-env node */

import {
  SessionSecretType,
  SessionCookieNameType,
  SessionCookieExpiresType,
} from 'fusion-types';

import {BasePlugin} from 'fusion-core';
const assert = require('assert');
const {promisify} = require('util');
const jwt = require('jsonwebtoken');
const get = require('just-safe-get');
const set = require('just-safe-set');
const verify = promisify(jwt.verify.bind(jwt));
const sign = promisify(jwt.sign.bind(jwt));

// Scope path to `data.` here since `jsonwebtoken` has some special top-level keys that we do not want to expose (ex: `exp`)
const getFullPath = keyPath => `data.${keyPath}`;

type JWTConfig = {
  secret: string,
  cookieName: string,
  expires: number,
};

export default class JWTServerPlugin extends BasePlugin {
  config: JWTConfig;
  static dependencies = [
    SessionSecretType,
    SessionCookieNameType,
    SessionCookieExpiresType,
  ];
  constructor(secret: string, cookieName: string, expires: number) {
    super();
    this.config = {secret, cookieName, expires};
  }
  factory(ctx: *) {
    return new JWTSession(ctx, this.config);
  }
  async middleware(ctx: *, next: () => Promise<void>) {
    const session = this.factory(ctx);
    const token = await session.loadToken();
    await next();
    if (token) {
      delete token.exp; // Clear previous exp time and instead use `expiresIn` option below
      const time = Date.now(); // get time *before* async signing
      const signed = await sign(token, this.config.secret, {
        expiresIn: this.config.expires,
      });
      if (signed !== session.cookie) {
        const expires = new Date(time + this.config.expires * 1000);
        // TODO(#3) provide way to not set cookie if not needed yet
        ctx.cookies.set(this.config.cookieName, signed, {expires});
      }
    }
  }
}

class JWTSession {
  cookie: string;
  token: ?Object | string;
  config: JWTConfig;

  constructor(ctx: *, config: JWTConfig) {
    this.config = config;
    this.cookie = ctx.cookies.get(this.config.cookieName);
    this.token = null;
  }
  async loadToken() {
    if (this.token == null) {
      this.token = this.cookie
        ? await verify(this.cookie, this.config.secret).catch(() => ({}))
        : {};
    }
    return this.token;
  }
  get(keyPath: string) {
    assert(
      this.token,
      "Cannot access token before loaded, please use this plugin before any of it's dependencies"
    );
    return get(this.token, getFullPath(keyPath));
  }
  set(keyPath: string, val: any) {
    assert(
      this.token,
      "Cannot access token before loaded, please use this plugin before any of it's dependencies"
    );
    return set(this.token, getFullPath(keyPath), val);
  }
}

// export default ({
//   secret,
//   cookieName = 'fusion-sess',
//   expiresIn = 86400,
// }: {
//   secret: string,
//   cookieName: string,
//   expiresIn: number,
// }) => {

//   assert(typeof secret === 'string', '{secret} should be a string');
//   assert(typeof cookieName === 'string', '{cookieName} should be a string');
//   return new Plugin({
//     Service: ,
//   });
// };

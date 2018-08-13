Test

# fusion-plugin-jwt

[![Build status](https://badge.buildkite.com/0652871d45303631a598c88e1231073ea80b5dffaea46aa2b4.svg?branch=master)](https://buildkite.com/uberopensource/fusion-plugin-jwt?branch=master)

Session library that uses JSON Web Token and cookies

---

### Table of contents

* [Installation](#installation)
* [Usage](#usage)
* [Setup](#setup)
* [API](#api)
  * [Registration API](#registration-api)
    * [`Session`](#session)
    * [`SessionToken`](#sessiontoken)
  * [Dependencies](#dependencies)
    * [`SessionSecretToken`](#sessionsecrettoken)
    * [`SessionCookieNameToken`](#sessioncookienametoken)
    * [`SessionCookieExpiresToken`](#sessioncookieexpirestoken)
  * [Service API](#service-api)
* [Caveats](#caveats)

---

### Installation

```sh
yarn add fusion-plugin-jwt
```

---

### Usage

```js
export default createPlugin({
  deps: {Session: SessionToken},
  middleware() {
    return ({Session}) => {
      return async (ctx, next) => {
        const session = Session.from(ctx);
        session.set('some-key', 'some-value');
        const someValue = session.get('some-key');
        return next();
      }
    });
  }
});
```

---

### Setup

```js
// src/main.js
import React from 'react';
import App from 'fusion-react';
import JWTSession, {
  SessionSecretToken,
  SessionCookieNameToken,
  SessionCookieExpiresToken
} from 'fusion-plugin-jwt';
import {SessionToken} from 'fusion-tokens';

export default () => {
  const app = new App();
  // ...
  if (__NODE__) {
    app.register(SessionToken, JWTSession);
    app.register(SessionSecretToken, 'some-secret'); // required
    app.register(SessionCookieNameToken, 'some-cookie-name'); // required
    app.register(SessionCookieExpiresToken, 86400); // optional
  }
  // ...
  return app;
}
```

---

### API

#### Registration API

##### `Session`

```js
import Session from 'fusion-plugin-jwt';
```

The plugin. Should typically be registered to [`SessionToken`](https://github.com/fusionjs/fusion-tokens#sessiontoken)

##### `SessionToken`

Typically should be registered with [`Session`](#session). See [https://github.com/fusionjs/fusion-tokens#sessiontoken](https://github.com/fusionjs/fusion-tokens#sessiontoken)

#### Dependencies

##### `SessionSecretToken`

```js
import {SessionSecretToken} from 'fusion-plugin-jwt';
```

Required. A secret for encrypting the JWT token / cookie. Can typically be a random static value.

###### Types

```flow
type Secret = string;
```

##### `SessionCookieNameToken`

```js
import {SessionCookieNameToken} from 'fusion-plugin-jwt';
```

Required. A cookie name

###### Types

```flow
type CookieName = string;
```

##### `SessionCookieExpiresToken`

```js
import {SessionCookieExpiresToken} from 'fusion-plugin-jwt';
```

Required. An expiration time in seconds.

###### Types

```flow
type CookieName = number;
```

---

#### Service API

```js
const session: Session = Session.from((ctx: Context));
```

* `ctx: Context` - a [Fusion.js context](https://github.com/fusionjs/fusion-core#context)
* returns `session: Session`

###### Types

```js
type Session = {
  set: (key: string, value: Object | Array | string | number | boolean) => any,
  get: (key: string) => any,
};
```

**session.set**

```flow
const value = session.set(key:string, val:Object|Array|string|number|boolean);
```

* `key: string` - Required
* `val: Object|Array|string|number|boolean` - A serializable value. Required
* returns `value: any`

**session.get**

```flow
const value: any = session.get(key: string);
```

* `key: string` - Required
* returns `value: any`

---

### Caveats

Note that there's a storage limit of ~4kb since data is stored in the cookie.

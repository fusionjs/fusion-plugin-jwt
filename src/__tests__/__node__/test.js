import tape from 'tape-cup';
import App from 'fusion-core';
import {createServer} from 'http';
import JWTServer from '../../jwt-server';
import fetch from 'node-fetch';
import {
  SessionSecretType,
  SessionCookieNameType,
  SessionCookieExpiresType,
} from 'fusion-types';

tape('JWTServer', async t => {
  const app = new App('fake-element', el => el);
  app.register(SessionSecretType, 'session-secret');
  app.register(SessionCookieNameType, 'cookie-name');
  app.register(SessionCookieExpiresType, 86300);
  app.register(JWTServer);

  let count = 0;
  app.middleware([JWTServer], Session => (ctx, next) => {
    count++;
    const session = Session.factory(ctx);
    if (count === 2) {
      t.equal(session.get('test-something'), 'test-value');
    }
    session.set('test-something', 'test-value');
    ctx.body = 'OK';
    return next();
  });

  const cb = app.callback();
  const server = createServer(cb);
  await new Promise(resolve => server.listen(3000, resolve));
  let res = await fetch('http://localhost:3000/');
  t.ok(res.headers.get('set-cookie'), 'generates a session');
  t.equal(res.status, 200);
  res = await fetch('http://localhost:3000/', {
    headers: {
      Cookie: res.headers.get('set-cookie'),
    },
  });
  t.equal(res.status, 200);
  server.close();
  t.end();
});

tape('JWTServer with expired token', async t => {
  const app = new App('fake-element', el => el);
  app.register(SessionSecretType, 'session-secret');
  app.register(SessionCookieNameType, 'cookie-name');
  app.register(SessionCookieExpiresType, 1);
  app.register(JWTServer);

  let count = 0;
  app.middleware([JWTServer], Session => (ctx, next) => {
    count++;
    const session = Session.factory(ctx);
    if (count === 2) {
      t.notok(
        session.get('test-something'),
        'does not set the session if it has expired'
      );
    }
    session.set('test-something', 'test-value');
    ctx.body = 'OK';
    return next();
  });

  const cb = app.callback();
  const server = createServer(cb);
  await new Promise(resolve => server.listen(3000, resolve));
  let res = await fetch('http://localhost:3000/');
  t.ok(res.headers.get('set-cookie'), 'generates a session');
  t.equal(res.status, 200);

  await new Promise(resolve => setTimeout(resolve, 2000));

  res = await fetch('http://localhost:3000/', {
    headers: {
      Cookie: res.headers.get('set-cookie'),
    },
  });
  t.equal(res.status, 200);
  server.close();
  t.end();
});

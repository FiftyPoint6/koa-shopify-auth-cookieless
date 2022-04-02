const Error = require("./errors");
const validateHmac = require("./validate-hmac");

const createOAuthCallback = (config) => {
  return async function oAuthCallback(ctx) {
    const { query } = ctx;
    const { code, hmac, shop, state: nonce, host } = query;
    const { apiKey, secret, afterAuth } = config;

    if (nonce == null) {
      ctx.throw(403, Error.NonceMatchFailed);
    }

    if (shop == null) {
      ctx.throw(400, Error.ShopParamMissing);
      return;
    }

    if (validateHmac(hmac, secret, query) === false) {
      ctx.throw(400, Error.InvalidHmac);
      return;
    }

    const accessTokenQuery = new URLSearchParams({
      code,
      client_id: apiKey,
      client_secret: secret,
    }).toString();

    const accessTokenResponse = await fetch(
      `https://${shop}/admin/oauth/access_token`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(accessTokenQuery).toString(),
        },
        body: accessTokenQuery,
      }
    );

    if (!accessTokenResponse.ok) {
      ctx.throw(401, Error.AccessTokenFetchFailure);
      return;
    }

    const accessTokenData = await accessTokenResponse.json();
    const { access_token: accessToken, scope: scope } = accessTokenData;

    ctx.state.shopify = {
      shop,
      accessToken,
      scope,
    };

    if (afterAuth) {
      await afterAuth(ctx);
    }
  };
}

module.exports = createOAuthCallback;

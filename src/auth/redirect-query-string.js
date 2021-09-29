const { getQueryKey } = require("./utilities");

const redirectQueryString = (ctx) => {
  const shop = ctx.state.shopify
    ? ctx.state.shopify.shop
    : getQueryKey(ctx, "shop");
  const host = ctx.query
    ? ctx.query.host 
    : getQueryKey(ctx, "host");

  const url = new URL(`https://${shop}${ctx.url || ctx.request.url}`);
  const hmac = url.searchParams.get("hmac");
  const timestamp = url.searchParams.get("timestamp");
  const locale = url.searchParams.get("locale");
  const session = url.searchParams.get("session");
  return new URLSearchParams({
    hmac,
    shop,
    timestamp,
    locale,
    session,
    host
  }).toString();
}

module.exports = redirectQueryString;

const Error = require("./errors");
const oAuthQueryString = require("./oauth-query-string");

const createOAuthStart = (options, callbackPath) => {
  return function oAuthStart(ctx) {
    const { myShopifyDomain } = options;
    const { query } = ctx;
    const { shop } = query;

    const shopRegex = new RegExp(
      `^[a-z0-9][a-z0-9\\-]*[a-z0-9]\\.${myShopifyDomain}$`,
      "i"
    );

    if (shop == null || !shopRegex.test(shop)) {
      ctx.throw(400, Error.ShopParamMissing);
      return;
    }

    const formattedQueryString = oAuthQueryString(ctx, options, callbackPath);

    const redirectUri = `https://${shop}/admin/oauth/authorize?${formattedQueryString}`;

    if (ctx.query.embedded === '1') {
      ctx.body = `<html><head><link rel="stylesheet" href="https://unpkg.com/@shopify/polaris@5.5.0/dist/styles.css"/><script src="https://cdn.shopify.com/shopifycloud/app-bridge.js?apiKey=${options.apiKey}"></script></head><body><div style="text-align:center;margin-top:30px"><div style="--top-bar-background:#00848e; --top-bar-background-lighter:#1d9ba4; --top-bar-color:#f9fafb; --p-frame-offset:0px;"><span class="Polaris-Spinner Polaris-Spinner--colorTeal Polaris-Spinner--sizeLarge"><svg viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg"><path d="M15.542 1.487A21.507 21.507 0 00.5 22c0 11.874 9.626 21.5 21.5 21.5 9.847 0 18.364-6.675 20.809-16.072a1.5 1.5 0 00-2.904-.756C37.803 34.755 30.473 40.5 22 40.5 11.783 40.5 3.5 32.217 3.5 22c0-8.137 5.3-15.247 12.942-17.65a1.5 1.5 0 10-.9-2.863z"></path></svg></span><span role="status"><span class="Polaris-VisuallyHidden">Loading...</span></span></div><h2 class="Polaris-Heading" style="margin-top:20px;">Loading...</h2><p><span class="Polaris-TextStyle--variationSubdued">Please do not refresh the page</span></p></div><script>open('${redirectUri}', '_top');</script></body></html>`
    } else {
      ctx.redirect(redirectUri);
    }
    
  };
}

module.exports = createOAuthStart;

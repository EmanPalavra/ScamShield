import * as nodeModule from "node:module";

const cloudflareMockUrl = new URL("./cloudflare-workers.mock.mjs", import.meta.url).href;

if (typeof nodeModule.registerHooks === "function") {
  nodeModule.registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === "cloudflare:workers") {
        return { url: cloudflareMockUrl, shortCircuit: true };
      }
      return nextResolve(specifier, context);
    },
  });
} else {
  // Node 22.13–22.14 fallback. Newer versions use the synchronous API above.
  nodeModule.register("./cloudflare-loader.mjs", import.meta.url);
}

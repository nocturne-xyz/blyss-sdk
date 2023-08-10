// Not the nicest way to import WASM, but allows Webpack
// to bundle everything into a single JS file
import initWasm, {
  ApiClient,
  DoublePIRApiClient,
  decode_response,
  extract_result,
  generate_keys,
  generate_query,
  get_row,
  initialize_client
} from '../../dist/lib/lib';
import wasmData from '../../dist/lib/lib_bg.wasm';

if (typeof crypto === 'undefined')
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  (globalThis as any).crypto = (require('node:crypto') as any).webcrypto;

(async function () {
  let imported: any = initWasm;
  if (typeof imported !== 'function') imported = function () { };
  await imported(wasmData);
})();


export {
  ApiClient,
  DoublePIRApiClient,
  decode_response,
  extract_result,
  generate_keys,
  generate_query,
  get_row,
  initialize_client
};

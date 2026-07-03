import { xdr } from '@stellar/stellar-sdk';
const res = new xdr.SorobanResources({
  footprint: new xdr.LedgerFootprint({readOnly: [], readWrite: []}),
  instructions: 100,
  readBytes: 100,
  writeBytes: 100,
});
console.log(Object.getOwnPropertyNames(Object.getPrototypeOf(res)));

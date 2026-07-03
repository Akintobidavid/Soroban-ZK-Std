import { xdr, StrKey } from '@stellar/stellar-sdk';
const contractId = 'CC5KGHEE6JB3ICEI3B4GCLMPFETSN5J44FCQLZN7TUWKG4E2TUKXI7CY';
async function run() {
  const contractIdBuffer = StrKey.decodeContract(contractId);
  const ledgerKey = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
    contract: new xdr.ScAddress.scAddressTypeContract(contractIdBuffer),
    key: xdr.ScVal.scvLedgerKeyContractInstance(),
    durability: xdr.ContractDataDurability.persistent(),
  }));
  const res = await fetch('https://soroban-testnet.stellar.org', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getLedgerEntries', params: { keys: [ledgerKey.toXDR('base64')] } })
  });
  const json = await res.json();
  if (json.result && json.result.entries && json.result.entries.length > 0) {
    const entryXdr = json.result.entries[0].xdr;
    const entry = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const instance = entry.contractData().val().instance();
    const executable = instance.executable();
    if (executable.switch() === xdr.ContractExecutableType.contractExecutableWasm()) {
      console.log('WASM HASH:', executable.wasmHash().toString('hex'));
    } else {
      console.log('Not a WASM contract');
    }
  } else {
    console.log('Contract not found', json);
  }
}
run().catch(console.error);

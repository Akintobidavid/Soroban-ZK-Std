import { rpc, Contract, Address, TransactionBuilder, Networks, Account, xdr, nativeToScVal } from '@stellar/stellar-sdk';
const SOROBAN_RPC = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
const NETWORK_PASSPHRASE = process.env.NETWORK_PASSPHRASE || Networks.TESTNET;
const CONTRACT_ID = process.env.CONTRACT_ID || 'CCE7SJDDRQEXOGF7PNIY26LY63ZUXGBIYXZ3ZY3J4MGSJSXFXTUS5NTN';
const contract = new Contract(CONTRACT_ID);
const SIM_ACCOUNT = new Account(process.env.SIM_ACCOUNT_PUBKEY || 'GBA2SJQYYNSPMLPZBJBYWUC6KROU6LUFPYPHYIU2WNMVMOIY7WOQ5HYW', '0');

async function sorobanRpc(method, params = null) {
  const res = await fetch(SOROBAN_RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return await res.json();
}

async function test() {
  const op = contract.call(
    'unshield', 
    Address.fromString('GBA2SJQYYNSPMLPZBJBYWUC6KROU6LUFPYPHYIU2WNMVMOIY7WOQ5HYW').toScVal(), 
    nativeToScVal(130000000, { type: 'i128' })
  );
  const tx = new TransactionBuilder(SIM_ACCOUNT, { fee: '1000', networkPassphrase: NETWORK_PASSPHRASE }).addOperation(op).setTimeout(30).build();
  
  const result = await sorobanRpc('simulateTransaction', { transaction: tx.toXDR() });
  console.log(JSON.stringify(result, null, 2));
}
test();

import { rpc, Contract, Address, TransactionBuilder, Networks, Account, xdr, nativeToScVal, Keypair } from '@stellar/stellar-sdk';
const SOROBAN_RPC = 'https://soroban-testnet.stellar.org';
const CONTRACT_ID = 'CC5KGHEE6JB3ICEI3B4GCLMPFETSN5J44FCQLZN7TUWKG4E2TUKXI7CY';
const contract = new Contract(CONTRACT_ID);

async function test() {
  const kp = Keypair.random(); const pub = kp.publicKey(); await fetch('https://friendbot.stellar.org?addr=' + pub);
  const server = new rpc.Server(SOROBAN_RPC);
  const account = await server.getAccount(pub);
  const sourceAccount = new Account(account.accountId(), account.sequenceNumber());
  
  // SEND 0x00 PROOF
  const proofBuf = new Uint8Array(256);
  const proofScVal = xdr.ScVal.scvBytes(proofBuf);
  
  const piBuf = new Uint8Array(32);
  const piScVal = xdr.ScVal.scvBytes(piBuf);
  
  const op = contract.call('transfer_shielded', Address.fromString(pub).toScVal(), Address.fromString(pub).toScVal(), nativeToScVal(100, { type: 'i128' }), proofScVal, piScVal);
  let tx = new TransactionBuilder(sourceAccount, { fee: '100000', networkPassphrase: Networks.TESTNET }).addOperation(op).setTimeout(30).build();
  
  const res = await fetch(SOROBAN_RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'simulateTransaction', params: { transaction: tx.toXDR() } }) });
  console.log(JSON.stringify(await res.json(), null, 2));
}
test().catch(console.error);

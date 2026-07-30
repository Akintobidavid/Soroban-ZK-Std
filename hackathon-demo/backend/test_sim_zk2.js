import { rpc, Contract, Address, TransactionBuilder, Networks, Account, xdr, nativeToScVal, Keypair } from '@stellar/stellar-sdk';
const SOROBAN_RPC = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
const FRIENDBOT_URL = process.env.FRIENDBOT_URL || 'https://friendbot.stellar.org';
const NETWORK_PASSPHRASE = process.env.NETWORK_PASSPHRASE || Networks.TESTNET;
const CONTRACT_ID = process.env.CONTRACT_ID || 'CBGILJ5PSIDMDNET4M7Z55DX6SUPLG7AJIH6CGDFNJZU5QKQIBXVWN26';
const contract = new Contract(CONTRACT_ID);

async function test() {
  const kp = Keypair.random(); const pub = kp.publicKey(); await fetch(FRIENDBOT_URL + '?addr=' + pub);
  const server = new rpc.Server(SOROBAN_RPC);
  const account = await server.getAccount(pub);
  const sourceAccount = new Account(account.accountId(), account.sequenceNumber());
  
  // SEND 0x00 PROOF
  const proofBuf = new Uint8Array(256);
  const proofScVal = xdr.ScVal.scvBytes(proofBuf);
  
  const piBuf = new Uint8Array(32);
  const piScVal = xdr.ScVal.scvBytes(piBuf);
  
  // First, shield 100
  let shieldOp = contract.call('shield', Address.fromString(pub).toScVal(), nativeToScVal(100, { type: 'i128' }));
  let tx1 = new TransactionBuilder(sourceAccount, { fee: '100000', networkPassphrase: NETWORK_PASSPHRASE }).addOperation(shieldOp).setTimeout(30).build();
  let sim1 = await server.prepareTransaction(tx1);
  sim1.sign(kp);
  let res1 = await server.sendTransaction(sim1);
  console.log("Shield result:", res1.status, res1.hash);
  
  // Wait for shield
  await new Promise(r => setTimeout(r, 6000));
  
  // Now transfer
  const account2 = await server.getAccount(pub);
  const sourceAccount2 = new Account(account2.accountId(), account2.sequenceNumber());
  const op = contract.call('transfer_shielded', Address.fromString(pub).toScVal(), Address.fromString(pub).toScVal(), nativeToScVal(10, { type: 'i128' }), proofScVal, piScVal);
  let tx2 = new TransactionBuilder(sourceAccount2, { fee: '100000', networkPassphrase: NETWORK_PASSPHRASE }).addOperation(op).setTimeout(30).build();
  
  const sim = await fetch(SOROBAN_RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'simulateTransaction', params: { transaction: tx2.toXDR() } }) });
  console.log("Transfer simulate:", JSON.stringify(await sim.json(), null, 2));
}
test().catch(console.error);

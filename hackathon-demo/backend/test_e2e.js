import { rpc, Contract, Address, TransactionBuilder, Networks, Account, xdr, nativeToScVal, Keypair } from '@stellar/stellar-sdk';
const SOROBAN_RPC = 'https://soroban-testnet.stellar.org';
const CONTRACT_ID = 'CCE7SJDDRQEXOGF7PNIY26LY63ZUXGBIYXZ3ZY3J4MGSJSXFXTUS5NTN';
const contract = new Contract(CONTRACT_ID);

// Create a new keypair and fund it with friendbot
const kp = Keypair.random();
const pub = kp.publicKey();
const sec = kp.secret();

async function test() {
  console.log("Funding account...", pub);
  await fetch(`https://friendbot.stellar.org?addr=${pub}`);
  
  const server = new rpc.Server(SOROBAN_RPC);
  const account = await server.getAccount(pub);
  const sourceAccount = new Account(account.accountId(), account.sequenceNumber());
  
  // 1. Shield 1 XLM
  console.log("Shielding 1 XLM...");
  const op1 = contract.call('shield', Address.fromString(pub).toScVal(), nativeToScVal(10000000, { type: 'i128' }));
  let tx1 = new TransactionBuilder(sourceAccount, { fee: '10000', networkPassphrase: Networks.TESTNET }).addOperation(op1).setTimeout(30).build();
  tx1 = await server.prepareTransaction(tx1);
  tx1.sign(kp);
  const res1 = await server.sendTransaction(tx1);
  console.log("Shield sent:", res1.status, res1.hash);
  await new Promise(r => setTimeout(r, 5000));
  
  // 2. Unshield 1 XLM
  console.log("Unshielding 1 XLM...");
  const account2 = await server.getAccount(pub);
  const sourceAccount2 = new Account(account2.accountId(), account2.sequenceNumber());
  
  const op2 = contract.call('unshield', Address.fromString(pub).toScVal(), nativeToScVal(10000000, { type: 'i128' }));
  let tx2 = new TransactionBuilder(sourceAccount2, { fee: '10000', networkPassphrase: Networks.TESTNET }).addOperation(op2).setTimeout(30).build();
  tx2 = await server.prepareTransaction(tx2);
  tx2.sign(kp);
  const res2 = await server.sendTransaction(tx2);
  console.log("Unshield sent:", res2.status, res2.hash);
}
test().catch(console.error);

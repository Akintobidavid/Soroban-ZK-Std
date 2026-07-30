const { TransactionBuilder, Networks, Horizon, Contract, Address, xdr, rpc } = require('@stellar/stellar-sdk');

const SOROBAN_RPC = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
const HORIZON_RPC = process.env.HORIZON_RPC_URL || 'https://horizon-testnet.stellar.org';
const NETWORK_PASSPHRASE = process.env.NETWORK_PASSPHRASE || Networks.TESTNET;
const CONTRACT_ID = process.env.CONTRACT_ID || 'CA6B6RY735XE4O7JT6NKOAGBAPNVLW5S63OD3JYWVYUG3OTDZCFZEXGP';

async function test() {
  const sorobanServer = new rpc.Server(SOROBAN_RPC);
  const horizonServer = new Horizon.Server(HORIZON_RPC);
  const address = process.env.TEST_ACCOUNT || "GC7H2QOVKD67X723CVDZ32537O2J24G6V4X5P7X77ZYB24YFRF33RMYB";
  let sourceAccount;
  try {
     sourceAccount = await horizonServer.loadAccount(address);
  } catch(e) {
     console.log("Failed to load account");
     return;
  }
  
  const contract = new Contract(CONTRACT_ID);
  const receiverScVal = Address.fromString(address).toScVal();
  const senderScVal = Address.fromString(address).toScVal();
  const proofScVal = xdr.ScVal.scvBytes(new Uint8Array(256));
  const piScVal = xdr.ScVal.scvBytes(new Uint8Array(32));
  
  const op = contract.call("transfer_shielded", senderScVal, receiverScVal, proofScVal, piScVal);

  let tx = new TransactionBuilder(sourceAccount, {
    fee: "1000",
    networkPassphrase: NETWORK_PASSPHRASE,
  })
  .addOperation(op)
  .setTimeout(30)
  .build();

  try {
     console.log("Preparing...");
     tx = await sorobanServer.prepareTransaction(tx);
     console.log("Prepared successfully");
  } catch(e) {
     console.error("Prepare failed:", e);
  }
}
test();

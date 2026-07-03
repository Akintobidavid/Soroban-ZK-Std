const { TransactionBuilder, Networks, Horizon, Contract, Address, xdr, rpc } = require('@stellar/stellar-sdk');

async function test() {
  const sorobanServer = new rpc.Server("https://soroban-testnet.stellar.org");
  const horizonServer = new Horizon.Server("https://horizon-testnet.stellar.org");
  const address = "GC7H2QOVKD67X723CVDZ32537O2J24G6V4X5P7X77ZYB24YFRF33RMYB"; // arbitrary funded testnet account
  let sourceAccount;
  try {
     sourceAccount = await horizonServer.loadAccount(address);
  } catch(e) {
     console.log("Failed to load account");
     return;
  }
  
  const contract = new Contract("CA6B6RY735XE4O7JT6NKOAGBAPNVLW5S63OD3JYWVYUG3OTDZCFZEXGP");
  const receiverScVal = Address.fromString(address).toScVal();
  const senderScVal = Address.fromString(address).toScVal();
  const proofScVal = xdr.ScVal.scvBytes(new Uint8Array(256));
  const piScVal = xdr.ScVal.scvBytes(new Uint8Array(32));
  
  const op = contract.call("transfer_shielded", senderScVal, receiverScVal, proofScVal, piScVal);

  let tx = new TransactionBuilder(sourceAccount, {
    fee: "1000",
    networkPassphrase: Networks.TESTNET,
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

// In migrations/2_deploy_contracts.js

// This tells Truffle which contract we want to interact with
const WafLog = artifacts.require("WafLog");

module.exports = function (deployer) {
  // This is the deployment command
  deployer.deploy(WafLog);
};
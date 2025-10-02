import json
from web3 import Web3

# --- Configuration ---
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

# 1. PASTE YOUR CONTRACT ADDRESS HERE
contract_address = "0x47649368f037D55E756500F7513319fADBD99485"

# 2. PASTE YOUR ABI HERE
#    Open the file 'build/contracts/WafLog.json'.
#    Copy the entire array that starts with '"abi": [' and ends with ']'
contract_abi = [
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": True,
          "internalType": "uint256",
          "name": "timestamp",
          "type": "uint256"
        },
        {
          "indexed": False,
          "internalType": "string",
          "name": "sourceIP",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "uint256",
          "name": "threatScore",
          "type": "uint256"
        },
        {
          "indexed": False,
          "internalType": "string",
          "name": "decision",
          "type": "string"
        }
      ],
      "name": "LogAdded",
      "type": "event"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "allLogs",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "timestamp",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "sourceIP",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "requestDetails",
          "type": "string"
        },
        {
          "internalType": "uint256",
          "name": "threatScore",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "decision",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "_sourceIP",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "_requestDetails",
          "type": "string"
        },
        {
          "internalType": "uint256",
          "name": "_threatScore",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "_decision",
          "type": "string"
        }
      ],
      "name": "addLog",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getLogsCount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    }
  ]

# --- Contract Interaction ---

# Load the deployed contract
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

def log_threat_to_blockchain(ip, details, score, decision):
    """Calls the addLog function on the smart contract."""
    try:
        # Get an account to send the transaction from (e.g., the first Ganache account)
        account = web3.eth.accounts[0]
        
        # Build and send the transaction
        tx_hash = contract.functions.addLog(
            ip, details, score, decision
        ).transact({'from': account})
        
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"✅ Threat logged successfully! Transaction hash: {receipt.transactionHash.hex()}")
        return True
    except Exception as e:
        print(f"❌ Error logging to blockchain: {e}")
        return False

# --- Connection Test (for standalone testing) ---
def get_connection_status():
    """Returns the connection status and latest block number."""
    if web3.is_connected():
        latest_block = web3.eth.block_number
        return f"✅ Connected to Ganache. Latest block: {latest_block}"
    else:
        return "❌ Failed to connect to Ganache."

if __name__ == '__main__':
    print(get_connection_status())
    # Test logging a fake threat
    log_threat_to_blockchain("192.168.1.10", "/login attempt", 95, "BLOCKED")
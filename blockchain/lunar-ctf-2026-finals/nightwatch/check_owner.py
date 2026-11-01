from web3 import Web3

RPC = "http://nightwatch.kumosec.rootriet.in/chain/rpc"
REGISTRY = Web3.to_checksum_address("0x614BB70b9AA56802036d1BaC0b667F4C45619595")
VAULT = Web3.to_checksum_address("0xD4543Fe1ded1637768516A3Ef35614F91F715370")
MY_ADDR = Web3.to_checksum_address("0x623bD7914fB1B70092509B559dF24A6B2ad6A75a")
PRIV = "0xa10ee93218fb3f3a49b44eca06e9bb5f7bc9b9038967c0a3c58a62e01149a67a"

w3 = Web3(Web3.HTTPProvider(RPC))
print("connected:", w3.is_connected())
print("chain_id:", w3.eth.chain_id)
print("my balance:", w3.from_wei(w3.eth.get_balance(MY_ADDR), "ether"), "ETH")

owner_abi = [{"inputs": [], "name": "owner", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"}]
status_abi = [{
    "inputs": [], "name": "getVaultStatus",
    "outputs": [
        {"type": "uint256", "name": "balance"},
        {"type": "uint256", "name": "threshold"},
        {"type": "bool", "name": "isEmergency"},
        {"type": "bool", "name": "solved"},
        {"type": "uint256", "name": "deposited"},
        {"type": "uint256", "name": "claimed"},
        {"type": "address", "name": "registry"},
    ],
    "stateMutability": "view", "type": "function"
}]
total_reg_abi = [{"inputs": [], "name": "totalRegistered", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"}]

reg = w3.eth.contract(address=REGISTRY, abi=owner_abi + total_reg_abi)
vault_owner = w3.eth.contract(address=VAULT, abi=owner_abi)
vault_status = w3.eth.contract(address=VAULT, abi=status_abi)

print("registry.owner():", reg.functions.owner().call())
print("registry.totalRegistered():", reg.functions.totalRegistered().call())
print("vault.owner():", vault_owner.functions.owner().call())
print("vault balance:", w3.from_wei(w3.eth.get_balance(VAULT), "ether"), "ETH")
print("getVaultStatus():", vault_status.functions.getVaultStatus().call())

# scan recent blocks for any events from the registry (AuditorRegistered / seedMigrationToken calls / etc)
latest = w3.eth.block_number
print("latest block:", latest)
logs = w3.eth.get_logs({"fromBlock": 0, "toBlock": latest, "address": REGISTRY})
print(f"registry logs ({len(logs)}):")
for l in logs:
    print(" ", l)

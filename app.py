from flask import request
from flask import Flask
from web3 import Web3
from solcx import compile_files
from solcx import install_solc
from solcx import set_solc_version
import subprocess
import json
import sys
import signal
import docker

client = docker.from_env()

transaction_from_addr = "0x8C564502972Cf16f94445d180FC1d968129Fd01c"
cfg = {
    "network": "http://127.0.0.1:7545",
    "contract_addr": "0x22a65143bE08821021Bb5BdF9cB0902A88eAA401",
    "app_location": "/Users/lilinjian/PycharmProjects/zksnark-app-demo"
}

container = client.containers.run(
    "zokrates/zokrates",
    "sleep infinity",
    volumes={
        cfg["app_location"] + '/code': {
            'bind': '/home/zokrates/ZoKrates/target/debug/code',
            'mode': 'rw',
        }},
    detach=True)

cfg["docker_cont_name"] = container.name


def handler(signal, frame):
    container.kill()
    print('\n\n\nCONTAINER STOPPED')
    sys.exit(0)


print("Conneting to local Blockchain Network at %s" % cfg["network"])
w3 = Web3(Web3.HTTPProvider(cfg["network"]))

install_solc(version='0.5.9')
set_solc_version('0.5.9')
compiled_sol = compile_files([cfg["app_location"] + "/contracts/Verifier.sol"], output_values=['abi'])
contract_id, contract_interface = compiled_sol.popitem()
abi = contract_interface['abi']
contract = w3.eth.contract(abi=abi, address=cfg["contract_addr"])
print("Loaded in hashing smart contract at %s" %
      cfg["contract_addr"])


def flatten_proof(proof):
    a = [int(hex, base=16) for hex in proof["proof"]["a"]]
    b = [[int(hex, base=16) for hex in proof["proof"]["b"][0]], [int(hex, base=16) for hex in proof["proof"]["b"][1]]]
    c = [int(hex, base=16) for hex in proof["proof"]["c"]]
    inputs = [int(hex, base=16) for hex in proof["inputs"]]
    return [a, b, c, inputs]


def compute_witness_docker(numerical_input, base, status):
    subprocess.call(
        "docker exec -t " +
        cfg["docker_cont_name"] +
        " bash -c 'cd /home/zokrates/ZoKrates/target/debug/code/preimage/ && \
        zokrates compute-witness -a " + numerical_input + " " + str(base) + " " + str(status) + "'", shell=True)

    with open(cfg["app_location"] +
              '/code/preimage/witness', 'r') as myfile:
        data = myfile.read().replace('\n', '')

    return data


def compute_get_hashes_witness_docker(numerical_input):
    subprocess.call(
        "/usr/local/bin/docker exec -t " +
        cfg["docker_cont_name"] +
        " bash -c 'cd /home/zokrates/ZoKrates/target/debug/code/get_hashes && \
        zokrates compute-witness -a 0 0 0 " + numerical_input + "'", shell=True)
    with open(cfg["app_location"] +
              '/code/get_hashes/witness', 'r') as myfile:
        data = myfile.read().replace('\n', '')
    return data


def generate_proof_docker():
    subprocess.call(
        "/usr/local/bin/docker  exec -t " +
        cfg["docker_cont_name"] +
        " bash -c 'cd /home/zokrates/ZoKrates/target/debug/code/preimage/ && \
        zokrates generate-proof'", shell=True)
    with open(cfg["app_location"]+'/code/preimage/proof.json') as f:
        data = json.load(f)
    return data


def witness_to_dict(data):
    nums = {}
    for z in data[0:90].split("~out_"):
        if z != "":
            y = z.split(" ")
            nums["h"+str(y[0])] = y[1]
    return nums


def verify_proof_eth(proof):
    inp = flatten_proof(proof)
    print(" ")
    print(json.dumps(inp, indent=4))
    try:
        a, b, c, inputs = flatten_proof(proof)
        response = contract.functions.verifyTx([a, b, c],inputs).call()
        print(response)
    except ValueError as e:
        print(e)
        response = False
    return response


def transact_proof_eth(proof):
    a, b, c, inputs = flatten_proof(proof)
    response = contract.functions.verifyTx([a, b, c],inputs).transact({
        'from': transaction_from_addr,
        'gas': (200*100*100)})
    return response.hex()


def create_witness_and_make_proof(input):
    witness_ref = compute_witness_docker(input)
    print("created witness")
    proof = generate_proof_docker()
    print("created proof")
    return proof

def start_docker():
    subprocess.call(
        "docker run -v $PWD/code:/home/zokrates/ZoKrates/target/debug/code \
        -ti zokrates_tutorial \/bin/bash", shell=True)


def hash_to_128(d): return [int(str(d)[0:34], 16), int(str(d)[34:], 16)]


app = Flask(__name__)


@app.route("/verify_local", methods=["POST"])
def verify_local():
    proof = json.loads(request.data)
    print(json.dumps(proof, indent=4))
    r = verify_proof_eth(proof)
    return json.dumps({"response": r})


@app.route("/verify", methods=["POST"])
def verify():
    proof = json.loads(request.data)
    print(json.dumps(proof, indent=4))
    r = transact_proof_eth(proof)
    return json.dumps({"response": r})


@app.route("/deploy")
def deploy():
    subprocess.call(
        "cd "+cfg["app_location"]+" && \
        truffle compile && truffle migrate", shell=True)
    return json.dumps({"status": 200})


@app.route("/proveit", methods=["POST"])
def proveit():
    payload = json.loads(request.data)
    # h0, h1 = hash_to_128(payload["digest"])
    board_status = payload["digest"]
    # final_digest = hex(int(h0)) + hex(int(h1))[2:]
    # print(final_digest, h0, h1, payload["preimage"])
    compute_witness_docker(" ".join([str(i) for i in payload["moves"]]), payload["base"], payload["digest"])
    proof = generate_proof_docker()
    return json.dumps(proof)


@app.route("/witness", methods=["POST"])
def witness():
    binary = "".join(["".join(['{:02b}'.format(i) for i in line]) for line in json.loads(request.data)["input"]])
    r = {
        "digest": int(binary, 2)
    }
    return json.dumps(r)


if __name__ == "__main__":
    start_docker()
    app.run()
    print('\n\n\nPRESS CTRL-C AGAIN TO KILL DOCKER CONTAINER!')
    signal.signal(signal.SIGINT, handler)
    signal.pause()

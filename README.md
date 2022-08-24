# zksnark-:wqchess-demo

A zksnark application demo that imitates Reversi chess. 

[Reversi - Wikipedia](https://en.wikipedia.org/wiki/Reversi)

# Introduction

Imagine Alice and Bob are playing Reversi, and Cindy is the referee. This program is playing Cindy's role to hiding the moves so that the board status can be verified without revealing any more information. There’s a third person called David, and he only knows the current board status. However, David has no idea how Alice and Bob made their moves. Therefore, he wants to verify if the board status he knows is valid or not. With a known board status, David can consult Cindy to verify the board status. Remark that in the following sections, these names will repeatly appears. 

# Pre-settings

make sure you have all the installation set up before diving into this demo.

1. Clone the project.
    
    ```bash
    git clone https://github.com/ForrestLinjianLi/zksnark-chess-demo.git
    ```
    
2. Pull docker image
    
    ```bash
    docker pull zokrates/zokrates
    ```
    
3. Truffle Suit
    1. Download Ganache at [https://trufflesuite.com/ganache/](https://trufflesuite.com/ganache/).
    2. Install Truffle for deploying smart contracts.
        
        ```bash
        npm install -g truffle
        ```
        
4. Postman
    
    Install Postman for making http requests. [https://www.postman.com/](https://www.postman.com/)
    

# Run the Demo

### Setup envrionment

1. **Compile `reversi.zok` by using ZoKrates CLI.** 
    
    `reversi.zok` is the program written by ZoKrates DSL such that ZoKrates can compile it into an arithmetic circuit. 
    
    ```bash
    cd zksnark-chess-demo/code
    # run zokrates docker image
    docker run -ti zokrates/zokrates /bin/bash
    # compile
    zokrates compile -i reversi.zok # --debug
    # perform the setup phase
    zokrates setup
    # export a solidity verifier
    zokrates export-verifier
    # the file tree looks like this
    tree
    .
    ├── abi.json
    ├── out
    ├── out.r1cs
    ├── proving.key
    ├── reversi.zok
    ├── verification.key
    └── verifier.sol
    
    0 directories, 7 files
    ```
    
2. **Update `Verifier.sol`**
    
    We have the `verifier.sol` which is auto-generated by Zokrates. When Truffle compiles, it will look for smart contracts under `conrtacts` folder, so we need to move the `verifier.sol` to 
    
3. **Start a new workspace in Ganache.** 
    
    Therefore we can check the deployed smart contract, and transactions. 
    
    ![截屏2022-08-17 下午10.19.17.png](images/%25E6%2588%25AA%25E5%25B1%258F2022-08-17_%25E4%25B8%258B%25E5%258D%258810.19.17.png)
    
    Add project and select `truffle-config.js` in the project.
    
    ![截屏2022-08-17 下午10.20.49.png](images/%25E6%2588%25AA%25E5%25B1%258F2022-08-17_%25E4%25B8%258B%25E5%258D%258810.20.49.png)
    
    ![截屏2022-08-17 下午10.25.59.png](images/%25E6%2588%25AA%25E5%25B1%258F2022-08-17_%25E4%25B8%258B%25E5%258D%258810.25.59.png)
    
4. **Deploy the smart contracts**
    
    ```bash
    truffle compile && truffle migrate
    ```
    
    ![截屏2022-08-22 下午3.23.00.png](images/%25E6%2588%25AA%25E5%25B1%258F2022-08-22_%25E4%25B8%258B%25E5%258D%25883.23.00.png)
    
    The Verifier smart contract is now deployed at  `0x30b385DDf61B809C33c96D3994285De5C6AD5BBA`.  
    
5. **Update the `app.py` configurations.** 
    
    After deploying the smart contracts, we now need to update the configurations.
    
    ```python
    transaction_from_addr = "0x8C564502972Cf16f94445d180FC1d968129Fd01c"
    cfg = {
        "network": "http://127.0.0.1:7545",
        "contract_addr": "0x30b385DDf61B809C33c96D3994285De5C6AD5BBA",
        "app_location": "/Users/lilinjian/PycharmProjects/zksnark-app-demo"
    }
    ```
    
    Here the `transaction_from_addr` can be any account in the Ganache test net.  
    
6. **Start the program**
    
    ```bash
    python3 app.py
    ```
    
    ![截屏2022-08-22 下午3.34.16.png](images/%25E6%2588%25AA%25E5%25B1%258F2022-08-22_%25E4%25B8%258B%25E5%258D%25883.34.16.png)
    

### Run demo

1. **Create digest**
    
    Starting from an empty board, where each position has three statuses where “0” means no piece is being placed, “1” means a black piece is being placed, and “2” means a white piece is being placed.
    
    ```bash
    [0, 0, 0, 0]
    [0, 0, 0, 0]
    [0, 0, 0, 0]
    [0, 0, 0, 0]
    ```
    
    Then, Alice placed a black piece at (0,0), and Bob placed a piece at (1,1). 
    
     After their moves, the board status become:
    
    ```bash
    [1, 0, 0, 0]
    [0, 2, 0, 0]
    [0, 0, 0, 0]
    [0, 0, 0, 0]
    ```
    
    However, David does not know what moves Alice and Bob had made. She only knows the updated board status. In order to call verifies to generate a proof, David needs to create a digest to send to Cindy. It basically converts the board status into a 32-bit integer. 
    

![截屏2022-08-23 下午1.35.28.png](images/%25E6%2588%25AA%25E5%25B1%258F2022-08-23_%25E4%25B8%258B%25E5%258D%25881.35.28.png)

1. **Generate proof**
    
    David can make a post request to `http://127.0.0.1:5000/proveit`. 
    
    ```json
    {
        "digest":"1075838976", 
        "moves": [0,0,1,1],
        "base": "0"
    }
    ```
    
    The digest is what David gets from Cindy. The moves are the coordinates where Alice and Bob placed their pieces. In this example, Alice placed a black piece at (0, 0), and Bob placed a White piece at (1, 1). And the base is the board status before making moves.
    
    This may take several minutes to generate the proof. If it takes too long and the POST request is expired, try an alternative way to generate the proof by zokrates CLI.
    
    ```bash
    # check which docker container is up and running
    docker container ls
    # enter the container by id
    docker exec -it 772c5c168c6a bash
    # cd into the mounted directory
    cd ZoKrates/target/debug/code
    # generate proof
    zokrates generate-proof
    ```
    
    Cindy now has generated the proof with the given digest, and the proving key which was generated when the `reversi.zok` was compiled and set up.  
    
2. **Verify**
    
    David can call the smart contract to further verify the returned proof by making a post request `http://127.0.0.1:5000/verify_local` with the content of `proof.key`
    
    ```json
    {
      "scheme": "g16",
      "curve": "bn128",
      "proof": {
        "a": [
          "0x22646a3e9e69356247247c8b607f7f55629887465550483d374e305e2f782334",
          "0x2214a22a568b27dd0049dbd564f7181d9a67426d972b3352425bdcb2fb31e70e"
        ],
        "b": [
          [
            "0x295abb6a1d9396c58e0fbe2bc136ae5697b2857eafaeef8841456f44e099621e",
            "0x11701397d19da8ae56fef8317e19516aec902c7f45e711ef641242c8edd3a381"
          ],
          [
            "0x08b8ef3eb645bda19cccc52851265caeee2aba3115dca9cb50281bd684502bbe",
            "0x1f5c09fcce1af32fc8023e5abb6a91f694565acc682c89f35de2508b694955c0"
          ]
        ],
        "c": [
          "0x0bc5e75389e3586f52dea0f2254c5d59db1fff1e9f13d41903e244878e663ecb",
          "0x2df006354741aa802637b3ad12549e31bd826640437788f0240e3eed3f140709"
        ]
      },
      "inputs": [
        "0x0000000000000000000000000000000000000000000000000000000040200000",
        "0x0000000000000000000000000000000000000000000000000000000040200000"
      ]
    }
    ```
    
    ![截屏2022-08-23 下午7.18.04.png](images/%25E6%2588%25AA%25E5%25B1%258F2022-08-23_%25E4%25B8%258B%25E5%258D%25887.18.04.png)
    
    Now the proving process has finished.
    

### Additional moves

Suppose for the next round, Alice placed a black piece at (2, 2), and Bob placed a white piece at (3, 3). The board status should be

```json
[1, 0, 0, 0]
[0, 2, 0, 0]
[0, 0, 1, 0]
[0, 0, 0, 2]

# after the update, the two white pieces on the diagonal should be replaced by black, thus

[1, 0, 0, 0]
[0, 1, 0, 0]
[0, 0, 1, 0]
[0, 0, 0, 2]
```

Given this board status, David wants to verify it. 

1. **Making digest**
    
    The digest David get is `1074791425`.
    
2. **Generate proof**
    
    The POST body is as follows. 
    
    ```json
    {
        "digest":"1074791425", 
        "moves": [2, 2, 3, 3],
        "base": "1075838976"
    }
    ```
    
3. **Verify**
    
    Verify with the generated proof.
    
    ```json
    {"scheme": "g16", "curve": "bn128", "proof": {"a":
    ["0x17739b933239587d1d7dac111eef7de986a1dfe0b3b637bee1e649eaada1b4f1",
    "0x0ee74433942b0d66513b8c817d944c3f1b455aa61c0ebe326643c2935db61989"], "b":
    [["0x27da16f7e91900d949d0029d63926b1d06d907cb5d42c7d9cb8121a9a885441b",
    "0x0d8dda90da85544aa195aaca31ac9c9437b8ac0a8d5ea88d65afa8533fe80b92"],
    ["0x2cbd733d38c1bd8b7506b3ba8c06018019c9546fb87b42e922a1b10da0eb15db",
    "0x298211a597801eb194ab2496b06b745d8f738b3d77630e70e4ca877d841b6621"]], "c":
    ["0x16a4e8b9684ba46180bf1dbaecb0ec47fd4df0908ce84945afc3ec2c02c00f84",
    "0x22150c779bfc9b572ec4569a5167d10f2787c689ce034051d2e6eb38e822c2f6"]}, "inputs":
    ["0x0000000000000000000000000000000000000000000000000000000040100402",
    "0x0000000000000000000000000000000000000000000000000000000040100402"]}
    ```
    
    The result should be
    
    ```json
    {"response": true}
    ```
    

# Assumptions of reversi.zok

1. For simplicity of `reversi.zok`, we assume that Alice and Bob make legal moves. For example, each piece must be placed at a position where at least one straight (horizontal, vertical, or diagonal) occupied line exists between placed pieced and other same-color pieces. 
    
    ![The next black piece should be placed in any of the grey grids. From: [https://en.wikipedia.org/wiki/Reversi](https://www.notion.so/df518cb0d1de467481e8751aac8cb7cf)](images/%25E6%2588%25AA%25E5%25B1%258F2022-08-23_%25E4%25B8%258B%25E5%258D%258810.52.23.png)
    
    The next black piece should be placed in any of the grey grids. From: [https://en.wikipedia.org/wiki/Reversi](https://www.notion.so/df518cb0d1de467481e8751aac8cb7cf)
    
2. Instead of an 8x8 uncheckered board, I make the demo based on a 4x4 board due to the limitation of ZoKrates. Now the number of constraints of the generated R1CS is 245,213. If we use an 8x8 board, the number of constraints can be around 900,000, and it will take an extremely long time to generate the proof.

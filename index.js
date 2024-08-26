function EXDC_SHOP_SDK(params) {
  let categories = [
    // 'All', 'Electronics', 'Clothing', 'Books', 'Home & Garden', 'Sports'
  ];
  // Get USDT balance (replace with actual USDT contract address on BSC Testnet)
  let erc20ContractAddress = '0x337610d27c682E347C9cD60BD4b3b107C9d34dDd'; // Example USDT contract on BSC Testnet
  
  const erc20abi = [
    // Read-Only Functions
    'function balanceOf(address owner) view returns (uint256)',
    'function decimals() view returns (uint8)',
    'function symbol() view returns (string)',
  
    // Authenticated Functions
    'function transfer(address to, uint amount) returns (bool)',
  
    // Events
    'event Transfer(address indexed from, address indexed to, uint amount)',
  ];
  
  const exchangeContractAbi = [
    'function userData() view returns (bytes)',
    'function wp() view returns (address)',
    'function decimals() view returns (uint8)',
    'function buyerOrders(address address) view returns (address)',
    'function createBuyItemsContract(uint contractValue, uint contractDivider, address paymentContract) external returns (address)'
  ]
  
  const buyContractAbi = [
    'function confirmPurchase(bytes data) external',
    'function confirmReceived() external',
    'function rateSeller(uint buyerRating) external',
    'function balanceOfContract() view returns (uint)',
    'function price() view returns (uint)',
    'function state() view returns (uint)',
    'function deliveryData() view returns (bytes)'
  ]
  
  let products = [];
  let orderKey;
  let provider, signer, address;
  const q = (new URL(window.location.href)).searchParams.get("q")
  const n = (new URL(window.location.href)).searchParams.get("n")
  let json;
  let decimals = 18;
  let symbol = "USDC"
  
  const keyEncAlgo = {
    name: 'RSA-OAEP',
  };
  const payloadKeyEncAlgo = {
    name: 'AES-GCM',
    length: 256,
  };
  const payloadEncAlgo = {
    name: 'AES-GCM',
  };
  
  async function generateNewKeyPair(
    seed,
  ) {
      const keyPair = (await window.crypto.subtle.generateKey(
        algo,
        true,
        ['encrypt', 'decrypt'],
      ));
      const kp = {
        publicKey: JSON.stringify(
          await window.crypto.subtle.exportKey(
            'jwk',
            keyPair.publicKey,
          ),
        ),
        privateKey: JSON.stringify(
          await window.crypto.subtle.exportKey(
            'jwk',
            keyPair.privateKey,
          ),
        ),
      };
      return kp;
  }
  
  function getHexFromArrayBuffer(array) {
    const hashArray = Array.from(new Uint8Array(array));
    const digest = hashArray
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return digest;
  }
  
  async function encryptAesKey(key, pubKey) {
    const k = await window.crypto.subtle.importKey(
      'jwk',
      pubKey,
      algo,
      true,
      ['encrypt'],
    );
    const encoder = new TextEncoder();
    const encoded = encoder.encode(key);
    const encrypted = await window.crypto.subtle.encrypt(
      keyEncAlgo,
      k,
      encoded,
    );
    return getHexFromArrayBuffer(encrypted);
  }
  
  async function decryptAesKey(
    key,
    privateKey,
  ) {
    try {
      const k = await window.crypto.subtle.importKey(
        'jwk',
        privateKey,
        algo,
        true,
        ['decrypt'],
      );
      const encoded = hexToArrayBuffer(key);
      const decrypted = await window.crypto.subtle.decrypt(
        keyEncAlgo,
        k,
        encoded,
      );
      // console.info('decryptedKey', decrypted);
      const decoder = new TextDecoder();
      const decode = JSON.parse(decoder.decode(decrypted, {}));
      // console.info('textdecoder decode', decode);
      const aesKey = await window.crypto.subtle.importKey(
        'jwk',
        decode,
        payloadKeyEncAlgo,
        true,
        ['encrypt', 'decrypt'],
      );
      return aesKey;
    } catch (err) {
      console.error('decryptkey error', err);
      throw err;
    }
  }
  
  async function decryptPayload(
    k,
    payload,
    ivb,
  ) {
    const iv = hexToArrayBuffer(ivb);
    const encoded = hexToArrayBuffer(payload);
    // console.info('encoded into buffer', encoded);
    const decrypted = await window.crypto.subtle.decrypt(
      {...payloadEncAlgo, iv},
      k,
      encoded,
    );
    // console.info('decryptedPayload', decrypted);
    const decoder = new TextDecoder();
    const decode = decoder.decode(decrypted);
    return decode;
  }
  
  async function decryptPayloadRaw(
    k,
    payload,
    ivb,
  ) {
    const iv = hexToArrayBuffer(ivb);
    const encoded = payload;
    // console.info('encoded into buffer', encoded);
    const decrypted = await window.crypto.subtle.decrypt(
      {...payloadEncAlgo, iv},
      k,
      encoded,
    );
    return decrypted;
    // console.info('decryptedPayload', decrypted);
    // const decoder = new TextDecoder();
    // const decode = decoder.decode(decrypted);
    // return decode;
  }
  async function generateAesKey() {
    const key = await window.crypto.subtle.generateKey(
      payloadKeyEncAlgo,
      true,
      ['encrypt', 'decrypt'],
    );
    // console.info('aeskey', key);
    const kp = JSON.stringify(
      await window.crypto.subtle.exportKey('jwk', key),
    );
    return { kp, key };
  }
  
  async function encryptPayload(k, payload) {
    try {
      const encoder = new TextEncoder();
      const encoded = encoder.encode(payload);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await window.crypto.subtle.encrypt(
        { ...payloadEncAlgo, iv },
        k,
        encoded,
      );
      // console.info('encrypted', encrypted);
      return {
        encryptedPayload: await getHexFromArrayBuffer(encrypted),
        iv: await getHexFromArrayBuffer(iv.buffer),
      };
    } catch (err) {
      console.error('encrypt payload err', err);
      throw err;
    }
  }
  
  const algo = {
    name: 'RSA-OAEP',
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  };
  
  const address0 = '0x0000000000000000000000000000000000000000';
  
  const getExchangeContractData = async () => {
    const exchangeContract = new ethers.Contract(q, exchangeContractAbi, provider);
    const data = await exchangeContract.userData();
    erc20ContractAddress = await exchangeContract.wp()
    decimals = await exchangeContract.decimals()
    // console.info('data', data)
    json = await processExchangeContractData(data)
    if(json.encrypted) {
      document.getElementById('password-modal').style.display = 'flex';
    }
    else initContent(json)
    // console.info("getExchangeContractData res", json)
  }
  
  const processExchangeContractData = async (data) => {
    const abiCoder = new ethers.utils.AbiCoder();
    try {
      const decode = await abiCoder.decode(["string"], data)
      return JSON.parse(decode);
    } catch (err) {
      console.error(err)
    }
  }
  
  

  async function rateSeller(rating) {
    const order = await getCurrentOrder()
    await (await order.rateSeller(rating)).wait(1)
  }
  
  
  const generateOrderBody = async (nload) => {
    const abiCoder = new ethers.utils.AbiCoder();
    const aeskey = await generateAesKey();
    const keypair = await generateNewKeyPair();
    nload.publicKey = keypair.publicKey;
    const payload = await encryptPayload(aeskey.key, JSON.stringify(nload))
    localStorage.setItem("easkp", JSON.stringify(keypair))
    const encKey = await encryptAesKey(aeskey.kp, orderKey)
    const strData = JSON.stringify({ encKey, payload })
    const data = abiCoder.encode(["string"], [strData])
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(keypair, null, 2)], {
      type: "text/plain"
    }));
    a.setAttribute("download", "orderKey.json");
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // console.info(data, strData)
    return data;
  }
  
  const getCurrentOrder = async () => {
    const signer = await provider.getSigner();
    const shop = new ethers.Contract(q, exchangeContractAbi, signer);
    const prevOrder = await shop.buyerOrders(address)
    // console.info('currentOrder', prevOrder)
    if (prevOrder !== address0) {
      const contract = new ethers.Contract(prevOrder, buyContractAbi, signer);
      contract.contractAddress = prevOrder;
      return contract;
    }
    return undefined;
  }
  
  const buyItemFromShop = async (
    value,
    deliveryAddress,
    cart
  ) => {
    const signer = await provider.getSigner();
    const shop = new ethers.Contract(q, exchangeContractAbi, signer);
    const coin = await shop.wp();
    const nload = {cart, deliveryAddress}
    // console.info('nload', nload)
    let contract;
    try {
      contract = await getCurrentOrder()
      if (contract) {
        const state = ethers.utils.formatUnits(await contract.state(), 10) * 10
        if(state > 2) {
          return true;
        }
        const {contractAddress} = contract;
        const balance = ethers.utils.formatUnits(await contract.balanceOfContract(), decimals)
        const price = ethers.utils.formatUnits(await contract.price(), decimals)
        // console.info("balance", balance, price, contract, contractAddress)
        if (balance < price) {
          await sendCoin(coin, contractAddress, price - balance);
        }
      } else {
        // console.info('creating a new contract', value)
        const contractTx = (await (
          await (
            await shop.createBuyItemsContract(value, 1, q)
          ).wait(1)
        ));
        contract = await getCurrentOrder()
        const trx = await sendCoin(coin, contract.contractAddress, value);
      }
      const data = await generateOrderBody(nload)
      const purchase = await (await contract.confirmPurchase(data)).wait(1);
      return purchase;
    } catch (err) {
      console.error(err)
      alert(err?.data?.message || err.message || err)
    }
    
    const purchase = await contract.confirmPurchase(data);
    return trx;
  };
  
  async function sendCoin(
    coin,
    to,
    valueNum,
  ) {
    const erc20 = new ethers.Contract(coin, erc20abi, await provider.getSigner());
    const amount = ethers.utils.parseUnits(
      valueNum.toString(),
      decimals,
    );
    const tx = await (await erc20.transfer(to, amount)).wait(1);
    return tx.hash;
  }
  
  
  const byteToHex = [];
  
  for (let n = 0; n <= 0xff; ++n)
  {
      const hexOctet = n.toString(16).padStart(2, "0");
      byteToHex.push(hexOctet);
  }
  function hex(arrayBuffer)
  {
      const buff = new Uint8Array(arrayBuffer);
      const hexOctets = []; // new Array(buff.length) is even faster (preallocates necessary array size), then use hexOctets[i] instead of .push()
  
      for (let i = 0; i < buff.length; ++i)
          hexOctets.push(byteToHex[buff[i]]);
  
      return hexOctets.join("");
  }
  function spliceBuffers(buffers) {
  
    const len = buffers.map((buffer) => buffer.byteLength).reduce((prevLength, curr) => {return prevLength + curr}, 0);
  
    const tmp = new Uint8Array(len);
  
    let bufferOffset = 0;
  
    for(var i=0; i < buffers.length; i++) {
      tmp.set(new Uint8Array(buffers[i]), bufferOffset);
      bufferOffset += buffers[i].byteLength;
    }
  
    return tmp;
  }
  
  const receiveOrder = async () => {
    try {
      const order = await getCurrentOrder()
      const state = ethers.utils.formatUnits(await order.state(), 1) * 10
      if(state < 4) {
        throw new Error("Waiting for the order to be delivered")
        return;
      }
      const abiCoder = new ethers.utils.AbiCoder()
      const deliveryData = JSON.parse(abiCoder.decode(["string"], await order.deliveryData())[0])
      let localKey = localStorage.getItem("easkp")
  
      // console.info('deliveryData', deliveryData, localKey)
      const decryptDeliveryData = async () => {
        try {
  
          const key = JSON.parse(JSON.parse(localKey).privateKey)
          const decryptedKey = await decryptAesKey(deliveryData.encryptedKey, key)
          const payload = JSON.parse(await decryptPayload(decryptedKey, deliveryData.encryptedPayload, deliveryData.iv))
          // console.info('dec payload', payload)
          const decryptPart = async (f) => {
            const link = "https://ipfs.io/ipfs/"+f.fileLink.IpfsHash
            const efile = await (await fetch(link)).arrayBuffer()
            // console.info(efile)
            const decrypted = await decryptPayloadRaw(decryptedKey, efile, f.iv)
            // console.info('decrypted', decrypted)
            return decrypted;
          }
          await Promise.all(payload.map(async (f, i)=>{
            let decrypted = []
            if(f.name) {
              decrypted = new File([await decryptPart(f)], {name:f.name})
            } else {
              const parts  = await Promise.all(f.map(async ff=>({...ff, decrypted: await decryptPart(ff)})))
              parts.sort((a,b)=>a.partId - b.partId)
              const pmap = spliceBuffers(parts.map(p=>p.decrypted))
              // console.info('parts dec', pmap)
              decrypted = new File([pmap], {name: parts[0].name})
            }
  
            const file = decrypted
            const a = document.createElement("a");
            a.href = URL.createObjectURL(file);
            a.setAttribute("download", f.name || f[0].name);
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
          }))
          // console.info('decrypted payload', payload)
        } catch(err) {
          console.error('decrypt error', err.message)
          alert(err?.data?.message || err?.message || err)
        }
      }
      if(localKey) {
        await decryptDeliveryData()
      }
      else {
        localKey = prompt('please attach the decryption key', '')
        await decryptDeliveryData()
      }
      await order.confirmReceived()
      switchOrderStatusToRating()
    } catch(err) {
      throw err
      // alert(err?.data?.message || err?.message || err)
    }
  }
  
  
  async function checkMetaMask() {
    if (typeof window.ethereum !== 'undefined') {
      console.log('MetaMask is installed!');
      document.getElementById('metamask-modal').style.display = 'none';
      try {
        // Request account access
        await window.ethereum.request({ method: 'eth_requestAccounts' });
        provider = new ethers.providers.Web3Provider(window.ethereum);
        signer = provider.getSigner();
        address = await signer.getAddress();
  
        // Switch to BNB Testnet
        try {
          await window.ethereum.request({
            method: 'wallet_switchEthereumChain',
            params: [{ chainId: n || '0x61' }], // BSC Testnet chain ID
          });
  
        } catch (switchError) {
          // This error code indicates that the chain has not been added to MetaMask.
          if (switchError.code === 4902) {
            try {
              await window.ethereum.request({
                method: 'wallet_addEthereumChain',
                params: [{
                  chainId: n || '0x61',
                  chainName: 'Binance Smart Chain Testnet',
                  nativeCurrency: {
                    name: 'BNB',
                    symbol: 'bnb',
                    decimals: 18
                  },
                  rpcUrls: ['https://data-seed-prebsc-1-s1.binance.org:8545/'],
                  blockExplorerUrls: ['https://testnet.bscscan.com']
                }]
              });
            } catch (addError) {
              console.error('Failed to add the BSC Testnet:', addError);
            }
          }
        }
  
        await getExchangeContractData()
        await updateWalletInfo();
      } catch (error) {
        console.error('Failed to connect to MetaMask:', error);
      }
    } else {
      console.log('MetaMask is not installed!');
      document.getElementById('metamask-modal').style.display = 'flex';
    }
  }
  
  async function getWalletInfo() {
    if (address) {
      const balance = await provider.getBalance(address);
      const etherBalance = ethers.utils.formatEther(balance);
  
      const usdtContract = new ethers.Contract(erc20ContractAddress, erc20abi, provider);
      const usdtBalance = await usdtContract.balanceOf(address);
      symbol = await usdtContract.symbol()
      const usdtBalanceFormatted = ethers.utils.formatUnits(usdtBalance, decimals); // Assuming 18 decimals, adjust if different
  
      return {
        textContent:`Address: ${address.slice(0, 6)}...${address.slice(-4)} | ETH: ${parseFloat(etherBalance).toFixed(4)} | ${symbol}: ${parseFloat(usdtBalanceFormatted).toFixed(2)}`,
        usdtBalance,
        usdtContract,
        etherBalance
      }
    } else {
      return {textContent: 'Wallet not connected'}
    }
  }
  
  function getKeyMaterial(password) {
    const enc = new TextEncoder();
    return window.crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"],
    );
  }
  
  function hexToArrayBuffer(hex) {
    const buff = new Uint8Array(
      (hex.match(/[\da-f]{2}/gi)).map(function (h) {
        return parseInt(h, 16);
      }),
    );
    return buff;
  }
  
  async function decrypt(password) {
    const dec = new TextDecoder()
    const data = hexToArrayBuffer(json.encrypted)
    const iv = hexToArrayBuffer(json.iv)
    const keyMaterial = await getKeyMaterial(password);
    const salt = hexToArrayBuffer(json.salt)
    const key = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
    // console.info("before decrypt", key, data, iv)
    const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return JSON.parse(dec.decode(decrypted))
  }
  
  function initIndex(decryptedData) {
    console.info('decrypteData', decryptedData)
    products = decryptedData.shopProducts
    categories = ["All", ...new Set(products.map(i => i.category))]
    orderKey = typeof decryptedData.ordersPubKey === "string" ? JSON.parse(decryptedData.ordersPubKey) : decryptedData.ordersPubKey
  }
  
  return {
    checkMetaMask,
    initIndex,
    decrypt,
    encryptAesKey,
    hexToArrayBuffer,
    getKeyMaterial,
    getWalletInfo,
    receiveOrder,
    hex,
    spliceBuffers,
    buyItemFromShop,
    getCurrentOrder,
    rateSeller,
    getExchangeContractData,
    exchangeContractAbi,
    buyContractAbi,
    categories,
    products
  };
}
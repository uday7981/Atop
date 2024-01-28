use candid::candid_method;
use ethereum_tx_sign::LegacyTransaction;
use ic_cdk::api::management_canister::main;
use ic_cdk::print;
use ic_cdk_macros::{self, update,query};
use ic_web3::contract;
use ic_web3::ic;
use std::sync::atomic::{AtomicU64, Ordering};


use serde::Deserialize;
use serde::Serialize;

use std::str::FromStr;

use ic_web3::transports::ICHttp;
use ic_web3::{Web3, Transport};
use ic_web3::ic::{get_eth_addr, KeyInfo};
use ic_web3::{
    contract::{Contract, Options},
    ethabi::ethereum_types::{U64, U256},
    types::{Address, TransactionParameters, BlockId, BlockNumber, Block},
};
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use std::cell::RefCell;
use candid::types::number::Nat;
// const URL: &str = "https://goerli.infura.io/v3/260bec7447134609a3d9488ae6481170";
const URL: &str = "https://opt-sepolia.g.alchemy.com/v2/6h3ymoWYmvZMq4ub7mqbdCMWJG8-GZ_v";
// const URL: &str = "https://eth-sepolia.g.alchemy.com/v2/eSvwWtgUFPq3xCErmU5h7zriE3UGCAUE";
const CHAIN_ID: u64 = 11155420;
const KEY_NAME: &str = "dfx_test_key";
const URL_POLYGON : &str = "https://polygon-mumbai.g.alchemy.com/v2/XcG0U49rmR40kygsOE2Z2MrqtZxXYjGS";
// const URL_POLYGON : &str = "https://polygon-mumbai.g.alchemy.com/v2/_wTBt1-Y4z8wV2D8cgAMp6QOGnSCZ9Au";

const TOKEN_ABI: &[u8] = include_bytes!("../../res/token.json");

// static LASTESET_BLOCK_READ: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static LASTESET_BLOCK_READ: RefCell<Nat> = RefCell::new(Nat::from(10));
}


type Result<T, E> = std::result::Result<T, E>;


#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogResponse {
    pub jsonrpc: String,
    pub id: i64,
    pub result: Vec<EventResult>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventResult {
    pub address: String,
    pub block_hash: String,
    pub block_number: String,
    pub data: String,
    pub log_index: String,
    pub removed: bool,
    pub topics: Vec<String>,
    pub transaction_hash: String,
    pub transaction_index: String,
}


#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Transaction {
    blockHash: String,
    blockNumber: String,
    hash: String,
    from: String,
    gas: String,
    gasPrice: String,
    input: String,
    nonce: String,
    r: String,
}
fn get_address_from_topic(input: &str) -> String {
    let address = &input[26..]; // Remove the leading "0x"
    println!("{}",address);
    let address_string = format!("0x{}", address.to_lowercase());
    address_string
}

fn number_to_hex(number: &u64) -> String {
    let hex_string = format!("0x{:0x}", number);
    return hex_string;
}


#[ic_cdk_macros::query]
fn lastestBlock() -> Nat {
    LASTESET_BLOCK_READ.with(|block| (*block.borrow()).clone())
}
async fn main_task() -> Result<String, String> {
    ic_cdk::print("eth main_task");
    // let idempotency_key = fastrand::i32(..);
    // ic_cdk::println!("idempotency_key: {}", idempotency_key);
    let latestBLockNumber = LASTESET_BLOCK_READ.with(|block| (*block.borrow()).clone());
    // let latestBlockNum64 =// Candid Nat as a string
    let block_big_int = latestBLockNumber.0.clone();
    let block_uint =  u64::try_from(block_big_int.clone()).unwrap();
   
    let block_string = format!("0x{:0x}", block_uint);
    ic_cdk::println!(" eth block string poly {}",block_string);
    ic_cdk::println!("eth block_uint {}",block_uint);
    let correctBlock = if Nat::from(0) == latestBLockNumber  {"earliest"} else { &block_string };
    // let body = "{\"jsonrpc\": \"2.0\",\"method\": \"eth_getLogs\",\"params\": [{\"fromBlock\": \"earliest\",\"toBlock\": \"latest\",\"address\":\"0xe7399b79838acc8caaa567fF84e5EFd0d11BB010\",\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\"]}],\"id\": 1}";
    // let unformated_body: &str = "{\"jsonrpc\": \"2.0\",\"method\": \"eth_getLogs\",\"params\": [{\"fromBlock\": \"#\",\"toBlock\": \"latest\",\"address\":\"0xe7399b79838acc8caaa567fF84e5EFd0d11BB010\",\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\"]}],\"id\": 1}";
    let unformated_body: &str = "{\"jsonrpc\": \"2.0\",\"method\": \"eth_getLogs\",\"params\": [{\"fromBlock\": \"#\",\"toBlock\": \"latest\",\"address\":\"0xFB85026860c2Db45c9E8409aCC7CBE86b8196EBc\",\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\"]}],\"id\": 1}";
    let body = unformated_body.replace("#",&correctBlock);
    ic_cdk::println!("eth body: {}", body);
    // rpc_call("{\"jsonrpc\": \"2.0\",\"method\": \"eth_getLogs\",\"params\": [{\"fromBlock\": \"earliest\",\"toBlock\": \"latest\",\"address\":\"0xe7399b79838acc8caaa567fF84e5EFd0d11BB010\",\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\"]}],\"id\": 1}").await()
    let w3 = match ICHttp::new(URL_POLYGON, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };


    let res = w3.json_rpc_call(body.as_ref()).await.map_err(|e| format!("{}", e))?;
    ic_cdk::println!("res: {}", res);
    // ic_cdk::println!("jsonString: {}", jsonString);
    let logResponse:Vec<EventResult> = serde_json::from_str(&res).unwrap();
    if(logResponse.len()==0){
        ic_cdk::println!("eth no transaction at all");
        return Ok("no new block".to_string());
    }
    let lastIndex : usize = logResponse.len() - 1;
    let blockNumberInHex = &logResponse[lastIndex].block_number;
    let withoutPrefixBloackNumberInHex = blockNumberInHex.trim_start_matches("0x");
    let lastestBlack  = u64::from_str_radix(withoutPrefixBloackNumberInHex, 16).unwrap(); 
    let hex_value = &logResponse[lastIndex].data;
    let value: U256 = U256::from_str_radix(&hex_value[2..], 16).unwrap();
    
    ic_cdk::println!("-----------------------------------value-eth---------------- :{}",value);
    ic_cdk::println!("lastestBlack: {}", lastestBlack);
    ic_cdk::println!("latestBLockNumber of application state: {}", latestBLockNumber);
    ic_cdk::println!(" boolean: {}", Nat::from(lastestBlack) > latestBLockNumber);
    if(Nat::from(lastestBlack)<=latestBLockNumber){
        ic_cdk::println!("eth no new block");
        return Ok("no new block".to_string());
    }
    let lastest_tx_hash=&logResponse[lastIndex].transaction_hash; 
    let tx_body: &str = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\": [\"#\"],\"id\":1}";
    let getTransactionBody =tx_body.replace("#", &*lastest_tx_hash);
    ic_cdk::println!("Eth getTransactionBody: {}", getTransactionBody);
    let getTransactionRes = w3.json_rpc_call(&getTransactionBody).await.map_err(|e| format!(" failed in transaction history{}", e))?;
    let transaction: Transaction = serde_json::from_str(&getTransactionRes).unwrap();
    let methodId = &transaction.input[0..10];
    let adminMethodId = "0x0d271720";
    ic_cdk::println!("Eth transaction: {}", getTransactionRes);
    if(methodId==adminMethodId){
        ic_cdk::println!(" eth adminMethodId: {}", adminMethodId);
        LASTESET_BLOCK_READ.with(|v| *v.borrow_mut() = Nat::from(lastestBlack));
        return Ok("This is the admin function".to_string());
    }
    if (Nat::from(lastestBlack) > latestBLockNumber ){
        let latestBlock: &EventResult = &logResponse[lastIndex];
        ic_cdk::println!("eth new block found");
         // ecdsa key info
        let derivation_path = vec![ic_cdk::id().as_slice().to_vec()];
        let key_info = KeyInfo{ derivation_path: derivation_path, key_name: KEY_NAME.to_string(), ecdsa_sign_cycles: None };
        //from address
        let raw_from = &latestBlock.topics[1];
        let from = Address::from_str(&get_address_from_topic(&raw_from)).unwrap();
        ic_cdk::println!("eth from----------------------------: {}", from);
        let w3 = match ICHttp::new(URL, None) {
            Ok(v) => { Web3::new(v) },
            Err(e) => { return Err(e.to_string()) },
        };
        //contract address
        // let poly_contract_address = "0xe7399b79838acc8caaa567fF84e5EFd0d11BB010";
        let poly_contract_address = "0x3E4c15FE9b267CF94E8241EbEaB7a447031a35C5";
        let contract_address = Address::from_str(&poly_contract_address).unwrap();
        let contract = Contract::from_json(w3.eth(),contract_address, TOKEN_ABI).map_err(|e| format!("init contract failed: {}", e))?;

        let canister_addr = get_eth_addr(None, None, KEY_NAME.to_string()).await.map_err(|e| format!("get canister eth addr failed: {}", e))?;
        // add nonce to options
            let tx_count = w3.eth()
                .transaction_count(canister_addr, None)
                .await
                .map_err(|e| format!("get tx count error: {}", e))?;
            
        
        let gas_price = w3.eth()
        .gas_price()
        .await
        .map_err(|e| format!("get gas_price error: {}", e))?;
        // legacy transaction type is still ok
        let options = Options::with(|op| { 
            op.nonce = Some(tx_count);
            op.gas_price = Some(gas_price);
            op.transaction_type = Some(U64::from(2)) //EIP1559_TX_ID
        });
        
        let raw_to = &latestBlock.topics[2];
        let to_addr = Address::from_str(&get_address_from_topic(&raw_to)).unwrap();
        ic_cdk::println!("to_addr-----------------------------: {}", to_addr);
        LASTESET_BLOCK_READ.with(|v| *v.borrow_mut() = Nat::from(lastestBlack));
        let txhash = contract
            .signed_call("transferFromAdmin", (from,to_addr, value,), options, hex::encode(canister_addr), key_info, CHAIN_ID)
            .await
            .map_err(|e| format!("token transfer failed: {}", e))?;
        ic_cdk::println!("eth txhash: {}", hex::encode(txhash));
        Ok(hex::encode(txhash))
    
}
else{
        ic_cdk::println!("eth no new block");
        Ok("no new block".to_string())
}
}

async fn enclose_main_task(){
    main_task().await;
}

#[ic_cdk_macros::init]
fn init() {
    let interval = std::time::Duration::from_secs(10);
    ic_cdk::println!("Starting a periodic task with interval {interval:?}");
    ic_cdk_timers::set_timer_interval(interval,  || {
        ic_cdk::println!("Periodic task fired");
        // Do something with the result of the async function
        ic_cdk::spawn(async {
            main_task().await;
        })
        // ...
    });
}






#[ic_cdk_macros::post_upgrade]
fn post_upgrade() {
    ic_cdk::println!("post_upgrade");
    init();
} 

#[query(name = "transform")]
#[candid_method(query, rename = "transform")]
fn transform(response: TransformArgs) -> HttpResponse {
    response.response
}

#[update(name = "get_block")]
#[candid_method(update, rename = "get_block")]
async fn get_block(number: Option<u64>) -> Result<String, String> {
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let block_id = match number {
        Some(id) => { BlockId::from(U64::from(id)) },
        None => { BlockId::Number(BlockNumber::Latest) },
    };
    let block = w3.eth().block(block_id).await.map_err(|e| format!("get block error: {}", e))?;
    ic_cdk::println!("block: {:?}", block.clone().unwrap());

    Ok(serde_json::to_string(&block.unwrap()).unwrap())

}
#[update(name = "get_eth_gas_price")]
#[candid_method(update, rename = "get_eth_gas_price")]
async fn get_eth_gas_price() -> Result<String, String> {
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let gas_price = w3.eth().gas_price().await.map_err(|e| format!("get gas price failed: {}", e))?;
    ic_cdk::println!("gas price: {}", gas_price);
    Ok(format!("{}", gas_price))
}
#[update(name = "get_canister_addr")]
#[candid_method(update, rename = "get_canister_addr")]
async fn get_canister_addr() -> Result<String, String> {
    match get_eth_addr(None, None, KEY_NAME.to_string()).await {
        Ok(addr) => { Ok(hex::encode(addr)) },
        Err(e) => { Err(e) },
    }
}
#[update(name = "get_eth_balance")]
#[candid_method(update, rename = "get_eth_balance")]
async fn get_eth_balance(addr: String) -> Result<String, String> {
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let balance = w3.eth().balance(Address::from_str(&addr).unwrap(), None).await.map_err(|e| format!("get balance failed: {}", e))?;
    Ok(format!("{}", balance))
}
#[update(name = "batch_request")]
#[candid_method(update, rename = "batch_request")]
async fn batch_request() -> Result<String, String> {
    let http = ICHttp::new(URL, None).map_err(|e| format!("init ICHttp failed: {}", e))?;
    let w3 = Web3::new(ic_web3::transports::Batch::new(http));

    let block_number: ic_web3::helpers::CallFuture<U64, _> = w3.eth().block_number();
    let gas_price = w3.eth().gas_price();
    let balance: ic_web3::helpers::CallFuture<U256, _> = w3.eth().balance(Address::from([0u8; 20]), None);
    let result = w3.transport().submit_batch().await.map_err(|e| format!("batch request err: {}", e))?;
    ic_cdk::println!("batch request result: {:?}", result);

    let block_number = block_number.await.map_err(|e| format!("get block number err: {}", e))?;
    ic_cdk::println!("block number: {:?}", block_number);

    let gas_price = gas_price.await.map_err(|e| format!("get gas price err: {}", e))?;
    ic_cdk::println!("gas price: {:?}", gas_price);

    let balance = balance.await.map_err(|e| format!("get balance err: {}", e))?;
    ic_cdk::println!("balance: {:?}", balance);

    Ok("done".into())
}
#[update]
#[candid_method(update,rename="get_eth_address")]
async fn get_eth_address() -> Result<String,String> {
   let address = get_eth_addr(None, None, KEY_NAME.to_string())
    .await
    .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    Ok(format!("{}",hex::encode(address)))
}
#[update(name = "send_eth")]
#[candid_method(update, rename = "send_eth")]
async fn send_eth(to: String, value: u64) -> Result<String, String> {
    // ecdsa key info
    let derivation_path = vec![ic_cdk::id().as_slice().to_vec()];
    let key_info = KeyInfo{ derivation_path: derivation_path, key_name: KEY_NAME.to_string(), ecdsa_sign_cycles: None };

    // get canister eth address
    let from_addr = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    // get canister the address tx count
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let tx_count = w3.eth()
        .transaction_count(from_addr, None)
        .await
        .map_err(|e| format!("get tx count error: {}", e))?;
        
    ic_cdk::println!("canister eth address {} tx count: {}", hex::encode(from_addr), tx_count);
    // construct a transaction
    let to = Address::from_str(&to).unwrap();
    let tx: TransactionParameters = TransactionParameters {
        to: Some(to),
        nonce: Some(tx_count), // remember to fetch nonce first
        value: U256::from(value),
        gas_price: Some(U256::exp10(10)), // 10 gwei
        gas: U256::from(21000),
        ..Default::default()
    };
    // sign the transaction and get serialized transaction + signature
    let signed_tx = w3.accounts()
        .sign_transaction(tx, hex::encode(from_addr), key_info, CHAIN_ID)
        .await
        .map_err(|e| format!("sign tx error: {}", e))?;
    match w3.eth().send_raw_transaction(signed_tx.raw_transaction).await {
        Ok(txhash) => { 
            ic_cdk::println!("txhash: {}", hex::encode(txhash.0));
            Ok(format!("{}", hex::encode(txhash.0)))
        },
        Err(e) => { Err(e.to_string()) },
    }
}


// call a contract, transfer some token to addr
#[update(name = "rpc_call")]
#[candid_method(update, rename = "rpc_call")]
async fn rpc_call(body: String) -> Result<String, String> {

    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };


    let res = w3.json_rpc_call(body.as_ref()).await.map_err(|e| format!("{}", e))?;

    ic_cdk::println!("result: {}", res);

    Ok(format!("{}", res))
}

// query a contract, token balance
#[update(name = "token_balance")]
#[candid_method(update, rename = "token_balance")]
async fn token_balance(contract_addr: String, addr: String) -> Result<String, String> {
    // goerli weth: 0xb4fbf271143f4fbf7b91a5ded31805e42b2208d6
    // account: 0x9c9fcF808B82e5fb476ef8b7A1F5Ad61Dc597625
    let w3: Web3<_> = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let contract_address = Address::from_str(&contract_addr).unwrap();
    let contract = Contract::from_json(
        w3.eth(),
        contract_address,
        TOKEN_ABI
    ).map_err(|e| format!("init contract failed: {}", e))?;

    let addr = Address::from_str(&addr).unwrap();
    let balance: U256 = contract
        .query("balanceOf", (addr,), None, Options::default(), None)
        .await
        .map_err(|e| format!("query contract error: {}", e))?;
    ic_cdk::println!("balance of {} is {}", addr, balance);
    Ok(format!("{}", balance))
}

// #[update(name = "getLogs")]
// #[candid_method(update, rename = "getLogs")]
// async fn token_balance(contract_addr: String) -> Result<String, String> {
//     // goerli weth: 0xb4fbf271143f4fbf7b91a5ded31805e42b2208d6
//     // account: 0x9c9fcF808B82e5fb476ef8b7A1F5Ad61Dc597625
//     let w3: Web3<_> = match ICHttp::new(URL, None) {
//         Ok(v) => { Web3::new(v) },
//         Err(e) => { return Err(e.to_string()) },
//     };
//     let contract_address = Address::from_str(&contract_addr).unwrap();
//     let contract = Contract::from_json(
//         w3.eth(),
//         contract_address,
//         TOKEN_ABI
//     ).map_err(|e| format!("init contract failed: {}", e))?;

//     let addr = Address::from_str(&addr).unwrap();
//     let balance: U256 = contract
//         .query("balanceOf", (addr,), None, Options::default(), None)
//         .await
//         .map_err(|e| format!("query contract error: {}", e))?;
//     ic_cdk::println!("balance of {} is {}", addr, balance);
//     Ok(format!("{}", balance))
// }


#[update(name = "send_token")]
#[candid_method(update, rename = "send_token")]
async fn send_token(token_addr: String, addr: String, value: u64, nonce: Option<u64>) -> Result<String, String> {
    // ecdsa key info
    let derivation_path = vec![ic_cdk::id().as_slice().to_vec()];
    let key_info = KeyInfo{ derivation_path: derivation_path, key_name: KEY_NAME.to_string(), ecdsa_sign_cycles: None };

    // get canister eth address
    let from_addr = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let contract_address = Address::from_str(&token_addr).unwrap();
    let contract = Contract::from_json(
        w3.eth(),
        contract_address,
        TOKEN_ABI
    ).map_err(|e| format!("init contract failed: {}", e))?;

    let canister_addr = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    // add nonce to options
    let tx_count: U256 = if let Some(count) = nonce {
        count.into() 
    } else {
        let v = w3.eth()
            .transaction_count(from_addr, None)
            .await
            .map_err(|e| format!("get tx count error: {}", e))?;
        v
    };
     
    // get gas_price
    let gas_price = w3.eth()
        .gas_price()
        .await
        .map_err(|e| format!("get gas_price error: {}", e))?;
    // legacy transaction type is still ok
    let options = Options::with(|op| { 
        op.nonce = Some(tx_count);
        op.gas_price = Some(gas_price);
        op.transaction_type = Some(U64::from(2)) //EIP1559_TX_ID
    });
    let to_addr = Address::from_str(&addr).unwrap();
    let txhash = contract
        .signed_call("transfer", (to_addr, value,), options, hex::encode(canister_addr), key_info, CHAIN_ID)
        .await
        .map_err(|e| format!("token transfer failed: {}", e))?;

    ic_cdk::println!("txhash: {}", hex::encode(txhash));

    Ok(format!("{}", hex::encode(txhash)))
}



// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
// getrandom::register_custom_getrandom!(always_fail);
// pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
//     Err(getrandom::Error::UNSUPPORTED)
// }

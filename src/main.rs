use std::net::{IpAddr, Ipv4Addr};

use kyoto::{
    Block, Client, Event, HeaderCheckpoint, NodeBuilder, ScriptBuf, TrustedPeer,
    tokio::{self, select},
};

use silentpayments::{
    Network, SilentPaymentAddress,
    receiving::{Label, Receiver},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    utils::receiving::calculate_ecdh_shared_secret,
};

const NETWORK: Network = Network::Testnet;
const VERSION: u8 = 0;
const TWEAK: &str = "02b3ef612e8a27b65a7ab5f3dbaa0f3dfd91cf20f4b49fa256e60d8129afd781f4";

fn build_public_key(message: &str) -> (SecretKey, PublicKey) {
    let secret_bytes: [u8; 32] = message.as_bytes().to_vec()[..32].try_into().unwrap();
    let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
    (
        secret_key,
        PublicKey::from_secret_key(&Secp256k1::new(), &secret_key),
    )
}

fn find_tx(block: Block, scripts: &[ScriptBuf]) {
    for tx in block.txdata {
        if tx
            .output
            .iter()
            .any(|out| scripts.contains(&out.script_pubkey))
        {
            tracing::info!("Found SP receiving transaction: {}", tx.compute_txid());
        }
    }
}

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    // Set up the SP wallet
    let scan_pk_bytes = "This is the start of a great silent payments address.";
    let spend_pk_bytes = "This is the end of an awesome silent payments address";
    let (scan_priv_key, scan_pk) = build_public_key(scan_pk_bytes);
    let (spend_priv_key, spend_pk) = build_public_key(spend_pk_bytes);
    let addr = SilentPaymentAddress::new(scan_pk, spend_pk, NETWORK, VERSION).unwrap();
    tracing::info!("SP address: {addr}");
    let receiver =
        Receiver::new(0, scan_pk, spend_pk, Label::new(scan_priv_key, 0), NETWORK).unwrap();
    let tweak_data = TWEAK.parse::<PublicKey>().unwrap();
    let shared_secret = calculate_ecdh_shared_secret(&tweak_data, &scan_priv_key);
    let spks_to_check = receiver
        .get_spks_from_shared_secret(&shared_secret)
        .unwrap();
    let scripts = spks_to_check
        .into_values()
        .map(|bytes| ScriptBuf::from_bytes(bytes.to_vec()))
        .collect::<Vec<ScriptBuf>>();
    // Set up the light client
    let peer_1: TrustedPeer = IpAddr::V4(Ipv4Addr::new(95, 217, 198, 121)).into();
    let peer_2: TrustedPeer = IpAddr::V4(Ipv4Addr::new(23, 137, 57, 100)).into();
    let checkpoint = HeaderCheckpoint::most_recent(kyoto::Network::Signet);
    let builder = NodeBuilder::new(kyoto::Network::Signet);
    let (node, client) = builder
        .add_peer(peer_1)
        .add_peer(peer_2)
        .anchor_checkpoint(checkpoint)
        .required_peers(2)
        .build()
        .unwrap();

    tokio::task::spawn(async move { node.run().await });

    let Client {
        requester,
        mut log_rx,
        mut warn_rx,
        mut event_rx,
    } = client;

    loop {
        select! {
            log = log_rx.recv() => {
                if let Some(log) = log {
                    tracing::info!("{log}");
                }
            }
            warn = warn_rx.recv() => {
                if let Some(warn) = warn {
                    tracing::warn!("{warn}");
                }
            }
            event = event_rx.recv() => {
                if let Some(event) = event {
                    match event {
                        Event::Synced(update) => {
                            tracing::info!("Synced chain up to block {}",update.tip().height);
                            tracing::info!("Chain tip: {}",update.tip().hash);
                            let fee = requester.broadcast_min_feerate().await.unwrap();
                            tracing::info!("Minimum transaction broadcast fee rate: {}", fee);
                            break;
                        },
                        Event::Block(indexed_block) => {
                            let hash = indexed_block.block.block_hash();
                            tracing::info!("Received block: {}", hash);
                        },
                        Event::BlocksDisconnected(_) => {
                            tracing::warn!("Some blocks were reorganized")
                        },
                        Event::IndexedFilter(mut filter) => {
                            if filter.contains_any(scripts.iter()) {
                                let hash = *filter.block_hash();
                                tracing::info!("Found script at {}!", hash);
                                let indexed_block = requester.get_block(hash).await.unwrap();
                                find_tx(indexed_block.block, &scripts);
                                break;
                            }
                        },
                    }
                }
            }
        }
    }
}

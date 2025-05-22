use std::sync::Arc;

use db::{DatabaseBuffer, WriteRange};
use kyoto::{
    Block, Client, Event, HeaderCheckpoint, Info, NodeBuilder, ScriptBuf, UnboundedReceiver,
    Warning,
    tokio::{self, select},
};

use redb::Database;
use request::TweakFetcher;
use silentpayments::{
    Network, SilentPaymentAddress,
    receiving::{Label, Receiver},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};

mod db;
mod request;

const NETWORK: Network = Network::Mainnet;
const NODE_NETWORK: kyoto::Network = kyoto::Network::Bitcoin;
const VERSION: u8 = 0;
const RECOVERY_HEIGHT: u32 = 870_000;

fn build_keypair(message: &str) -> (SecretKey, PublicKey) {
    let secret_bytes: [u8; 32] = message.as_bytes().to_vec()[..32].try_into().unwrap();
    let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
    (
        secret_key,
        PublicKey::from_secret_key(&Secp256k1::new(), &secret_key),
    )
}

#[allow(unused)]
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

async fn trace(
    mut log_rx: kyoto::Receiver<String>,
    mut info_rx: kyoto::Receiver<Info>,
    mut warn_rx: UnboundedReceiver<Warning>,
) {
    loop {
        select! {
            log = log_rx.recv() => {
                if let Some(log) = log {
                    tracing::info!("{log}");
                }
            }
            info = info_rx.recv() => {
                if let Some(info) = info {
                    tracing::info!("{info}");
                }
            }
            warn = warn_rx.recv() => {
                if let Some(warn) = warn {
                    tracing::warn!("{warn}");
                }
            }
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
    let (scan_priv_key, scan_pk) = build_keypair(scan_pk_bytes);
    let (_spend_priv_key, spend_pk) = build_keypair(spend_pk_bytes);
    let addr = SilentPaymentAddress::new(scan_pk, spend_pk, NETWORK, VERSION).unwrap();
    tracing::info!("SP address: {addr}");
    let sp_receiver =
        Receiver::new(0, scan_pk, spend_pk, Label::new(scan_priv_key, 0), NETWORK).unwrap();
    // Set up the database
    tracing::info!("Setting up tweak database...");
    let db = Arc::new(Database::create("filter_data.redb").unwrap());
    let mut db_buffer = DatabaseBuffer::new(Arc::clone(&db));
    // Set up the light client
    let checkpoint =
        HeaderCheckpoint::closest_checkpoint_below_height(RECOVERY_HEIGHT, NODE_NETWORK);
    let builder = NodeBuilder::new(NODE_NETWORK);
    let (node, client) = builder
        .after_checkpoint(checkpoint)
        .required_peers(2)
        .build()
        .unwrap();
    let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<WriteRange>();
    let http_client = reqwest::Client::new();
    let mut tweak_fetcher = TweakFetcher::new(
        Arc::clone(&db),
        sp_receiver,
        http_client,
        scan_priv_key,
        rrx,
    );

    tracing::info!("Starting the node...");
    tokio::task::spawn(async move { node.run().await });

    tracing::info!("Staring the HTTPS client...");
    tokio::task::spawn(async move { tweak_fetcher.run().await });

    let Client {
        requester: _,
        log_rx,
        info_rx,
        warn_rx,
        mut event_rx,
    } = client;

    tracing::info!("Initializing log loop...");
    tokio::task::spawn(async move { trace(log_rx, info_rx, warn_rx).await });

    loop {
        if let Some(event) = event_rx.recv().await {
            match event {
                Event::Synced(update) => {
                    tracing::info!("Synced chain up to block {}", update.tip().height);
                }
                Event::Block(indexed_block) => {
                    let hash = indexed_block.block.block_hash();
                    tracing::info!("Received block: {}", hash);
                }
                Event::BlocksDisconnected { accepted: _, disconnected: _ } => {
                    tracing::warn!("Some blocks were reorganized")
                }
                Event::IndexedFilter(filter) => {
                    let changes = db_buffer.push_filter(filter);
                    if let Some(change) = changes {
                        rtx.send(change).unwrap();
                    }
                }
            }
        }
    }
}

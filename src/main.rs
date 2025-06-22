use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc};

use bdk_sp::{
    bitcoin::{
        Network,
        secp256k1::{PublicKey, Secp256k1, SecretKey},
    },
    encoding::SilentPaymentCode,
    receive::scan::Scanner,
};
use bitcoin::secp256k1::Scalar;
use db::{DatabaseBuffer, WriteRange};
use kyoto::{
    tokio::{self, select}, AddrV2, Block, Client, Event, HeaderCheckpoint, Info, NodeBuilder, ScriptBuf, ServiceFlags, TrustedPeer, UnboundedReceiver, Warning
};

use miniscript::{
    Descriptor,
    descriptor::{DescriptorSecretKey, DescriptorType},
};
use redb::Database;
use request::TweakFetcher;

mod db;
mod request;

const NETWORK: Network = Network::Regtest;
const NODE_NETWORK: kyoto::Network = kyoto::Network::Regtest;
const VERSION: u8 = 0;
const RECOVERY_HEIGHT: u32 = 800_000;

fn get_keypair_from_descriptor(desc_str: &str) -> Option<(SecretKey, PublicKey)> {
    let secp = Secp256k1::signing_only();
    let (descriptor, keymap) =
        Descriptor::parse_descriptor(&secp, desc_str).expect("wrong descriptor");

    if descriptor.desc_type() != DescriptorType::Tr {
        return None;
    }

    if keymap.is_empty() {
        return None;
    }

    // note: we're only looking at the first entry in the keymap
    // the idea is to find something that impls `GetKey`
    match keymap.iter().next().expect("not empty") {
        (_, DescriptorSecretKey::XPrv(xpriv)) => {
            let derived_key = xpriv
                .xkey
                .derive_priv(&secp, &xpriv.derivation_path)
                .expect("should derive");
            let sk = derived_key.private_key;
            let pk = sk.public_key(&secp);
            Some((sk, pk))
        }
        _ => unimplemented!("multi xkey signer"),
    }
}

#[allow(unused)]
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
    let scan_descriptor: String = std::env::var("SCAN_DESCRIPTOR")
        .expect("provide scan private descriptor as environment variable");
    let spend_descriptor: String = std::env::var("SPEND_DESCRIPTOR")
        .expect("provide spend private descriptor as environment variable");
    let (scan_sk, scan_pk) = if let Some(keys) = get_keypair_from_descriptor(&scan_descriptor) {
        keys
    } else {
        return;
    };

    let (_, spend_pk) = if let Some(keys) = get_keypair_from_descriptor(&spend_descriptor) {
        keys
    } else {
        return;
    };

    let addr = SilentPaymentCode {
        scan: scan_pk,
        spend: spend_pk,
        network: NETWORK,
        version: VERSION,
    };
    tracing::info!("SP address: {addr}");
    let label_lookup: BTreeMap<PublicKey, (Scalar, u32)> = BTreeMap::default();
    let sp_scanner = Scanner::new(scan_sk, spend_pk, label_lookup);
    // Set up the database

    // Add regtest node as Peer
    let peer = TrustedPeer::new(
        AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
        None,
        ServiceFlags::P2P_V2,
    );

    tracing::info!("Setting up filter database...");
    let db = Arc::new(Database::create("filter_data.redb").unwrap());
    let mut db_buffer = DatabaseBuffer::new(Arc::clone(&db));
    // Set up the light client
    let checkpoint =
        HeaderCheckpoint::closest_checkpoint_below_height(RECOVERY_HEIGHT, NODE_NETWORK);
    let builder = NodeBuilder::new(NODE_NETWORK);
    let (node, client) = builder
        .after_checkpoint(checkpoint)
        .add_peer(peer)
        .required_peers(1)
        .build()
        .unwrap();
    let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<WriteRange>();
    let http_client = reqwest::Client::new();
    let mut tweak_fetcher = TweakFetcher::new(Arc::clone(&db), sp_scanner, http_client, rrx);

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
                    let changes = db_buffer.write_queue();
                    rtx.send(changes).unwrap();
                }
                Event::Block(indexed_block) => {
                    let hash = indexed_block.block.block_hash();
                    tracing::info!("Received block: {}", hash);
                }
                Event::BlocksDisconnected(_) => {
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

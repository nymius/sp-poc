use std::{collections::HashSet, sync::Arc};

use kyoto::{BlockFilter, ScriptBuf, UnboundedReceiver, tokio::time::Instant};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use redb::Database;
use reqwest::Client;
use silentpayments::{
    secp256k1::{PublicKey, SecretKey},
    utils::receiving::calculate_ecdh_shared_secret,
};

use crate::db::{TABLE_DEF, WriteRange};

fn time(what: &str, then: Instant) {
    let now = Instant::now();
    let duration = now.duration_since(then).as_micros();
    tracing::info!("{what} took {duration} microseconds");
}

pub struct TweakFetcher {
    db: Arc<Database>,
    sp_receiver: silentpayments::receiving::Receiver,
    client: Client,
    scan_priv_key: SecretKey,
    requests: UnboundedReceiver<WriteRange>,
}

impl TweakFetcher {
    pub fn new(
        db: Arc<Database>,
        sp_receiver: silentpayments::receiving::Receiver,
        client: Client,
        scan_priv_key: SecretKey,
        requests: UnboundedReceiver<WriteRange>,
    ) -> Self {
        Self {
            db,
            sp_receiver,
            client,
            scan_priv_key,
            requests,
        }
    }

    pub async fn run(&mut self) {
        loop {
            if let Some(write_range) = self.requests.recv().await {
                tracing::info!(
                    "Requesting tweaks up to {}",
                    write_range
                        .writes
                        .last_key_value()
                        .map(|(height, _)| height)
                        .unwrap()
                );
                let read = self.db.begin_read().unwrap();
                let table = read.open_table(TABLE_DEF).unwrap();
                for (height, hash) in write_range.writes.into_iter() {
                    let request_string = format!(
                        "https://silentpayments.dev/blindbit/mainnet/tweaks/{}",
                        height
                    );
                    let then = Instant::now();
                    let response = self.client.get(request_string).send().await.unwrap();
                    time("HTTP query", then);
                    let then = Instant::now();
                    let tweaks: Vec<String> = response.json().await.unwrap();
                    let tweaks: Vec<PublicKey> = tweaks
                        .into_iter()
                        .map(|str| str.parse::<PublicKey>().unwrap())
                        .collect();
                    time("Parsing", then);
                    let then = Instant::now();
                    let filter_bytes = table.get(&height).unwrap().unwrap();
                    let filter = BlockFilter::new(&filter_bytes.value());
                    time("Database read", then);
                    let then = Instant::now();
                    let all_spks: HashSet<_> = tweaks
                        .par_iter()
                        .filter_map(|tweak| {
                            let shared_secret =
                                calculate_ecdh_shared_secret(tweak, &self.scan_priv_key);
                            self.sp_receiver
                                .get_spks_from_shared_secret(&shared_secret)
                                .ok()
                        })
                        .map(|map| {
                            map.into_values()
                                .map(|bytes| ScriptBuf::from_bytes(bytes.to_vec()))
                                .collect::<HashSet<_>>()
                        })
                        .reduce(HashSet::new, |mut acc, set| {
                            acc.extend(set);
                            acc
                        });
                    time("Computing SPKs", then);
                    let then = Instant::now();
                    if filter
                        .match_any(&hash, all_spks.iter().map(|script| script.to_bytes()))
                        .unwrap()
                    {
                        tracing::info!("Found a match at {height}");
                    }
                    time("Matching scripts", then);
                }
            }
        }
    }
}

use futures::StreamExt;
use std::{collections::HashSet, sync::Arc};

use kyoto::{BlockFilter, UnboundedReceiver};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use redb::Database;
use reqwest::Client;
use silentpayments::{
    secp256k1::{PublicKey, SecretKey},
    utils::receiving::calculate_ecdh_shared_secret,
};

use crate::db::{TABLE_DEF, WriteRange};

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
                let _ = write_range.writes.len();
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
                let client = self.client.clone();
                let mut stream = futures::stream::iter(write_range.writes.into_iter())
                    .map(move |(height, hash)| {
                        let client = client.clone();
                        let request_string = format!(
                            "https://silentpayments.dev/blindbit/mainnet/tweaks/{}?dustLimit=1000",
                            height
                        );
                        async move {
                            let response = client.get(request_string).send().await.unwrap();
                            let tweaks: Vec<String> = response.json().await.unwrap();
                            let tweaks: Vec<PublicKey> = tweaks
                                .into_iter()
                                .map(|str| str.parse::<PublicKey>().unwrap())
                                .collect();
                            (height, hash, tweaks)
                        }
                    })
                    .buffer_unordered(200);

                while let Some((height, hash, tweaks)) = stream.next().await {
                    let filter_bytes = table.get(&height).unwrap().unwrap();
                    let filter = BlockFilter::new(&filter_bytes.value());
                    let all_spks: HashSet<[u8; 34]> = tweaks
                        .par_iter()
                        .filter_map(|tweak| {
                            let shared_secret =
                                calculate_ecdh_shared_secret(tweak, &self.scan_priv_key);
                            self.sp_receiver
                                .get_spks_from_shared_secret(&shared_secret)
                                .ok()
                        })
                        .map(|map| map.into_values().collect::<HashSet<_>>())
                        .reduce(HashSet::new, |mut acc, set| {
                            acc.extend(set);
                            acc
                        });

                    if filter.match_any(&hash, all_spks.into_iter()).unwrap() {
                        tracing::info!("Found a match at {height}");
                    }
                }
            }
        }
    }
}

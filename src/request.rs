use bdk_sp::bitcoin::secp256k1::PublicKey;
use bdk_sp::receive::scan::Scanner;
use futures::StreamExt;
use std::sync::Arc;

use kyoto::{BlockFilter, UnboundedReceiver};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use redb::Database;
use reqwest::Client;

use crate::db::{TABLE_DEF, WriteRange};

pub struct TweakFetcher {
    db: Arc<Database>,
    scanner: Scanner,
    client: Client,
    requests: UnboundedReceiver<WriteRange>,
}

impl TweakFetcher {
    pub fn new(
        db: Arc<Database>,
        scanner: Scanner,
        client: Client,
        requests: UnboundedReceiver<WriteRange>,
    ) -> Self {
        Self {
            db,
            scanner,
            client,
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
                        let blindbit_url = std::env::var("BLINDBIT_URL")
                            .expect("blindbit url should be set to make tweak requests");
                        let request_string = format!("{blindbit_url}/tweaks/{}", height);
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
                    let all_spks: Vec<[u8; 34]> = tweaks
                        .par_iter()
                        .flat_map(|tweak| {
                            self.scanner
                                .get_spks_from_tweak(tweak, 0_u32)
                                .into_par_iter()
                                .map(|x| {
                                    let script_bytes: [u8; 34] = x.into_bytes().try_into().expect(
                                        "all spks should be p2tr scripts which have 34 bytes",
                                    );
                                    script_bytes
                                })
                        })
                        .collect::<Vec<[u8; 34]>>();

                    if !all_spks.is_empty()
                        && filter.match_any(&hash, all_spks.into_iter()).unwrap()
                    {
                        tracing::info!("Found a match at {height}");
                    }
                }
            }
        }
    }
}

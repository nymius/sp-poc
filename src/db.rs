use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use kyoto::{BlockHash, IndexedFilter};
use redb::{Database, TableDefinition};

const QUEUE_SIZE: usize = 999;
pub const TABLE_DEF: TableDefinition<u32, Vec<u8>> = TableDefinition::new("filters");

pub struct WriteRange {
    pub writes: BTreeMap<u32, BlockHash>,
}

pub struct DatabaseBuffer {
    queue: BTreeSet<IndexedFilter>,
    db: Arc<Database>,
}

impl DatabaseBuffer {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            queue: BTreeSet::new(),
            db,
        }
    }

    pub fn push_filter(&mut self, filter: IndexedFilter) -> Option<WriteRange> {
        self.queue.insert(filter);
        if self.queue.len() > QUEUE_SIZE {
            let write = self.db.begin_write().unwrap();
            let mut writes = BTreeMap::new();
            {
                let mut table = write.open_table(TABLE_DEF).unwrap();
                for indexed_filter in core::mem::take(&mut self.queue) {
                    writes.insert(indexed_filter.height(), *indexed_filter.block_hash());
                    table
                        .insert(indexed_filter.height(), indexed_filter.into_contents())
                        .unwrap();
                }
            }
            write.commit().unwrap();
            return Some(WriteRange { writes });
        }
        None
    }
}

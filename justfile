[doc("List all available commands.")]
default:
  just --list --unsorted

run:
    cargo run --release

clean:
    rm -rf light_client_data
    rm filter_data.redb


cbf_scan BDK_SP_PATH="" BLINDBIT_URL="":
  #!/usr/bin/env bash
    export SCAN_DESCRIPTOR=$(cat {{BDK_SP_PATH}}/.bdk_sp_private_scan.desc)
    export SPEND_DESCRIPTOR=$(cat {{BDK_SP_PATH}}/.bdk_sp_private_spend.desc)
    export BLINDBIT_URL={{BLINDBIT_URL}}

    cargo run

// src/bin/my_iota_did.rs
use anyhow::Result;
use tokio::io::{stdin, AsyncReadExt};

use identity_stronghold::StrongholdStorage;

use iota_sdk::{
    client::{
        api::GetAddressesOptions,
        secret::{stronghold::StrongholdSecretManager, SecretManager},
        Client,
    },
    crypto::keys::bip39::Mnemonic,
    types::block::address::Bech32Address,
};

use identity_iota::{
    iota::{IotaClientExt, IotaDocument, IotaIdentityClientExt, NetworkName},
    storage::{JwkDocumentExt, JwkMemStore, Storage},
    verification::{jws::JwsAlgorithm, MethodScope},
};

#[tokio::main]
async fn main() -> Result<()> {
    /* ── node ────────────────────────────────────────────────────────── */
    let client = Client::builder()
        .with_primary_node("http://127.0.0.1:14265", None)?
        .finish()
        .await?;

    let path = "wallet.stronghold";

    /* ── Stronghold for STORAGE (keys) ───────────────────────────────── */
    let stronghold_storage_mgr = StrongholdSecretManager::builder()
        .password("some-very-secure-password".to_owned())
        .build(path)?;

    // store dev mnemonic once
    let _ = stronghold_storage_mgr.store_mnemonic(
        Mnemonic::from(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
    ).await;

    let sh_storage   = StrongholdStorage::new(stronghold_storage_mgr);
    let storage: Storage<_, _> = Storage::new(sh_storage.clone(), sh_storage);

    /* ── Stronghold for SIGNING (alias output) ───────────────────────── */
    let stronghold_sign_mgr = StrongholdSecretManager::builder()
        .password("some-very-secure-password".to_owned())
        .build(path)?;

    let secret_manager = SecretManager::Stronghold(stronghold_sign_mgr);

    /* ── funding address ─────────────────────────────────────────────── */
    let network: NetworkName = client.network_name().await?;
    let addr: Bech32Address = secret_manager
        .generate_ed25519_addresses(
            GetAddressesOptions::default()
                .with_range(0..1)
                .with_bech32_hrp((&network).try_into()?),
        )
        .await?[0];

    println!("💡  Send test tokens to: {addr}");
    println!("⏳  Press <Enter> once funded …");
    stdin().read_u8().await?;

    /* ── create, publish, print two DIDs ─────────────────────────────── */
    let did_doc = create_and_publish(
        &client, &secret_manager, &storage, &addr, &network, "key-issuer",
    ).await?;
    println!("\nDID  : {}", did_doc.id());

    

    Ok(())
}

/* helper ---------------------------------------------------------------- */
async fn create_and_publish(
    client: &Client,
    secret_manager: &SecretManager,
    storage: &Storage<StrongholdStorage, StrongholdStorage>,
    addr: &Bech32Address,
    network: &NetworkName,
    fragment: &str,
) -> Result<IotaDocument> {
    let mut doc = IotaDocument::new(network);

    doc.generate_method(
        storage,
        JwkMemStore::ED25519_KEY_TYPE,
        JwsAlgorithm::EdDSA,
        Some(fragment),
        MethodScope::assertion_method(),
    )
    .await?;

    let alias = client.new_did_output(addr.clone().into(), doc, None).await?;
    Ok(client.publish_did_output(secret_manager, alias).await?)
}

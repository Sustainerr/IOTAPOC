// src/bin/vc_creator.rs
use anyhow::{anyhow, Result};
use std::{fs::File, io::Write};

use iota_sdk::client::{
    Client,
    secret::stronghold::StrongholdSecretManager,
};

use identity_iota::{
    core::{json, FromJson, Url},
    credential::{Credential, CredentialBuilder, Jwt, Subject},
    did::DID,                             // adds `.as_str()`
    iota::{IotaDocument, IotaIdentityClientExt},
    prelude::IotaDID,
    storage::{JwkDocumentExt, JwsSignatureOptions, Storage},
};

use identity_stronghold::StrongholdStorage;

#[tokio::main]
async fn main() -> Result<()> {
    /* ── 1. Node connection ─────────────────────────────────────────────── */
    let client = Client::builder()
        .with_primary_node("http://127.0.0.1:14265", None)?
        .finish()
        .await?;

    /* ── 2. Open the Stronghold snapshot ───────────────────────────────── */
    let sh_secret_mgr = StrongholdSecretManager::builder()
        .password("some-very-secure-password".to_owned())   // ← String, not &str
        .build("wallet.stronghold")?;

    /* ── 3. Wrap Stronghold for identity-rs storage ─────────────────────── */
    let sh_storage = StrongholdStorage::new(sh_secret_mgr);
    let storage: Storage<_, _> = Storage::new(sh_storage.clone(), sh_storage);

    /* ── 4. Resolve existing DIDs ───────────────────────────────────────── */
    let issuer_did: IotaDID =
        "did:iota:tst:0xa8f3dd15e2344b9c6735868bc8a17a233284c7b7be17dc6063790ab3e9cf3486"
            .parse()?;
    let vehicle_did: IotaDID =
        "did:iota:tst:0xdbcf16f6335d96a686f069fd26a080e3d4d49879ee5bfc0f10e85fc3358db1dd"
            .parse()?;

    let issuer_doc: IotaDocument = client.resolve_did(&issuer_did).await?;
    let vehicle_doc: IotaDocument = client.resolve_did(&vehicle_did).await?;

    /* ── 5. Build the unsigned credential ──────────────────────────────── */
    let subject_json = json!({
        "id": vehicle_doc.id().as_str(),
        "authorized": true,
        "mqtt_topic": "mqtt/topic/vehicle"
    })
    .to_string();
    let subject: Subject = Subject::from_json(&subject_json)?;

    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse("https://example.org/credentials/vehicle-auth")?)
        .issuer(Url::parse(issuer_doc.id().as_str())?)
        .type_("VehicleAuthorization")
        .subject(subject)
        .build()?;

    /* ── 6. Pick issuer’s first authentication method ─────────────────── */
    let signing_fragment = issuer_doc
        .core_document()
        .assertion_method()
        .first()
        .ok_or(anyhow!("issuer DID has no assertion method"))?
        .id()
        .fragment()
        .ok_or(anyhow!("auth method id lacks fragment"))?
        .to_owned();

    /* ── 7. Sign as a JWT ──────────────────────────────────────────────── */
    let jwt: Jwt = issuer_doc
        .create_credential_jwt(
            &credential,
            &storage,
            &signing_fragment,
            &JwsSignatureOptions::default(),
            None,
        )
        .await?;

    File::create("vehicle_vc.jwt")?.write_all(jwt.as_str().as_bytes())?;
    println!("✅  JWT saved to vehicle_vc.jwt");

    Ok(())
}

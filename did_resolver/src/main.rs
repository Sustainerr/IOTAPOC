use anyhow::Result;
use identity_iota::iota::{IotaDocument, IotaIdentityClientExt};
use iota_sdk::client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let did = "did:iota:tst:0xa8f3dd15e2344b9c6735868bc8a17a233284c7b7be17dc6063790ab3e9cf3486";

    let client = Client::builder()
        .with_primary_node("http://127.0.0.1:14265", None)?
        .finish()
        .await?;

    let parsed_did = did.parse()?;
    let document: IotaDocument = client.resolve_did(&parsed_did).await?;

    println!("{:#}", document);

    Ok(())
}

//bin/vehicle_ppm.rs
use anyhow::Result;
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, Transport};
use serde::{Deserialize, Serialize};
use std::fs;
use identity_iota::credential::Presentation;
use identity_iota::did::DID;
use identity_iota::prelude::IotaDID;
use identity_iota::{
    core::Object,
    credential::{Jwt, PresentationBuilder},
    iota::{IotaDocument, IotaIdentityClientExt},
    storage::{JwsSignatureOptions, Storage, JwkDocumentExt},
};
use identity_stronghold::StrongholdStorage;
use iota_sdk::client::{
    Client,
    secret::stronghold::StrongholdSecretManager,
};

/* HiveMQ Cloud ----------------------------------------------------- */
const BROKER:&str="f03ebe48b16246b980a173f2aaa1a2dd.s1.eu.hivemq.cloud";
const PORT:u16=8883;
const USER:&str="hivemq.webclient.1750848554164";
const PASS:&str="y25;!:jB%g8MSzNaFm0A";

/* Holder DID / key fragment / VC path ------------------------------ */
const DID:&str="did:iota:tst:0xdbcf16f6335d96a686f069fd26a080e3d4d49879ee5bfc0f10e85fc3358db1dd";
const FRAG:&str="key-vehicle";
const VC_PATH:&str=concat!(env!("CARGO_MANIFEST_DIR"),"/vehicle_vc.jwt");

/* Topics ----------------------------------------------------------- */
const T_REQ:&str="auth/request";
fn t_chal ()->String{format!("auth/challenge/{DID}") }
fn t_resp ()->String{format!("auth/response/{DID}") }
fn t_ok   ()->String{format!("auth/success/{DID}") }
fn t_data ()->String{format!("mqtt/topic/vehicle/{DID}") }

/* JSON helpers ----------------------------------------------------- */
#[derive(Serialize)]          struct Req<'a>{ did:&'a str }
#[derive(Deserialize)]        struct Chal{ nonce:String }
#[derive(Serialize)]          struct Resp<'a>{ vp:&'a str }

#[tokio::main]
async fn main() -> Result<()> {
    /* 1️⃣  Load VC JWT */
    let vc: Jwt = fs::read_to_string(VC_PATH)?.trim().to_owned().into();

    /* 2️⃣  Stronghold storage with vehicle key */
    let sh = StrongholdSecretManager::builder()
        .password("some-very-secure-password".to_string())
        .build("wallet.stronghold")?;
    let st  = StrongholdStorage::new(sh);
    let storage: Storage<_, _> = Storage::new(st.clone(), st);

    /* 3️⃣  Resolve holder DID once (local node) */
    let node = Client::builder()
        .with_primary_node("http://127.0.0.1:14265", None)?
        .finish()
        .await?;
    let doc: IotaDocument = node.resolve_did(&DID.parse()?).await?;

    /* 4️⃣  MQTT TLS client */
    let mut opts = MqttOptions::new(DID, BROKER, PORT);
    opts.set_credentials(USER, PASS);
    opts.set_transport(Transport::tls_with_default_config());
    let (mqtt, mut conn) = AsyncClient::new(opts, 10);

    mqtt.subscribe(t_chal(), QoS::AtMostOnce).await?;
    mqtt.subscribe(t_ok(),   QoS::AtMostOnce).await?;
    mqtt.publish(T_REQ, QoS::AtLeastOnce, false,
                 serde_json::to_string(&Req{did:DID})?).await?;

    println!("📡 waiting for challenge …");

    loop {
        match conn.poll().await {
            Ok(Event::Incoming(Packet::Publish(p))) if p.topic == t_chal() => {
                let ch: Chal = serde_json::from_slice(&p.payload)?;
                println!("🔑 nonce received: {}", ch.nonce);


                let holder_did: IotaDID = DID.parse()?;
                /* build unsigned presentation */
                let pres: Presentation<Jwt> = PresentationBuilder::new(holder_did.to_url().into(), Default::default())
                .credential(vc.clone())
                .build()?;

                /* sign VP with nonce */
                let vp = doc.create_presentation_jwt::<_, _, Jwt, Object>(
                    &pres,
                    &storage,
                    FRAG,
                    &JwsSignatureOptions::default().nonce(ch.nonce.clone()),
                    &identity_iota::credential::JwtPresentationOptions::default(),
                ).await?;

                mqtt.publish(t_resp(), QoS::AtLeastOnce, false,
                             serde_json::to_string(&Resp{vp:vp.as_str()})?).await?;
                println!("🚀 VP sent, awaiting authorisation …");
            }

            Ok(Event::Incoming(Packet::Publish(p))) if p.topic == t_ok() => {
                println!("✅ authorised – sending telemetry");
                mqtt.publish(t_data(), QoS::AtLeastOnce, false,
                             r#"{"temp":36.7,"speed":45}"#).await?;
            }

            Ok(_) => {}               // ignore other packets
            Err(e) => { eprintln!("❌ mqtt error: {e:?}"); break; }
        }
    }
    Ok(())
}

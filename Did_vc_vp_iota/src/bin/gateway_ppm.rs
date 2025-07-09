//bin/gateway_ppm.rs
use anyhow::{anyhow, Result};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, Transport};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::{
    core::Object,
    credential::{
        Jwt, JwtPresentationValidator, JwtPresentationValidationOptions,
        JwtPresentationValidatorUtils, JwtCredentialValidator,
        JwtCredentialValidationOptions, JwtCredentialValidatorUtils, FailFast,
    },
    document::verifiable::JwsVerificationOptions,
    did::CoreDID,
    resolver::Resolver,
    iota::IotaDocument,
};
use iota_sdk::client::Client;
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;

/* MQTT ------------------------------------------------------------------ */
const BROKER:&str="f03ebe48b16246b980a173f2aaa1a2dd.s1.eu.hivemq.cloud";
const PORT:u16=8883;
const USER:&str="hivemq.webclient.1750848554164";
const PASS:&str="y25;!:jB%g8MSzNaFm0A";
const TTL:u64 = 60;

/* JSON ------------------------------------------------------------------ */
#[derive(Deserialize)] struct Req{ did:String }
#[derive(Serialize)]   struct Cha<'a>{ nonce:String, domain:&'a str }
#[derive(Deserialize)] struct Resp{ vp:Jwt }

struct Nonce{ nonce:String, exp:u64 }
fn now()->u64{ SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }

/* helper: extract first VC ------------------------------------------------*/
fn first_vc(jwt:&str)->Result<Jwt>{
    let payload = jwt.split('.').nth(1).ok_or_else(|| anyhow!("bad jwt"))?;
    let padded = match payload.len()%4 {2=>format!("{payload}=="),3=>format!("{payload}="), _=>payload.to_owned()};
    let bytes  = URL_SAFE.decode(padded)?;
    let json:serde_json::Value = serde_json::from_slice(&bytes)?;
    let vc = json["vp"]["verifiableCredential"][0]
                .as_str().ok_or_else(|| anyhow!("no VC"))?;
    Ok(vc.to_owned().into())
}

#[tokio::main]
async fn main()->Result<()>{
    let mut map:HashMap<String,Nonce>=HashMap::new();

    /* MQTT connect */
    let mut opt=MqttOptions::new("gateway-verifier",BROKER,PORT);
    opt.set_credentials(USER,PASS);
    opt.set_transport(Transport::tls_with_default_config());
    let (mqtt,mut conn)=AsyncClient::new(opt,10);

    mqtt.subscribe("auth/request",QoS::AtMostOnce).await?;
    mqtt.subscribe("auth/response/#",QoS::AtMostOnce).await?;
    println!("Gateway waiting …");

    /* Resolver for iota:DIDs */
    let node=Client::builder().with_primary_node("http://127.0.0.1:14265",None)?
        .finish().await?;
    let mut resolver:Resolver<IotaDocument>=Resolver::new();
    resolver.attach_iota_handler(node);

    loop {
        match conn.poll().await {
            Ok(Event::Incoming(Packet::ConnAck(_))) =>{
                println!("✅ MQTT connected");
            }

            /* 1️⃣  issue nonce */
            Ok(Event::Incoming(Packet::Publish(p))) if p.topic=="auth/request" =>{
                let r:Req=serde_json::from_slice(&p.payload)?;
                let nonce=Uuid::new_v4().simple().to_string();
                map.insert(r.did.clone(),Nonce{nonce:nonce.clone(),exp:now()+TTL});
                println!("→ nonce {nonce} issued for {}",r.did);
                mqtt.publish(format!("auth/challenge/{}",r.did),QoS::AtLeastOnce,false,
                             serde_json::to_string(&Cha{nonce,domain:""})?).await?;
            }

            /* 2️⃣  RECEIVES VP */
            Ok(Event::Incoming(Packet::Publish(p))) if p.topic.starts_with("auth/response/") =>{
                let did=p.topic.trim_start_matches("auth/response/").to_string();
                let Some(n)=map.get(&did) else {continue};
                let resp:Resp=serde_json::from_slice(&p.payload)?;

                /* VP check */
                let holder:CoreDID=JwtPresentationValidatorUtils::extract_holder(&resp.vp)?;
                println!("Holder DID: {holder}");
                let holder_doc=resolver.resolve(&holder).await?;
                let vp_ok = JwtPresentationValidator
                    ::with_signature_verifier(EdDSAJwsVerifier::default())
                    .validate::<IotaDocument,Jwt,Object>(
                        &resp.vp,&holder_doc,
                        &JwtPresentationValidationOptions::default()
                         .presentation_verifier_options(
                             JwsVerificationOptions::default().nonce(n.nonce.clone())
                         )
                    ).is_ok();
                println!("VP signature+nonce: {vp_ok}");

                /* first VC check */
                let mut vc_ok=false;
                if vp_ok {
                    let vc=first_vc(resp.vp.as_str())?;
                    let issuer:CoreDID=JwtCredentialValidatorUtils
                        ::extract_issuer_from_jwt::<CoreDID>(&vc)?;
                    println!("VC issuer DID: {issuer}");
                    let issuer_doc=resolver.resolve(&issuer).await?;
                    vc_ok = JwtCredentialValidator
                        ::with_signature_verifier(EdDSAJwsVerifier::default())
                        .validate::<_,Object>(
                            &vc,&issuer_doc,
                            &JwtCredentialValidationOptions::default(),
                            FailFast::FirstError).is_ok();
                    println!("VC signature: {vc_ok}");
                }

                let fresh = now()<n.exp;
                println!("Nonce fresh: {fresh}");

                let ok = vp_ok && vc_ok && fresh;
                if ok {
                    mqtt.publish(format!("auth/success/{did}"),
                        QoS::AtLeastOnce,false,"ok").await?;
                }
                println!("{} {}\n", if ok{"ACCEPT ✅"}else{"REJECT"}, did);
            }

            Ok(_) => {}
            Err(e)=>{eprintln!("❌ mqtt error: {e:?}"); break;}
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}

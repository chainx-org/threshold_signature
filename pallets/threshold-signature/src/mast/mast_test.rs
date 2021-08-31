use super::mast::{Mast, XOnly};
use super::{serialize, VarInt};
use bech32::{u5, ToBase32, Variant};
use hashes::hex::ToHex;

#[test]
fn test_ser_compact_size_tests() {
    let r1 = serialize(&VarInt(34 as u64));
    let r2 = serialize(&VarInt(253 as u64));
    let r3 = serialize(&VarInt(254 as u64));
    let r4 = serialize(&VarInt(255 as u64));
    let r5 = serialize(&VarInt(55555 as u64));
    let r6 = serialize(&VarInt(666666 as u64));
    let r7 = serialize(&VarInt(999999999 as u64));
    let r8 = serialize(&VarInt(10000000000000 as u64));

    assert_eq!(r1.to_hex(), "22");
    assert_eq!(r2.to_hex(), "fdfd00");
    assert_eq!(r3.to_hex(), "fdfe00");
    assert_eq!(r4.to_hex(), "fdff00");
    assert_eq!(r5.to_hex(), "fd03d9");
    assert_eq!(r6.to_hex(), "fe2a2c0a00");
    assert_eq!(r7.to_hex(), "feffc99a3b");
    assert_eq!(r8.to_hex(), "ff00a0724e18090000");
}

#[test]
fn mast_generate_root_should_work() {
    let script_a = XOnly::parse_slice(
        &hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9").unwrap(),
    )
    .unwrap();
    let script_b = XOnly::parse_slice(
        &hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34").unwrap(),
    )
    .unwrap();
    let script_c = XOnly::parse_slice(
        &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap(),
    )
    .unwrap();
    let scripts = vec![script_a, script_b, script_c];
    let mast = Mast { scripts };
    let root = mast.calc_root().unwrap();
    println!("root is {:?}", root);

    assert_eq!(
        "4ac28f45b41d96319f16141ec8433362f35cadb1a44a0e40aea424a5ef34d828",
        root.to_hex()
    );
}

#[test]
fn mast_generate_merkle_proof_should_work() {
    let script_a = XOnly::parse_slice(
        &hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9").unwrap(),
    )
    .unwrap();
    let script_b = XOnly::parse_slice(
        &hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34").unwrap(),
    )
    .unwrap();
    let script_c = XOnly::parse_slice(
        &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap(),
    )
    .unwrap();
    let scripts = vec![script_a.clone(), script_b, script_c];
    let mast = Mast { scripts };
    let proof = mast.generate_merkle_proof(&script_a).unwrap();
    println!(
        "proof is {:?}",
        proof.iter().map(|p| p.to_hex()).collect::<Vec<_>>()
    );

    assert_eq!(
        proof.iter().map(|p| p.to_hex()).collect::<Vec<_>>(),
        vec![
            "c51bcfc34f78ae1518b7feaed7d0702d790d946aa5732cb9ad75d22fcd3917d4",
            "f49b4c19bf53dfcdd50bc565ccca5cfc64226ef20301502f2264b25e2f0adb3a",
            "aa4bc1ce7be6887fad68d95fcf8b0d19788640ead71837ed43a2b518e673ba2f",
        ]
    )
}

#[test]
fn mast_generate_address_should_work() {
    let mut data = vec![u5::try_from_u8(1).unwrap()];
    data.extend(
        hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .to_base32(),
    );
    let address = bech32::encode("bc", data, Variant::Bech32m).unwrap();
    assert_eq!(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        address
    )
}

#[test]
fn test_bech32m_addr() {
    let internal_key = XOnly::parse_slice(
        &hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9").unwrap(),
    )
    .unwrap();

    let script_a = XOnly::parse_slice(
        &hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9").unwrap(),
    )
    .unwrap();
    let script_b = XOnly::parse_slice(
        &hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34").unwrap(),
    )
    .unwrap();
    let script_c = XOnly::parse_slice(
        &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659").unwrap(),
    )
    .unwrap();
    let scripts = vec![script_a, script_b, script_c];
    let mast = Mast { scripts };
    let root = mast.calc_root().unwrap();
    println!("root is {:?}", root);

    let bech32_addr = mast.generate_address(&internal_key);
    println!("bech32 addr is {:?}", bech32_addr);

    assert_eq!(
        "4ac28f45b41d96319f16141ec8433362f35cadb1a44a0e40aea424a5ef34d828",
        root.to_hex()
    );
}

use crate::{
    mock::{self, *},
    primitive::OpCode,
    AddrToPubkey, Error, Pallet, ScriptHashToAddr,
};
use codec::Decode;
use frame_support::{assert_noop, assert_ok};

#[test]
fn generate_address_should_work() {
    new_test_ext().execute_with(|| {
        let who = 1;
        let abc = hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768")
            .unwrap();
        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861")
            .unwrap();
        let ac = hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356")
            .unwrap();
        let bc = hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b")
            .unwrap();
        let pubkeys = vec![abc, ab, ac, bc];
        assert_ok!(Pallet::<Test>::generate_address(
            Origin::signed(who),
            pubkeys
        ));
        let tweaked =
            &hex::decode("001604bef08d1fe4cefb2e75a2b786287821546f6acbe89570acc5d5a9bd5049")
                .unwrap();
        let addr =
            <mock::Test as frame_system::Config>::AccountId::decode(&mut &tweaked[..]).unwrap();
        assert!(AddrToPubkey::<Test>::contains_key(addr));
    });
}

#[test]
fn generate_address_wrong_scripts() {
    new_test_ext().execute_with(|| {
        let who = 1;
        let abc = vec![1; 32];
        let pubkeys = vec![abc];
        assert_noop!(
            Pallet::<Test>::generate_address(Origin::signed(who), pubkeys),
            Error::<Test>::MastBuildError
        );

        let ab = vec![1; 32];
        let ac = vec![1; 32];
        let bc = vec![1; 32];
        let abc = vec![1; 32];
        let pubkeys = vec![ab, ac, bc, abc];
        assert_noop!(
            Pallet::<Test>::generate_address(Origin::signed(who), pubkeys),
            Error::<Test>::InvalidMast
        );
    });
}

#[test]
fn pass_script_should_work() {
    new_test_ext().execute_with(|| {
        // https://github.com/chainx-org/threshold_signature/issues/1#issuecomment-909896156
        let who = 1;
        let abc = hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768").unwrap();
        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861").unwrap();
        let ac = hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356").unwrap();
        let bc = hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b").unwrap();
        let pubkeys = vec![abc, ab.clone(), ac, bc];
        assert_ok!(Pallet::<Test>::generate_address(Origin::signed(who), pubkeys));

        let tweaked = &hex::decode("001604bef08d1fe4cefb2e75a2b786287821546f6acbe89570acc5d5a9bd5049").unwrap();
        let addr = <mock::Test as frame_system::Config>::AccountId::decode(&mut &tweaked[..]).unwrap();
        let signature_ab = hex::decode("7227f84f853853527488ba5b9939c56dd4ecd0ae96687e0d8d4d5da10cb4e6651cb2aca89236f3c3766d80e3b2ab37c74abb91ad6bb66677a0f1e3bd7e68118f").unwrap();
        let message = b"We are legion!".to_vec();
        assert_eq!("576520617265206c6567696f6e21", hex::encode(&message));
        let script_hash = Pallet::<Test>::compute_script_hash(who, OpCode::Transfer, 10, (0, 10));
        assert_ok!(Pallet::<Test>::pass_script(Origin::signed(who), addr, signature_ab, ab, message, script_hash.clone()));
        assert_eq!(ScriptHashToAddr::<Test>::get(script_hash), addr);
    });
}

#[test]
fn pass_script_no_address() {
    new_test_ext().execute_with(|| {
        let who = 1;

        let ab =
            hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861").unwrap();

        let tweaked = &hex::decode("001604bef08d1fe4cefb2e75a2b786287821546f6acbe89570acc5d5a9bd5049").unwrap();
        let addr = <mock::Test as frame_system::Config>::AccountId::decode(&mut &tweaked[..]).unwrap();
        let signature_ab = hex::decode("7227f84f853853527488ba5b9939c56dd4ecd0ae96687e0d8d4d5da10cb4e6651cb2aca89236f3c3766d80e3b2ab37c74abb91ad6bb66677a0f1e3bd7e68118f").unwrap();
        let message = b"We are legion!".to_vec();
        let script_hash = Pallet::<Test>::compute_script_hash(who, OpCode::Transfer, 10, (0, 10));
        assert_noop!(Pallet::<Test>::pass_script(
            Origin::signed(who),
            addr,
            signature_ab,
            ab,
            message,
            script_hash
        ), Error::<Test>::NoAddressInStorage);
    });
}

#[test]
fn pass_script_with_invalid_signature() {
    new_test_ext().execute_with(|| {
        let who = 1;
        let abc = hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768")
            .unwrap();
        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861")
            .unwrap();
        let ac = hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356")
            .unwrap();
        let bc = hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b")
            .unwrap();
        let pubkeys = vec![abc, ab, ac, bc];
        assert_ok!(Pallet::<Test>::generate_address(
            Origin::signed(who),
            pubkeys
        ));

        let who = 1;

        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861")
            .unwrap();

        let tweaked =
            &hex::decode("001604bef08d1fe4cefb2e75a2b786287821546f6acbe89570acc5d5a9bd5049")
                .unwrap();
        let addr =
            <mock::Test as frame_system::Config>::AccountId::decode(&mut &tweaked[..]).unwrap();
        let signature_ab = vec![1; 64];
        let message = b"We are legion!".to_vec();
        let script_hash = Pallet::<Test>::compute_script_hash(who, OpCode::Transfer, 10, (0, 10));
        assert_noop!(
            Pallet::<Test>::pass_script(
                Origin::signed(who),
                addr,
                signature_ab,
                ab,
                message,
                script_hash
            ),
            Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn exec_script_should_work() {
    new_test_ext().execute_with(|| {
        // https://github.com/chainx-org/threshold_signature/issues/1#issuecomment-909896156
        let who = 1;
        let abc = hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768").unwrap();
        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861").unwrap();
        let ac = hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356").unwrap();
        let bc = hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b").unwrap();
        let pubkeys = vec![abc, ab.clone(), ac, bc];
        assert_ok!(Pallet::<Test>::generate_address(Origin::signed(who), pubkeys));

        let tweaked = &hex::decode("001604bef08d1fe4cefb2e75a2b786287821546f6acbe89570acc5d5a9bd5049").unwrap();
        let addr = <mock::Test as frame_system::Config>::AccountId::decode(&mut &tweaked[..]).unwrap();
        let signature_ab = hex::decode("7227f84f853853527488ba5b9939c56dd4ecd0ae96687e0d8d4d5da10cb4e6651cb2aca89236f3c3766d80e3b2ab37c74abb91ad6bb66677a0f1e3bd7e68118f").unwrap();
        let message = b"We are legion!".to_vec();
        assert_eq!("576520617265206c6567696f6e21", hex::encode(&message));
        let script_hash = Pallet::<Test>::compute_script_hash(who, OpCode::Transfer, 10, (0, 10));
        assert_ok!(Pallet::<Test>::pass_script(Origin::signed(who), addr, signature_ab, ab, message, script_hash));
        assert_ok!(Pallet::<Test>::exec_script(Origin::signed(who), OpCode::Transfer, 10, (0, 10)));
        assert_eq!(pallet_balances::Pallet::<Test>::free_balance(who), 20);
    });
}

#[test]
fn exec_script_mismatch_time_lock() {
    new_test_ext().execute_with(|| {
        // https://github.com/chainx-org/threshold_signature/issues/1#issuecomment-909896156
        let who = 1;
        let abc = hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768").unwrap();
        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861").unwrap();
        let ac = hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356").unwrap();
        let bc = hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b").unwrap();
        let pubkeys = vec![abc, ab.clone(), ac, bc];
        assert_ok!(Pallet::<Test>::generate_address(Origin::signed(who), pubkeys));

        let tweaked = &hex::decode("001604bef08d1fe4cefb2e75a2b786287821546f6acbe89570acc5d5a9bd5049").unwrap();
        let addr = <mock::Test as frame_system::Config>::AccountId::decode(&mut &tweaked[..]).unwrap();
        let signature_ab = hex::decode("7227f84f853853527488ba5b9939c56dd4ecd0ae96687e0d8d4d5da10cb4e6651cb2aca89236f3c3766d80e3b2ab37c74abb91ad6bb66677a0f1e3bd7e68118f").unwrap();
        let message = b"We are legion!".to_vec();
        assert_eq!("576520617265206c6567696f6e21", hex::encode(&message));
        let script_hash = Pallet::<Test>::compute_script_hash(who, OpCode::Transfer, 10, (2, 10));
        assert_ok!(Pallet::<Test>::pass_script(Origin::signed(who), addr, signature_ab, ab, message, script_hash));
        // TODO fix lib.rs 307-309
        // assert_noop!(Pallet::<Test>::exec_script(Origin::signed(who), OpCode::Transfer, 10, (2, 10)), Error::<Test>::MisMatchTimeLock);
        assert_eq!(pallet_balances::Pallet::<Test>::free_balance(who), 10);
    });
}

#[test]
fn exec_script_no_pass_script() {
    new_test_ext().execute_with(|| {
        // https://github.com/chainx-org/threshold_signature/issues/1#issuecomment-909896156
        let who = 1;
        let abc = hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768").unwrap();
        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861").unwrap();
        let ac = hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356").unwrap();
        let bc = hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b").unwrap();
        let pubkeys = vec![abc, ab.clone(), ac, bc];
        assert_ok!(Pallet::<Test>::generate_address(Origin::signed(who), pubkeys));

        let tweaked = &hex::decode("001604bef08d1fe4cefb2e75a2b786287821546f6acbe89570acc5d5a9bd5049").unwrap();
        let addr = <mock::Test as frame_system::Config>::AccountId::decode(&mut &tweaked[..]).unwrap();
        let signature_ab = hex::decode("7227f84f853853527488ba5b9939c56dd4ecd0ae96687e0d8d4d5da10cb4e6651cb2aca89236f3c3766d80e3b2ab37c74abb91ad6bb66677a0f1e3bd7e68118f").unwrap();
        let message = b"We are legion!".to_vec();
        assert_eq!("576520617265206c6567696f6e21", hex::encode(&message));
        let script_hash = Pallet::<Test>::compute_script_hash(who, OpCode::Transfer, 10, (0, 10));
        assert_ok!(Pallet::<Test>::pass_script(Origin::signed(who), addr, signature_ab, ab, message, script_hash));
        assert_ok!(Pallet::<Test>::exec_script(Origin::signed(who), OpCode::Transfer, 10, (0, 10)));
        assert_eq!(pallet_balances::Pallet::<Test>::free_balance(who), 20);
        assert_noop!(Pallet::<Test>::exec_script(Origin::signed(who), OpCode::Transfer, 10, (0, 10)), Error::<Test>::NoPassScript);
        assert_eq!(pallet_balances::Pallet::<Test>::free_balance(who), 20);
    });
}

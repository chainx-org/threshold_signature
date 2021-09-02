use crate::{mock::*, AddrToScript, Pallet};
use frame_support::assert_ok;

#[test]
fn generate_address_should_work() {
    new_test_ext().execute_with(|| {
        let who = 1;
        let abc = hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768").unwrap();
        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861").unwrap();
        let ac = hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356").unwrap();
        let bc = hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b").unwrap();
        let scripts = vec![abc, ab, ac, bc];
        assert_ok!(Pallet::<Test>::generate_address(Origin::signed(who), scripts));
        assert!(AddrToScript::<Test>::contains_key(
            hex::decode("6263317067367a64793376706436723974777338386e687039703767616e33783232336a766432636b3871726b796a6776763673386e6771706a64327965")
                .unwrap()));
    });
}

#[test]
fn verify_signature_should_work() {
    new_test_ext().execute_with(|| {
        // https://github.com/chainx-org/threshold_signature/issues/1#issuecomment-909896156
        let who = 1;
        let abc = hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768").unwrap();
        let ab = hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861").unwrap();
        let ac = hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356").unwrap();
        let bc = hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b").unwrap();
        let scripts = vec![abc, ab.clone(), ac, bc];
        assert_ok!(Pallet::<Test>::generate_address(Origin::signed(who), scripts));

        let addr = hex::decode("6263317067367a64793376706436723974777338386e687039703767616e33783232336a766432636b3871726b796a6776763673386e6771706a64327965").unwrap();
        let signature_ab = hex::decode("7227f84f853853527488ba5b9939c56dd4ecd0ae96687e0d8d4d5da10cb4e6651cb2aca89236f3c3766d80e3b2ab37c74abb91ad6bb66677a0f1e3bd7e68118f").unwrap();
        let message = b"We are legion!".to_vec();
        assert_ok!(Pallet::<Test>::verify_threshold_signature(Origin::signed(who), addr, signature_ab, ab, message));
    });
}

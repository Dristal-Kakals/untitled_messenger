use um_crypto::{
    double_ratchet::RatchetSession,
    identity::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey},
    sender_keys::GroupSession,
    x3dh::{initiate, receive},
};

fn establish_pair() -> (RatchetSession, RatchetSession) {
    let bob = IdentityKey::generate();
    let spk = SignedPreKey::generate(1, &bob);
    let otpk = OneTimePreKey::generate(10);
    let bundle = PreKeyBundle::from_identity(&bob, &spk, &[&otpk]);
    let alice = IdentityKey::generate();

    let (init, init_msg) = initiate(&alice, &bundle, Some(10)).unwrap();
    let bob_init = receive(&bob, &spk, Some(&otpk), &init_msg).unwrap();

    let alice_r = RatchetSession::init_alice(&init).unwrap();
    let bob_r = RatchetSession::init_bob(&bob_init, &spk.priv_key).unwrap();
    (alice_r, bob_r)
}

#[test]
fn full_1to1_conversation_many_rounds() {
    let (mut alice, mut bob) = establish_pair();
    for i in 0..20u32 {
        let msg = format!("alice-{i}");
        let ct = alice.encrypt(msg.as_bytes()).unwrap();
        assert_eq!(bob.decrypt(&ct).unwrap(), msg.as_bytes());

        let msg = format!("bob-{i}");
        let ct = bob.encrypt(msg.as_bytes()).unwrap();
        assert_eq!(alice.decrypt(&ct).unwrap(), msg.as_bytes());
    }
}

#[test]
fn group_then_private_works_independently() {
    // Group session between alice and bob.
    let group = random_group_id();

    let alice_id = IdentityKey::generate();
    let bob_id = IdentityKey::generate();
    let mut ga = GroupSession::new(group, &alice_id).unwrap();
    let mut gb = GroupSession::new(group, &bob_id).unwrap();
    ga.add_peer(gb.export_self_state()).unwrap();
    gb.add_peer(ga.export_self_state()).unwrap();

    let gct = ga.encrypt(b"group msg").unwrap();
    assert_eq!(gb.decrypt(&gct).unwrap(), b"group msg");

    // Independent 1:1 session.
    let (mut a, mut b) = establish_pair();
    let ct = a.encrypt(b"private msg").unwrap();
    assert_eq!(b.decrypt(&ct).unwrap(), b"private msg");
}

fn random_group_id() -> [u8; 32] {
    let mut g = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut g);
    g
}

proptest::proptest! {
    #[test]
    fn prop_ratchet_roundtrip_random_plaintexts(
        pts in proptest::collection::vec("[a-z]{0,200}", 1..20)
    ) {
        let (mut alice, mut bob) = establish_pair();
        for p in &pts {
            let ct = alice.encrypt(p.as_bytes()).unwrap();
            let dec = bob.decrypt(&ct).unwrap();
            assert_eq!(dec, p.as_bytes());
        }
    }

    #[test]
    fn prop_ratchet_out_of_order_all_decrypt(
        // distinct plaintexts so we can identify each message
        n in 2u32..15u32
    ) {
        let (mut alice, mut bob) = establish_pair();
        let mut msgs: Vec<_> = (0..n)
            .map(|i| alice.encrypt(format!("m{i}").as_bytes()).unwrap())
            .collect();
        // Reverse the order.
        msgs.reverse();
        for ct in &msgs {
            let dec = bob.decrypt(ct).unwrap();
            assert!(dec.starts_with(b"m"));
        }
    }
}

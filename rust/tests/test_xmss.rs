#[test]
fn test_api() {
    let mut rng = rand::thread_rng();
    let seed = [0u8; 48];
    xmss::Xmss::new_key(xmss::XmssParams::Sha2_10_256, &seed);
}

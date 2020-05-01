use rand::rngs::OsRng;

use cpace;

#[test]
fn key_agreement() {
    let (init_msg, state) = cpace::init(
        "password",
        cpace::Context {
            initiator_id: "Alice",
            responder_id: "Bob",
            associated_data: b"",
        },
        OsRng,
    )
    .unwrap();

    let (bob_key, rsp_msg) = cpace::respond(
        init_msg,
        "password",
        cpace::Context {
            initiator_id: "Alice",
            responder_id: "Bob",
            associated_data: b"",
        },
        OsRng,
    )
    .unwrap();

    let alice_key = state.recv(rsp_msg).unwrap();

    assert_eq!(alice_key.0[..], bob_key.0[..]);
}

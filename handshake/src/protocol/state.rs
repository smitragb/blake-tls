#[derive(Debug, PartialEq)]
pub enum ClientHandshakeState {
    Start, 
    AwaitingServerHello,
    AwaitingServerInfo,
    AwaitingServerHelloDone,
    Finished,
}

pub enum ServerHandshakeState {
    AwaitingClientHello,
    AwaitingClientPreMasterKey,
    AwaitingClientKeyExchange,
    Finished,
}

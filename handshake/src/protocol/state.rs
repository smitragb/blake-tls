pub enum ClientHandshakeState {
    Start, 
    AwaitingServerHello,
    AwaitingServerInfo,
    AwaitingServerHelloDone,
}

pub enum ServerHandshakeState {
    Start,
    AwaitingClientHello,
    AwaitingClientPreMasterKey,
    AwaitingClientKeyExchange,
}

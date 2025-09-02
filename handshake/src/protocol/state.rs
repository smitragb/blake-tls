#[derive(Debug, PartialEq)]
pub enum ClientHandshakeState {
    Start, 
    AwaitingServerHello,
    AwaitingServerInfo,
    AwaitingServerHelloDone,
    SendingPublicKeyInfo,
    SendingFinished,
    AwaitingServerFinished,
    Finished,
}

pub enum ServerHandshakeState {
    AwaitingClientHello,
    SendingServerHello,
    SendingServerInfo,
    SendingServerHelloDone,
    AwaitingClientKeyExchange,
    AwaitingClientFinished,
    SendingFinished,
    Finished,
}

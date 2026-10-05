use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::Duration;

use babel_protocol::{
    decode_packet, encode_packets, Action, DecodeContext, Engine, EngineConfig, Event, RouteKey,
    RouterId, SelectedRoute,
};
use jni::objects::{JByteArray, JObject};
use jni::sys::{jboolean, jint};
use jni::JNIEnv;
use pktkit::slirp::Stack as UserSpaceGateway;
use pktkit::{IpPrefix, L3Device, Packet};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, ServerConfig, TokioRuntime, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tun_rs::AsyncDevice;

static STOP: AtomicBool = AtomicBool::new(false);
static RUSTLS_PROVIDER: Once = Once::new();
static BABEL_ENGINE: OnceLock<Mutex<Engine>> = OnceLock::new();
static PEER_SENDERS: OnceLock<Mutex<HashMap<String, mpsc::UnboundedSender<Frame>>>> =
    OnceLock::new();
static STOPPED_PEERS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static ROUTING_CLOCK: OnceLock<std::time::Instant> = OnceLock::new();
static GATEWAY_STACK: OnceLock<Arc<UserSpaceGateway>> = OnceLock::new();
static GATEWAY_PACKET_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
enum Frame {
    Ip(Vec<u8>),
    Babel(Vec<u8>),
}

#[link(name = "log")]
extern "C" {
    fn __android_log_write(priority: i32, tag: *const i8, text: *const i8) -> i32;
}

fn native_log(message: &str) {
    if let Ok(message) = CString::new(message) {
        unsafe {
            __android_log_write(4, c"AwareTun".as_ptr().cast(), message.as_ptr().cast());
        }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic payload")
}

#[derive(Debug)]
struct PrototypePeerVerifier;

impl ServerCertVerifier for PrototypePeerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Prototype only: QUIC encryption is enabled, but peer identities are not checked.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn overlay_address(id_bytes: [u8; 8]) -> Ipv6Addr {
    Ipv6Addr::new(
        0xfd71,
        0x6177,
        0,
        0,
        u16::from_be_bytes([id_bytes[0], id_bytes[1]]),
        u16::from_be_bytes([id_bytes[2], id_bytes[3]]),
        u16::from_be_bytes([id_bytes[4], id_bytes[5]]),
        u16::from_be_bytes([id_bytes[6], id_bytes[7]]),
    )
}

fn client_ipv4(id_bytes: [u8; 8]) -> Ipv4Addr {
    Ipv4Addr::new(10, 71, id_bytes[6] % 254 + 1, id_bytes[7] % 252 + 2)
}

fn routing_now_ms() -> u64 {
    ROUTING_CLOCK
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

fn babel_engine(id_bytes: [u8; 8], is_gateway: bool) -> Result<Engine, Box<dyn Error>> {
    let router_id =
        RouterId::new(id_bytes).ok_or_else(|| std::io::Error::other("invalid Babel router ID"))?;
    let mut engine = Engine::try_new(EngineConfig::recommended(router_id))?;
    let overlay = RouteKey::new(format!("{}/128", overlay_address(id_bytes)).parse()?, None)
        .ok_or_else(|| std::io::Error::other("invalid overlay prefix"))?;
    engine.try_handle(Event::Originate {
        key: overlay,
        metric: 0,
        now_ms: routing_now_ms(),
    })?;
    let client = RouteKey::new(format!("{}/32", client_ipv4(id_bytes)).parse()?, None)
        .ok_or_else(|| std::io::Error::other("invalid client IPv4 prefix"))?;
    engine.try_handle(Event::Originate {
        key: client,
        metric: 0,
        now_ms: routing_now_ms(),
    })?;
    if is_gateway {
        let gateway_address = RouteKey::new("10.71.0.1/32".parse()?, None)
            .ok_or_else(|| std::io::Error::other("invalid gateway address prefix"))?;
        engine.try_handle(Event::Originate {
            key: gateway_address,
            metric: 0,
            now_ms: routing_now_ms(),
        })?;
        let default_v4 = RouteKey::new("0.0.0.0/0".parse()?, None)
            .ok_or_else(|| std::io::Error::other("invalid IPv4 default route"))?;
        engine.try_handle(Event::Originate {
            key: default_v4,
            metric: 0,
            now_ms: routing_now_ms(),
        })?;
    }
    Ok(engine)
}

fn babel_state(
    id_bytes: [u8; 8],
    is_gateway: bool,
) -> Result<&'static Mutex<Engine>, Box<dyn Error>> {
    if let Some(engine) = BABEL_ENGINE.get() {
        return Ok(engine);
    }
    let engine = babel_engine(id_bytes, is_gateway)?;
    Ok(BABEL_ENGINE.get_or_init(|| Mutex::new(engine)))
}

fn peer_senders() -> &'static Mutex<HashMap<String, mpsc::UnboundedSender<Frame>>> {
    PEER_SENDERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn peer_key(id: [u8; 8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn peer_is_stopped(id: [u8; 8]) -> bool {
    STOPPED_PEERS
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .map(|peers| peers.contains(&peer_key(id)))
        .unwrap_or(true)
}

fn dispatch_babel_actions(actions: Vec<Action>) {
    for action in actions {
        if let Action::Send {
            interface, packet, ..
        } = action
        {
            match encode_packets(&packet, 1200) {
                Ok(datagrams) => {
                    if let Some(sender) = peer_senders()
                        .lock()
                        .ok()
                        .and_then(|peers| peers.get(&interface).cloned())
                    {
                        for datagram in datagrams {
                            let _ = sender.send(Frame::Babel(datagram));
                        }
                    }
                }
                Err(error) => native_log(&format!("Babel packet encoding failed: {error}")),
            }
        }
    }
}

fn prefix_route(destination: IpAddr) -> Option<SelectedRoute> {
    let engine = BABEL_ENGINE.get()?;
    let engine = engine.lock().ok()?;
    engine
        .selected_routes()
        .into_iter()
        .filter(|route| route.key.destination.contains(&destination))
        .max_by_key(|route| route.key.destination.prefix_len())
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).ok()?,
        ))),
        _ => None,
    }
}

fn decrement_hop_limit(packet: &mut [u8]) -> bool {
    match packet.first().map(|version| version >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || header_len > packet.len() || packet[8] <= 1 {
                return false;
            }
            packet[8] -= 1;
            packet[10] = 0;
            packet[11] = 0;
            let mut sum = 0u32;
            for bytes in packet[..header_len].chunks_exact(2) {
                sum += u32::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            true
        }
        Some(6) if packet.len() >= 40 && packet[7] > 1 => {
            packet[7] -= 1;
            true
        }
        _ => false,
    }
}

fn packet_is_ipv4(packet: &[u8]) -> bool {
    packet.first().is_some_and(|version| version >> 4 == 4)
}

fn is_mesh_ipv4(packet: &[u8]) -> bool {
    packet_destination(packet).is_some_and(|destination| match destination {
        IpAddr::V4(address) => address.octets()[0..2] == [10, 71],
        IpAddr::V6(_) => false,
    })
}

fn send_to_next_hop(mut packet: Vec<u8>) -> bool {
    let Some(destination) = packet_destination(&packet) else {
        return false;
    };
    if !decrement_hop_limit(&mut packet) {
        native_log("Dropping forwarded IP packet with an invalid or expired hop limit");
        return false;
    }
    let Some(route) = prefix_route(destination) else {
        return false;
    };
    let Some(sender) = peer_senders()
        .lock()
        .ok()
        .and_then(|peers| peers.get(&route.interface).cloned())
    else {
        return false;
    };
    sender.send(Frame::Ip(packet)).is_ok()
}

fn user_space_gateway() -> Arc<UserSpaceGateway> {
    GATEWAY_STACK
        .get_or_init(|| {
            let stack = UserSpaceGateway::new();
            stack
                .set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 71, 0, 1)), 16))
                .expect("fixed gateway address is valid");
            stack.set_handler(Arc::new(|packet: &Packet| {
                let count = GATEWAY_PACKET_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if count <= 10 {
                    native_log(&format!(
                        "User-space gateway produced packet {count}: {} bytes",
                        packet.as_bytes().len()
                    ));
                }
                if send_to_next_hop(packet.as_bytes().to_vec()) {
                    Ok(())
                } else {
                    Err(std::io::Error::other(
                        "no Babel return route for gateway packet",
                    ))
                }
            }));
            stack
        })
        .clone()
}

fn attach_babel_interface(interface: &str, local_id: [u8; 8]) {
    if let Some(engine) = BABEL_ENGINE.get() {
        if let Ok(mut engine) = engine.lock() {
            let actions = engine
                .try_handle(Event::InterfaceUp {
                    interface: interface.to_owned(),
                    local_addresses: vec![
                        IpAddr::V6(overlay_address(local_id)),
                        IpAddr::V4(client_ipv4(local_id)),
                    ],
                    now_ms: routing_now_ms(),
                })
                .unwrap_or_default();
            dispatch_babel_actions(actions);
        }
    }
}

fn quic_configs() -> Result<(ServerConfig, ClientConfig), Box<dyn Error>> {
    // Quinn enables Rustls without selecting a process-wide crypto provider. Select
    // the ring provider before Rustls builds either TLS config; otherwise it panics.
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    let cert = rcgen::generate_simple_self_signed(vec!["awaretun".to_owned()])?;
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    // The Aware firmware can retire an otherwise idle data path. QUIC PINGs keep
    // the negotiated connection active while no user packets are crossing the tunnel.
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    let transport = Arc::new(transport);

    let mut server = ServerConfig::with_single_cert(vec![cert_der], key)?;
    server.transport_config(Arc::clone(&transport));
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PrototypePeerVerifier))
        .with_no_client_auth();
    let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    client.transport_config(transport);
    Ok((server, client))
}

async fn bridge_packets(
    connection: quinn::Connection,
    tun: Arc<AsyncDevice>,
    is_gateway: bool,
    local_id: [u8; 8],
    remote_id: [u8; 8],
) {
    // Quinn does not expose an opened stream to the peer until its sender writes
    // data. Send a small stream preface before waiting for the peer's stream;
    // otherwise both peers wait in accept_bi forever after the QUIC handshake.
    let (mut send, _) = match connection.open_bi().await {
        Ok(stream) => stream,
        Err(error) => {
            native_log(&format!("AwareTun QUIC stream open failed: {error}"));
            return;
        }
    };
    if let Err(error) = send.write_all(b"ATUN").await {
        native_log(&format!(
            "AwareTun QUIC stream preface send failed: {error}"
        ));
        return;
    }
    let (_, mut receive) = match connection.accept_bi().await {
        Ok(stream) => stream,
        Err(error) => {
            native_log(&format!("AwareTun QUIC peer stream accept failed: {error}"));
            return;
        }
    };
    let mut preface = [0u8; 4];
    if let Err(error) = receive.read_exact(&mut preface).await {
        native_log(&format!(
            "AwareTun QUIC stream preface read failed: {error}"
        ));
        return;
    }
    if &preface != b"ATUN" {
        native_log("AwareTun QUIC peer sent an invalid stream preface");
        return;
    }

    let interface = remote_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let remote_address = IpAddr::V6(overlay_address(remote_id));
    let local_overlay = IpAddr::V6(overlay_address(local_id));
    let local_ipv4 = IpAddr::V4(client_ipv4(local_id));
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Frame>();
    if let Ok(mut peers) = peer_senders().lock() {
        peers.insert(interface.clone(), outbound_tx);
    }
    attach_babel_interface(&interface, local_id);

    let gateway = is_gateway.then(user_space_gateway);
    native_log(&format!("QUIC packet bridge active; gateway={is_gateway}"));

    let writer_tun = tun.clone();
    let writer_gateway = gateway.clone();
    let writer = tokio::spawn(async move {
        let mut packet = vec![0u8; 65_535];
        let mut packet_count = 0usize;
        loop {
            let frame = tokio::select! {
                result = writer_tun.recv(&mut packet) => {
                    let size = result.map_err(|error| error.to_string())?;
                    let outgoing = packet[..size].to_vec();
                    if packet_destination(&outgoing) == Some(local_overlay) || packet_destination(&outgoing) == Some(local_ipv4) {
                        continue;
                    }
                    if is_gateway && packet_is_ipv4(&outgoing) && !is_mesh_ipv4(&outgoing) {
                        if let Some(gateway) = &writer_gateway {
                            gateway.send(Packet::from_slice(&outgoing)).map_err(|error| error.to_string())?;
                            continue;
                        }
                    }
                    if send_to_next_hop(outgoing.clone()) { continue; }
                    native_log("No Babel route for packet read from VPN interface");
                    continue;
                }
                frame = outbound_rx.recv() => {
                    frame.ok_or_else(|| "peer forwarding channel stopped".to_owned())?
                }
            };
            packet_count += 1;
            let (kind, outgoing) = match frame {
                Frame::Ip(bytes) => (1u8, bytes),
                Frame::Babel(bytes) => (2u8, bytes),
            };
            let mut framed = Vec::with_capacity(outgoing.len() + 1);
            framed.push(kind);
            framed.extend_from_slice(&outgoing);
            if packet_count <= 10 && kind == 1 {
                native_log(&format!(
                    "QUIC routed packet {packet_count}: {} bytes",
                    outgoing.len()
                ));
            }
            send.write_u32(framed.len() as u32)
                .await
                .map_err(|error| error.to_string())?;
            send.write_all(&framed)
                .await
                .map_err(|error| error.to_string())?;
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    });

    let reader_tun = tun.clone();
    let reader_interface = interface.clone();
    let reader_gateway = is_gateway;
    let reader_local_overlay = local_overlay;
    let reader_local_ipv4 = local_ipv4;
    let reader = tokio::spawn(async move {
        loop {
            let size = receive
                .read_u32()
                .await
                .map_err(|error| error.to_string())? as usize;
            if size == 0 || size > 65_535 {
                return Err("bad packet frame".to_owned());
            }
            let mut framed = vec![0u8; size];
            receive
                .read_exact(&mut framed)
                .await
                .map_err(|error| error.to_string())?;
            if framed.is_empty() {
                return Err("empty frame".to_owned());
            }
            match framed[0] {
                1 => {
                    let packet = framed[1..].to_vec();
                    let destination = packet_destination(&packet);
                    let reaches_gateway =
                        destination == Some(IpAddr::V4(Ipv4Addr::new(10, 71, 0, 1)));
                    if reader_gateway
                        && packet_is_ipv4(&packet)
                        && (reaches_gateway || !is_mesh_ipv4(&packet))
                    {
                        if let Some(gateway) = &gateway {
                            let mut forwarded = packet;
                            if !decrement_hop_limit(&mut forwarded) {
                                native_log("Dropping gateway packet with an expired IPv4 TTL");
                                continue;
                            }
                            gateway
                                .send(Packet::from_slice(&forwarded))
                                .map_err(|error| error.to_string())?;
                            continue;
                        }
                    }
                    if packet_destination(&packet) == Some(reader_local_overlay)
                        || packet_destination(&packet) == Some(reader_local_ipv4)
                    {
                        reader_tun
                            .send(&packet)
                            .await
                            .map_err(|error| error.to_string())?;
                    } else if !send_to_next_hop(packet) {
                        native_log("No Babel route for packet received from peer");
                    }
                }
                2 => {
                    let packet = decode_packet(
                        &framed[1..],
                        DecodeContext {
                            source: remote_address,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                    if let Some(engine) = BABEL_ENGINE.get() {
                        let mut engine = engine.lock().map_err(|_| "Babel engine lock poisoned")?;
                        let actions = engine
                            .try_handle(Event::PacketReceived {
                                interface: reader_interface.clone(),
                                source: remote_address,
                                packet,
                                now_ms: routing_now_ms(),
                            })
                            .map_err(|error| error.to_string())?;
                        let selected = engine.selected_routes();
                        if !selected.is_empty() {
                            native_log(&format!(
                                "Babel selected {} overlay routes",
                                selected.len()
                            ));
                        }
                        drop(engine);
                        dispatch_babel_actions(actions);
                    }
                }
                _ => return Err("unknown tunnel frame type".to_owned()),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    });

    tokio::select! {
        result = writer => {
            if let Err(error) = result {
                native_log(&format!("QUIC packet writer stopped: {error}"));
            }
        },
        result = reader => {
            if let Err(error) = result {
                native_log(&format!("QUIC packet reader stopped: {error}"));
            }
        },
    }
    if let Some(engine) = BABEL_ENGINE.get() {
        if let Ok(mut engine) = engine.lock() {
            let actions = engine
                .try_handle(Event::InterfaceDown {
                    interface: interface.clone(),
                    now_ms: routing_now_ms(),
                })
                .unwrap_or_default();
            dispatch_babel_actions(actions);
        }
    }
    if let Ok(mut peers) = peer_senders().lock() {
        peers.remove(&interface);
    }
    connection.close(0u32.into(), b"packet bridge stopped");
}

fn run_transport(
    tun_fd: jint,
    udp_fd: jint,
    peer_bytes: [u8; 16],
    local_node_id: [u8; 8],
    remote_node_id: [u8; 8],
    scope_id: jint,
    port: jint,
    should_dial: bool,
    is_gateway: bool,
) -> Result<(), Box<dyn Error>> {
    if let Ok(mut peers) = STOPPED_PEERS
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
    {
        peers.remove(&peer_key(remote_node_id));
    }
    // The UDP descriptor is already bound to the Aware Network by Android.
    let udp = unsafe { UdpSocket::from_raw_fd(udp_fd) };
    udp.set_nonblocking(true)?;
    native_log(&format!("QUIC UDP local socket: {}", udp.local_addr()?));
    let peer = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(peer_bytes),
        port as u16,
        0,
        scope_id as u32,
    ));
    native_log(&format!(
        "Starting QUIC endpoint: peer={peer}, dial={should_dial}"
    ));
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    native_log("Native transport runtime is ready");
    tokio_runtime.block_on(async {
        let _babel = babel_state(local_node_id, is_gateway)?;
        // AsyncDevice registers the TUN descriptor with Tokio, so create it from inside
        // the runtime rather than before the runtime starts.
        native_log("Registering VPN packet device with Tokio");
        let tun = Arc::new(unsafe { AsyncDevice::from_fd(tun_fd)? });
        native_log("VPN packet device registered with Tokio");
        let runtime = Arc::new(TokioRuntime);
        let (server_config, client_config) = quic_configs()?;
        native_log("Creating QUIC endpoint");
        let endpoint_result = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            udp,
            runtime.clone(),
        );
        let mut endpoint = match endpoint_result {
            Ok(endpoint) => endpoint,
            Err(error) => {
                native_log(&format!("QUIC endpoint setup failed: {error}"));
                return Err(error.into());
            }
        };
        native_log(&format!("QUIC endpoint listening: {}", endpoint.local_addr()?));
        endpoint.set_default_client_config(client_config);

        if should_dial {
            let endpoint = endpoint.clone();
            let tun = tun.clone();
            tokio::spawn(async move {
                match endpoint.connect(peer, "awaretun") {
                    Ok(connecting) => match connecting.await {
                        Ok(connection) => {
                            native_log("QUIC dial connected");
                            bridge_packets(connection, tun, is_gateway, local_node_id, remote_node_id).await
                        }
                        Err(error) => native_log(&format!("QUIC connection failed: {error}")),
                    },
                    Err(error) => native_log(&format!("QUIC dial failed: {error}")),
                }
            });
        }

        let mut stop_tick = tokio::time::interval(Duration::from_millis(200));
        stop_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = stop_tick.tick() => {
                    if STOP.load(Ordering::SeqCst) || peer_is_stopped(remote_node_id) { break; }
                    if let Some(engine) = BABEL_ENGINE.get() {
                        if let Ok(mut engine) = engine.lock() {
                            if let Ok(actions) = engine.try_handle(Event::Tick { now_ms: routing_now_ms() }) {
                                dispatch_babel_actions(actions);
                            }
                        }
                    }
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };
                    let tun = tun.clone();
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            native_log("QUIC incoming connection accepted");
                            bridge_packets(connection, tun, is_gateway, local_node_id, remote_node_id).await;
                        } else {
                            native_log("QUIC incoming handshake failed");
                        }
                    });
                }
            }
        }
        endpoint.close(0u32.into(), b"service stopped");
        endpoint.wait_idle().await;
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_dev_awaretun_NativeCore_start(
    env: JNIEnv,
    _receiver: JObject,
    tun_fd: jint,
    udp_fd: jint,
    peer_address: JByteArray,
    local_node_id: JByteArray,
    remote_node_id: JByteArray,
    scope_id: jint,
    port: jint,
    should_dial: jboolean,
    is_gateway: jboolean,
) {
    STOP.store(false, Ordering::SeqCst);
    let peer_bytes = match env.convert_byte_array(&peer_address) {
        Ok(bytes) if bytes.len() == 16 => bytes.try_into().expect("checked IPv6 address length"),
        _ => return,
    };
    let local_node_id = match env.convert_byte_array(&local_node_id) {
        Ok(bytes) if bytes.len() == 8 => bytes.try_into().expect("checked node ID length"),
        _ => return,
    };
    let remote_node_id = match env.convert_byte_array(&remote_node_id) {
        Ok(bytes) if bytes.len() == 8 => bytes.try_into().expect("checked node ID length"),
        _ => return,
    };
    let result = std::panic::catch_unwind(|| {
        run_transport(
            tun_fd,
            udp_fd,
            peer_bytes,
            local_node_id,
            remote_node_id,
            scope_id,
            port,
            should_dial != 0,
            is_gateway != 0,
        )
    });
    match result {
        Ok(Ok(())) => native_log("Native transport stopped"),
        Ok(Err(error)) => native_log(&format!("Native transport setup failed: {error}")),
        Err(error) => native_log(&format!(
            "Native transport panicked: {}; backtrace={}",
            panic_message(error.as_ref()),
            std::backtrace::Backtrace::force_capture()
        )),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_awaretun_NativeCore_removePeer(
    env: JNIEnv,
    _receiver: JObject,
    remote_node_id: JByteArray,
) {
    let Ok(bytes) = env.convert_byte_array(&remote_node_id) else {
        return;
    };
    let Ok(id): Result<[u8; 8], _> = bytes.try_into() else {
        return;
    };
    if let Ok(mut peers) = STOPPED_PEERS
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
    {
        peers.insert(peer_key(id));
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_awaretun_NativeCore_stop(_env: JNIEnv, _receiver: JObject) {
    STOP.store(true, Ordering::SeqCst);
}

# AwareTun prototype

An Android Wi-Fi Aware peer-link prototype with a Rust packet tunnel core. Both devices run the app, advertise/subscribe to the same service, request an Aware data path, and establish a QUIC connection over the scoped IPv6 link-local address.

## Current scope

- Android `WifiAwareManager` discovery and `ConnectivityManager` peer network requests.
- Android `VpnService` TUN descriptor passed into Rust through JNI and wrapped by `tun-rs`.
- IPv6 UDP sockets bound to each Aware `Network`, using UDP port `4242` per link.
- Quinn QUIC bidirectional stream framing for TUN packets.
- A shared Rust `babel-protocol` engine exchanges Babel control packets with each live peer over its QUIC link, learns routes, and selects the next peer for each IPv4 or IPv6 packet.
- Routers originate their overlay IPv6 address and private client IPv4 address; a router with validated Internet access also advertises an IPv4 default route.
- The VPN routes the `fd71:6177::/48` overlay through Babel. Non-exit phones add an IPv4 default route when a peer link comes up, allowing Babel to find an Internet exit through multiple relays.
- Relays forward IP packets over the selected peer link and decrement IPv4 TTL or IPv6 Hop Limit. The exit feeds IPv4 Internet packets into `pktkit::slirp`, which handles TCP/UDP flows in userspace and opens ordinary outbound sockets on the exit phone.
- HTTP/1.1 and HTTP/3 need no protocol-specific handling in the tunnel: their TCP/UDP packets are carried as IP packets. HTTP/3 currently shares a reliable QUIC stream with other packets, so loss can cause head-of-line blocking.

This version supports multi-hop routing for overlay IPv6 addresses and IPv4 traffic to a Babel-advertised Internet exit. Public IPv6 Internet egress is not implemented: the exit userspace gateway currently handles IPv4 only. Babel control packets share the reliable QUIC stream with IP data, so control traffic can be delayed behind packet loss. The exit uses Rust [`pktkit::slirp`](https://docs.rs/pktkit/latest/pktkit/slirp/) instead of Android kernel NAT rules. Peer authentication is not implemented.

QUIC uses TLS encryption but an intentionally permissive certificate verifier. Do not use this build on an untrusted network or route sensitive traffic through it. Add peer identity verification before treating it as a VPN.

## Build prerequisites

- Android Studio with Android SDK 36 and JDK 17.
- Gradle 8.11 or later.
- Rust 1.90 or later, Android Rust targets, and `cargo-ndk`.
- Android 12 or later on physical devices with Wi-Fi Aware support. Emulators generally cannot validate the Aware data path. Android 11 and earlier are blocked by a platform crash while decoding Aware network information.

Install Rust tooling and targets:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
```

Open this directory in Android Studio and run the `app` configuration, or build a debug APK with:

```sh
gradle :app:assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`. Install it on each physical device (Android 12+, with Wi-Fi Aware support), grant Nearby Wi-Fi and VPN permissions, and tap **Start peer discovery** on each. Keep the apps in the foreground for the prototype. The app displays each phone's stable overlay address; exchange those addresses between phones.

For example, with both phones connected over ADB, install the same APK using their serials:

```sh
adb -s PHONE_ONE install -r app/build/outputs/apk/debug/app-debug.apk
adb -s PHONE_TWO install -r app/build/outputs/apk/debug/app-debug.apk
```

Start discovery on each phone. Routers with a validated Internet connection advertise an IPv4 default route; Babel propagates it through connected relays. A phone without Internet access installs an IPv4 default route into the VPN and forwards traffic along the best learned route. Open a browser on that phone to check HTTP or HTTPS access. HTTP/3 may be used by compatible sites, but its packets and Babel control share reliable QUIC streams and can be delayed by packet loss. A two-phone single-hop setup was verified earlier; this multi-hop routing change has been build-verified but needs a three-phone topology for on-device verification. Inspect `adb -s PHONE_ONE logcat -s AwareTun` and the foreground notification if the Aware path does not come up.

## Design notes

- Aware supplies a scoped link-local IPv6 peer address. The app binds the UDP socket to the returned `Network` before handing its duplicated descriptor to Quinn.
- The prototype uses a fixed local UDP port for each Aware-bound socket and can hold multiple peer links per device.
- The VPN installs `fd71:6177::/48` for overlay IPv6 destinations. It adds the IPv4 default route on non-exit devices after an Aware peer link is established; Babel chooses whether the packet can reach an Internet exit.
- The exit stack opens normal TCP and UDP sockets through Android's default network. The exit phone keeps its own default routes outside the VPN, preventing those sockets from looping back into the tunnel.
- Babel state is shared across Aware links in the Rust process. Control frames are carried point-to-point over each QUIC link rather than sent as UDP multicast.

## License

AwareTun is licensed under the MIT License. Copyright (c) 2026 AwareTun
contributors. See [LICENSE](LICENSE) for the complete license text.

# Contributing

Thanks for your interest in AwareTun. This is an experimental Android and Rust
prototype, so reports that include device models, Android versions, and logs are
especially useful.

## Before opening a change

- Search existing issues before filing a new one.
- For behavior changes, describe the devices and topology used to verify them.
- Keep changes focused and update the README when setup steps, supported
  devices, or known limitations change.
- Do not include private keys, personal data, or unredacted device logs.

## Build

See the README for Android, Gradle, and Rust prerequisites. Build the app with:

```sh
gradle :app:assembleDebug
```

Hardware-dependent Wi-Fi Aware behavior should be described separately from
build results; emulators generally cannot validate the Aware data path.

## Pull requests

Explain the user-visible change, how it was checked, and any known limitations.
Keep unrelated cleanup out of the change so it is easier to review.

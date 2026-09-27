# Contributing

Thanks for looking. A few rules keep this project trustworthy.

## Before you send code

```bash
make test     # gofmt check, go vet, go test (stdlib build, works offline)
make race     # go test -race ./...
```

If you touched anything under a build tag (`nknsdk`, `libp2pdht`):

```bash
make deps
go vet -tags "nknsdk libp2pdht" ./...
```

## Rules the code already follows — please keep them

1. **No cryptography of our own.** WireGuard encrypts; Ed25519/HMAC-SHA256 from
   the standard library sign and prove. Nothing else.
2. **Data plane first.** "Is this tunnel working" is answered from `wg show`,
   never from the control plane. A control-plane outage must not tear down a
   working tunnel.
3. **Everything from the network is untrusted** until it passes the one
   verification path for its kind (`ingestRecord`, `Dispatcher.Dispatch`).
   Do not add a second one.
4. **Bounded everything.** Every retry has a limit or a backoff with jitter;
   every cache has a cap; every goroutine is started with `Controller.spawn`
   (or equivalent) and exits on context cancellation.
5. **No secrets in logs, config, API responses or diagnostics.**
6. **No shell.** External commands are argument vectors.
7. **Standard library in the default build.** New third-party dependencies go
   behind a build tag, with a reason.
8. **Honest status.** Do not report "connected" unless a handshake was seen.
   Do not claim symmetric NAT traversal, anonymity, or 100 % P2P.

## Protocol changes

Anything that changes bytes on the wire or on disk needs a note in
[docs/PROTOCOL.md](docs/PROTOCOL.md) and must stay readable by the previous
version, or bump `protocol.Version` and keep `MinVersion` honest.

## Commits

Small and focused, conventional prefixes (`feat(nat):`, `fix(mesh):`,
`docs:`). Include a test for every behaviour change.

## License

By contributing you agree your contribution is licensed under Apache-2.0.

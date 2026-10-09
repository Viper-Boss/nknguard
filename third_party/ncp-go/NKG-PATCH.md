# NKNGuard compatibility patch

Based on ncp-go v1.0.5. Original Apache 2.0 licence and source notices are retained.

The optional `Config.FullMesh` creates at most 4 x 4 logical channel pairs
instead of zipping local and remote subclient lists by position. A NAS with
three subclients must not exclude a phone's only working fourth subclient.
Packets still use one NCP connection at a time; data is not broadcast to all
pairs. NCP's existing acknowledgements, windows and retransmissions remain.
Handshake routing snapshots, window reads and retransmission-timeout reads
now use the existing locks, addressing races exposed by the asymmetric-path
regression test.

The default is unchanged. NKNGuard's opt-in SDK compatibility configuration
enables this option. Legacy peers can still exchange data on their original
paired channels; upgraded peers can use any surviving pair. This does not
guarantee delivery if all NKN routes are unreachable.

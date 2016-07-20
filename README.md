# silk-twoway-fast
Modified twoway packlogic for Silk for large number of IP netblocks

The twoway packlogic shipped with Silk is not particularly efficient when you have a large number of netblocks.

eg where P1-P4 are probes from core routers on a large network providing connectivity to a number of offices where in/out interfaces can not be used to discriminate.
```
sensor OFFICE1
netflow-v5-probes P1,P2,P3,P4
internal-ipblocks 192.168.1.0/24,192.168.2.0/24
external-ipblocks remainder
discard-unless any-ipblock 192.168.1.0/24,192.168.2.0/24
end sensor

.
.
.

sensor OFFICE127
netflow-v5-probes P1,P2,P3,P4
internal-ipblocks 192.168.253.0/24,192.168.254.0/24
external-ipblocks remainder
discard-unless any-ipblock 192.168.253.0/24,192.168.254.0/24
end sensor
```

For each netflow record the packlogic attempts to match each sip and dip against every sensor in turn, which can quite CPU intensive.

This revised packlogic makes use of a Patricia trie (c code as used by Net::Patricia) to match the flow record with the correct sensor.  For flows between a sip and dip where both are defined as internal on different sensors the sip takes priority.

Code is quite rough in places.  This was really written to prove the concept.


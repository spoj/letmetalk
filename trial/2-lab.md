# Lab results

Written by `lab/run.sh`. The roles are stand-ins until the bench lands: each row checks the NAT and then that
both peers log in through it and the dialer relays over UDP and TLS. Not measurements.

| pair | profile | NAT a | NAT b | dialer relay (udp, tls 443) | accepter ICE URLs |
|---|---|---|---|---|---|
| none-none | wan | none | none | ok, ok | 2 |
| none-pr | wan | none | pr | ok, ok | 2 |
| none-sym | wan | none | sym | ok, ok | 2 |
| eif-none | wan | eif | none | ok, ok | 2 |
| eif-pr | wan | eif | pr | ok, ok | 2 |
| eif-sym | wan | eif | sym | ok, ok | 2 |
| pr-pr | wan | pr | pr | ok, ok | 2 |
| pr-sym | wan | pr | sym | ok, ok | 2 |
| sym-sym | wan | sym | sym | ok, ok | 2 |
| blk-none | wan | blk | none | failed, ok | 2 |
| blk-eif | wan | blk | eif | failed, ok | 2 |
| blk-pr | wan | blk | pr | failed, ok | 2 |
| blk-sym | wan | blk | sym | failed, ok | 2 |
| same-host | lan | pr | pr | ok, ok | 2 |
| same-lan | lan | pr | pr | ok, ok | 2 |
| hairpin | wan | pr | pr | ok, ok | 2 |
| browser-none-pr | wan | none | pr | ok, ok | 2 |
| browser-eif-none | wan | eif | none | ok, ok | 2 |
| browser-eif-pr | wan | eif | pr | ok, ok | 2 |
| browser-pr-pr | wan | pr | pr | ok, ok | 2 |
| browser-pr-sym | wan | pr | sym | ok, ok | 2 |
| browser-sym-sym | wan | sym | sym | ok, ok | 2 |
| browser-blk-none | wan | blk | none | failed, ok | 2 |
| browser-blk-pr | wan | blk | pr | failed, ok | 2 |
| browser-blk-sym | wan | blk | sym | failed, ok | 2 |
| browser-pr-pr-b | wan | pr | pr | ok, ok | 2 |
| pr-pr-lan | lan | pr | pr | ok, ok | 2 |
| pr-pr-constrained | constrained | pr | pr | ok, ok | 2 |
| browser-pr-pr-lan | lan | pr | pr | ok, ok | 2 |

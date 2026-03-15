# slopq4 
Use case is to remove IRR prefix-list checking from NOS, while improving
security as RPKI unknown prefixes are also validated for correctness of IRR
route-object origin.

Unknown route-objects are synthesized via SLURM as RPKI valid.

RPKI valid which do not appear in AS-SET (e.g. AS-YTTI cannot advertise RPKI
valid Google) are dropped by verifying that origin in AS_PATH matches IRR data

WARNING: entirely LLM slopped POC 

## Junos example
```shell
policy-options {
    policy-statement DSS:OriginAS {
        term valid {
            from {
                as-path-origins as-list-group AS-DSS-ALL;
            }
            then next policy;
        }
        term invalid {
            then reject;
        }
    } 
    policy-statement RPKI {
        term valid {
           from {
               validation-database valid;
           }
           then next policy:
        term invalid {
           then reject; 
        }
    }
}
# DSS:OriginAS drops RPKI valid that is not in AS-SET, no prefix-check is needed
protocols bgp group X neighbor Y import [ DSS:OriginAS RPKI RestOfTheOwl ];
```
       
## Example run
400805 is invalid, because it doesn't originate any prefixes. This way no
matter how pathological AS-SET you encounter, the maximum length will be about
70k. This configuration will always commit on Junos and IOS-XR, so the few
AS-SET that are really poor quality are Internet problem, but won't stop you
from committing the config.
The slurmed data contains route objects that are unknown, and will be sent via
RTR to NOS

```shell
❯ cargo run AS-DSS-ALL  --nos junos,iosxr --slurm --audit
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.07s
     Running `/Users/ytti/code/slopq4/target/debug/slopq4 AS-DSS-ALL --nos junos,iosxr --slurm --audit`
[6 ASNs, 12 steps] ............
wrote AS-DSS-ALL.junos
wrote AS-DSS-ALL.iosxr
wrote AS-DSS-ALL.slurm.json
wrote AS-DSS-ALL.audit.json

❯ cat AS-DSS-ALL.junos
as-list-group AS-DSS-ALL {
    as-list l1 members 11251;
    as-list l2 members 22604;
    as-list l3 members 23286;
    as-list l4 members 23344;
    as-list l5 members 398849;
}

❯ cat AS-DSS-ALL.iosxr
as-set AS-DSS-ALL
  11251,
  22604,
  23286,
  23344,
  398849
end-set

❯ cat AS-DSS-ALL.audit.json
{
  "invalid_asns": [
    400805
  ],
  "invalid_prefixes": []
}

❯ head -n 18 AS-DSS-ALL.slurm.json
{
  "slurmVersion": 1,
  "validationOutputFilters": {
    "prefixFilters": [],
    "bgpsecFilters": []
  },
  "locallyAddedAssertions": {
    "prefixAssertions": [
      {
        "asn": 23286,
        "prefix": "199.200.48.0/22",
        "maxPrefixLength": 22
      },
      {
        "asn": 23286,
        "prefix": "199.200.48.0/23",
        "maxPrefixLength": 23
      },
```

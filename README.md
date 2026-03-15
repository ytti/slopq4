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
    policy-statement AS133469:OriginAS {
        term valid {
            from {
                as-path-origins as-list-group as133469:as-customers;
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
           then next policy;
        term invalid {
           then reject; 
        }
    }
}
# AS133469:OriginAS drops RPKI valid that is not in AS-SET, no prefix-check is needed
protocols bgp group AS133469 neighbor Y import [ AS133469:OriginAS RPKI RestOfTheOwl ];
```
       
## Example run
ASN is invalid, because it doesn't originate any prefixes. This way no
matter how pathological AS-SET you encounter, the maximum length will be about
70k. This configuration will always commit on Junos and IOS-XR, so the few
AS-SET that are really poor quality are Internet problem, but won't stop you
from committing the config.
The slurmed data contains route objects that are unknown, and will be sent via
RTR to NOS

```shell
❯ cargo run as133469:as-customers --nos junos,iosxr --slurm --audit
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running `/Users/ytti/code/slopq4/target/debug/slopq4 'as133469:as-customers' --nos junos,iosxr --slurm --audit`
[8 ASNs, 16 steps] ................
wrote as133469:as-customers.junos
wrote as133469:as-customers.iosxr
wrote as133469:as-customers.slurm.json
wrote as133469:as-customers.audit.json

❯ cat as133469:as-customers.junos
as-list-group as133469:as-customers {
    as-list l1 members 133469;
    as-list l2 members 134324;
    as-list l3 members 136328;
    as-list l4 members 136366;
}

❯ cat as133469:as-customers.iosxr
as-set as133469:as-customers
  133469,
  134324,
  136328,
  136366
end-set

❯ cat as133469:as-customers.audit.json
{
  "invalid_asns": [
    135725,
    135770,
    138263,
    138703
  ],
  "invalid_prefixes": []
}

❯ cat as133469:as-customers.slurm.json
{
  "slurmVersion": 1,
  "validationOutputFilters": {
    "prefixFilters": [],
    "bgpsecFilters": []
  },
  "locallyAddedAssertions": {
    "prefixAssertions": [
      {
        "asn": 136366,
        "prefix": "103.123.86.0/23",
        "maxPrefixLength": 23
      },
      {
        "asn": 136366,
        "prefix": "103.89.252.0/22",
        "maxPrefixLength": 22
      },
      {
        "asn": 136366,
        "prefix": "103.91.252.0/24",
        "maxPrefixLength": 24
      },
      {
        "asn": 136366,
        "prefix": "103.92.252.0/24",
        "maxPrefixLength": 24
      },
      {
        "asn": 136328,
        "prefix": "2407:68c0::/32",
        "maxPrefixLength": 32
      }
    ],
    "bgpsecAssertions": []
  }
}
```

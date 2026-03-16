# slopq4 
Use case is to remove IRR prefix-list checking from NOS, while improving
security as RPKI unknown prefixes are also validated for correctness of IRR
route-object origin.

Unknown route-objects are synthesized via SLURM as RPKI valid.

RPKI valid which do not appear in AS-SET (e.g. AS-YTTI cannot advertise RPKI
valid Google) are dropped by verifying that origin in AS_PATH matches IRR data

RPKI validation is done against rpki.json produced by rpki-client, this is
redundant against irrd4, as it already rejects invalids and returns validation
status on the route objects. If it is always redundant, it can be optimised
away.

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
       
## Example runs
ASN is invalid, because it doesn't originate any prefixes. This way no
matter how pathological AS-SET you encounter, the maximum length will be about
70k. This configuration will always commit on Junos and IOS-XR, so the few
AS-SET that are really poor quality are Internet problem, but won't stop you
from committing the config.
The slurmed data contains route objects that are unknown, and will be sent via
RTR to NOS


### NOS config and slurm, for neighbor prefix validation without prefix-list
By default we ignore valid prefixes, added here just for receiving audit count for them.
```shell
❯ cargo run as133469:as-customers --nos junos,iosxr --slurm --audit --valid-prefixes
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running `/Users/ytti/code/slopq4/target/debug/slopq4 'as133469:as-customers' --nos junos,iosxr --slurm --audit --valid-prefixes`
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
  "valid_asn_count": 4,
  "valid_prefix_count": 566,
  "unknown_prefix_count": 5,
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
### Default output with and without --valid-prefixes

Without valids:
```shell
❯ cargo run as133469:as-customers
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.07s
     Running `/Users/ytti/code/slopq4/target/debug/slopq4 'as133469:as-customers'`
[8 ASNs, 16 steps] ................
{
  "as_set": "as133469:as-customers",
  "as": {
    "valid": [
      133469,
      134324,
      136328,
      136366
    ],
    "invalid": [
      135725,
      135770,
      138263,
      138703
    ]
  },
  "prefix": {
    "valid": [],
    "unknown": [
      [
        "103.123.86.0/23",
        136366
      ],
      [
        "103.89.252.0/22",
        136366
      ],
      [
        "103.91.252.0/24",
        136366
      ],
      [
        "103.92.252.0/24",
        136366
      ],
      [
        "2407:68c0::/32",
        136328
      ]
    ],
    "invalid": []
  }
}%
```

With valids:
```shell
❯ cargo run as133469:as-customers --valid-prefixes > out
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.19s
     Running `/Users/ytti/code/slopq4/target/debug/slopq4 'as133469:as-customers' --valid-prefixes`
[8 ASNs, 16 steps] ................
{
  "as_set": "as133469:as-customers",
  "as": {
    "valid": [
      133469,
      134324,
      136328,
      136366
    ],
    "invalid": [
      135725,
      135770,
      138263,
      138703
    ]
  },
  "prefix": {
    "valid": [
      [
        "103.129.2.0/24",
        136328
      ],
      [
        "103.129.3.0/24",
        136328
      ],
      [
        "103.135.38.0/23",
        133469
      ],
      [
        "103.135.38.0/24",
        133469
      ],
      [
        "103.135.39.0/24",
        133469
      ],
...clipped...
      [
        "43.252.220.0/24",
        133469
      ],
      [
        "43.252.221.0/24",
        133469
      ]
    ],
    "unknown": [
      [
        "103.123.86.0/23",
        136366
      ],
      [
        "103.89.252.0/22",
        136366
      ],
      [
        "103.91.252.0/24",
        136366
      ],
      [
        "103.92.252.0/24",
        136366
      ],
      [
        "2407:68c0::/32",
        136328
      ]
    ],
    "invalid": []
  }
}
```

# PeeringDB Analysis 3.0

PeeringDB Analysis is a long-running project for ranking and analysing Internet Exchange Points using PeeringDB data. The public v2 code dates back to 28 February 2016. Version 3.0 is a complete rewrite in C focused on speed, compactness, historical analysis and future metrics.

Current version: **3.07**

## Files

- `peeringdb3.c` - single C source containing configuration parsing, HTTP access, JSON parsing, MariaDB access, import logic, history management and CLI commands.
- `peeringdb.conf` - runtime configuration for MariaDB and optional PeeringDB API key.
- `peeringdb3` - compiled executable.

## Database model

MariaDB database: `peeringdb`.

The current state is stored in compact tables used for fast analysis:

- `organization_current`
- `facility_current`
- `ix_current`
- `ixfac_current`
- `ixlan_current`
- `ixpfx_current`
- `network_current`
- `netfac_current`
- `netixlan_current`

Historical changes are stored in `object_history`. A new historical row is written only when a PeeringDB object changes. The full source JSON object is compressed and retained so future metrics can use fields that are not currently materialised in the `_current` tables. Historical validity is represented directly with `valid_from` and `valid_to`.

## Imported PeeringDB objects

The updater handles these PeeringDB API objects:

- `org`
- `fac`
- `ix`
- `ixfac`
- `ixlan`
- `ixpfx`
- `net`
- `netfac`
- `netixlan`

The API is queried with `depth=0`. Each object is hashed with SHA-256. Unchanged objects do not generate database writes or additional historical rows. Removed objects are removed from the corresponding `_current` table and their open history interval is closed.

## Configuration

`peeringdb.conf` uses simple `key=value` syntax:

```text
db_host=...
db_port=3306
db_user=...
db_pass=...
db_name=peeringdb
api_key=...
```

`api_key` is optional but recommended for automated PeeringDB API access.

## Commands

```text
./peeringdb3 dbcheck
./peeringdb3 status
./peeringdb3 update
./peeringdb3 generate <path>
```

- `dbcheck` verifies database connectivity and schema availability.
- `status` provides a concise database summary.
- `update` synchronises all configured PeeringDB object types.
- `generate <path>` creates a fully static HTML site in the selected directory. The current generator produces world rankings by members, total declared port speed, IPv4 speed, IPv6 speed, IPv6 member adoption, high-speed connections and facility footprint; ASN/member rankings are also generated for every country and continent present in the current data. A static detail page is generated for each Internet Exchange.


## Static output

The initial 3.0 presentation layer is deliberately static and contains no graphs or JavaScript. Each HTML file is self-contained, including its CSS.

Example:

```sh
./peeringdb3 generate /home/tools/mcp/work/peeringdb/test
```

Generated structure:

```text
index.html
rank/asn.html
rank/capacity.html
rank/ipv4.html
rank/ipv6.html
rank/ports.html
rank/facilities.html
country/<CC>.html
continent/<name>.html
ix/<peeringdb-id>.html
```

Version 3.04 modernises the v2 methodology. Only `netixlan` records with `status=ok`, `operational=true` and a positive declared speed are used. The historical 100 Mbps minimum and 10 Tbps maximum filters have been removed. Total declared port speed counts every qualifying connection once; IPv4 and IPv6 speed are protocol views and can overlap on dual-stack connections, so they must not be added together as physical capacity.

New current-state metrics include IPv4/IPv6 member counts, dual-stack members, operational connection count, average declared connection speed, 100G+/400G+/800G+ connection counts, facility footprint, peering LAN count and top-10 ASN share of declared speed. Individual IX pages show the top 20 ASN by declared speed, while global ranking tables remain limited to the top 10 for compactness. The generated site also includes lightweight static bar charts on the world ranking pages. A sticky header carries the project title, navigation and the data disclaimer on every page. Country and continent pages are created from the values actually present in PeeringDB rather than from a hard-coded list.

## Build

The program currently uses MariaDB Connector/C, libcurl, OpenSSL and zlib.

Example build command:

```sh
cc -O2 -Wall -Wextra -Werror -std=gnu89 peeringdb3.c -o peeringdb3 $(pkg-config --cflags --libs libmariadb libcurl openssl zlib)
```

## Design principles

- One C source file for the application.
- Minimal number of project files.
- Current-state tables optimised for fast rankings and reports.
- Historical storage grows with real changes, not with daily snapshots.
- Full source objects retained in compressed history for future metrics.
- No dependency on PeeringDB internal SQL schema.
- MariaDB used as the persistent data store.

## Next development

The current static generator includes the v2 ranking concepts plus modern current-state metrics and static charts. The next stage is to accumulate history and add change-oriented metrics such as growth, churn, historical ranking and network overlap once enough historical versions exist to make them meaningful.

## Version 3.06

Removed the redundant `Rankings` button from internal-page navigation. Internal pages now keep only the `Home` button in the sticky header.

## Version 3.07

The generated site now shows the full `3.xx` version in the sticky header, avoids duplicating the application name on the home page, and includes `gianluca@mazzini.org` in the persistent disclaimer.

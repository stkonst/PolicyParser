# Description
---
**LibRPSL** is a component of the *ENGRIT* project.

Given an Autonomous System it fetches the RPSL policy and resolves the export
and import filters. The result is an intermediate XML document that includes all
the necessary information (eg. peers, filters, prefix lists) to be used by other
parts of the *ENGRIT* project for creating the BGP configuration on the router(s).

*In order to fetch the required information, RIPE DB's API is used to collect
information from RIPE. For RPSL objects residing in other DBs (eg. ARIN) RIPE is
asked to provide the mirrored information it holds.*

# Dependencies and Requirements
---
Python(2) dependencies:
- requests
- xxhash
- gevent (Not required but will provide speedup and less memory consumption)

Install with:
`pip install -r requirements.txt`

# Usage
---
Librpsl is not meant to be used as a standalone tool as the resulting XML
document's format is to be used by the rest of the *ENGRIT* project.
However, one can run the tool for testing/debugging reasons with the following
parameters.

### Init flags and parameters
General usage:

`librpsl.py [-h] [-o OUTPUTFILE] [-b BLACKLIST] [-d] ASN`

- `ASN`
Autonomous System name in AS<number> format.

- `-o`
The name of the output file for exporting the XML policy.
An additional file (.log) will also be created containing the tool's log. It is
highly recommended to pass this parameter for cleaner reporting.

- `-b`
A comma separated list of AS numbers that can be excluded from the resolving.

- `-d`
Log additional debugging information.

### Usage example:
`python librpsl.py -b AS1234,AS5678 -o as3333.xml AS3333`

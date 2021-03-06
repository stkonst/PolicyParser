# Description
---
**PolicyParser** is a component of the *mantaBGP* project.

Given an Autonomous System it fetches the corresponding RPSL policy and 
resolves the export and import filters. The result is an intermediate 
XML or YAML document that includes all the necessary information 
(eg. peers, filters, prefix lists) to be used by other parts of the *mantaBGP* project
for creating the BGP configuration on the router(s).

*In order to fetch the required information, RIPE DB's API is used to collect
information from RIPE. For RPSL objects residing in other DBs (eg. ARIN) RIPE is
asked to provide the mirrored information it holds.*

# Dependencies and Requirements
---
Python(2) dependencies:
- requests
- PyYaml
- xxhash
- gevent (Not required but will provide speedup and less memory consumption)
- IPy

Install with:
`pip install -r requirements.txt`

# Usage
---
PolicyParser is meant to be used as the main input library of the *mantaBGP* project.
Additionally, the XML/YAML output is suitable to be integrated with other
automation tools either well known (e.g. Ansible) or custome made.
However, one can run the tool for testing/debugging reasons with the following
parameters.

### Init flags and parameters
General usage:

`libParser.py [-h] [-o OUTPUTFILE] [-b BLACKLIST] [-f FORMAT] [-d] [-r] [-a] ASN`

- `ASN`
Autonomous System name in AS<number> format.

- `-o`
The name of the output file for exporting the XML policy.
An additional file (.log) will also be created containing the tool's log. It is
highly recommended to pass this parameter for cleaner reporting.

- `-b`
A comma separated list of AS numbers that can be excluded from the resolving.

- `-r`
For the given AS number, return only is corresponding routes. It skips the 
filter resolving and and the policy sections. 

- `-f`
The format of the output file YAML|XML. If omitted, the default XML format will be used. 

- `-d`
Log additional debugging information.

- `-a`
Aggregate the routes of the prefix lists.

### Usage example:
`python libParser.py -b AS1234,AS5678 -o as3333 -f XML AS3333`

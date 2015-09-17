# bro-awk

### About

`bro-awk` is a way to parse and filter Bro Network Monitor logs with the ability to filter
the columns by the name of the Bro field, rather than the number of the column. This makes
it much more intuitive to use.

`bro-awk` also uses a parallel pipeline to split string processing across all available
processors, making it much faster at crunching through large gzipped logs.

### Installation

	go get github.com/compilewithstyle/bro-awk

### Usage

	USAGE:
		bro-awk [OPTIONS...] [FILTERS...] [LOGS...]

	OPTIONS:
		-d, --debug		turn on program debugging
		-p, --print_fields	only print the listed fields

	FILTER SYNTAX:
		[literal strings]
		<FIELD>=<VALUE>
		<FIELD>!=<VALUE>

		[regexes]
		<FIELD>~<VALUE>
		<FIELD!~<VALUE>>
	
The filter expressions take the form of <bro_field><operator><value>, where operator can be "=" for exactly equality or "~" for regex searching.
	
### Examples

Print all incoming port22 traffic into the wireless subnet 25 /24:

	`bro-awk conn.log local_orig=F id.resp_p=22 id.orig_h~^125\.252\.25\.`
	
Print the history column for all HTTP/S traffic:

	`bro-awk -p history conn.log id.orig_p,id.resp_p=80,443`
	
Print the line for any traffic on the 120 /24 where the connection ends in a F flag:

	`bro-awk $TESTLOG id.orig_h,id.resp_h~^128\.252\.120\. history~F$`



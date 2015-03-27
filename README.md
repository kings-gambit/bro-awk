# bro-blackbook

### About

`bro-awk` is a way to parse and filter Bro Network Monitor logs with the ability to filter
the columns by the name of the Bro field, rather than the number of the column. This makes
it much more intuitive to use.

`bro-awk` also uses a parallel pipeline to split string processing across all available
processors, making it much faster at crunching through large gzipped logs.

### Installation

	go get github.com/compilewithstyle/bro-awk

### Usage

__TODO__

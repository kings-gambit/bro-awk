/*
	Author:
		Nicholas Siow | compilewithstyle@gmail.com

	Description:
		Implements a fast awk-esque searching through Bro log files
		that allows you to filter the results by statements ... ?
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/compilewithstyle/bro-awk/qreader"
)

/*
	Prints a detail usage message showing how the script should be used
*/
func usage() {
	fmt.Println("USAGE:\n\tbro-awk [OPTIONS...] [FILTERS...] [LOGS...]\n")
	fmt.Println("OPTIONS:\n\t-d, --debug\t\tturn on program debugging")
	fmt.Println("\t-p, --print_fields\tonly print the listed fields\n")
	fmt.Println("FILTER SYNTAX:\n\t[literal strings]\n\t<FIELD>=<VALUE>\n\t<FIELD>!=<VALUE>\n\n\t[regexes]\n\t<FIELD>~<VALUE>\n\t<FIELD!~<VALUE>>\n")
	fmt.Println("EXAMPLES:\n\tTODO\n")
	os.Exit(1)
}

/*
	Parses user arguments so that they don't have to use command-line
	flags because those are so 1990s
*/

var log_re *regexp.Regexp = regexp.MustCompile(`.*\.log(?:\.gz)?$`)
var filter_re *regexp.Regexp = regexp.MustCompile(`^\S+(?:=|!=|~|!~)\S+$`)

func parse_args(args []string) ([]string, []string) {

	// make sure at least some arguments were supplied
	if len(args) == 1 {
		fmt.Println("[ERROR] not enough arguments")
		os.Exit(1)
	}

	// if not, then continue to parse the arguments, adding them
	// to the appropriate slices
	logs := make([]string, 0)
	filters := make([]string, 0)

	for _, arg := range args[1:] {
		if filter_re.MatchString(arg) {
			filters = append(filters, arg)
		} else if log_re.MatchString(arg) {
			logs = append(logs, arg)
		}
	}

	// make sure that some parameters were supplied for both logs and filters

	if len(logs) == 0 {
		fmt.Println("[ERROR] No logs specified. Use `bro-awk --help` for more info")
		os.Exit(1)
	}

	if len(filters) == 0 {
		fmt.Println("[ERROR] No filters specified. Use `bro-awk --help` for more info")
		os.Exit(1)
	}

	return logs, filters
}

/*
	Using the given arguments, construct the necessary filters and run them against the logs
*/
func main() {
	// first, check to see if usage string was requested
	for _, x := range os.Args {
		if x == "-h" || x == "--help" {
			usage()
		}
	}

	// next, parse the option flags
	print_fields := flag.String("p", "", "")
	flag.Parse()

	// next, parse through the remaining arguments to find user-supplied filters and logs
	logs, filters := parse_args(os.Args)

	// create a new Qreader:
	// 		unzipper, []string of filters, number of processors, reading blocksize
	q := qreader.NewQreader("", filters, 0, 0, *print_fields)

	// iterate through the logs and apply the filter to each of them
	for _, log := range logs {
		q.Parse(log)
	}
}

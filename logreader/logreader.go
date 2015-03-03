/*
	Author:
		Nicholas Siow | compilewithstyle@gmail.com

	Description:
		Super-fast gzip reader that uses goroutine pools to
		eliminate bottlenecks in filereading
*/

package logreader

import (
	"../filters"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

//--------------------------------------------------------------------------------
//	PROGRAM VARIABLES
//--------------------------------------------------------------------------------

var chansize int = 10000

//--------------------------------------------------------------------------------
//	READER
//--------------------------------------------------------------------------------

/*
	Reader class which handles the
*/
type Reader struct {
	filename string
	unzipper string
	bsize    int
	outq     chan []byte
}

/*
	Returns an appropriate io.Reader object based on whether or not
	the file is gzipped. Uses the `Unzipper` variable to determine
	which program to use in the case of a gzipped file
*/
func (self Reader) GetReader() io.Reader {
	if strings.HasSuffix(self.filename, ".gz") {

		// init a subprocess using the Unzipper command
		// TODO -- let the -c be an option
		c := exec.Command(self.unzipper, "-c", self.filename)
		pipe, err := c.StdoutPipe()
		if err != nil {
			panic(err)
		}

		// start the subprocess and return a reader connected to
		// its STDOUT
		c.Start()
		return pipe

	} else {

		// otherwise just open a file as normal and return
		// an io.Reader object for it
		file, err := os.Open(self.filename)
		if err != nil {
			panic(err)
		}

		return io.Reader(file)

	}
}

/*
	Begins to read from the given file and pushes data
	into a channel. Closes the channel upon EOF
*/
func (self Reader) Start() {
	// get an appropriate reader
	reader := self.GetReader()

	// initialize a byteslice for the partial lines
	// to be added to the following read chunk
	var leftovers []byte

	// loop until EOF
	for {
		// read in the next chunk
		buffer := make([]byte, self.bsize)
		length, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			panic(err)
		}

		// break if reading is done
		if length == 0 {
			break
		}

		// add partial line from previous chunk to beginning of this chunk
		// add partial line from this chunk to leftovers variable for next
		end_it := length - 1
		for {
			if end_it == 0 {
				leftovers = append(leftovers, buffer...)
				break
			}
			if buffer[end_it] == '\n' {
				leftovers = append(leftovers, buffer[:end_it]...)
				self.outq <- leftovers
				leftovers = buffer[end_it+1:]
				break
			} else {
				end_it -= 1
			}
		}
	}

	// close channel to let next worker know that you're done
	close(self.outq)
}

//--------------------------------------------------------------------------------
//	PARSER
//--------------------------------------------------------------------------------

/*
	Parser class which handles splitting data at newlines and separating
	out relevant data
*/
type Parser struct {
	filter  *filters.FilterSet
	limiter chan int
	inq     chan []byte
}

func (self Parser) Parse(fileslice []byte) {
	// split incoming byteslice @ newlines
	raw_lines := strings.Split(string(fileslice), "\n")

	for _, line := range raw_lines {
		// skip commented lines
		if line[0] == '#' {
			continue
		}

		// split on tabs to create Linedata object
		var ld filters.Linedata = strings.Split(line, "\t")
		if self.filter.Passes(&ld) {
			fmt.Println(line)
		}
	}

	<-self.limiter
}

func (self Parser) Start() {
	for fileslice := range self.inq {
		self.limiter <- 1
		go self.Parse(fileslice)
	}

	for {
		if len(self.limiter) == 0 {
			break
		} else {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

//--------------------------------------------------------------------------------
//	MAIN QREADER CLASS
//--------------------------------------------------------------------------------

type Qreader struct {
	Filename   string
	Unzipper   string
	ParserPool int
	Blocksize  int
	Filter     *filters.FilterSet
}

/*
	Struct initializer for QREADER
*/
func NewQreader(Unzipper string, filter_strings []string, ParserPool int, Blocksize int) *Qreader {
	// initialize a new, empty Qreader
	q := Qreader{}

	// set the unzipper, find one if not given
	if Unzipper == "" {
		Unzipper = FindUnzipper()
	}
	q.Unzipper = Unzipper

	// set the number of workers in the parser pool, use default if not given
	if ParserPool <= 0 {
		ParserPool = runtime.NumCPU() - 1
	}
	q.ParserPool = ParserPool

	// set the reading blocksize, use default if not given
	if Blocksize <= 0 {
		Blocksize = 8192
	}
	q.Blocksize = Blocksize

	// set the number of max concurrent goroutines
	runtime.GOMAXPROCS(runtime.NumCPU() - 1)

	// set up the filters
	q.Filter = filters.NewFilterSet(filter_strings)

	return &q
}

/*
	Function to find a program for gz decompression
*/
func FindUnzipper() string {
	possibilities := []string{"unpigz", "gzcat", "zcat"}

	for _, p := range possibilities {
		cmd, err := exec.LookPath(p)
		if err == nil {
			return cmd
		}
	}

	fmt.Println("[ERROR] could not find a program for gz decompression")
	os.Exit(1)
	return ""
}

/*
	Read in the bro log file up to the `#fields` line and find the names of the various fields
*/
func GetHeader(unzipper string, fn string) []string {
	cmdstring := fmt.Sprintf("%s -c %s | grep -m1 fields", unzipper, fn)
	cmd := exec.Command("bash", "-c", cmdstring)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}

	cmd.Start()

	field_string, err := ioutil.ReadAll(stdout)
	if err != nil {
		panic(err)
	}

	// to from 0:end-1 of the field string (to ignore newline)
	// then take 1:end to get everything except the '#fields' string
	return strings.Split(string(field_string[:len(field_string)-1]), "\t")[1:]
}

/*
	Set up the workers and read through a given file
*/
func (self Qreader) Parse(fn string) {
	// find the header for the bro file
	header := GetHeader(self.Unzipper, fn)

	// use the header and the filter strings to generate a FilterSet
	// TODO find a more elegant way of doing this??
	self.Filter.ApplyHeader(header)

	// create the necessary channels
	chan1 := make(chan []byte, chansize)

	// create buffered controller channels that can act as semaphores
	// to limit overall throughput
	limiter1 := make(chan int, self.ParserPool)

	// intialize the various worker objects
	r := Reader{fn, self.Unzipper, self.Blocksize, chan1}
	p := Parser{self.Filter, limiter1, chan1}

	// start each of the worker functions on its own goroutine
	go r.Start()
	p.Start()
}

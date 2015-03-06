package filters

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

/*
	global indexmap which allows mapping from field -> index in Linedata slice

	this allows us to pass around []string instead of map[string]string and just
	use this map to index into the given field
*/
var indexmap map[string]int

//--------------------------------------------------------------------------------
//	Linedata wrapper for []string
//--------------------------------------------------------------------------------

/* define a custom wrapper for []string that allows helper functions */
type Linedata []string

/*
	helper function that allows for easy indexing into a Linedata struct
	via the name of the field you're interested in
*/
func (self Linedata) get(field string) string {
	idx, ok := indexmap[field]
	if !ok {
		fmt.Printf("[ERROR] unable to find index for field: %s\n", field)
		fmt.Println("indexmap dump:")
		fmt.Println(indexmap)
		os.Exit(1)
	}

	return self[idx]
}

//--------------------------------------------------------------------------------
//	Single Filter class
//--------------------------------------------------------------------------------

/*
	Filter interface that allows agnostic treatment of string/regex based filters
*/
type BaseFilter interface {
	Passes(data *Linedata) bool
}

/*
	Filter struct that represents a single, non-regex rule
*/
type Filter struct {
	fields           []string
	values           []string
	compare_function func(a string, b string) bool
}

/*
	Filter struct that represents a single, regex-based rule
*/
type RegexFilter struct {
	fields           []string
	values           []*regexp.Regexp
	compare_function func(a string, re *regexp.Regexp) bool
}

/*
	Constructor for single filter type
	TODO check with regex or something to make sure it's a valid rule!
*/
func NewFilter(rule string) BaseFilter {
	// set the appropriate comparison function based on which
	// operator is given
	var op string
	var isregex, negate bool

	if strings.Contains(rule, "!=") {
		op = "!="
		negate = true
		isregex = false
	} else if strings.Contains(rule, "=") {
		op = "="
		negate = false
		isregex = false
	} else if strings.Contains(rule, "!~") {
		op = "!~"
		negate = true
		isregex = true
	} else if strings.Contains(rule, "~") {
		op = "~"
		negate = false
		isregex = true
	} else {
		fmt.Println("[ERROR] not sure how to parse rule: " + rule)
		os.Exit(1)
	}

	// split the rule into fields/values and set the appropriate fields
	// in the new filter
	opsides := strings.Split(rule, op)
	if len(opsides) != 2 {
		fmt.Println("[ERROR] rule contains too many boolean operators: " + rule)
		os.Exit(1)
	}

	fields := strings.Split(opsides[0], ",")
	values := strings.Split(opsides[1], ",")

	// choose the comparison operator based on whether or not to negate
	// the filter
	if isregex {
		f := &RegexFilter{}

		// compile the user-supplied regexes
		regex_values := make([]*regexp.Regexp, len(values))
		for i, v := range values {
			my_regex, err := regexp.Compile(v)
			if err != nil {
				fmt.Println("[ERROR] unable to compile POSIX regex: " + v)
				os.Exit(1)
			} else {
				regex_values[i] = my_regex
			}
		}

		// set the fields and values of the filter
		f.fields = fields
		f.values = regex_values

		// set the compare function based on whether or not negation should be used
		if negate {
			f.compare_function = func(a string, re *regexp.Regexp) bool {
				return !re.MatchString(a)
			}
		} else {
			f.compare_function = func(a string, re *regexp.Regexp) bool {
				return re.MatchString(a)
			}
		}

		return BaseFilter(f)
	} else {
		f := &Filter{}

		// set the fields and values of the filter
		f.fields = fields
		f.values = values

		// set the compare function based on whether or not negation should be used
		if negate {
			f.compare_function = func(a string, b string) bool {
				return (a != b)
			}
		} else {
			f.compare_function = func(a string, b string) bool {
				return (a == b)
			}
		}

		return BaseFilter(f)
	}
}

/*
	Determines whether or not that line passes based off the given filter
	TODO
*/
func (self Filter) Passes(data *Linedata) bool {
	for _, field := range self.fields {
		for _, value := range self.values {
			if !self.compare_function(data.get(field), value) {
				return false
			}
		}
	}

	return true
}

/*
	Determines whether or not that line passes based off the given filter
	TODO
*/
func (self RegexFilter) Passes(data *Linedata) bool {
	for _, field := range self.fields {
		for _, value := range self.values {
			if !self.compare_function(data.get(field), value) {
				return false
			}
		}
	}

	return true
}

//--------------------------------------------------------------------------------
//	Aggregate FilterSet class
//--------------------------------------------------------------------------------

/*
	Combined set of filters that can be used to match against a given line

	The line must match all contained filters in order for it to 'pass'
*/
type FilterSet struct {
	filters []BaseFilter
}

/*
	Helper function to set up the index map and turn string parameters
	into Filter objects
*/
func NewFilterSet(params []string) *FilterSet {
	fs := FilterSet{}
	fs.filters = make([]BaseFilter, len(params))

	for i, param_string := range params {
		fs.filters[i] = NewFilter(param_string)
	}

	return &fs
}

/*
	Function that creates the indexmap for these filters using the Bro
	header for a given file
*/
func (self FilterSet) ApplyHeader(header []string) {
	indexmap = make(map[string]int)

	for idx, field := range header {
		indexmap[field] = idx
	}
}

/*
	Official interface for Filter program -- test lines against
	this to determine whether or not they should be printed
*/
func (self FilterSet) Passes(data *Linedata) bool {
	for _, f := range self.filters {
		if !f.Passes(data) {
			return false
		}
	}

	return true
}

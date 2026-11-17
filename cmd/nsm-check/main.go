// Command nsm-check checks that the Nitro Security Module of the enclave it
// runs in behaves as the NSM API says it should. It follows nsm-check from
// aws-nitro-enclaves-nsm-api.
//
// By default it only reads from the NSM. With -pcr-writes it also extends and
// locks PCRs, which stay that way until the enclave terminates.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/pkilar/nitro-enclaves-sdk-go/internal/nsmcheck"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
)

// Exit codes.
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

// passedLine is the last line of a run in which every check passed. An
// enclave has no exit code to give its parent, so the Makefile's run target
// looks for this line in the enclave's console output.
const passedLine = "nsm-check: all checks passed"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run checks the NSM of the enclave this process runs in.
func run(args []string, stdout, stderr io.Writer) int {
	return runWith(nsm.Open, args, stdout, stderr)
}

// runWith parses args, opens the NSM with open, runs the checks and returns
// the exit code.
func runWith(open func() (*nsm.Session, error), args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("nsm-check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	pcrWrites := flags.Bool("pcr-writes", false,
		"also extend and lock PCRs; the changes last until the enclave terminates")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	session, err := open()
	if err != nil {
		return fail(stderr, err)
	}

	err = nsmcheck.Run(session, stdout, nsmcheck.Options{PCRWrites: *pcrWrites})
	if err := errors.Join(err, session.Close()); err != nil {
		return fail(stderr, err)
	}
	if _, err := fmt.Fprintln(stdout, passedLine); err != nil {
		return fail(stderr, err)
	}

	return exitOK
}

// fail reports err and returns the failure exit code.
func fail(stderr io.Writer, err error) int {
	// There is nowhere left to report a failure to write to stderr.
	_, _ = fmt.Fprintf(stderr, "nsm-check: %v\n", err)

	return exitFailed
}

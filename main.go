package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"

	p "github.com/lair-framework/drone-nmap/project"
	"github.com/lair-framework/go-nmap"
)

const (
	version = "2.1.1"
	usage   = `
Parses an nmap XML file into a lair project.

Usage:
  drone-nmap [options] <id> <filename>
  export LAIR_ID=<id>; drone-nmap [options] <filename>
Options:
  -v              show version and exit
  -h              show usage and exit
  -k              allow insecure SSL connections
  -force-ports    disable data protection in the API server for excessive ports
  -limit-hosts    only import hosts that have listening ports
  -tags           a comma separated list of tags to add to every host that is imported
`
)

func main() {
	showVersion := flag.Bool("v", false, "")
	insecureSSL := flag.Bool("k", false, "")
	forcePorts := flag.Bool("force-ports", false, "")
	limitHosts := flag.Bool("limit-hosts", false, "")
	tags := flag.String("tags", "", "")
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	if *showVersion {
		log.Println(version)
		os.Exit(0)
	}
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	lairPID := os.Getenv("LAIR_ID")

	var filename string
	switch len(flag.Args()) {
	case 2:
		lairPID = flag.Arg(0)
		filename = flag.Arg(1)
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}
	if lairPID == "" {
		log.Fatal("Fatal: Missing LAIR_ID")
	}
	u, err := url.Parse(lairURL)
	if err != nil {
		log.Fatalf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	if u.User == nil {
		log.Fatal("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Fatal: Missing username and/or password")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Fatal: Could not open file. Error %s", err.Error())
	}
	hostTags := []string{}
	if *tags != "" {
		hostTags = strings.Split(*tags, ",")
	}
	nmapRun, err := nmap.Parse(data)
	if err != nil {
		log.Fatalf("Fatal: Error parsing nmap. Error %s", err.Error())
	}
	project, err := p.BuildProject(nmapRun, lairPID, hostTags)
	if err != nil {
		log.Fatalf("Fatal: Error building project. Error %s", err.Error())
	}
	droneRes, err := p.ImportProject(user, pass, u, project, *insecureSSL, *forcePorts, *limitHosts)
	if err != nil {
		log.Fatalf("Fatal: Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		log.Fatalf("Fatal: Import failed. Error %s", droneRes.Message)
	}
	log.Println("Success: Operation completed successfully")
}

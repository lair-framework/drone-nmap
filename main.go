package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
	"github.com/lair-framework/go-nmap"
)

const (
	version  = "2.1.0"
	tool     = "nmap"
	osWeight = 50
	usage    = `
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

func buildProject(run *nmap.NmapRun, projectID string, tags []string) (*lair.Project, error) {
	project := &lair.Project{}
	project.ID = projectID
	project.Tool = tool
	project.Commands = append(project.Commands, lair.Command{Tool: tool, Command: run.Args})

	for _, h := range run.Hosts {
		host := &lair.Host{Tags: tags}
		if h.Status.State != "up" {
			continue
		}

		for _, address := range h.Addresses {
			switch {
			case address.AddrType == "ipv4":
				host.IPv4 = address.Addr
			case address.AddrType == "mac":
				host.MAC = address.Addr
			}
		}

		for _, hostname := range h.Hostnames {
			host.Hostnames = append(host.Hostnames, hostname.Name)
		}

		for _, p := range h.Ports {
			service := lair.Service{}
			service.Port = p.PortId
			service.Protocol = p.Protocol

			if p.State.State != "open" {
				continue
			}

			if p.Service.Name != "" {
				service.Service = p.Service.Name
				service.Product = "Unknown"
				if p.Service.Product != "" {
					service.Product = p.Service.Product
					if p.Service.Version != "" {
						service.Product += " " + p.Service.Version
					}
				}
			}

			for _, script := range p.Scripts {
				note := &lair.Note{Title: script.Id, Content: script.Output, LastModifiedBy: tool}
				service.Notes = append(service.Notes, *note)
			}

			host.Services = append(host.Services, service)
		}

		if len(h.Os.OsMatch) > 0 {
			os := lair.OS{}
			os.Tool = tool
			os.Weight = osWeight
			os.Fingerprint = h.Os.OsMatch[0].Name
			host.OS = os
		}

		project.Hosts = append(project.Hosts, *host)

	}

	return project, nil
}

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
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: *insecureSSL,
	})
	if err != nil {
		log.Fatalf("Fatal: Error setting up client. Error %s", err.Error())
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
	project, err := buildProject(nmapRun, lairPID, hostTags)
	if err != nil {
		log.Fatalf("Fatal: Error building project. Error %s", err.Error())
	}
	res, err := c.ImportProject(&client.DOptions{ForcePorts: *forcePorts, LimitHosts: *limitHosts}, project)
	if err != nil {
		log.Fatalf("Fatal: Unable to import project. Error %s", err.Error())
	}
	defer res.Body.Close()
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Fatal: Error %s", err.Error())
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		log.Fatalf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		log.Fatalf("Fatal: Import failed. Error %s", droneRes.Message)
	}
	log.Println("Success: Operation completed successfully")
}

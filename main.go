package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
	"github.com/lair-framework/go-nmap"
)

const (
	TOOL     = "Nmap"
	OSWEIGHT = 50
)

const usage = `
	Usage: nmap.go <project_id> <file>
`

func buildProject(run *nmap.NmapRun, projectId string) (*lair.Project, error) {
	project := &lair.Project{}
	project.Id = projectId
	project.Tool = TOOL
	project.Commands = append(project.Commands, lair.Command{Tool: TOOL, Command: run.Args})

	// Loop through all hosts
	for _, h := range run.Hosts {
		host := &lair.Host{}
		if h.Status.State != "up" {
			// Don't import dead hosts
			continue
		}
		host.Alive = true

		// Find IP address and Mac Address
		for _, address := range h.Addresses {
			switch {
			case address.AddrType == "ipv4":
				host.StringAddr = address.Addr
			case address.AddrType == "mac":
				host.MacAddr = address.Addr
			}
		}

		// Find all hostnames
		for _, hostname := range h.Hostnames {
			host.Hostnames = append(host.Hostnames, hostname.Name)
		}

		// Find all ports
		for _, p := range h.Ports {
			port := &lair.Port{}
			port.Port = p.PortId
			port.Protocol = p.Protocol

			// Find the port status
			if p.State.State != "open" {
				// only import open ports
				continue
			}
			port.Alive = true

			// Find service and product
			if p.Service.Name != "" {
				port.Service = p.Service.Name
				port.Product = "unknown" // Default value
				if p.Service.Product != "" {
					// Set product name
					port.Product = p.Service.Product
					if p.Service.Version != "" {
						// Append version
						port.Product += " " + p.Service.Version
					}
				}
			}

			// Add any NSE script output
			for _, script := range p.Scripts {
				note := &lair.Note{Title: script.Id, Content: script.Output, LastModifiedBy: TOOL}
				port.Notes = append(port.Notes, *note)
			}

			host.Ports = append(host.Ports, *port)
		}

		// Find the operating system
		if len(h.Os.OsMatch) > 0 {
			os := &lair.OS{}
			os.Tool = TOOL
			os.Weight = OSWEIGHT
			os.Fingerprint = h.Os.OsMatch[0].Name
			host.OS = append(host.OS, *os)
		}

		project.Hosts = append(project.Hosts, *host)

	}

	return project, nil
}

func main() {

	// Parse command line args
	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()
	if len(flag.Args()) != 2 {
		log.Fatal("You need to supply the Lair project ID and file you wish to import")
	}
	pid := flag.Arg(0)
	f := flag.Arg(1)

	// Parse and setup to target drone server info
	dest := os.Getenv("LAIR_API_SERVER")
	if dest == "" {
		log.Fatal("Missing LAIR_API_SERVER environment variable.")
	}
	u, err := url.Parse(dest)
	if err != nil {
		log.Fatal(err)
	}
	if u.User == nil {
		log.Fatal("Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Missing username and/or password")
	}
	target := &client.LairTarget{User: user, Password: pass, Host: u.Host}

	// Read the raw data file and parse
	buf, err := ioutil.ReadFile(f)
	if err != nil {
		log.Fatal(err)
	}
	nmapRun, err := nmap.Parse(buf)
	if err != nil {
		log.Fatal(err)
	}

	// Convert the Nessus structs to a go-lair-drone project
	project, err := buildProject(nmapRun, pid)
	if err != nil {
		log.Fatal(err)
	}

	// Import the project into Lair
	res, err := client.ImportProject(target, project)
	if err != nil {
		log.Fatal("Unable to import project: ", err)
	}
	defer res.Body.Close()

	// Inspect the reponse
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		log.Fatal(err)
	}
	if droneRes.Status == "Error" {
		log.Fatal("Import failed : ", droneRes.Message)
	} else {
		log.Println("Import complete, status : ", droneRes.Status)
	}

}

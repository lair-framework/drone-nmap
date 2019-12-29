package project

import (
	"encoding/json"
	"io/ioutil"
	"net/url"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
	"github.com/lair-framework/go-nmap"
)

const (
	osWeight = 50
	tool     = "nmap"
)

// BuildProject creates and builds a lair project
// from an nmap run
func BuildProject(run *nmap.NmapRun, projectID string, tags []string) (*lair.Project, error) {
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

		if len(h.Os.OsMatches) > 0 {
			os := lair.OS{}
			os.Tool = tool
			os.Weight = osWeight
			os.Fingerprint = h.Os.OsMatches[0].Name
			host.OS = os
		}

		project.Hosts = append(project.Hosts, *host)

	}

	return project, nil
}

// ImportProject takes API info and imports a project using lair API
func ImportProject(user string, pass string, u *url.URL, project *lair.Project, opts ...bool) (*client.Response, error) {
	insecureSSL, forcePorts, limitHosts := getOptions(opts...)

	droneRes := &client.Response{}
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: insecureSSL,
	})
	if err != nil {
		return droneRes, err
	}

	res, err := c.ImportProject(&client.DOptions{ForcePorts: forcePorts, LimitHosts: limitHosts}, project)
	if err != nil {
		return droneRes, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return droneRes, err
	}

	if err := json.Unmarshal(body, droneRes); err != nil {
		return droneRes, err
	}

	return droneRes, nil
}

func getOptions(opts ...bool) (bool, bool, bool) {
	insecureSSL := false
	forcePorts := false
	limitHosts := false
	for ind, b := range opts {
		switch ind {
		case 0:
			insecureSSL = b
		case 1:
			forcePorts = b
		case 2:
			limitHosts = b
		}
	}

	return insecureSSL, forcePorts, limitHosts
}

package securitymanager

import (
	"fmt"
	"os/exec"

	"github.com/Sirupsen/logrus"
	"github.com/leodotcloud/vethhunter/vethhunter"
)

const (
	atomicFile = "/tmp/rancher-ebtables"

	antiSpoofChainName   = "R_ANTI_SPOOF"
	arpCheckSrcChainName = "R_ARP_CHECK_SRC"
	arpCheckDstChainName = "R_ARP_CHECK_DST"
)

func getEBTCmd(cmdStr string) *exec.Cmd {
	c := buildCommand(cmdStr)
	c.Env = []string{fmt.Sprintf("EBTABLES_ATOMIC_FILE=%v", atomicFile)}
	return c
}

func programEBTablesRules(i *infoForRules) error {
	logrus.Debugf("programming ebtables")

	execCmd(getEBTCmd("ebtables --init-table"))

	// write all the rules to atomic file
	execCmd(getEBTCmd(fmt.Sprintf("ebtables -N %v", antiSpoofChainName)))
	execCmd(getEBTCmd(fmt.Sprintf("ebtables -P %v RETURN", antiSpoofChainName)))

	execCmd(getEBTCmd(fmt.Sprintf("ebtables -N %v", arpCheckSrcChainName)))
	execCmd(getEBTCmd(fmt.Sprintf("ebtables -P %v RETURN", arpCheckSrcChainName)))

	execCmd(getEBTCmd(fmt.Sprintf("ebtables -N %v", arpCheckDstChainName)))
	execCmd(getEBTCmd(fmt.Sprintf("ebtables -P %v RETURN", arpCheckDstChainName)))

	vh := vethhunter.NewVethHunterFromLocalDocker()

	for _, c := range i.localContainers {
		logrus.Debugf("c: %+v", c)

		// Anti Spoof
		hostVeth, err := vh.GetHostVethOfContainer(c.ExternalId)
		if err != nil {
			logrus.Errorf("Error: %v", err)
			return err
		}
		execCmd(getEBTCmd(fmt.Sprintf("ebtables -A %s -i %s -s ! %s -j DROP", antiSpoofChainName, hostVeth, c.PrimaryMacAddress)))

		// check arp src
		//ebtables -A R_ARP_CHECK_SRC -p arp -i veth7eb5133 --arp-mac-src ! 02:00:10:42:01:11 --arp-ip-src ! 10.42.1.11 -j DROP
		execCmd(getEBTCmd(fmt.Sprintf("ebtables -A %s -p arp -i %s --arp-mac-src ! %s --arp-ip-src ! %s -j DROP",
			arpCheckSrcChainName, hostVeth, c.PrimaryMacAddress, c.PrimaryIp)))

		// check arp dst
		//ebtables -A R_ARP_CHECK_DST -p arp -o veth7eb5133 --arp-ip-dst ! 10.42.1.11 -j DROP
		execCmd(getEBTCmd(fmt.Sprintf("ebtables -A %s -p arp -o %s --arp-ip-dst ! %s -j DROP",
			arpCheckSrcChainName, hostVeth, c.PrimaryIp)))
	}

	// Commit the atomic file and delete it
	execCmd(getEBTCmd("ebtables --atomic-commit"))

	return nil
}

func cleanupEBTables(info *infoForRules) error {
	executeCommand("ebtables -F FORWARD")
	executeCommand(fmt.Sprintf("ebtables -X %v", antiSpoofChainName))
	executeCommand(fmt.Sprintf("ebtables -X %v", arpCheckSrcChainName))
	executeCommand(fmt.Sprintf("ebtables -X %v", arpCheckDstChainName))

	return nil
}

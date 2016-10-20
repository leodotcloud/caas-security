package securitymanager

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher-metadata/metadata"
)

func programIPTablesRules(i *infoForRules) error {
	// Create ipset, iptables for the tenants
	for tenant, containers := range i.tenantContainersMap {
		logrus.Debugf("tenant: %v", tenant)
		logrus.Debugf("containers: %+v", containers)

		tmpTenantIPSetName := fmt.Sprintf("TMP-%s", tenant)
		createIPSet(tmpTenantIPSetName, containers)

		// Create or (swap, delete)
		if existsIPSet(tenant) {
			swapCmdStr := fmt.Sprintf("ipset swap %s %s", tmpTenantIPSetName, tenant)
			executeCommand(swapCmdStr)

			deleteCmdStr := fmt.Sprintf("ipset destroy %s", tmpTenantIPSetName)
			executeCommand(deleteCmdStr)
		} else {
			renameCmdStr := fmt.Sprintf("ipset rename %s %s", tmpTenantIPSetName, tenant)
			executeCommand(renameCmdStr)
		}

		// Create tmp ipset for the NetworkAgents with the IPs

		// Create iptables chain for each tenant
		checkAndCreateIPTablesChain(tenant)

		// Append the tenant iptables chain to the toplevel chain
		checkAndAppendChainToToplevelChain(tenant)

	}

	return nil
}

func checkAndAppendChainToToplevelChain(tenant string) {
	tenantChainName := fmt.Sprintf("to_%v", tenant)
	checkTenantCmdStr := fmt.Sprintf("iptables --check %s -m set --match-set %v dst -j %v", rancherTopLevelChainName, tenant, tenantChainName)
	appendTenantCmdStr := fmt.Sprintf("iptables --append %s -m set --match-set %v dst -j %v", rancherTopLevelChainName, tenant, tenantChainName)

	err := executeCommand(checkTenantCmdStr)
	if err != nil {
		executeCommand(appendTenantCmdStr)
	}
}

func checkAndCreateTopLevelChain() {
	err := executeCommand(fmt.Sprintf("iptables -n --list %s", rancherTopLevelChainName))
	if err != nil {
		executeCommand(fmt.Sprintf("iptables --new-chain %s", rancherTopLevelChainName))
	}
}

func checkAndAppendTopLevelChainToForward() {
	err := executeCommand(fmt.Sprintf("iptables --check FORWARD -d 10.42.0.0/16 -s 10.42.0.0/16 -j %s", rancherTopLevelChainName))
	if err != nil {
		executeCommand(fmt.Sprintf("iptables --insert FORWARD 1 -d 10.42.0.0/16 -s 10.42.0.0/16 -j %s", rancherTopLevelChainName))
	}
}

func checkAndCreateIPTablesChain(tenant string) {
	tenantChainName := fmt.Sprintf("to_%v", tenant)
	listChainCmdStr := fmt.Sprintf("iptables -n --list %v", tenantChainName)
	err := executeCommand(listChainCmdStr)
	if err != nil {
		createIPTablesChain(tenant)
	}
}

func createIPTablesChain(tenant string) {
	tenantChainName := fmt.Sprintf("to_%v", tenant)
	newChainCmdStr := fmt.Sprintf("iptables --new-chain %v", tenantChainName)
	executeCommand(newChainCmdStr)

	r1 := "iptables --append %v -m set --match-set %v src -j RETURN"
	appendTenantIPSetCmdStr := fmt.Sprintf(r1, tenantChainName, tenant)
	executeCommand(appendTenantIPSetCmdStr)

	r3 := "iptables --append %v -j DROP"
	dropCmdStr := fmt.Sprintf(r3, tenantChainName)
	executeCommand(dropCmdStr)
}

func existsIPSet(name string) bool {
	checkCmdStr := fmt.Sprintf("ipset list %s -name", name)
	err := executeCommand(checkCmdStr)

	return err == nil
}

func createIPSet(name string, containers []metadata.Container) {

	//ipset -N %s iphash
	createStr := fmt.Sprintf("ipset create %s iphash counters", name)
	executeCommand(createStr)

	for _, c := range containers {
		appendIPStr := fmt.Sprintf("ipset add %s %s", name, c.Ips[0])
		executeCommand(appendIPStr)
	}
}

func cleanupIPTables(info *infoForRules) error {
	// Flush the top level chain
	executeCommand(fmt.Sprintf("iptables --flush %s", rancherTopLevelChainName))

	// Remove from FORWARD chain
	executeCommand(fmt.Sprintf("iptables --delete FORWARD -d 10.42.0.0/16 -s 10.42.0.0/16 -j %s", rancherTopLevelChainName))

	// Delete the toplevel chain
	executeCommand(fmt.Sprintf("iptables --delete-chain %s", rancherTopLevelChainName))

	// Flush and delete the tenant chains
	// Delete the tenant ipsets
	for tenant := range info.tenantContainersMap {
		tenantChainName := fmt.Sprintf("to_%v", tenant)
		executeCommand(fmt.Sprintf("iptables --flush %v", tenantChainName))
		executeCommand(fmt.Sprintf("iptables --delete-chain %v", tenantChainName))

		executeCommand(fmt.Sprintf("ipset destroy %v", tenant))
	}

	return nil
}

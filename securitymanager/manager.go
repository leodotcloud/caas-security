package securitymanager

import (
	"github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher-metadata/metadata"
)

const (
	metadataURL = "http://rancher-metadata/2015-12-19"

	rancherTopLevelChainName = "RANCHER_CONTAINERS_TALKING"
)

// SecurityManager struct holds info needed for programming the iptables/ebtables
type SecurityManager struct {
	started bool
	mc      metadata.Client
}

type infoForRules struct {
	networkAgents       []metadata.Container
	localContainers     []metadata.Container
	tenantContainersMap map[string][]metadata.Container
}

//NewSecurityManager creates a new instance
func NewSecurityManager() (*SecurityManager, error) {
	mc, err := metadata.NewClientAndWait(metadataURL)
	if err != nil {
		logrus.Errorf("couldn't create metadata client: %v", err)
		return nil, err
	}
	return &SecurityManager{
		started: false,
		mc:      mc,
	}, nil
}

// Start initializes and starts the Security Manager
func (sm *SecurityManager) Start() error {
	logrus.Debugf("sm: Start")

	sm.started = true
	checkAndCreateTopLevelChain()

	// Append the toplevel chain to the first line of FORWARD chain
	checkAndAppendTopLevelChainToForward()

	return nil
}

// Configure takes care of programming the rules on the host
func (sm *SecurityManager) Configure() error {
	logrus.Debugf("sm: Configure")

	if !sm.started {
		logrus.Warnf("Security Manager state: not started, so not configuring")
		return nil
	}

	var err error
	info, err := sm.getInfoForRules()
	if err != nil {
		logrus.Errorf("error fetching information from metadata: %v", err)
		return err
	}

	err = programIPTablesRules(info)
	if err != nil {
		logrus.Errorf("error programming iptables rules: %v", err)
		return err
	}

	err = programEBTablesRules(info)
	if err != nil {
		logrus.Errorf("error programming ebtables rules: %v", err)
		return err
	}

	return nil
}

// Reload reprograms all the rules
func (sm *SecurityManager) Reload() error {
	logrus.Debugf("sm: Reload")
	sm.Configure()
	return nil
}

func fetchInfoFromMetadata(mc metadata.Client) (*infoForRules, error) {

	networkAgents := []metadata.Container{}
	localContainers := []metadata.Container{}
	tenantContainersMap := map[string][]metadata.Container{}

	containers, err := mc.GetContainers()
	if err != nil {
		logrus.Errorf("Couldn't get containers from metadata: %v", err)
		return nil, err
	}

	selfHost, err := mc.GetSelfHost()
	if err != nil {
		logrus.Errorf("Couldn't get containers from metadata: %v", err)
		return nil, err
	}

	logrus.Debugf("containers: %+v", containers)
	logrus.Debugf("selfHost: %+v", selfHost)

	for _, c := range containers {
		logrus.Debugf("c: %+v", c)
		if c.Name == "Network Agent" {
			networkAgents = append(networkAgents, c)
			continue
		}

		// TODO: How to get only tenant containers but not system?
		if tenant, ok := c.Labels["io.rancher.container.tenant"]; ok {
			if c.HostUUID == selfHost.UUID {
				localContainers = append(localContainers, c)
			}
			if _, ok := tenantContainersMap[tenant]; !ok {
				tenantContainersMap[tenant] = []metadata.Container{}
			}
			tenantContainersMap[tenant] = append(tenantContainersMap[tenant], c)
		}
	}

	logrus.Debugf("networkAgents: %+v", networkAgents)
	logrus.Debugf("localContainers: %+v", localContainers)
	logrus.Debugf("tenantContainersMap: %+v", tenantContainersMap)

	return &infoForRules{networkAgents, localContainers, tenantContainersMap}, nil
}

func (sm *SecurityManager) getInfoForRules() (*infoForRules, error) {
	logrus.Debugf("Fetching information from Metadata")
	return fetchInfoFromMetadata(sm.mc)
}

// Cleanup deletes all the rules, chains based on the current metadata
func (sm *SecurityManager) Cleanup() error {

	var err error
	info, err := sm.getInfoForRules()
	if err != nil {
		logrus.Errorf("error fetching information from metadata: %v", err)
		return err
	}

	cleanupIPTables(info)
	return nil
}

// Dump prints the current state from metadata
func (sm *SecurityManager) Dump() error {
	logrus.Infof("Dump requested")
	sm.getInfoForRules()

	return nil
}

// Stop prints the current state from metadata
func (sm *SecurityManager) Stop() error {
	logrus.Infof("Stop requested")

	sm.started = false

	return nil
}

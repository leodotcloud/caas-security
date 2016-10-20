package securitymanager

import (
	//"math/rand"
	"fmt"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher-metadata/metadata"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func TestEBTables(t *testing.T) {
	var err error
	mc, err := metadata.NewClientAndWait(metadataURL)
	if err != nil {
		errMsg := fmt.Sprintf("Not expecting error got err: %v", err)
		logrus.Errorf(errMsg)
		t.Fatalf(errMsg)
	}

	info, err := fetchInfoFromMetadata(mc)
	if err != nil {
		errMsg := fmt.Sprintf("Not expecting error got err: %v", err)
		logrus.Errorf(errMsg)
		t.Fatalf(errMsg)
	}

	err = programEBTablesRules(info)
	if err != nil {
		errMsg := fmt.Sprintf("Not expecting error got err: %v", err)
		logrus.Errorf(errMsg)
		t.Fatalf(errMsg)
	}

	err = cleanupEBTables(info)
	if err != nil {
		errMsg := fmt.Sprintf("Not expecting error got err: %v", err)
		logrus.Errorf(errMsg)
		t.Fatalf(errMsg)
	}

}

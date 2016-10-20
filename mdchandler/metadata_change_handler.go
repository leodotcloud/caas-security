package mdchandler

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher-metadata/metadata"
)

const (
	changeCheckInterval = 2
	metadataURL         = "http://rancher-metadata/2015-12-19"
)

// MetadataChangeHandler listens for version changes of metadata
// and triggers appropriate handlers in the current application
type MetadataChangeHandler struct {
	mc metadata.Client
	cb func() error
}

// NewMetadataChangeHandler is used to create a OnChange
// handler for Meatadta
func NewMetadataChangeHandler(cb func() error) (*MetadataChangeHandler, error) {

	if cb == nil {
		return nil, fmt.Errorf("no callback function provided")
	}

	mc, err := metadata.NewClientAndWait(metadataURL)
	if err != nil {
		logrus.Errorf("couldn't create metadata client: %v", err)
		return nil, err
	}
	return &MetadataChangeHandler{
		mc: mc,
		cb: cb,
	}, nil
}

// OnChangeHandler is the actual callback function called when
// the metadata changes
func (mdch *MetadataChangeHandler) OnChangeHandler(version string) {
	logrus.Infof("Metadata OnChange received, version: %v", version)
	err := mdch.cb()
	if err != nil {
		logrus.Errorf("Error calling callback: %v", err)
	} else {
		logrus.Debugf("Reload successful")
	}
}

// Start is used to begin the OnChange handling
func (mdch *MetadataChangeHandler) Start() error {
	logrus.Debugf("Starting the MetadataChangeHandler")
	mdch.mc.OnChange(changeCheckInterval, mdch.OnChangeHandler)

	return nil
}

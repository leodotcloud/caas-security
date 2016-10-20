package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/rancher/caas-security/mdchandler"
	"github.com/rancher/caas-security/securitymanager"
	"github.com/rancher/caas-security/server"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func main() {
	appMain()
}

func appMain() error {
	done := make(chan error)

	sm, err := securitymanager.NewSecurityManager()
	if err != nil {
		logrus.Errorf("Error creating new SecurityManager: %v", err)
		return err
	}
	sm.Start()

	listenPort := ":9999"
	logrus.Infof("About to start server and listen on port: %v", listenPort)
	go func() {
		//s := server.Server{sm}
		s := server.NewServer(sm)
		done <- s.ListenAndServe(listenPort)
	}()

	logrus.Infof("About to start server and listen on socket")
	go func() {
		lss := server.NewServer(sm)
		done <- lss.ServeOnLocalSocket()
	}()

	logrus.Infof("Starting metadata change handler")
	go func() {
		mdch, err := mdchandler.NewMetadataChangeHandler(sm.Reload)
		if err != nil {
			logrus.Errorf("Error creating new MetadataChangeHandler: %v", err)
			done <- err
		}
		done <- mdch.Start()
	}()

	return <-done
}

package server

import (
	"net"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/rancher/caas-security/securitymanager"
)

// Server holds the information for the web server
type Server struct {
	sm *securitymanager.SecurityManager
}

// NewServer returns an instance of the Server
func NewServer(sm *securitymanager.SecurityManager) *Server {
	return &Server{sm}
}

// ListenAndServe is used to setup handlers and
// start listening on the specified port
func (s *Server) ListenAndServe(listen string) error {
	http.HandleFunc("/settings", s.settingsHandler)
	http.HandleFunc("/dump", s.dumpHandler)
	http.HandleFunc("/cleanup", s.cleanupHandler)
	http.HandleFunc("/reload", s.reloadHandler)
	http.HandleFunc("/start", s.startHandler)
	http.HandleFunc("/stop", s.stopHandler)
	logrus.Infof("Listening on %s", listen)
	err := http.ListenAndServe(listen, nil)
	if err != nil {
		logrus.Errorf("got error while ListenAndServe: %v", err)
	}
	return err
}

func (s *Server) ServeOnLocalSocket() error {
	var err error
	http.HandleFunc("/api", s.apiHandler)

	l, err := net.Listen("unix", "/tmp/rancher-debug.sock")
	if err != nil {
		logrus.Errorf("listen error:", err)
		return err
	}

	err = http.Serve(l, nil)
	if err != nil {
		logrus.Errorf("got error while Serve: %v", err)
	}
	return err
}

func (s *Server) apiHandler(rw http.ResponseWriter, req *http.Request) {
	var err error

	if err == nil {
		rw.Write([]byte("OK"))
	} else {
		rw.Write([]byte("NOT OK"))
	}
}

func (s *Server) settingsHandler(rw http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Received settings request")
	logrus.Debugf("GET params were:", req.URL.Query())

	loglevel := req.URL.Query().Get("loglevel")
	var err error
	if loglevel != "" {
		level, err := logrus.ParseLevel(loglevel)
		if err != nil {
			logrus.Errorf("invalid loglevel: %v", loglevel)
		} else {
			logrus.Infof("Changing to loglevel: %v", loglevel)
			logrus.SetLevel(level)
		}
	}

	if err == nil {
		rw.Write([]byte("OK"))
	} else {
		rw.Write([]byte("NOT OK"))
	}
}

func (s *Server) dumpHandler(rw http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Received dump request")

	err := s.sm.Dump()
	if err == nil {
		rw.Write([]byte("OK"))
	} else {
		rw.Write([]byte("NOT OK"))
	}
}

func (s *Server) cleanupHandler(rw http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Received cleanup request")

	err := s.sm.Cleanup()
	if err == nil {
		rw.Write([]byte("OK"))
	} else {
		rw.Write([]byte("NOT OK"))
	}
}

func (s *Server) stopHandler(rw http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Received stop request")

	err := s.sm.Stop()
	if err == nil {
		rw.Write([]byte("OK"))
	} else {
		rw.Write([]byte("NOT OK"))
	}
}

func (s *Server) startHandler(rw http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Received start request")

	err := s.sm.Start()
	if err == nil {
		rw.Write([]byte("OK"))
	} else {
		rw.Write([]byte("NOT OK"))
	}
}

func (s *Server) reloadHandler(rw http.ResponseWriter, req *http.Request) {
	logrus.Debugf("Received reload request")

	err := s.sm.Reload()
	if err == nil {
		rw.Write([]byte("OK"))
	} else {
		rw.Write([]byte("NOT OK"))
	}
}

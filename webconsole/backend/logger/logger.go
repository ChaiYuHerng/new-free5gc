package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	"bitbucket.org/free5gc-team/logger_conf"
	"bitbucket.org/free5gc-team/logger_util"
)

var log *logrus.Logger
var AppLog *logrus.Entry
var InitLog *logrus.Entry
var WebUILog *logrus.Entry
var ContextLog *logrus.Entry
var GinLog *logrus.Entry

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	free5gcLogHook, err := logger_util.NewFileHook(logger_conf.Free5gcLogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err == nil {
		log.Hooks.Add(free5gcLogHook)
	}

	selfLogHook, err := logger_util.NewFileHook(
		logger_conf.Free5gcLogDir+"webconsole.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err == nil {
		log.Hooks.Add(selfLogHook)
	}

	AppLog = log.WithFields(logrus.Fields{"component": "WebUI", "category": "App"})
	InitLog = log.WithFields(logrus.Fields{"component": "WebUI", "category": "Init"})
	WebUILog = log.WithFields(logrus.Fields{"component": "WebUI", "category": "WebUI"})
	ContextLog = log.WithFields(logrus.Fields{"component": "WebUI", "category": "Context"})
	GinLog = log.WithFields(logrus.Fields{"component": "WebUI", "category": "GIN"})
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(bool bool) {
	log.SetReportCaller(bool)
}

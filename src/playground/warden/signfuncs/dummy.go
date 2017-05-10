package signfuncs

import (
	"fmt"

	"playground/log"
	"playground/warden"
)

// DemoConfig is a trivial configuration struct for DemoSignFunc.
type DemoConfig struct {
	Hello  string
	Invert bool
}

// DemoSignFunc is a very simple, sample SignFunc that returns its input, possibly binary-NOTed
// based on the value of the Invert field of its config struct.
func DemoSignFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	code, ctype, response = 500, "text/plain", []byte("panic in DemoSignHandler")
	defer func() {
		if r := recover(); r != nil {
			log.Error("DemoSignHandler", "paniced during execution", r)
		}
	}()

	cfg := config.(*DemoConfig)
	log.Status("DemoSignHandler", "Your honor, my client has instructed me to say '"+cfg.Hello+"'")

	response = req.Payload[:]
	if cfg.Invert {
		for i := range response {
			response[i] = ^response[i]
		}
	}

	log.Status("DemoSignHandler",
		fmt.Sprintf("signed payload '%s' for '%s' at '%s'",
			req.PayloadSHA256, req.CertSubject, req.When.UTC().Format("2006-01-02T15:04:05-0700")))
	return 200, "application/octet-stream", response
}

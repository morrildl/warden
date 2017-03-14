package signfuncs

import (
	"playground/log"
)

type DemoConfig struct {
	Hello string
	Invert bool
}

func DemoSignFunc(payload []byte, config interface{}) (code int, ctype string, response []byte) {
	code, ctype, response = 500, "text/plain", []byte("panic in DemoSignHandler")
	defer func() {
		if r := recover(); r != nil {
			log.Error("DemoSignHandler", "paniced during execution", r)
		}
	}()

	cfg := config.(*DemoConfig)
	log.Status("warden.signers.DemoSignHandler", "Your honor, my client has instructed me to say '" + cfg.Hello + "'")

	response = payload[:]
	if cfg.Invert {
		for i, _ := range(response) {
			response[i] = ^response[i]
		}
	}

	return 200, "application/octet-stream", response
}

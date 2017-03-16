package signfuncs

import (
	"playground/warden"
)

func init() {
	warden.Registry["demo"] = func() *warden.Handler { return &warden.Handler{&DemoConfig{}, DemoSignFunc} }
	warden.Registry["stm32"] = func() *warden.Handler { return &warden.Handler{&STM32Config{}, STM32SignFunc} }
}

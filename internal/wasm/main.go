//go:build js && wasm

package main

import (
	"syscall/js"

	"widevine/internal/wv"
)

var (
	cdms = map[int]*wv.Cdm{}
	next = 0
)

func toGo(v js.Value) []byte {
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b
}

func toJS(b []byte) js.Value {
	v := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(v, b)
	return v
}

func exp(name string, fn func([]js.Value) (any, error)) {
	js.Global().Set(name, js.FuncOf(func(this js.Value, args []js.Value) any {
		return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, pa []js.Value) any {
			resolve := pa[0]
			go func() {
				out, err := fn(args)
				obj := js.Global().Get("Object").New()
				if err != nil {
					e := js.Global().Get("Object").New()
					e.Set("code", "internal")
					e.Set("message", err.Error())
					obj.Set("ok", false)
					obj.Set("error", e)
				} else {
					obj.Set("ok", true)
					if b, ok := out.([]byte); ok {
						obj.Set("data", toJS(b))
					} else {
						obj.Set("data", out)
					}
				}
				resolve.Invoke(obj)
			}()
			return nil
		}))
	}))
}

func cdm(id int) (*wv.Cdm, error) {
	c, ok := cdms[id]
	if !ok {
		return nil, wv.ErrSession
	}
	return c, nil
}

func main() {
	exp("wvLoadWvd", func(args []js.Value) (any, error) {
		d, err := wv.LoadWvd(toGo(args[0]))
		if err != nil {
			return nil, err
		}
		next++
		cdms[next] = wv.New(d)
		return next, nil
	})
	exp("wvLoadDev", func(args []js.Value) (any, error) {
		d, err := wv.NewDevice(toGo(args[0]), toGo(args[1]), args[2].Int(), args[3].Int())
		if err != nil {
			return nil, err
		}
		next++
		cdms[next] = wv.New(d)
		return next, nil
	})
	exp("wvOpen", func(args []js.Value) (any, error) {
		c, err := cdm(args[0].Int())
		if err != nil {
			return nil, err
		}
		return c.Open(), nil
	})
	exp("wvClose", func(args []js.Value) (any, error) {
		c, err := cdm(args[0].Int())
		if err != nil {
			return nil, err
		}
		c.Close(args[1].String())
		return "ok", nil
	})
	exp("wvCert", func(args []js.Value) (any, error) {
		c, err := cdm(args[0].Int())
		if err != nil {
			return nil, err
		}
		return "ok", c.Cert(args[1].String(), toGo(args[2]))
	})
	exp("wvChal", func(args []js.Value) (any, error) {
		c, err := cdm(args[0].Int())
		if err != nil {
			return nil, err
		}
		return c.Chal(args[1].String(), toGo(args[2]))
	})
	exp("wvUpd", func(args []js.Value) (any, error) {
		c, err := cdm(args[0].Int())
		if err != nil {
			return nil, err
		}
		return "ok", c.Upd(args[1].String(), toGo(args[2]))
	})
	exp("wvDec", func(args []js.Value) (any, error) {
		c, err := cdm(args[0].Int())
		if err != nil {
			return nil, err
		}
		return c.Dec(args[1].String(), toGo(args[2]), toGo(args[3]), toGo(args[4]), toGo(args[5]))
	})
	exp("wvDecRaw", func(args []js.Value) (any, error) {
		return wv.Decrypt(toGo(args[0]), toGo(args[1]), toGo(args[2]), toGo(args[3]))
	})
	js.Global().Set("__wvReady", true)
	select {}
}

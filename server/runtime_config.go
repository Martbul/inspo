package server

import "github.com/martbul/inspo-common/runtime"

type RuntimeConfigClone struct {
	Name          string
	ShutdownGrace int
	Logger        runtime.LoggerConfig
	Session       runtime.SessionConfig
	Socket        runtime.SocketConfig
	Social        runtime.SocialConfig
	Runtime       runtime.RuntimeConfig
	Iap           runtime.IAPConfig
	GoogleAuth    runtime.GoogleAuthConfig
	Satori        runtime.SatoriConfig
}

func (c *RuntimeConfigClone) GetName() string {
	return c.Name
}

func (c *RuntimeConfigClone) GetShutdownGraceSec() int {
	return c.ShutdownGrace
}

func (c *RuntimeConfigClone) GetLogger() runtime.LoggerConfig {
	return c.Logger
}

func (c *RuntimeConfigClone) GetSession() runtime.SessionConfig {
	return c.Session
}

func (c *RuntimeConfigClone) GetSocket() runtime.SocketConfig {
	return c.Socket
}

func (c *RuntimeConfigClone) GetSocial() runtime.SocialConfig {
	return c.Social
}

func (c *RuntimeConfigClone) GetRuntime() runtime.RuntimeConfig {
	return c.Runtime
}

func (c *RuntimeConfigClone) GetIAP() runtime.IAPConfig {
	return c.Iap
}

func (c *RuntimeConfigClone) GetGoogleAuth() runtime.GoogleAuthConfig {
	return c.GoogleAuth
}

func (c *RuntimeConfigClone) GetSatori() runtime.SatoriConfig {
	return c.Satori
}

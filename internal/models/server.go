package models

import (
	"context"
	"os"
	"runtime"

	"github.com/doncicuto/openuem_ent/server"
)

func (m *Model) SetComponent(component server.Component, version string, channel server.Channel) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	exists, err := m.Client.Server.Query().Where(server.Hostname(hostname), server.ComponentEQ(component), server.Arch(runtime.GOARCH), server.Os(runtime.GOOS), server.Version(version), server.ChannelEQ(channel)).Exist(context.Background())
	if err != nil {
		return err
	}

	if !exists {
		return m.Client.Server.Create().SetHostname(hostname).SetComponent(component).SetArch(runtime.GOARCH).SetOs(runtime.GOOS).SetVersion(version).SetChannel(channel).Exec(context.Background())
	}
	return m.Client.Server.Update().SetHostname(hostname).SetComponent(component).SetArch(runtime.GOARCH).SetOs(runtime.GOOS).SetVersion(version).SetChannel(channel).Exec(context.Background())
}

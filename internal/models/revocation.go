package models

import (
	"context"

	"github.com/doncicuto/openuem_ent"
	"github.com/doncicuto/openuem_ent/revocation"
)

func (m *Model) AddRevocation(serial int64, reason int, info string) error {
	_, err := m.Client.Revocation.Create().SetID(serial).SetReason(reason).SetInfo(info).Save(context.Background())
	if err != nil {
		return err
	}
	return nil
}

func (m *Model) GetRevoked(serial int64) (*openuem_ent.Revocation, error) {
	return m.Client.Revocation.Query().Where(revocation.ID(serial)).Only(context.Background())
}

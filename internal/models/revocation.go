package models

import "context"

func (m *Model) AddRevocation(serial int64, reason string) error {
	_, err := m.Client.Revocation.Create().SetID(serial).SetReason(reason).Save(context.Background())
	if err != nil {
		return err
	}
	return nil
}

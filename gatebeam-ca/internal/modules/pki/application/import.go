package application

import "context"

// ImportCommand consumes already signed standard files in an offline ceremony.
// Neither this command nor its importer has a database or online root signer.
type ImportCommand struct{ SourceDirectory, OnlineDirectory string }
type OfflineImporter interface {
	Import(context.Context, ImportCommand) error
}

func Import(ctx context.Context, p OfflineImporter, c ImportCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || c.SourceDirectory == "" || c.OnlineDirectory == "" {
		return ErrBootstrap
	}
	return p.Import(ctx, c)
}

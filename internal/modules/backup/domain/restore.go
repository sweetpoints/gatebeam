package domain

type RestoreMode string

const Conservative RestoreMode = "conservative-local"

// A timestamp or caller-supplied trust flag is never a latest security watermark.
// Until an independently verified authority protocol exists there is one mode.
func (m RestoreMode) Validate() error {
	if m != Conservative {
		return ErrInvalid
	}
	return nil
}

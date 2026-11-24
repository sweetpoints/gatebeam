package secrets

// RolePolicy contains only operator-authorized public age recipients. Private
// identities stay distinct on each instance and are never part of this map.
type RolePolicy map[string][]string

func ValidateRoleRecipients(policy map[string][]string) error {
	seen := map[string]string{}
	for role, public := range policy {
		switch role {
		case "api", "provider", "notification", "ca", "leaf":
		default:
			return errSecret
		}
		keys, e := parseRecipients(public)
		if e != nil {
			return e
		}
		for _, key := range keys {
			if previous, ok := seen[key.String()]; ok && previous != role {
				return errSecret
			}
			seen[key.String()] = role
		}
	}
	return nil
}

// ConfiguredStore retains legacy single-recipient behavior when no role policy
// was supplied. A configured role must include this instance's own recipient.
func ConfiguredStore(identityFile string, public []string) (*Store, error) {
	if len(public) == 0 {
		return New(identityFile)
	}
	return NewRoleStore(identityFile, public)
}
func ConfiguredRecipient(primary string, public []string) (*RecipientStore, error) {
	if len(public) == 0 {
		return NewRecipient(primary)
	}
	found := false
	for _, p := range public {
		if p == primary {
			found = true
		}
	}
	if !found {
		return nil, errSecret
	}
	ordered := []string{primary}
	for _, p := range public {
		if p != primary {
			ordered = append(ordered, p)
		}
	}
	return NewRecipients(ordered)
}
func (p RolePolicy) Role(name string) []string { return append([]string{}, p[name]...) }

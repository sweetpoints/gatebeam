package domain

import "regexp"

type Role string
type Action string

const (
	Readonly  Role = "readonly"
	Editor    Role = "editor"
	Publisher Role = "publisher"
	Admin     Role = "admin"
)
const (
	View    Action = "view"
	Edit    Action = "edit"
	Publish Action = "publish"
	Manage  Action = "manage"
)

func (r Role) Valid() bool { return r == Readonly || r == Editor || r == Publisher || r == Admin }
func (r Role) Allows(a Action) bool {
	switch a {
	case View:
		return r.Valid()
	case Edit:
		return r == Editor || r == Publisher || r == Admin
	case Publish:
		return r == Publisher || r == Admin
	case Manage:
		return r == Admin
	}
	return false
}

type Grant struct {
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id"`
}

func Granted(role Role, grants []Grant, site string, groups []string) bool {
	if role == Admin {
		return true
	}
	for _, g := range grants {
		if g.Kind == "site" && g.ResourceID == site {
			return true
		}
		if g.Kind == "group" {
			for _, id := range groups {
				if id == g.ResourceID {
					return true
				}
			}
		}
	}
	return false
}

var resourceID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func ValidResourceID(id string) bool { return resourceID.MatchString(id) }

package domain

type SiteGroup struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision int64  `json:"revision"`
}

func (g *SiteGroup) Normalize() error {
	if !ValidID(g.ID) {
		return ErrInvalid
	}
	n, e := Name(g.Name)
	g.Name = n
	return e
}

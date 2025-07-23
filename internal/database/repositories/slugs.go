package repositories

import "fmt"

type slugger[T any] interface {
	Same(T) bool
	GetSlug() string
	SetSlug(string)
}

func injectUniqueSlugs[T slugger[T]](existing []T, projects []T) error {
	taken := make(map[string]T)
	for _, s := range existing {
		taken[s.GetSlug()] = s
	}

	// Resolve unique slugs
	for _, p := range projects {
		base := p.GetSlug()
		slug := base
		i := 1

		for {
			if _, exists := taken[slug]; !exists {
				// we found a unique slug
				p.SetSlug(slug)
				taken[slug] = p
				break
			} else if p.Same(taken[slug]) {
				// the slug is already taken - check if it is the same project
				// if it is the same project, we can keep the slug
				p.SetSlug(slug)
				taken[slug] = p
				break
			}
			// slug is already taken by another project - append a number to the slug to check if this is unique in the next iteration
			slug = fmt.Sprintf("%s-%d", base, i)
			i++
		}
	}

	return nil
}

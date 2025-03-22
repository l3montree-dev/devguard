package compliance

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

type Policy struct {
	Content string
	Name    string
	query   rego.PreparedEvalQuery
}

func NewPolicy(name string, content string) (*Policy, error) {
	r := rego.New(
		rego.Query("data.sigstore.isCompliant"),
		rego.Module(name, content),
	)

	ctx := context.TODO()
	query, err := r.PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}

	return &Policy{
		Content: content,
		Name:    name,
		query:   query,
	}, nil
}

func (p *Policy) Eval(input string) error {
	// parse the input
	var parsed any

	if err := json.Unmarshal([]byte(input), &parsed); err != nil {
		return err
	}

	rs, err := p.query.Eval(context.TODO(), rego.EvalInput(parsed))
	if err != nil {
		return err
	}

	fmt.Println(rs.Allowed(), rs)
	return nil
}

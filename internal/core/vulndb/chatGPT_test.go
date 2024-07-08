package vulndb

import (
	"testing"
)

func TestAskChatGPT(t *testing.T) {

	t.Run("test AskChatGPT", func(t *testing.T) {

		question := "What is the capital of France?"
		resp, err := AskChatGPT(question)
		if err != nil {
			t.Fatal(err)
		}
		if resp == "1" {
			t.Fatalf("expected non-empty response, got empty response")
		}
		t.Fail()
	})
}

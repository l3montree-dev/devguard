package vulndb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	apiEndpoint = "https://api.openai.com/v1/chat/completions"
)

func AskChatGPT(question string) (string, error) {
	// Get the API key from the environment
	apiKey := os.Getenv("CHATGPT_API_KEY")
	fmt.Println(apiKey)
	if apiKey == "" {
		return "", fmt.Errorf("OPENAI_API_KEY environment variable not set")
	}

	// Create the request body
	type requestBody struct {
		Model     string `json:"model"`
		MaxTokens int    `json:"max_tokens"`
		Prompt    string `json:"prompt"`
	}
	body := requestBody{
		Model:     "gpt-3.5-turbo",
		MaxTokens: 100,
		Prompt:    question,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", apiEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// Send the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse the response JSON
	type responseBody struct {
		Choices []struct {
			Text string `json:"text"`
		} `json:"choices"`
	}
	var data responseBody
	err = json.Unmarshal(respBody, &data)
	if err != nil {
		return "", err
	}

	fmt.Println(data.Choices[0].Text)
	// Return the generated text
	return data.Choices[0].Text, nil
}

// Copyright (C) 2024 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package commands

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/services"

	"github.com/spf13/cobra"
)

type CurlOptions struct {
	// HTTP method
	method string
	// Request data
	data string
	// Headers
	headers []string
	// Output options
	output  string
	silent  bool
	verbose bool
	// Follow redirects
	followRedirects bool
	maxRedirects    int
	// Timeout
	timeout time.Duration
	// User-Agent
	userAgent string
	// Include response headers in output
	includeHeaders bool
	// Show only response headers
	headOnly bool
	// Insecure (skip SSL verification)
	insecure bool
	// URL
	url string
	// Personal Access Token
	token string
}

func NewCurlCommand() *cobra.Command {
	var opts CurlOptions

	cmd := &cobra.Command{
		Use:               "curl [flags] <url>",
		Short:             "Make HTTP requests with DevGuard PAT signing (curl-compatible)",
		DisableAutoGenTag: true,
		Long: `Make HTTP requests with DevGuard Personal Access Token signing.
This command provides curl-compatible syntax while automatically signing requests
for authentication.`,
		Example: `  # Simple GET request
  devguard-scanner curl https://api.example.com/users

  # POST request with JSON data
  devguard-scanner curl -X POST -d '{"name":"test"}' -H "Content-Type: application/json" https://api.example.com/users

  # Verbose request with custom headers
  devguard-scanner curl -v -H "Accept: application/json" https://api.example.com/data

  # Request with explicit token
  devguard-scanner curl --token <your-pat-token> -X GET https://api.example.com/protected`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("URL is required")
			}
			opts.url = args[0]
			return runCurl(&opts)
		},
		DisableFlagsInUseLine: true,
	}

	// HTTP method flags
	cmd.Flags().StringVarP(&opts.method, "request", "X", "GET", "HTTP method (GET, POST, PUT, DELETE, etc.)")

	// Data flags
	cmd.Flags().StringVarP(&opts.data, "data", "d", "", "HTTP POST data")

	// Header flags
	cmd.Flags().StringArrayVarP(&opts.headers, "header", "H", []string{}, "Pass custom header(s) to server")

	// Output flags
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().BoolVarP(&opts.silent, "silent", "s", false, "Silent mode")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVarP(&opts.includeHeaders, "include", "i", false, "Include response headers in output")
	cmd.Flags().BoolVarP(&opts.headOnly, "head", "I", false, "Fetch headers only")

	// Redirect flags
	cmd.Flags().BoolVarP(&opts.followRedirects, "location", "L", false, "Follow redirects")
	cmd.Flags().IntVar(&opts.maxRedirects, "max-redirs", 50, "Maximum number of redirects to follow")

	// Timeout flags
	cmd.Flags().DurationVar(&opts.timeout, "max-time", 0, "Maximum time allowed for transfer")

	// User-Agent flag
	cmd.Flags().StringVarP(&opts.userAgent, "user-agent", "A", "", "User-Agent to send to server")

	// Security flags
	cmd.Flags().BoolVarP(&opts.insecure, "insecure", "k", false, "Allow insecure server connections")

	// DevGuard specific flags
	cmd.Flags().StringVar(&opts.token, "token", "", "DevGuard Personal Access Token (can also be set via DEVGUARD_TOKEN env var). Used to sign requests.")

	return cmd
}

func runCurl(opts *CurlOptions) error {
	// Get token from flag or environment
	token := opts.token
	if token == "" {
		token = os.Getenv("DEVGUARD_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("DevGuard token is required. Set it via --token flag or DEVGUARD_TOKEN environment variable")
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(opts.url)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		opts.url = parsedURL.String()
	}

	// Determine HTTP method
	method := strings.ToUpper(opts.method)
	if opts.data != "" && method == "GET" {
		method = "POST"
	}
	if opts.headOnly {
		method = "HEAD"
	}

	// Prepare request body
	var body io.Reader
	if opts.data != "" && method != "GET" && method != "HEAD" {
		body = strings.NewReader(opts.data)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, opts.url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	for _, header := range opts.headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format: %s (expected 'Name: Value')", header)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		req.Header.Set(key, value)
	}

	// Set User-Agent if specified
	if opts.userAgent != "" {
		req.Header.Set("User-Agent", opts.userAgent)
	} else {
		req.Header.Set("User-Agent", config.UserAgent)
	}

	// Set Content-Type for POST data if not already set
	if opts.data != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Sign the request using DevGuard PAT
	if err := services.SignRequest(token, req); err != nil {
		return fmt.Errorf("failed to sign request: %v", err)
	}

	// Create HTTP client
	client := &http.Client{}

	// Configure timeout
	if opts.timeout > 0 {
		client.Timeout = opts.timeout
	}

	// Configure redirect policy
	if !opts.followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if opts.maxRedirects >= 0 {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.maxRedirects {
				return fmt.Errorf("maximum number of redirects (%d) exceeded", opts.maxRedirects)
			}
			return nil
		}
	}

	// Configure TLS settings
	if opts.insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
		if !opts.silent {
			slog.Warn("Insecure mode requested - SSL verification disabled")
		}
	}

	// Make the request
	if opts.verbose && !opts.silent {
		slog.Info("Making request", "method", method, "url", opts.url)
		slog.Debug("Request headers", "headers", req.Header)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Prepare output
	var output io.Writer = os.Stdout
	if opts.output != "" {
		file, err := os.Create(opts.output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer file.Close()
		output = file
	}

	// Handle verbose output
	if opts.verbose && !opts.silent {
		slog.Info("Response received", "status", resp.Status, "status_code", resp.StatusCode)
		slog.Debug("Response headers", "headers", resp.Header)
	}

	// Write response headers if requested
	if opts.includeHeaders || opts.headOnly {
		fmt.Fprintf(output, "%s %s\r\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Fprintf(output, "%s: %s\r\n", key, value)
			}
		}
		fmt.Fprintf(output, "\r\n")
	}

	// Write response body (unless head-only)
	if !opts.headOnly {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		if _, err := output.Write(bodyBytes); err != nil {
			return fmt.Errorf("failed to write response: %v", err)
		}
	}

	// Exit with non-zero status for HTTP errors (like curl does)
	if resp.StatusCode >= 400 {
		if !opts.silent {
			slog.Error("HTTP error", "status_code", resp.StatusCode, "status", resp.Status)
		}
		os.Exit(resp.StatusCode / 100) // Exit with 4 for 4xx, 5 for 5xx
	}

	return nil
}

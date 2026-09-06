// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
)

func newRenderCommand() *cobra.Command {
	var (
		inputFile    string
		outputFile   string
		format       string
		layout       string
		fromPURL     string
		maxDepth     int
		showVulns    bool
		includeFiles bool
	)

	renderCmd := &cobra.Command{
		Use:   "render",
		Short: "Render a CycloneDX SBOM as a graphviz diagram",
		Long: `Render a CycloneDX SBOM as a graphviz diagram.

This command reads a CycloneDX SBOM file and generates a visualization using graphviz.
The graph shows the dependency tree and can optionally include vulnerability information.

Examples:
  # Render SBOM to PDF (requires graphviz installed)
  devguard-cli sbom render -i sbom.json -o diagram.pdf

  # Render to PNG
  devguard-cli sbom render -i sbom.json -o diagram.png

  # Render to DOT file (no graphviz needed)
  devguard-cli sbom render -i sbom.json -o output.dot

  # Render with vulnerabilities shown
  devguard-cli sbom render -i sbom.json --showVulns -o diagram.pdf

  # Limit depth to avoid huge graphs
  devguard-cli sbom render -i sbom.json --maxDepth 5 -o diagram.pdf

  # Render only the subgraph rooted at a specific component
  devguard-cli sbom render -i sbom.json --from 'pkg:golang/github.com/foo/bar@v1.2.3' -o go.svg`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return renderSBOM(inputFile, outputFile, format, layout, fromPURL, maxDepth, showVulns, includeFiles)
		},
	}

	renderCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input CycloneDX SBOM file (JSON format)")
	renderCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (pdf, png, svg, or dot)")
	renderCmd.Flags().StringVarP(&format, "format", "f", "", "Output format (auto-detected from file extension, or specify: dot, svg, png, pdf)")
	renderCmd.Flags().StringVarP(&layout, "layout", "l", "twopi", "Graphviz layout engine: dot (hierarchical tree, slow on large graphs), twopi (radial tree, best for SBOMs), sfdp (force-directed), fdp, circo")
	renderCmd.Flags().StringVar(&fromPURL, "from", "", "Start the graph from the component with this PURL instead of the root (renders only the subgraph(s) rooted at every subtree carrying this PURL)")
	renderCmd.Flags().IntVarP(&maxDepth, "maxDepth", "d", 0, "Maximum depth of dependency tree to render (0 = unlimited)")
	renderCmd.Flags().BoolVarP(&showVulns, "showVulns", "v", false, "Show vulnerabilities in the graph")
	renderCmd.Flags().BoolVar(&includeFiles, "includeFiles", false, "Include 'file' type components (source tarballs, scripts — skipped by default as they cannot match CVEs)")

	if err := renderCmd.MarkFlagRequired("input"); err != nil {
		slog.Error("Failed to mark input flag as required", "err", err)
	}

	return renderCmd
}

func renderSBOM(inputFile, outputFile, format, layout, fromPURL string, maxDepth int, showVulns, includeFiles bool) error {
	// Read the SBOM file
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read SBOM file: %w", err)
	}

	// Parse CycloneDX SBOM
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return fmt.Errorf("failed to parse CycloneDX SBOM: %w", err)
	}

	// Convert to a content-addressed merkle tree
	parsed, err := normalize.MerkleTreeFromCycloneDX(&bom, inputFile)
	if err != nil {
		return fmt.Errorf("failed to convert SBOM to merkle tree: %w", err)
	}

	// Generate DOT format
	var vulns []cdx.Vulnerability
	if bom.Vulnerabilities != nil {
		vulns = *bom.Vulnerabilities
	}
	dotContent, err := generateDOT(parsed, vulns, layout, fromPURL, maxDepth, showVulns, includeFiles)
	if err != nil {
		return err
	}

	// Determine output format
	if format == "" && outputFile != "" {
		// Auto-detect from file extension
		ext := filepath.Ext(outputFile)
		format = strings.TrimPrefix(ext, ".")
	}
	if format == "" {
		format = "dot"
	}

	// Output result
	if outputFile == "" {
		// Write DOT to stdout
		fmt.Println(dotContent)
		return nil
	}

	// Check if we need to call graphviz
	if format == "dot" {
		// Just write the DOT file
		if err := os.WriteFile(outputFile, []byte(dotContent), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		slog.Info("DOT file written successfully", "file", outputFile)
		return nil
	}

	// For other formats (pdf, png, svg), call the chosen layout engine binary
	if _, err := exec.LookPath(layout); err != nil {
		return fmt.Errorf("graphviz layout engine %q not found in PATH\nInstall with: brew install graphviz (macOS) or apt-get install graphviz (Linux)", layout)
	}

	cmd := exec.Command(layout, "-T"+format, "-o", outputFile)
	cmd.Stdin = strings.NewReader(dotContent)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run graphviz dot command: %w\nStderr: %s", err, stderr.String())
	}

	slog.Info("Diagram generated successfully", "file", outputFile, "format", format)
	return nil
}

func generateDOT(parsed *normalize.ParsedSBOM, vulns []cdx.Vulnerability, layout, fromPURL string, maxDepth int, showVulns, includeFiles bool) (string, error) {
	tree := parsed.Tree
	components := parsed.Components

	var sb strings.Builder

	sb.WriteString("digraph SBOM {\n")

	// Graph-level attributes tuned per layout engine.
	// concentrate=true merges parallel edges (shared deps), which dramatically
	// reduces visual noise in large SBOMs regardless of layout.
	sb.WriteString("  concentrate=true;\n")
	sb.WriteString("  overlap=false;\n")
	sb.WriteString("  splines=curved;\n")
	switch layout {
	case "dot":
		// Hierarchical — respects rankdir, good for small/medium graphs
		sb.WriteString("  rankdir=TB;\n")
		sb.WriteString("  ranksep=0.8;\n")
		sb.WriteString("  nodesep=0.4;\n")
	case "twopi":
		// Radial tree — root in centre, deps fan outward; scales to 1000+ nodes
		sb.WriteString("  ranksep=3;\n")
	case "circo":
		// Circular — good when all nodes have similar importance
		sb.WriteString("  ranksep=1.5;\n")
	default:
		// sfdp / fdp — force-directed; add spring tuning to reduce clumping
		sb.WriteString("  K=0.8;\n")
		sb.WriteString("  repulsiveforce=2.0;\n")
	}
	sb.WriteString("  node [shape=box, style=rounded, fontsize=9, width=0.3, height=0.2];\n")
	sb.WriteString("  edge [color=gray60, arrowsize=0.6];\n\n")

	visited := make(map[uuid.UUID]bool)
	depths := make(map[uuid.UUID]int)

	// Helper to sanitize node IDs for DOT format
	// DOT node IDs must be valid identifiers (alphanumeric + underscore)
	sanitizeID := func(id string) string {
		var result strings.Builder
		for i, r := range id {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
				result.WriteRune(r)
			} else {
				result.WriteRune('_')
			}
			// Prevent leading digit
			if i == 0 && r >= '0' && r <= '9' {
				result.Reset()
				result.WriteString("n_")
				result.WriteRune(r)
			}
		}
		sanitized := result.String()
		// Ensure not empty
		if sanitized == "" {
			return "node_empty"
		}
		return sanitized
	}

	// Helper to escape strings for DOT labels
	escapeLabel := func(s string) string {
		s = strings.ReplaceAll(s, "\\", "\\\\")
		s = strings.ReplaceAll(s, "\"", "\\\"")
		s = strings.ReplaceAll(s, "\n", "\\n")
		return s
	}

	// Helper to parse and format PURL for display
	formatPURL := func(purlStr string) (label, pkgType string) {
		purl, err := packageurl.FromString(purlStr)
		if err != nil {
			// Not a valid PURL, return as-is
			return purlStr, "unknown"
		}

		// Build a concise label
		var labelParts []string

		// Add type badge
		labelParts = append(labelParts, fmt.Sprintf("[%s]", strings.ToUpper(purl.Type)))

		// Add namespace if present (common in golang, maven)
		if purl.Namespace != "" {
			// Shorten long namespaces (like github.com/org/...)
			ns := purl.Namespace
			parts := strings.Split(ns, "/")
			if len(parts) > 2 {
				ns = parts[0] + "/.../" + parts[len(parts)-1]
			}
			labelParts = append(labelParts, ns+"/")
		}

		// Add name
		labelParts = append(labelParts, purl.Name)

		// Add version if present
		if purl.Version != "" {
			labelParts = append(labelParts, "@"+purl.Version)
		}

		return strings.Join(labelParts, ""), purl.Type
	}

	// Helper to get a node's label. The root node represents the artifact
	// itself; every other node is an ordinary component identified by its
	// ComponentID (a purl), with metadata looked up from parsed.Components.
	getLabel := func(node *normalize.MerkleNode) string {
		if node == nil {
			return ""
		}

		if node.SubtreeHash == tree.Root {
			return fmt.Sprintf("ROOT: %s", node.ComponentID)
		}

		// Try to use PURL formatting first
		if node.ComponentID != "" {
			if _, err := packageurl.FromString(node.ComponentID); err == nil {
				label, _ := formatPURL(node.ComponentID)
				return label
			}
		}

		// Fallback to component name/version from the metadata map
		if comp, ok := components[node.ComponentID]; ok {
			name := comp.Name
			if comp.Version != "" {
				name = fmt.Sprintf("%s@%s", name, comp.Version)
			}
			return name
		}
		return node.ComponentID
	}

	// Helper to get package type for styling
	getPkgType := func(node *normalize.MerkleNode) string {
		if node != nil && node.SubtreeHash != tree.Root && node.ComponentID != "" {
			_, pkgType := formatPURL(node.ComponentID)
			return pkgType
		}
		return ""
	}

	// Helper to get node color based on node kind (root vs. component) and
	// package type
	getNodeColor := func(node *normalize.MerkleNode) string {
		if node == nil {
			return "lightgray"
		}

		if node.SubtreeHash == tree.Root {
			// The old graph model's root/artifact colours (lightblue,
			// lightgreen) collapse into one root node now; keep lightblue,
			// since it read as the "start here" node before.
			return "lightblue"
		}

		// Color by package type for better visual grouping
		pkgType := getPkgType(node)
		switch pkgType {
		case "npm", "yarn":
			return "#ffebcd" // blanched almond
		case "golang", "go":
			return "#add8e6" // light blue
		case "pypi", "python":
			return "#ffe4b5" // moccasin
		case "maven", "jar":
			return "#f0e68c" // khaki
		case "cargo", "rust":
			return "#ffdab9" // peach puff
		case "nuget", "dotnet":
			return "#e6e6fa" // lavender
		case "gem", "rubygems":
			return "#ffb6c1" // light pink
		case "deb", "debian":
			return "#ffc0cb" // pink
		case "rpm", "redhat":
			return "#f08080" // light coral
		default:
			return "white"
		}
	}

	isFileNode := func(node *normalize.MerkleNode) bool {
		if includeFiles || node == nil || node.SubtreeHash == tree.Root {
			return false
		}
		comp, ok := components[node.ComponentID]
		return ok && comp.Type == cdx.ComponentTypeFile
	}

	// Traversal builds the DOT graph.
	//
	// effectiveParentID is the sanitized ID of the nearest rendered ancestor.
	// When a file-type node is elided we pass the effectiveParentID unchanged
	// to its children, so that A → B(file) → C is rendered as A → C.
	//
	// Nodes are addressed by subtree hash, not by component id: two different
	// components can share a purl only if they have identical subtrees, so
	// keying by subtree hash is always collision-free.
	var traverse func(node *normalize.MerkleNode, depth int, effectiveParentID string)
	traverse = func(node *normalize.MerkleNode, depth int, effectiveParentID string) {
		if node == nil || (maxDepth > 0 && depth > maxDepth) {
			return
		}

		if isFileNode(node) {
			// Elide this node: don't render it, but keep traversing its
			// children with the same effectiveParentID so transitive deps
			// are still connected (A → file → C becomes A → C).
			if visited[node.SubtreeHash] {
				return // already processed this file node, avoid cycles
			}
			visited[node.SubtreeHash] = true
			for _, childHash := range node.Children {
				traverse(tree.Node(childHash), depth+1, effectiveParentID)
			}
			return
		}

		sanitizedID := sanitizeID(node.SubtreeHash.String())

		// Draw the incoming edge from the effective parent (if any).
		if effectiveParentID != "" {
			fmt.Fprintf(&sb, "  \"%s\" -> \"%s\";\n", effectiveParentID, sanitizedID)
		}

		if visited[node.SubtreeHash] {
			return // node already rendered, edge drawn above, stop here
		}
		visited[node.SubtreeHash] = true
		depths[node.SubtreeHash] = depth

		// Render this node.
		label := escapeLabel(getLabel(node))
		color := getNodeColor(node)
		var nodeAttrs string
		if node.SubtreeHash != tree.Root {
			pkgType := getPkgType(node)
			if pkgType != "" {
				nodeAttrs = fmt.Sprintf("label=\"%s\", fillcolor=\"%s\", style=\"rounded,filled\", fontname=\"Courier\"", label, color)
			} else {
				nodeAttrs = fmt.Sprintf("label=\"%s\", fillcolor=\"%s\", style=\"rounded,filled\"", label, color)
			}
		} else {
			nodeAttrs = fmt.Sprintf("label=\"%s\", fillcolor=\"%s\", style=\"rounded,filled\"", label, color)
		}
		fmt.Fprintf(&sb, "  \"%s\" [%s];\n", sanitizedID, nodeAttrs)

		for _, childHash := range node.Children {
			traverse(tree.Node(childHash), depth+1, sanitizedID)
		}
	}

	// Resolve the starting node(s). By default we start at the SBOM root;
	// --from selects every subtree whose component matches the given PURL
	// instead (a component can appear under more than one subtree hash if its
	// dependency set differs by position in the document).
	if fromPURL == "" {
		traverse(tree.RootNode(), 0, "")
	} else {
		var startNodes []*normalize.MerkleNode
		for node := range tree.MerkleNodes() {
			if node.SubtreeHash != tree.Root && strings.EqualFold(node.ComponentID, fromPURL) {
				startNodes = append(startNodes, node)
			}
		}
		if len(startNodes) == 0 {
			return "", fmt.Errorf("PURL %q not found in SBOM", fromPURL)
		}
		for _, node := range startNodes {
			traverse(node, 0, "")
		}
	}

	// Optionally add vulnerability information
	if showVulns {
		sb.WriteString("\n  // Vulnerabilities\n")
		for _, vuln := range vulns {
			if vuln.ID == "" {
				continue
			}
			vulnID := vuln.ID
			sanitizedVulnID := sanitizeID("vuln_" + vulnID)
			label := escapeLabel(vulnID)
			if vuln.Description != "" {
				// Truncate description if too long
				desc := vuln.Description
				if len(desc) > 50 {
					desc = desc[:47] + "..."
				}
				label = escapeLabel(fmt.Sprintf("%s\\n%s", vulnID, desc))
			}
			fmt.Fprintf(&sb, "  \"%s\" [label=\"%s\", fillcolor=red, style=\"rounded,filled\", fontcolor=white, shape=ellipse];\n",
				sanitizedVulnID, label)
		}
	}

	sb.WriteString("}\n")
	return sb.String(), nil
}

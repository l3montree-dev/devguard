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
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
)

func newRenderCommand() *cobra.Command {
	var (
		inputFile                     string
		outputFile                    string
		format                        string
		layout                        string
		fromBOMRef                    string
		maxDepth                      int
		showVulns                     bool
		includeFiles                  bool
		keepOriginalSbomRootComponent bool
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
  devguard-cli sbom render -i sbom.json --show-vulns -o diagram.pdf

  # Limit depth to avoid huge graphs
  devguard-cli sbom render -i sbom.json --max-depth 5 -o diagram.pdf

  # Render only the subgraph rooted at a specific component
  devguard-cli sbom render -i sbom.json --from '/nix/store/h19kjqi10ynjk0i6scllhv82gx45p58w-go-1.25.5.drv' -o go.svg`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return renderSBOM(inputFile, outputFile, format, layout, fromBOMRef, maxDepth, showVulns, includeFiles, keepOriginalSbomRootComponent)
		},
	}

	renderCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input CycloneDX SBOM file (JSON format)")
	renderCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (pdf, png, svg, or dot)")
	renderCmd.Flags().StringVarP(&format, "format", "f", "", "Output format (auto-detected from file extension, or specify: dot, svg, png, pdf)")
	renderCmd.Flags().StringVarP(&layout, "layout", "l", "twopi", "Graphviz layout engine: dot (hierarchical tree, slow on large graphs), twopi (radial tree, best for SBOMs), sfdp (force-directed), fdp, circo")
	renderCmd.Flags().StringVar(&fromBOMRef, "from", "", "Start the graph from this BOM ref instead of the root (renders only the subgraph reachable from this node)")
	renderCmd.Flags().IntVarP(&maxDepth, "max-depth", "d", 0, "Maximum depth of dependency tree to render (0 = unlimited)")
	renderCmd.Flags().BoolVarP(&showVulns, "show-vulns", "v", false, "Show vulnerabilities in the graph")
	renderCmd.Flags().BoolVar(&includeFiles, "include-files", false, "Include 'file' type components (source tarballs, scripts — skipped by default as they cannot match CVEs)")
	renderCmd.Flags().BoolVarP(&keepOriginalSbomRootComponent, "keep-root-component", "", false, "Keep the original SBOM root component instead of replacing it with an info source node")

	if err := renderCmd.MarkFlagRequired("input"); err != nil {
		slog.Error("Failed to mark input flag as required", "err", err)
	}

	return renderCmd
}

func renderSBOM(inputFile, outputFile, format, layout, fromBOMRef string, maxDepth int, showVulns, includeFiles, keepOriginalSbomRootComponent bool) error {
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

	// Convert to SBOMGraph
	graph, err := normalize.SBOMGraphFromCycloneDX(&bom, inputFile, "cli-render", keepOriginalSbomRootComponent)
	if err != nil {
		return fmt.Errorf("failed to convert SBOM to graph: %w", err)
	}

	// Generate DOT format
	dotContent, err := generateDOT(graph, layout, fromBOMRef, maxDepth, showVulns, includeFiles)
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

func generateDOT(graph *normalize.SBOMGraph, layout, fromBOMRef string, maxDepth int, showVulns, includeFiles bool) (string, error) {
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

	visited := make(map[string]bool)
	depths := make(map[string]int)

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

	// Helper to get node label
	getLabel := func(node *normalize.GraphNode) string {
		if node == nil {
			return ""
		}

		switch node.Type {
		case normalize.GraphNodeTypeRoot:
			return "ROOT"
		case normalize.GraphNodeTypeArtifact:
			return strings.TrimPrefix(node.BOMRef, "artifact:")
		case normalize.GraphNodeTypeInfoSource:
			return fmt.Sprintf("%s: %s", node.InfoType, strings.TrimPrefix(node.BOMRef, string(node.InfoType)+":"))
		case normalize.GraphNodeTypeComponent:
			// Try to use PURL from component
			if node.Component != nil && node.Component.PackageURL != "" {
				label, _ := formatPURL(node.Component.PackageURL)
				return label
			}
			// Fallback to component name/version
			if node.Component != nil {
				name := node.Component.Name
				if node.Component.Version != "" {
					name = fmt.Sprintf("%s@%s", name, node.Component.Version)
				}
				return name
			}
			return node.BOMRef
		default:
			return node.BOMRef
		}
	}

	// Helper to get package type for styling
	getPkgType := func(node *normalize.GraphNode) string {
		if node != nil && node.Type == normalize.GraphNodeTypeComponent && node.Component != nil && node.Component.PackageURL != "" {
			_, pkgType := formatPURL(node.Component.PackageURL)
			return pkgType
		}
		return ""
	}

	// Helper to get node color based on type and package type
	getNodeColor := func(node *normalize.GraphNode) string {
		if node == nil {
			return "lightgray"
		}

		switch node.Type {
		case normalize.GraphNodeTypeRoot:
			return "lightblue"
		case normalize.GraphNodeTypeArtifact:
			return "lightgreen"
		case normalize.GraphNodeTypeInfoSource:
			return "lightyellow"
		case normalize.GraphNodeTypeComponent:
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
		default:
			return "lightgray"
		}
	}

	// Traversal builds the DOT graph.
	//
	// effectiveParentID is the sanitized ID of the nearest rendered ancestor.
	// When a file-type node is elided we pass the effectiveParentID unchanged
	// to its children, so that A → B(file) → C is rendered as A → C.
	var traverse func(node *normalize.GraphNode, depth int, effectiveParentID string)
	traverse = func(node *normalize.GraphNode, depth int, effectiveParentID string) {
		if node == nil || (maxDepth > 0 && depth > maxDepth) {
			return
		}

		isFileNode := !includeFiles &&
			node.Type == normalize.GraphNodeTypeComponent &&
			node.Component != nil &&
			node.Component.Type == cdx.ComponentTypeFile

		if isFileNode {
			// Elide this node: don't render it, but keep traversing its
			// children with the same effectiveParentID so transitive deps
			// are still connected (A → file → C becomes A → C).
			if visited[node.BOMRef] {
				return // already processed this file node, avoid cycles
			}
			visited[node.BOMRef] = true
			for child := range graph.Children(node.BOMRef) {
				traverse(child, depth+1, effectiveParentID)
			}
			return
		}

		sanitizedID := sanitizeID(node.BOMRef)

		// Draw the incoming edge from the effective parent (if any).
		if effectiveParentID != "" {
			fmt.Fprintf(&sb, "  \"%s\" -> \"%s\";\n", effectiveParentID, sanitizedID)
		}

		if visited[node.BOMRef] {
			return // node already rendered, edge drawn above, stop here
		}
		visited[node.BOMRef] = true
		depths[node.BOMRef] = depth

		// Render this node.
		label := escapeLabel(getLabel(node))
		color := getNodeColor(node)
		var nodeAttrs string
		if node.Type == normalize.GraphNodeTypeComponent {
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

		for child := range graph.Children(node.BOMRef) {
			traverse(child, depth+1, sanitizedID)
		}
	}

	// Resolve the starting node.
	startBOMRef := normalize.GraphRootNodeID
	if fromBOMRef != "" {
		startBOMRef = fromBOMRef
	}
	startNode := graph.Node(startBOMRef)
	if startNode == nil {
		return "", fmt.Errorf("BOM ref %q not found in SBOM", startBOMRef)
	}
	traverse(startNode, 0, "")

	// Optionally add vulnerability information
	if showVulns {
		sb.WriteString("\n  // Vulnerabilities\n")
		for vuln := range graph.Vulnerabilities() {
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

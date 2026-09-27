package config

import (
	"fmt"
	"strconv"
	"strings"
)

// A parser for the subset of YAML this configuration file uses.
//
// Taking a YAML library would be one more module in a program whose whole
// pitch is a single static binary with no supply chain to audit, for a file
// that is forty lines of key/value. So this parses exactly what the documented
// configuration uses — nested maps by indentation, scalar values, lists of
// scalars, and lists of maps — and returns a clear error for anything else
// rather than guessing.
//
// What it does NOT support, deliberately: anchors, aliases, multi-document
// files, flow syntax, block scalars, tags. If the configuration ever needs
// those, that is the signal to take the dependency, not to grow this.

type yamlNode struct {
	scalar   string
	mapping  map[string]*yamlNode
	sequence []*yamlNode
	isScalar bool
}

type yamlLine struct {
	indent  int
	content string
	number  int
}

func parseYAML(source string) (*yamlNode, error) {
	lines := make([]yamlLine, 0, 64)
	for number, raw := range strings.Split(source, "\n") {
		text := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimLeft(text, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(text, "\t") && strings.HasPrefix(text, "\t") {
			return nil, fmt.Errorf("config: line %d is indented with a tab; YAML requires spaces", number+1)
		}
		lines = append(lines, yamlLine{indent: len(text) - len(trimmed), content: trimmed, number: number + 1})
	}
	node, consumed, err := parseBlock(lines, 0)
	if err != nil {
		return nil, err
	}
	if consumed != len(lines) {
		return nil, fmt.Errorf("config: line %d: unexpected indentation", lines[consumed].number)
	}
	return node, nil
}

// parseBlock consumes every line at the given indent and returns the node they
// describe together with how many lines it used.
func parseBlock(lines []yamlLine, indent int) (*yamlNode, int, error) {
	if len(lines) == 0 {
		return &yamlNode{mapping: map[string]*yamlNode{}}, 0, nil
	}
	if strings.HasPrefix(lines[0].content, "- ") || lines[0].content == "-" {
		return parseSequence(lines, indent)
	}
	node := &yamlNode{mapping: make(map[string]*yamlNode)}
	consumed := 0
	for consumed < len(lines) {
		line := lines[consumed]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return nil, 0, fmt.Errorf("config: line %d: unexpected indentation", line.number)
		}
		key, rest, found := splitKey(line.content)
		if !found {
			return nil, 0, fmt.Errorf("config: line %d: expected `key: value`", line.number)
		}
		key = strings.TrimSpace(key)
		rest = strings.TrimSpace(rest)
		consumed++
		if rest != "" {
			node.mapping[key] = &yamlNode{scalar: unquote(rest), isScalar: true}
			continue
		}
		child, used, err := parseChild(lines[consumed:], indent)
		if err != nil {
			return nil, 0, err
		}
		node.mapping[key] = child
		consumed += used
	}
	return node, consumed, nil
}

// parseChild reads the indented block belonging to a key that had no inline
// value. A key with nothing under it is an empty mapping, not an error: an
// operator commenting out every entry under `rules:` should not break startup.
func parseChild(lines []yamlLine, parentIndent int) (*yamlNode, int, error) {
	if len(lines) == 0 || lines[0].indent <= parentIndent {
		if len(lines) > 0 && lines[0].indent == parentIndent && strings.HasPrefix(lines[0].content, "- ") {
			return parseSequence(lines, parentIndent)
		}
		return &yamlNode{mapping: map[string]*yamlNode{}}, 0, nil
	}
	return parseBlock(lines, lines[0].indent)
}

func parseSequence(lines []yamlLine, indent int) (*yamlNode, int, error) {
	node := &yamlNode{sequence: make([]*yamlNode, 0, 4)}
	consumed := 0
	for consumed < len(lines) {
		line := lines[consumed]
		if line.indent != indent || !strings.HasPrefix(line.content, "-") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(line.content, "-"))
		consumed++
		if item == "" {
			child, used, err := parseChild(lines[consumed:], indent)
			if err != nil {
				return nil, 0, err
			}
			node.sequence = append(node.sequence, child)
			consumed += used
			continue
		}
		if key, rest, found := splitKey(item); found {
			// `- key: value` starts a map whose remaining keys are indented
			// past the dash.
			entry := &yamlNode{mapping: map[string]*yamlNode{
				strings.TrimSpace(key): {scalar: unquote(strings.TrimSpace(rest)), isScalar: true},
			}}
			for consumed < len(lines) && lines[consumed].indent > indent {
				follow := lines[consumed]
				followKey, followValue, ok := splitKey(follow.content)
				if !ok {
					return nil, 0, fmt.Errorf("config: line %d: expected `key: value`", follow.number)
				}
				entry.mapping[strings.TrimSpace(followKey)] = &yamlNode{scalar: unquote(strings.TrimSpace(followValue)), isScalar: true}
				consumed++
			}
			node.sequence = append(node.sequence, entry)
			continue
		}
		node.sequence = append(node.sequence, &yamlNode{scalar: unquote(item), isScalar: true})
	}
	return node, consumed, nil
}

// splitKey splits `key: value` the way YAML does: the colon only separates
// when followed by a space or the end of the line, so a URL or host:port is
// a scalar, not a mapping.
func splitKey(text string) (key, value string, ok bool) {
	if strings.HasPrefix(text, "\"") || strings.HasPrefix(text, "'") {
		return "", "", false
	}
	if index := strings.Index(text, ": "); index >= 0 {
		return text[:index], text[index+2:], true
	}
	if strings.HasSuffix(text, ":") {
		return text[:len(text)-1], "", true
	}
	return "", "", false
}

func unquote(text string) string {
	if len(text) >= 2 {
		if (text[0] == '"' && text[len(text)-1] == '"') || (text[0] == '\'' && text[len(text)-1] == '\'') {
			return text[1 : len(text)-1]
		}
	}
	if index := strings.Index(text, " #"); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return text
}

func (n *yamlNode) child(path ...string) *yamlNode {
	current := n
	for _, key := range path {
		if current == nil || current.mapping == nil {
			return nil
		}
		current = current.mapping[key]
	}
	return current
}

func (n *yamlNode) stringOr(fallback string, path ...string) string {
	node := n.child(path...)
	if node == nil || !node.isScalar || node.scalar == "" {
		return fallback
	}
	return node.scalar
}

func (n *yamlNode) intOr(fallback int, path ...string) int {
	node := n.child(path...)
	if node == nil || !node.isScalar {
		return fallback
	}
	value, err := strconv.Atoi(node.scalar)
	if err != nil {
		return fallback
	}
	return value
}

func (n *yamlNode) boolOr(fallback bool, path ...string) bool {
	node := n.child(path...)
	if node == nil || !node.isScalar {
		return fallback
	}
	switch strings.ToLower(node.scalar) {
	case "true", "yes", "on", "1":
		return true
	case "false", "no", "off", "0":
		return false
	default:
		return fallback
	}
}

func (n *yamlNode) strings(path ...string) []string {
	node := n.child(path...)
	if node == nil || node.sequence == nil {
		return nil
	}
	out := make([]string, 0, len(node.sequence))
	for _, item := range node.sequence {
		if item.isScalar {
			out = append(out, item.scalar)
		}
	}
	return out
}

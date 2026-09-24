package firewall

import (
	"fmt"
	"strconv"
	"strings"
)

const Chain = "SEC_REMEDIATOR_INPUT"

type Command struct {
	Args []string
	Undo []string
}

type portRule struct {
	Protocol string
	Port     int
}

var requiredRules = []portRule{
	{Protocol: "tcp", Port: 22},
	{Protocol: "tcp", Port: 135},
	{Protocol: "udp", Port: 137},
	{Protocol: "udp", Port: 138},
	{Protocol: "tcp", Port: 139},
	{Protocol: "tcp", Port: 445},
	{Protocol: "tcp", Port: 3389},
	{Protocol: "udp", Port: 3389},
}

var legacyRules = []portRule{
	{Protocol: "tcp", Port: 136},
	{Protocol: "udp", Port: 136},
}

func cemsCoverage(saveOutput string) (covered []portRule, missing []portRule, managed bool) {
	lines := normalizedLines(saveOutput)
	managed = contains(lines, "-A INPUT -j CEMS_COMMON_INPUT")
	if !managed {
		return nil, nil, false
	}
	for _, required := range requiredRules {
		if cemsDecision(lines, required) == "DROP" {
			covered = append(covered, required)
		} else {
			missing = append(missing, required)
		}
	}
	return covered, missing, true
}

func cemsDecision(lines []string, required portRule) string {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "-A" || fields[1] != "CEMS_COMMON_INPUT" {
			continue
		}
		if !ruleMatchesPort(fields, required) {
			continue
		}
		target := optionValue(fields, "-j")
		if target == "DROP" || target == "REJECT" {
			return "DROP"
		}
		if target == "ACCEPT" {
			return "ACCEPT"
		}
	}
	return ""
}

func ruleMatchesPort(fields []string, required portRule) bool {
	protocol := optionValue(fields, "-p")
	if protocol != "" && protocol != required.Protocol {
		return false
	}
	if optionValue(fields, "--sport") != "" || optionValue(fields, "--sports") != "" {
		return false
	}
	for _, option := range []string{"-s", "--source", "-i", "--in-interface"} {
		if optionValue(fields, option) != "" {
			return false
		}
	}
	ports := optionValue(fields, "--dport")
	if ports == "" {
		ports = optionValue(fields, "--dports")
	}
	if ports == "" {
		return true
	}
	return portListContains(ports, required.Port)
}

func optionValue(fields []string, option string) string {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == option {
			return strings.Trim(fields[index+1], "\"")
		}
	}
	return ""
}

func portListContains(value string, port int) bool {
	for _, part := range strings.Split(value, ",") {
		bounds := strings.SplitN(part, ":", 2)
		start, err := strconv.Atoi(bounds[0])
		if err != nil {
			continue
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(bounds[1])
			if err != nil {
				continue
			}
		}
		if port >= start && port <= end {
			return true
		}
	}
	return false
}

func BuildPlan(saveOutput string) ([]Command, error) {
	lines := normalizedLines(saveOutput)
	hasChain := false
	for _, line := range lines {
		if line == "-N "+Chain || strings.HasPrefix(line, ":"+Chain+" ") {
			hasChain = true
			break
		}
	}
	var plan []Command
	if !hasChain {
		plan = append(plan, Command{Args: []string{"-N", Chain}, Undo: []string{"-X", Chain}})
	}
	inputJumps := managedInputJumpPositions(lines)
	insertedJump := firstInputJump(lines) != "-A INPUT -j "+Chain
	if insertedJump {
		plan = append(plan, Command{
			Args: []string{"-I", "INPUT", "1", "-j", Chain},
			Undo: []string{"-D", "INPUT", "-j", Chain},
		})
	}
	keepPosition := -1
	if !insertedJump && len(inputJumps) > 0 && inputJumps[0] == 1 {
		keepPosition = 1
	}
	shift := 0
	if insertedJump {
		shift = 1
	}
	for index := len(inputJumps) - 1; index >= 0; index-- {
		position := inputJumps[index]
		if position == keepPosition {
			continue
		}
		actualPosition := fmt.Sprint(position + shift)
		plan = append(plan, Command{
			Args: []string{"-D", "INPUT", actualPosition},
			Undo: []string{"-I", "INPUT", actualPosition, "-j", Chain},
		})
	}
	for _, rule := range requiredRules {
		count := countManagedRule(lines, rule)
		for duplicate := 1; duplicate < count; duplicate++ {
			plan = append(plan, Command{Args: ruleArgs("-D", rule), Undo: ruleArgs("-A", rule)})
		}
		if count == 0 {
			plan = append(plan, Command{Args: ruleArgs("-A", rule), Undo: ruleArgs("-D", rule)})
		}
	}
	plan = append(plan, legacyCleanupPlan(saveOutput)...)
	return plan, nil
}

func legacyCleanupPlan(saveOutput string) []Command {
	lines := normalizedLines(saveOutput)
	var plan []Command
	for _, rule := range legacyRules {
		for count := countManagedRule(lines, rule); count > 0; count-- {
			plan = append(plan, Command{Args: ruleArgs("-D", rule), Undo: ruleArgs("-A", rule)})
		}
	}
	return plan
}

func ExpectedSaveFixture() string {
	lines := []string{"-P INPUT ACCEPT", "-N " + Chain, "-A INPUT -j " + Chain}
	for _, rule := range requiredRules {
		lines = append(lines, ruleLine(rule))
	}
	return strings.Join(lines, "\n")
}

func ruleArgs(operation string, rule portRule) []string {
	return []string{operation, Chain, "-p", rule.Protocol, "--dport", fmt.Sprint(rule.Port),
		"-m", "comment", "--comment", "SecurityRemediator", "-j", "DROP"}
}

func ruleLine(rule portRule) string {
	return strings.Join(ruleArgs("-A", rule), " ")
}

func normalizedLines(output string) []string {
	var result []string
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func firstInputJump(lines []string) string {
	for _, line := range lines {
		if strings.HasPrefix(line, "-A INPUT ") {
			return line
		}
	}
	return ""
}

func contains(lines []string, expected string) bool {
	for _, line := range lines {
		if line == expected {
			return true
		}
	}
	return false
}

func countLine(lines []string, expected string) int {
	count := 0
	for _, line := range lines {
		if line == expected {
			count++
		}
	}
	return count
}

func countManagedRule(lines []string, rule portRule) int {
	expected := canonicalManagedRule(ruleLine(rule), rule.Protocol)
	count := 0
	for _, line := range lines {
		if canonicalManagedRule(line, rule.Protocol) == expected {
			count++
		}
	}
	return count
}

func canonicalManagedRule(line, protocol string) string {
	fields := strings.Fields(line)
	result := make([]string, 0, len(fields))
	for index := 0; index < len(fields); index++ {
		field := strings.Trim(fields[index], "\"")
		if field == "-m" && index+1 < len(fields) && strings.Trim(fields[index+1], "\"") == protocol {
			index++
			continue
		}
		result = append(result, field)
	}
	return strings.Join(result, " ")
}

func managedInputJumpPositions(lines []string) []int {
	position := 0
	var result []int
	for _, line := range lines {
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		position++
		if line == "-A INPUT -j "+Chain {
			result = append(result, position)
		}
	}
	return result
}

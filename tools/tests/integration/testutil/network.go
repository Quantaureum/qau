// Quantaureum Node source, version 1.0.0.
//go:build integration || e2e || chaos

// Package testutil provides utilities for integration testing.
package testutil

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// NetworkController provides control over the test network.
type NetworkController struct {
	composeFile string
	projectDir  string
}

// NewNetworkController creates a new network controller.
func NewNetworkController(composeFile, projectDir string) *NetworkController {
	return &NetworkController{
		composeFile: composeFile,
		projectDir:  projectDir,
	}
}

// StartNetwork starts the test network.
func (nc *NetworkController) StartNetwork(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker-compose", "-f", nc.composeFile, "up", "-d")
	cmd.Dir = nc.projectDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start network: %w, output: %s", err, string(output))
	}
	return nil
}

// StopNetwork stops the test network.
func (nc *NetworkController) StopNetwork(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker-compose", "-f", nc.composeFile, "down", "-v", "--remove-orphans")
	cmd.Dir = nc.projectDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop network: %w, output: %s", err, string(output))
	}
	return nil
}

// RestartNode restarts a specific node.
func (nc *NetworkController) RestartNode(ctx context.Context, nodeName string) error {
	cmd := exec.CommandContext(ctx, "docker-compose", "-f", nc.composeFile, "restart", nodeName)
	cmd.Dir = nc.projectDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart node %s: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

// StopNode stops a specific node.
func (nc *NetworkController) StopNode(ctx context.Context, nodeName string) error {
	cmd := exec.CommandContext(ctx, "docker-compose", "-f", nc.composeFile, "stop", nodeName)
	cmd.Dir = nc.projectDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop node %s: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

// StartNode starts a specific node.
func (nc *NetworkController) StartNode(ctx context.Context, nodeName string) error {
	cmd := exec.CommandContext(ctx, "docker-compose", "-f", nc.composeFile, "start", nodeName)
	cmd.Dir = nc.projectDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start node %s: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

// PauseNode pauses a specific node (simulates network partition).
func (nc *NetworkController) PauseNode(ctx context.Context, nodeName string) error {
	containerName := fmt.Sprintf("qau-%s", nodeName)
	cmd := exec.CommandContext(ctx, "docker", "pause", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to pause node %s: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

// UnpauseNode unpauses a specific node.
func (nc *NetworkController) UnpauseNode(ctx context.Context, nodeName string) error {
	containerName := fmt.Sprintf("qau-%s", nodeName)
	cmd := exec.CommandContext(ctx, "docker", "unpause", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unpause node %s: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

// GetNodeLogs gets logs from a specific node.
func (nc *NetworkController) GetNodeLogs(ctx context.Context, nodeName string, lines int) (string, error) {
	cmd := exec.CommandContext(ctx, "docker-compose", "-f", nc.composeFile, "logs", "--tail", fmt.Sprintf("%d", lines), nodeName)
	cmd.Dir = nc.projectDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get logs for node %s: %w", nodeName, err)
	}
	return string(output), nil
}

// IsNodeHealthy checks if a node is healthy.
func (nc *NetworkController) IsNodeHealthy(ctx context.Context, nodeName string) (bool, error) {
	containerName := fmt.Sprintf("qau-%s", nodeName)
	cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Health.Status}}", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check health for node %s: %w", nodeName, err)
	}
	status := strings.TrimSpace(string(output))
	return status == "healthy", nil
}

// WaitForNodeHealthy waits for a node to become healthy.
func (nc *NetworkController) WaitForNodeHealthy(ctx context.Context, nodeName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		healthy, err := nc.IsNodeHealthy(ctx, nodeName)
		if err == nil && healthy {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			// Retry
		}
	}

	return fmt.Errorf("timeout waiting for node %s to become healthy", nodeName)
}

// DisconnectNodeNetwork disconnects a node from the network (simulates network partition).
func (nc *NetworkController) DisconnectNodeNetwork(ctx context.Context, nodeName string) error {
	containerName := fmt.Sprintf("qau-%s", nodeName)
	cmd := exec.CommandContext(ctx, "docker", "network", "disconnect", "qau-testnet", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disconnect node %s from network: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

// ReconnectNodeNetwork reconnects a node to the network.
func (nc *NetworkController) ReconnectNodeNetwork(ctx context.Context, nodeName string) error {
	containerName := fmt.Sprintf("qau-%s", nodeName)
	cmd := exec.CommandContext(ctx, "docker", "network", "connect", "qau-testnet", containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reconnect node %s to network: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

// InjectLatency injects network latency to a node.
func (nc *NetworkController) InjectLatency(ctx context.Context, nodeName string, latencyMs int) error {
	containerName := fmt.Sprintf("qau-%s", nodeName)
	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", fmt.Sprintf("%dms", latencyMs))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to inject latency to node %s: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

// RemoveLatency removes injected network latency from a node.
func (nc *NetworkController) RemoveLatency(ctx context.Context, nodeName string) error {
	containerName := fmt.Sprintf("qau-%s", nodeName)
	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "tc", "qdisc", "del", "dev", "eth0", "root")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove latency from node %s: %w, output: %s", nodeName, err, string(output))
	}
	return nil
}

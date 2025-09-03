#!/bin/bash

# Copyright 2025 l3montree GmbH.
# SPDX-License-Identifier: AGPL-3.0-or-later

# Test script for DevGuard Helm chart installation and basic functionality testing using minikube

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="devguard-test"
RELEASE_NAME="devguard-test"
CHART_PATH="./charts/devguard"
TIMEOUT="600s"
MINIKUBE_PROFILE="devguard-test"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to cleanup resources
cleanup() {
    print_status "Cleaning up resources..."
    
    # Delete helm release if it exists
    if helm list -n "$NAMESPACE" | grep -q "$RELEASE_NAME"; then
        print_status "Uninstalling Helm release..."
        helm uninstall "$RELEASE_NAME" -n "$NAMESPACE" || true
    fi
    
    # Delete namespace if it exists
    if kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
        print_status "Deleting namespace..."
        kubectl delete namespace "$NAMESPACE" --timeout=60s || true
    fi
    
    # Stop and delete minikube profile
    print_status "Stopping minikube..."
    minikube stop -p "$MINIKUBE_PROFILE" || true
    minikube delete -p "$MINIKUBE_PROFILE" || true
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Function to wait for deployment to be ready
wait_for_deployment() {
    local deployment_name=$1
    local namespace=$2
    local timeout=${3:-300}
    
    print_status "Waiting for deployment $deployment_name to be ready..."
    kubectl wait --for=condition=available deployment/"$deployment_name" -n "$namespace" --timeout="${timeout}s"
}

# Function to check pod status
check_pod_status() {
    local namespace=$1
    print_status "Checking pod status in namespace $namespace..."
    kubectl get pods -n "$namespace" -o wide
    
    # Check if any pods are in error state
    local failed_pods=$(kubectl get pods -n "$namespace" --field-selector=status.phase=Failed --no-headers 2>/dev/null | wc -l)
    if [ "$failed_pods" -gt 0 ]; then
        print_error "Found $failed_pods failed pods"
        kubectl get pods -n "$namespace" --field-selector=status.phase=Failed
        return 1
    fi
    
    # Check for pods in CrashLoopBackOff or ImagePullBackOff
    local problematic_pods=$(kubectl get pods -n "$namespace" --no-headers 2>/dev/null | grep -E "(CrashLoopBackOff|ImagePullBackOff|Error)" | wc -l)
    if [ "$problematic_pods" -gt 0 ]; then
        print_error "Found $problematic_pods pods with issues"
        kubectl get pods -n "$namespace" | grep -E "(CrashLoopBackOff|ImagePullBackOff|Error)"
        return 1
    fi
    
    return 0
}

# Function to test basic connectivity
test_connectivity() {
    local namespace=$1
    print_status "Testing basic connectivity..."
    
    # Get service information
    kubectl get services -n "$namespace"
    
    # Test if services are accessible (port-forward test)
    local api_service=$(kubectl get service -n "$namespace" -l app.kubernetes.io/name=devguard -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    local web_service=$(kubectl get service -n "$namespace" -l app.kubernetes.io/name=devguard-web -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -n "$api_service" ]; then
        print_status "Testing API service connectivity..."
        kubectl port-forward -n "$namespace" service/"$api_service" 8080:80 &
        local pf_pid=$!
        sleep 5
        
        # Test connection
        if curl -s --max-time 10 http://localhost:8080/health > /dev/null 2>&1; then
            print_success "API service is responding"
        else
            print_warning "API service health check failed (this might be expected if health endpoint is not available)"
        fi
        
        kill $pf_pid 2>/dev/null || true
        wait $pf_pid 2>/dev/null || true
    fi
}

# Function to validate helm chart
validate_chart() {
    print_status "Validating Helm chart..."
    
    # Check if chart directory exists
    if [ ! -d "$CHART_PATH" ]; then
        print_error "Chart directory $CHART_PATH not found"
        exit 1
    fi
    
    # Lint the chart
    print_status "Linting Helm chart..."
    helm lint "$CHART_PATH"
    
    # Dry run template rendering
    print_status "Testing template rendering..."
    helm template "$RELEASE_NAME" "$CHART_PATH" --namespace "$NAMESPACE" > /dev/null
    
    print_success "Chart validation completed"
}

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check if required tools are installed
    local missing_tools=()
    
    if ! command -v minikube >/dev/null 2>&1; then
        missing_tools+=("minikube")
    fi
    
    if ! command -v kubectl >/dev/null 2>&1; then
        missing_tools+=("kubectl")
    fi
    
    if ! command -v helm >/dev/null 2>&1; then
        missing_tools+=("helm")
    fi
    
    if ! command -v docker >/dev/null 2>&1; then
        missing_tools+=("docker")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    
    print_success "All required tools are available"
}

# Main test function
main() {
    print_status "Starting DevGuard Helm chart test..."
    
    # Check requirements
    check_requirements
    
    # Validate chart
    validate_chart
    
    # Start minikube
    print_status "Starting minikube with profile: $MINIKUBE_PROFILE..."
    minikube start --driver=docker --profile="$MINIKUBE_PROFILE" --kubernetes-version=stable
    
    # Set kubectl context
    kubectl config use-context "$MINIKUBE_PROFILE"
    
    # Wait for minikube to be ready
    print_status "Waiting for minikube to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=300s
    
    # Create namespace
    print_status "Creating namespace: $NAMESPACE..."
    kubectl create namespace "$NAMESPACE" || true
    
    # Create required secrets for testing (with dummy values)
    print_status "Creating test secrets..."
    kubectl create secret generic ec-private-key \
        --from-literal=privateKey="dummy-private-key" \
        -n "$NAMESPACE" || true
    
    kubectl create secret generic github-app-webhook-secret \
        --from-literal=webhookSecret="dummy-webhook-secret" \
        -n "$NAMESPACE" || true
    
    kubectl create secret generic github-app-private-key \
        --from-literal=privateKey="dummy-github-private-key" \
        -n "$NAMESPACE" || true
    
    # Install the chart
    print_status "Installing DevGuard Helm chart..."
    helm install "$RELEASE_NAME" "$CHART_PATH" \
        --namespace "$NAMESPACE" \
        --wait \
        --timeout="$TIMEOUT"
    
    # Check deployment status
    print_status "Checking deployment status..."
    helm status "$RELEASE_NAME" -n "$NAMESPACE"
    
    # Wait for deployments to be ready
    print_status "Waiting for deployments to be ready..."
    
    # Get all deployments in the namespace
    local deployments=$(kubectl get deployments -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
    
    for deployment in $deployments; do
        wait_for_deployment "$deployment" "$NAMESPACE" 300
    done
    
    # Check pod status
    check_pod_status "$NAMESPACE"
    
    # Test basic connectivity
    test_connectivity "$NAMESPACE"
    
    # Run additional tests
    print_status "Running additional validation tests..."
    
    # Check if all expected resources are created
    local expected_deployments=("devguard-api-deployment" "devguard-web-deployment" "kratos")
    for deployment in "${expected_deployments[@]}"; do
        if kubectl get deployment "$deployment" -n "$NAMESPACE" >/dev/null 2>&1; then
            print_success "Deployment $deployment exists"
        else
            print_warning "Deployment $deployment not found"
        fi
    done

    if kubectl get statefulset "postgresql" -n "$NAMESPACE" >/dev/null 2>&1; then
        print_success "Stafulset postgresql exists"
    else
        print_warning "Stafulset postgresql not found"
    fi
    
    # Check services
    local services=$(kubectl get services -n "$NAMESPACE" --no-headers | wc -l)
    print_status "Found $services services in namespace"
    
    # Check configmaps and secrets
    local configmaps=$(kubectl get configmaps -n "$NAMESPACE" --no-headers | wc -l)
    local secrets=$(kubectl get secrets -n "$NAMESPACE" --no-headers | wc -l)
    print_status "Found $configmaps configmaps and $secrets secrets"
    
    print_success "DevGuard Helm chart test completed successfully!"
}

# Run main function
main "$@"

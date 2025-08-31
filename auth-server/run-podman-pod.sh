#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 [--start | --stop-service SERVICE | --stop-all]"
    echo "Options:"
    echo "  --start            Start the pod and all services"
    echo "  --stop-service SERVICE  Stop and remove a specific service (db or redis)"
    echo "  --stop-all         Stop and remove the entire pod and all services"
    exit 1
}

# Check if podman is installed
if ! command -v podman &> /dev/null; then
    echo "Podman is not installed. Please install Podman and try again."
    exit 1
fi

# Check if envsubst is installed
if ! command -v envsubst &> /dev/null; then
    echo "envsubst is not installed. Please install gettext (which includes envsubst) and try again."
    exit 1
fi

# Parse command-line arguments
ACTION=""
SERVICE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --start)
            ACTION="start"
            shift
            ;;
        --stop-service)
            ACTION="stop-service"
            SERVICE="$2"
            shift 2
            ;;
        --stop-all)
            ACTION="stop-all"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# If no action specified, default to usage
if [ -z "$ACTION" ]; then
    usage
fi

# Function to perform environment variable substitution
substitute_env_vars() {
    # Check if the YAML file exists
    if [ ! -f podman-pod.yaml ]; then
        echo "podman-pod.yaml not found in the current directory."
        exit 1
    fi

    # Load environment variables from .env file if it exists
    if [ -f .env ]; then
        source .env
    else
        echo "Warning: .env file not found. Ensure environment variables (DB_USER, DB_PASSWORD, DB_NAME, DB_PORT, REDIS_PORT) are set."
    fi

    # Check for required environment variables
    required_vars=("DB_USER" "DB_PASSWORD" "DB_NAME" "DB_PORT" "REDIS_PORT")
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            echo "Error: Environment variable $var is not set."
            exit 1
        fi
    done

    # Perform environment variable substitution
    echo "Substituting environment variables in podman-pod.yaml..."
    envsubst < podman-pod.yaml > podman-pod-processed.yaml

    # Check if substitution was successful
    if [ ! -f podman-pod-processed.yaml ]; then
        echo "Error: Failed to create podman-pod-processed.yaml."
        exit 1
    fi
}

# Function to clean up temporary file
cleanup() {
    rm -f podman-pod-processed.yaml
    echo "Cleaned up temporary file."
}

# Handle actions
case "$ACTION" in
    start)
        substitute_env_vars
        echo "Running pod with podman play kube..."
        podman play kube podman-pod-processed.yaml
        if [ $? -eq 0 ]; then
            echo "Pod started successfully. Checking pod status..."
            podman pod ls
        else
            echo "Error: Failed to start the pod."
            cleanup
            exit 1
        fi
        cleanup
        ;;
    stop-service)
        if [ "$SERVICE" != "db" ] && [ "$SERVICE" != "redis" ]; then
            echo "Error: Service must be 'db' or 'redis'."
            usage
        fi
        echo "Stopping and removing $SERVICE service..."
        podman stop app-pod-$SERVICE
        if [ $? -eq 0 ]; then
            echo "Service $SERVICE stopped successfully."
        else
            echo "Error: Failed to stop service $SERVICE."
            exit 1
        fi
        podman rm app-pod-$SERVICE
        if [ $? -eq 0 ]; then
            echo "Service $SERVICE removed successfully."
            podman ps -a --pod
        else
            echo "Error: Failed to remove service $SERVICE."
            exit 1
        fi
        ;;
    stop-all)
        substitute_env_vars
        echo "Taking down pod with podman play kube --down..."
        podman play kube --down podman-pod-processed.yaml
        if [ $? -eq 0 ]; then
            echo "Pod and services stopped and removed successfully."
            podman pod ls
        else
            echo "Error: Failed to take down the pod."
            cleanup
            exit 1
        fi
        cleanup
        ;;
esac

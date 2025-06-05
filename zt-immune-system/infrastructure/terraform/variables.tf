# /infrastructure/terraform/variables.tf
# Placeholder for Terraform variable definitions.
# Define variables here to parameterize your Terraform configurations.

# --- General Configuration Variables ---
variable "environment" {
  description = "The deployment environment (e.g., dev, staging, prod)."
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod", "test"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod, test."
  }
}

variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "us-east-1"
  # Add validation for valid AWS regions if desired
}

# variable "gcp_project_id" {
#   description = "The GCP project ID."
#   type        = string
#   # No default, should be explicitly set
# }

# variable "gcp_region" {
#   description = "The GCP region."
#   type        = string
#   default     = "us-central1"
# }

# variable "azure_location" {
#   description = "The Azure location (region)."
#   type        = string
#   default     = "East US"
# }

# --- Networking Variables ---
variable "vpc_cidr_block" {
  description = "The CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
  # Add CIDR validation if needed
}

# variable "subnet_cidr_blocks" {
#   description = "A list of CIDR blocks for subnets."
#   type        = list(string)
#   default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
# }

# --- Kubernetes Specific Variables ---
variable "kubernetes_namespace" {
  description = "The Kubernetes namespace for ZT Immune System components."
  type        = string
  default     = "zt-immune-system"
}

# variable "kube_context" {
#   description = "The kubectl context to use (if multiple are configured in kubeconfig)."
#   type        = string
#   default     = null # Terraform will use the current context if null
# }

# variable "cluster_name" {
#   description = "Name for the Kubernetes cluster (e.g., EKS, GKE, AKS cluster name)."
#   type        = string
#   default     = "zt-k8s-cluster"
# }

# --- Docker Image Variables ---
variable "image_tag" {
  description = "The Docker image tag to use for deployments (e.g., latest, v1.0.0)."
  type        = string
  default     = "latest"
}

# variable "docker_registry_url" {
#   description = "URL of the Docker registry where images are stored/pushed."
#   type        = string
#   # default     = "your-docker-registry.example.com" # Set your default or leave empty
# }


# --- Sensitive Variables (Example - consider using .tfvars files or environment variables) ---
# variable "db_password" {
#   description = "Password for the database."
#   type        = string
#   sensitive   = true # Marks the variable as sensitive, preventing its output in logs/CLI.
#   # No default for sensitive variables is a good practice.
# }

# variable "api_key_threat_intel" {
#   description = "API key for an external threat intelligence service."
#   type        = string
#   sensitive   = true
# }

# --- How to Use These Variables ---
# 1. Default values are used if no other value is provided.
# 2. Override defaults by:
#    a. Creating a `terraform.tfvars` file (e.g., `environment = "prod"`).
#    b. Creating `*.auto.tfvars` files.
#    c. Using `-var` flag on the command line: `terraform apply -var="aws_region=us-west-2"`
#    d. Using environment variables prefixed with `TF_VAR_`: `export TF_VAR_aws_region="us-west-2"`
#
# For sensitive variables, prefer using a dedicated `secrets.tfvars` file (added to .gitignore)
# or environment variables, rather than checking them into version control.

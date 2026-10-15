########################################################################
# Veritas — Trade Reporting Platform
# AWS Infrastructure (Terraform)
#
# Architecture:
#   Trade events → SQS → Ingestor pods → Aurora PostgreSQL (ledger)
#   Reporter pods → S3 (regulatory submissions) → Regulators
#   ElastiCache Redis → Reference data cache (instruments, counterparties)
#
# Compliance:
#   MiFID II  — trade reporting accuracy and timeliness
#   EMIR      — OTC derivatives reporting
#   Dodd-Frank — US swap data repository reporting
#   SOC 2 Type II — security & availability
#   PCI-DSS v4.0  — where payment data touches the platform
########################################################################

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Recommended: remote state with locking
  # backend "s3" {
  #   bucket         = "veritas-tfstate"
  #   key            = "veritas/terraform.tfstate"
  #   region         = var.aws_region
  #   encrypt        = true
  #   dynamodb_table = "veritas-tf-lock"
  # }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      App         = "veritas"
      Product     = "Trade Reporting"
      Environment = var.environment
      ManagedBy   = "terraform"
      Compliance  = "mifid2-emir-dodd-frank-soc2"
      DataClass   = "confidential"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

########################################################################
# KMS — Single CMK for all Veritas data at rest
# MiFID II data integrity / SOC 2 CC6.7 / PCI-DSS 3.5
########################################################################
resource "aws_kms_key" "veritas" {
  description             = "Veritas Trade Reporting — master encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # PCI-DSS 3.7.4 — annual rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RootFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "DenyUnencryptedTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "kms:*"
        Resource  = "*"
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_kms_alias" "veritas" {
  name          = "alias/veritas-${var.environment}"
  target_key_id = aws_kms_key.veritas.key_id
}

########################################################################
# VPC — Isolated network
# PCI-DSS 1.3 — no direct internet path to cardholder / trade data
########################################################################
resource "aws_vpc" "veritas" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "veritas-vpc" }
}

# VPC Flow Logs — full network audit trail
# PCI-DSS 10.2 / MiFID II audit requirements
resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/veritas/vpc-flow"
  retention_in_days = 2557
  kms_key_id        = aws_kms_key.veritas.arn
}

resource "aws_flow_log" "veritas" {
  vpc_id          = aws_vpc.veritas.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow.arn
}

# Private subnets — workloads, database, cache, queues
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.veritas.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "veritas-private-${count.index + 1}", Tier = "private" }
}

# Public subnets — NAT gateway + ALB only
resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.veritas.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index + 8)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "veritas-public-${count.index + 1}", Tier = "public" }
}

resource "aws_internet_gateway" "veritas" {
  vpc_id = aws_vpc.veritas.id
  tags   = { Name = "veritas-igw" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "veritas-nat-eip" }
}

resource "aws_nat_gateway" "veritas" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "veritas-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.veritas.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.veritas.id
  }
  tags = { Name = "veritas-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.veritas.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.veritas.id
  }
  tags = { Name = "veritas-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

########################################################################
# Security Groups
# PCI-DSS 1.2 / SOC 2 CC6.6
########################################################################
resource "aws_security_group" "eks_nodes" {
  name        = "veritas-eks-nodes"
  description = "EKS worker nodes — no direct inbound from internet"
  vpc_id      = aws_vpc.veritas.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Egress via NAT only"
  }
  tags = { Name = "veritas-eks-nodes" }
}

resource "aws_security_group" "aurora" {
  name        = "veritas-aurora"
  description = "Aurora PostgreSQL — EKS nodes only"
  vpc_id      = aws_vpc.veritas.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
    description     = "PostgreSQL from EKS nodes only"
  }
  tags = { Name = "veritas-aurora" }
}

resource "aws_security_group" "redis" {
  name        = "veritas-redis"
  description = "ElastiCache Redis — EKS nodes only"
  vpc_id      = aws_vpc.veritas.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
    description     = "Redis from EKS nodes only"
  }
  tags = { Name = "veritas-redis" }
}

########################################################################
# EKS — Private control plane
# PCI-DSS 1.3, 2.2 / SOC 2 CC6.1
########################################################################
resource "aws_eks_cluster" "veritas" {
  name     = "veritas-${var.environment}"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.eks_version

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.eks_nodes.id]
  }

  # Full control plane audit logging — MiFID II / PCI-DSS 10.2
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Kubernetes Secrets encrypted at rest
  encryption_config {
    provider   { key_arn = aws_kms_key.veritas.arn }
    resources  = ["secrets"]
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
}

resource "aws_eks_node_group" "veritas" {
  cluster_name    = aws_eks_cluster.veritas.name
  node_group_name = "veritas-workers"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = aws_subnet.private[*].id
  instance_types  = [var.node_instance_type]

  scaling_config {
    desired_size = 3
    min_size     = 3
    max_size     = 9   # Headroom for end-of-day reporting spikes
  }

  launch_template {
    id      = aws_launch_template.eks_node.id
    version = aws_launch_template.eks_node.latest_version
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_ecr_policy,
  ]
}

resource "aws_launch_template" "eks_node" {
  name_prefix = "veritas-node-"

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 100
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.veritas.arn
      delete_on_termination = true
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 — blocks SSRF credential theft
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "veritas-node" }
  }
}

########################################################################
# Aurora PostgreSQL — Trade Ledger
#
# Why Aurora over standard RDS:
#   - Distributed storage automatically replicates across 3 AZs
#   - Instant failover (~30s) vs standard RDS Multi-AZ (~60-120s)
#   - Critical for MiFID II T+1 reporting SLAs
#   - Serverless v2 scales with end-of-day reporting bursts
#
# PCI-DSS 3.4, 3.5 / SOC 2 CC6.1 / MiFID II data integrity
########################################################################
resource "aws_rds_cluster" "trade_ledger" {
  cluster_identifier     = "veritas-trade-ledger-${var.environment}"
  engine                 = "aurora-postgresql"
  engine_version         = "16.2"
  database_name          = "trade_ledger"
  master_username        = "veritas_admin"

  # Password managed by Secrets Manager — never in TF state
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.veritas.arn

  db_subnet_group_name   = aws_db_subnet_group.veritas.name
  vpc_security_group_ids = [aws_security_group.aurora.id]

  storage_encrypted = true       # PCI-DSS 3.5
  kms_key_id        = aws_kms_key.veritas.arn

  backup_retention_period = 35   # 35-day PITR — MiFID II 5-year audit requirement
  # Note: archive older snapshots to S3 Glacier for full 5-year compliance
  preferred_backup_window      = "01:00-02:00"
  preferred_maintenance_window = "sun:02:00-sun:03:00"

  deletion_protection             = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "veritas-trade-ledger-final"
  enabled_cloudwatch_logs_exports = ["postgresql"]

  serverlessv2_scaling_configuration {
    min_capacity = 0.5   # Idle at night
    max_capacity = 16    # Scale for end-of-day T+1 reporting bursts
  }

  tags = { Name = "veritas-trade-ledger", DataClass = "trade-data" }
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.aurora_ssl_param_group.id
}

resource "aws_rds_cluster_instance" "trade_ledger" {
  count              = 2   # Writer + one read replica (reporting queries)
  identifier         = "veritas-trade-ledger-${count.index}"
  cluster_identifier = aws_rds_cluster.trade_ledger.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.trade_ledger.engine
  engine_version     = aws_rds_cluster.trade_ledger.engine_version
}

resource "aws_db_subnet_group" "veritas" {
  name       = "veritas-db"
  subnet_ids = aws_subnet.private[*].id
  tags       = { Name = "veritas-db-subnet-group" }
}

########################################################################
# ElastiCache Redis — Reference Data Cache
#
# Caches: instrument static data, counterparty LEI lookups,
#         UTI (Unique Trade Identifier) deduplication set,
#         regulatory endpoint rate-limit state
#
# MiFID II: UTI uniqueness must be enforced — Redis SETNX is the
#           mechanism that prevents duplicate UTI generation across pods
########################################################################
resource "aws_elasticache_subnet_group" "veritas" {
  name       = "veritas-redis"
  subnet_ids = aws_subnet.private[*].id
  tags       = { Name = "veritas-redis-subnet-group" }
}

resource "aws_elasticache_replication_group" "ref_data" {
  replication_group_id = "veritas-ref-data"
  description          = "Veritas reference data cache — UTI dedup, instrument data, LEI cache"
  node_type            = "cache.t4g.small"
  num_cache_clusters   = 2   # Primary + replica for HA
  port                 = 6379

  subnet_group_name          = aws_elasticache_subnet_group.veritas.name
  security_group_ids         = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true  # TLS in transit — PCI-DSS 4.2.1
  kms_key_id                 = aws_kms_key.veritas.arn

  automatic_failover_enabled = true
  multi_az_enabled           = true

  # Persist UTI dedup set across restarts
  snapshot_retention_limit = 7
  snapshot_window          = "03:00-04:00"

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "engine-log"
  }

  tags = { Name = "veritas-ref-data-cache" }
}

resource "aws_cloudwatch_log_group" "redis" {
  name              = "/aws/veritas/redis"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.veritas.arn
}

########################################################################
# SQS — Trade Event Ingestion Queue
#
# Inbound trade events arrive here before the ingestor validates,
# enriches, and writes them to the trade ledger.
# DLQ captures trades that fail repeated processing — requires
# manual review (MiFID II: no trade can be silently dropped)
########################################################################
resource "aws_sqs_queue" "trade_dlq" {
  name                      = "veritas-trade-events-dlq"
  message_retention_seconds = 1209600  # 14 days — time to investigate failures
  kms_master_key_id         = aws_kms_key.veritas.arn

  tags = { Name = "veritas-trade-dlq", DataClass = "trade-data" }
}

resource "aws_sqs_queue" "trade_events" {
  name                       = "veritas-trade-events"
  visibility_timeout_seconds = 300     # 5 min — matches max ingestor processing time
  message_retention_seconds  = 86400   # 24 hours
  kms_master_key_id          = aws_kms_key.veritas.arn

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.trade_dlq.arn
    maxReceiveCount     = 3  # 3 attempts before DLQ — MiFID II: no silent drops
  })

  tags = { Name = "veritas-trade-events", DataClass = "trade-data" }
}

resource "aws_sqs_queue" "submission_events" {
  name                       = "veritas-submission-events"
  visibility_timeout_seconds = 600
  message_retention_seconds  = 86400
  kms_master_key_id          = aws_kms_key.veritas.arn

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.trade_dlq.arn
    maxReceiveCount     = 5
  })

  tags = { Name = "veritas-submission-events", DataClass = "regulatory" }
}

########################################################################
# S3 — Regulatory Submission Archive
#
# Stores: generated regulatory reports (XML/JSON), submission receipts,
#         rejection notices, reconciliation files
#
# MiFID II Art. 25 — records must be kept for 5 years minimum
# EMIR Art. 9      — trade repository reports retained for 10 years
# We use a 10-year lifecycle to cover the most stringent requirement
########################################################################
resource "aws_s3_bucket" "regulatory_archive" {
  bucket        = "veritas-regulatory-archive-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = { Name = "veritas-regulatory-archive", DataClass = "regulatory", Retention = "10yr" }
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "regulatory_archive" {
  bucket = aws_s3_bucket.regulatory_archive.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "regulatory_archive" {
  bucket = aws_s3_bucket.regulatory_archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.veritas.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "regulatory_archive" {
  bucket                  = aws_s3_bucket.regulatory_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "regulatory_archive" {
  bucket = aws_s3_bucket.regulatory_archive.id

  rule {
    id     = "reports-to-glacier"
    status = "Enabled"
    filter { prefix = "reports/" }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    expiration { days = 3650 }  # 10 years — EMIR requirement
  }

  rule {
    id     = "receipts-retain"
    status = "Enabled"
    filter { prefix = "receipts/" }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }
    expiration { days = 3650 }
  }

  rule {
    id     = "noncurrent-cleanup"
    status = "Enabled"
    filter { prefix = "" }
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}

resource "aws_s3_bucket_policy" "regulatory_archive" {
  bucket = aws_s3_bucket.regulatory_archive.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = ["${aws_s3_bucket.regulatory_archive.arn}", "${aws_s3_bucket.regulatory_archive.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

########################################################################
# S3 — Audit Log Bucket
# PCI-DSS 10.5 — tamper-proof, long-retention
########################################################################
resource "aws_s3_bucket" "audit_logs" {
  bucket        = "veritas-audit-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = { Name = "veritas-audit-logs", DataClass = "audit" }
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.veritas.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    id     = "audit-retain-7yr"
    status = "Enabled"
    filter { prefix = "" }
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    expiration { days = 2555 }  # 7 years
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.audit_logs.arn
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = ["${aws_s3_bucket.audit_logs.arn}", "${aws_s3_bucket.audit_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

########################################################################
# CloudTrail — All API activity audit
# PCI-DSS 10.2 / MiFID II audit trail
########################################################################
resource "aws_cloudtrail" "veritas" {
  name                          = "veritas-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true  # Tamper detection
  kms_key_id                    = aws_kms_key.veritas.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.regulatory_archive.arn}/"]
    }
    data_resource {
      type   = "AWS::SQS::Queue"
      values = ["${aws_sqs_queue.trade_events.arn}"]
    }
  }

  depends_on = [aws_s3_bucket_policy.audit_logs]
}

########################################################################
# CloudWatch Alarms — Operational + compliance monitoring
# MiFID II: reporting pipeline must be monitored for failures
########################################################################
resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "veritas-trade-dlq-depth"
  alarm_description   = "CRITICAL: Trades in DLQ — manual review required (MiFID II: no silent drops)"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.trade_dlq.name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "aurora_cpu" {
  alarm_name          = "veritas-aurora-cpu-high"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBClusterIdentifier = aws_rds_cluster.trade_ledger.id }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_sns_topic" "ops_alerts" {
  name              = "veritas-ops-alerts"
  kms_master_key_id = aws_kms_key.veritas.arn
}

########################################################################
# IAM — Least-privilege roles
# PCI-DSS 7.1 / SOC 2 CC6.1
########################################################################
resource "aws_iam_role" "eks_cluster" {
  name = "veritas-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "eks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_node" {
  name = "veritas-eks-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy_attachment" "eks_node_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}
resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}
resource "aws_iam_role_policy_attachment" "eks_ecr_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# Ingestor workload — SQS consumer + Aurora writer + Redis
resource "aws_iam_role" "ingestor" {
  name = "veritas-ingestor"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(aws_eks_cluster.veritas.identity[0].oidc[0].issuer, "https://", "")}" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = { "${replace(aws_eks_cluster.veritas.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:veritas:veritas-ingestor" } }
    }]
  })
}

resource "aws_iam_role_policy" "ingestor" {
  name = "veritas-ingestor-policy"
  role = aws_iam_role.ingestor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SQSConsume"
        Effect = "Allow"
        Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility"]
        Resource = [aws_sqs_queue.trade_events.arn, aws_sqs_queue.submission_events.arn]
      },
      {
        Sid    = "SQSPublishSubmission"
        Effect = "Allow"
        Action = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.submission_events.arn
      },
      {
        Sid    = "SecretsDB"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = aws_rds_cluster.trade_ledger.master_user_secret[0].secret_arn
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.veritas.arn
      }
    ]
  })
}

# Reporter workload — S3 writer + SQS consumer
resource "aws_iam_role" "reporter" {
  name = "veritas-reporter"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(aws_eks_cluster.veritas.identity[0].oidc[0].issuer, "https://", "")}" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = { "${replace(aws_eks_cluster.veritas.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:veritas:veritas-reporter" } }
    }]
  })
}

resource "aws_iam_role_policy" "reporter" {
  name = "veritas-reporter-policy"
  role = aws_iam_role.reporter.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3RegArchiveWrite"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = ["${aws_s3_bucket.regulatory_archive.arn}", "${aws_s3_bucket.regulatory_archive.arn}/*"]
      },
      {
        Sid    = "SQSConsume"
        Effect = "Allow"
        Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.submission_events.arn
      },
      {
        Sid    = "SecretsDB"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = aws_rds_cluster.trade_ledger.master_user_secret[0].secret_arn
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.veritas.arn
      }
    ]
  })
}

resource "aws_iam_role" "flow_log" {
  name = "veritas-flow-log"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "flow_log" {
  role = aws_iam_role.flow_log.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"], Resource = "*" }]
  })
}

resource "aws_rds_cluster_parameter_group" "aurora_ssl_param_group" {
  name        = "aurora-ssl-param-group-${var.environment}"
  family      = "aurora-postgresql14"
  description = "Force SSL for Aurora cluster connections"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "immediate"
  }
}
resource "aws_sns_topic" "regulatory_affairs_alerts" {
  name              = "veritas-regulatory-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.veritas.arn
}
resource "aws_sqs_queue" "submission_dlq" {
  name                      = "submission-dlq-${var.environment}"
  kms_master_key_id         = aws_kms_key.veritas.id
  message_retention_seconds = 1209600
}
resource "aws_cloudwatch_metric_alarm" "submission_dlq_alarm" {
  alarm_name          = "submission-dlq-alarm-${var.environment}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Critical alarm for Regulatory Affairs when submission messages enter DLQ"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]

  dimensions = {
    QueueName = aws_sqs_queue.trade_dlq.name
  }
}
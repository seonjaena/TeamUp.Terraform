locals {
    service_name                           = "TeamUp"
    env                                    = "prod"
    timezone                               = "Asia/Seoul"
    aws_region                             = "ap-northeast-2"
    cloudwatch_log_group_retention_in_days = 30

    #alb dns주소를 넣기 위한 route53 record name
    route53_web_record = "sjna.xyz"

    # 일반 사용자가 접속하는 URL(https포함)
    web_url = "https://www.${local.route53_web_record}"
    api_url = "https://${local.route53_web_record}"

    web_api_path = "${lower(local.service_name)}/api/web"
    admin_path   = "${lower(local.service_name)}/admin"

    instance_type = "t3.micro"

    ecr_force_destroy_enable = true

    #container insight(var변수였다가 local로 변경. 이유: 사이트별로 사용유무가 정해져 있기 때문에 코드에 고정, 필요시 true로 변경하여 사용)
    enable_container_insights = true


    # #s3 bucket
    s3_bucket_name                  = "${lower(local.service_name)}-common-data"
    s3_bucket_force_destroy_enable  = true
    s3_config_bucket_name           = "${lower(local.service_name)}-config-data"

    # keystore_keyname = "teamup-developer"

    default_vpc_id          = "vpc-03250f6dc73a4a7f5"
    public_subnets          = [ "subnet-0a1e0e7b8826c509c", "subnet-0bb610cd6a10b6fe6" ]
    default_security_group  = "sg-0f5ed12b8472cd1f3"
}

data "terraform_remote_state" "common" {
    backend = "s3"
    config = {
        bucket          = "teamup-terraform-backend"
        key             = "terraform/teamup.tfstate"
        region          = "ap-northeast-2"
        dynamodb_table  = "teamup-common-terraform-backend"
    }
}

#################################
# 자동으로 설정되는 설정
#################################
locals {
    ecs_web_cluster_name = upper("${local.service_name}-${local.env}-WEB-CLUSTER")

    user_default_tags = {
        SERVICE_NAME = local.service_name
        ENV          = local.env
        IAC_TOOL     = "terraform"
    }


    # task에서 공통으로 사용하는 assume_role
    common_task_assume_role_policy = jsonencode({
        Version : "2012-10-17",
        Statement : [{
            Effect : "Allow",
            Principal : {
                Service : [
                    "ecs-tasks.amazonaws.com",
                ]
            },
            Action : "sts:AssumeRole"
        }]
    })


    tag_specifications_resource_types = ["instance", "volume", "network-interface"] #"elastic-gpu"는 지정하면 안됨. ap-northeast-2에서는 지원안한다며 asg실패함. "spot-instances-request"도 asg실패
    
    protocol_patterns = "/(http|https)?:///"

    # 프로토콜을 제거한 호스트 이름
    hostname = replace(local.web_url, local.protocol_patterns, "")

    # heapdump를 보관할 s3의 디렉터리
    heapdump_dir = "heapdump"

    # ECS task role postfix 규칙
    task_role_postfix = "ecsTaskRole"
}

terraform {
    required_providers {
        aws = {
        source  = "hashicorp/aws"
        version = "~> 4.0"
        }
    }

    backend "s3" {
        bucket         = "teamup-terraform-backend"
        key            = "terraform/ecs/teamup.tfstate"
        region         = "ap-northeast-2"
        dynamodb_table = "teamup-common-terraform-backend"
    }
}


provider "aws" {
    region  = local.aws_region


    default_tags {
        tags = local.user_default_tags
    }
}

###############################################
# Key Pair
###############################################
resource "tls_private_key" "teamup_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "teamup_keypair" {
  key_name   = "${lower(local.service_name)}-keypair.pem"
  public_key = tls_private_key.teamup_key.public_key_openssh
} 

resource "local_file" "teamup_key_local" {
  filename        = pathexpand("~/.aws/${lower(local.service_name)}-keypair.pem")
  content         = tls_private_key.teamup_key.private_key_pem
  file_permission = "0600"
}


###############################################
# Private Subnet
###############################################
resource "aws_subnet" "first_private_subnet" {
  vpc_id            = local.default_vpc_id
  availability_zone = "ap-northeast-2c"
  cidr_block        = "172.31.32.0/20"
}

resource "aws_subnet" "second_private_subnet" {
  vpc_id            = local.default_vpc_id
  availability_zone = "ap-northeast-2d"
  cidr_block        = "172.31.48.0/20"
}

###############################################
# Security Group
###############################################
resource "aws_security_group" "teamup_security_group" {
    vpc_id = "${local.default_vpc_id}"
    name = "${lower(local.service_name)}"
    ingress {
        from_port   = 0
        to_port     = 0
        protocol    = -1
        cidr_blocks = ["${var.home_ipv4}/32"]
    }
    ingress {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
    ingress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
    ingress {
        from_port   = 0
        to_port     = 0
        protocol    = -1
        self        = true
    }
}

###############################################
# ECR
###############################################
resource "aws_ecr_repository" "api_ecr" {
    name                 = "${lower(local.service_name)}.server" # ECR 리포지토리의 이름을 설정하세요
    image_tag_mutability = "MUTABLE"
    force_delete         = local.ecr_force_destroy_enable
    image_scanning_configuration {
        scan_on_push = true
    }
}

###############################################
# ECS
###############################################
resource "aws_ecs_cluster" "ecs_cluster" {
    name = "${local.service_name}-ecs-cluster"

    setting {
        name  = "containerInsights"
        value = local.enable_container_insights ? "enabled" : "disabled"
    }
}

resource "aws_launch_template" "ecs_lt" {
    name_prefix     = "${local.service_name}-ecs-template"
    image_id        = data.aws_ami.amazon_linux_2.image_id
    instance_type   = local.instance_type
    key_name        = aws_key_pair.teamup_keypair.key_name

    iam_instance_profile {
        name = aws_iam_instance_profile.ec2_instance_role_profile.name
    }

    block_device_mappings {
        device_name = "/dev/xvda"
        ebs {
            volume_size = 30
            volume_type = "gp2"
        }
    }

    tag_specifications {
        resource_type = "instance"
        tags = {
            Name = "ecs-instance"
        }
    }

    network_interfaces {
        associate_public_ip_address = true
        security_groups             = [ aws_security_group.teamup_security_group.id, local.default_security_group ]
        subnet_id                   = local.public_subnets[0]
    }

    user_data = base64encode(templatefile("launch_template_user_data.tftpl", { ecs_cluster_name = aws_ecs_cluster.ecs_cluster.name }))
}

resource "aws_autoscaling_group" "ecs_asg" {
    vpc_zone_identifier = local.public_subnets
    desired_capacity    = var.asg_desired_size
    max_size            = var.asg_max_size
    min_size            = 1

    launch_template {
        id      = aws_launch_template.ecs_lt.id
        version = "$Latest"
    }

    tag {
        key                 = "AmazonECSManaged"
        value               = true
        propagate_at_launch = true
    }
}

resource "aws_ecs_capacity_provider" "ecs_capacity_provider" {
    name = "${local.service_name}-capacity-provider"

    auto_scaling_group_provider {
        auto_scaling_group_arn = aws_autoscaling_group.ecs_asg.arn

        managed_scaling {
            maximum_scaling_step_size = 1000
            minimum_scaling_step_size = 1
            status                    = "ENABLED"
            target_capacity           = 3
        }
    }
}

resource "aws_ecs_cluster_capacity_providers" "example" {
    cluster_name = aws_ecs_cluster.ecs_cluster.name

    capacity_providers = [aws_ecs_capacity_provider.ecs_capacity_provider.name]

    default_capacity_provider_strategy {
        base              = 1
        weight            = 100
        capacity_provider = aws_ecs_capacity_provider.ecs_capacity_provider.name
    }
}

###############################################
# IAM
###############################################

resource "aws_iam_role" "ec2_instance_role" {
    name               = "${local.service_name}_EC2_InstanceRole"
    assume_role_policy = data.aws_iam_policy_document.ec2_instance_role_policy.json
}

resource "aws_iam_role_policy_attachment" "ec2_instance_role_policy" {
    role       = aws_iam_role.ec2_instance_role.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ec2_instance_role_profile" {
    name  = "${local.service_name}_EC2_InstanceRoleProfile"
    role  = aws_iam_role.ec2_instance_role.id
}

data "aws_iam_policy_document" "ec2_instance_role_policy" {
    statement {
        actions = ["sts:AssumeRole"]
        effect  = "Allow"

        principals {
        type        = "Service"
        identifiers = [
            "ec2.amazonaws.com",
            "ecs.amazonaws.com"
        ]
        }
    }
}

#ecs agent가 실행할 때 사용할 role
resource "aws_iam_role" "ecsTaskExecutionRole" {
    name = "${local.service_name}-ecsTaskExecutionRole"

    managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]

    assume_role_policy = local.common_task_assume_role_policy
}



# resource "aws_iam_instance_profile" "ecsContainerInstanceRole_profile" {
#     name = "${local.service_name}-ecsContainerInstanceRole"
#     role = aws_iam_role.ecsContainerInstanceRole.name
# }


# container instance(EC2)가 실행할 때 사용할 role
resource "aws_iam_role" "ecsContainerInstanceRole" {
    name = "${local.service_name}-ecsContainerInstanceRole"

    managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"]

    assume_role_policy = jsonencode(merge(
        jsondecode(local.common_task_assume_role_policy),
        {
        "Statement" : [
            for stmt in jsondecode(local.common_task_assume_role_policy).Statement : merge(
            stmt,
            {
                "Principal" : {
                "Service" : [
                    "ecs-tasks.amazonaws.com",
                    "ec2.amazonaws.com",
                    "ecs.amazonaws.com"
                ]
                }
            }
            )
        ]
        }
    ))
}

#이메일 전송 policy
resource "aws_iam_policy" "email_send_policy" {
    name = "${local.service_name}-email-send-policy"

    policy = jsonencode({
        "Version" : "2012-10-17",
        "Statement" : [
            {
                "Effect" : "Allow",
                "Action" : [
                    "ses:SendEmail",
                    "ses:SendRawEmail"
                ],
                "Resource" : "arn:aws:ses:ap-northeast-2:${var.aws_account_id}:identity/${var.ses_sender}"
            }
        ]
    })
}

# heapdump policy (필요한 곳에 arn을 추가하여 사용)
resource "aws_iam_policy" "heapdump" {
    name = "${local.service_name}-heapdump-write-only-policy"

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Action = [
                    "s3:PutObject",
                ]
                Resource = "arn:aws:s3:::${aws_s3_bucket.s3bucket.id}/${local.heapdump_dir}/*"
            },
        ]
    })
}

resource "aws_s3_bucket" "s3bucket" {
    bucket        = local.s3_bucket_name
    force_destroy = local.s3_bucket_force_destroy_enable
}

resource "aws_s3_bucket" "s3_config_bucket" {
    bucket        = local.s3_config_bucket_name
    force_destroy = local.s3_bucket_force_destroy_enable
}

resource "aws_s3_object" "server_dev_env" {
    bucket        = aws_s3_bucket.s3_config_bucket.id
    key           = "server/dev.env"
    source        = pathexpand("~/private-study/${local.service_name}/${local.service_name}.Server/dev.env")
}

resource "aws_s3_object" "server_prod_env" {
    bucket        = aws_s3_bucket.s3_config_bucket.id
    key           = "server/prod.env"
    source        = pathexpand("~/private-study/${local.service_name}/${local.service_name}.Server/prod.env")
}

resource "aws_s3_object" "terraform_tfvars" {
    bucket        = aws_s3_bucket.s3_config_bucket.id
    key           = "terraform/terraform.tfvars"
    source        = pathexpand("./terraform.tfvars")
}

resource "aws_s3_object" "db_dev_env" {
    bucket        = aws_s3_bucket.s3_config_bucket.id
    key           = "database/db.env"
    source        = pathexpand("~/private-study/${local.service_name}/${local.service_name}.Database/db.env")
}

resource "aws_db_instance" "teamup_main_db" {
    allocated_storage = 20
    allow_major_version_upgrade = false
    apply_immediately = false
    auto_minor_version_upgrade = true
    availability_zone = "ap-northeast-2b"
    ca_cert_identifier = "rds-ca-rsa2048-g1"
    # db_subnet_group_name = "default-${local.default_vpc_id}"
    customer_owned_ip_enabled = false
    engine = "mariadb"
    engine_version = "10.11.6"
    iam_database_authentication_enabled = false
    identifier = "teamup"
    instance_class = "db.t3.micro"
    license_model = "general-public-license"
    multi_az = false
    network_type = "IPV4"
    option_group_name = "default:mariadb-10-11"
    parameter_group_name = "default.mariadb10.11"
    username = var.main_db_username
    password = var.main_db_password
    port = tonumber(var.main_db_port)
    publicly_accessible = false
    skip_final_snapshot = true
    storage_type = "gp2"
    vpc_security_group_ids = [ aws_security_group.teamup_security_group.id, local.default_security_group ]
}

resource "aws_elasticache_subnet_group" "teamup_redis_subnet_group" {
    name       = "teamup"
    subnet_ids = [ aws_subnet.first_private_subnet.id, aws_subnet.second_private_subnet.id ]
}

resource "aws_elasticache_cluster" "teamup_redis" {
    cluster_id                  = "teamup"
    engine                      = "redis"
    node_type                   = "cache.t3.micro"
    num_cache_nodes             = 1
    parameter_group_name        = "default.redis7"
    engine_version              = "7.0"
    port                        = 6379
    network_type                = "ipv4"
    security_group_ids          = [ aws_security_group.teamup_security_group.id, local.default_security_group ]
    snapshot_retention_limit    = 0
    subnet_group_name           = aws_elasticache_subnet_group.teamup_redis_subnet_group.name
}

data "aws_ami" "amazon_linux_2" {
    most_recent = true
    owners      = ["amazon"]

    filter {
        name   = "name"
        values = ["amzn2-ami-ecs-hvm-*-x86_64-ebs"]
    }
}
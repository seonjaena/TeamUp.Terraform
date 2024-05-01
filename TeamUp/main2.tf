locals {
    service_name                           = "TeamUp"          #todo service_name값은 FXSKR값만 허용하도록 validate기능 추가
    env                                    = "prod"            #todo env값은 dev,stage,prod값만 허용하도록 validate기능 추가
    timezone                               = "Asia/Seoul"     #todo validate기능 추가
    aws_region                             = "ap-northeast-2" #todo validate기능 추가
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

    keystore_keyname = "teamup-developer"

    default_vpc_id          = "vpc-0c0078fd9f1552b2a"
    private_subnets         = [ "subnet-017adddb6a94630bc", "subnet-033244547b54d8a5f" ]
    public_subnets          = [ "subnet-00c76c8bab5ee26d3", "subnet-010e36e1e0b856c88" ]
    security_groups         = [ "sg-09d68618cd428d2a8" ]
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
# ECR
###############################################
resource "aws_ecr_repository" "api-ecr" {
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
    name_prefix   = "${local.service_name}-ecs-template"
    image_id      = data.aws_ami.amazon_linux_2.image_id
    instance_type = local.instance_type

    key_name               = local.keystore_keyname

    iam_instance_profile {
        name = "ecsInstanceRole"
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
        security_groups             = local.security_groups
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

#todo import되었는지 안되었는지 확인하기
#import terraform import aws_s3_bucket.s3bucket xshield-fxskr-prod
resource "aws_s3_bucket" "s3bucket" {
    bucket        = local.s3_bucket_name
    force_destroy = local.s3_bucket_force_destroy_enable
}

resource "aws_db_instance" "teamup_main_db" {
    allocated_storage = 20
    allow_major_version_upgrade = false
    apply_immediately = false
    auto_minor_version_upgrade = true
    availability_zone = "ap-northeast-2b"
    ca_cert_identifier = "rds-ca-rsa2048-g1"
    db_subnet_group_name = "default-vpc-0c0078fd9f1552b2a"
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
    port = 3306
    publicly_accessible = false
    skip_final_snapshot = true
    storage_type = "gp2"
    vpc_security_group_ids = local.security_groups
}

resource "aws_elasticache_subnet_group" "teamup_redis_subnet_group" {
    name       = "teamup"
    subnet_ids = local.private_subnets
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
    security_group_ids          = local.security_groups
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
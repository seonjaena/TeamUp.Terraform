# locals {
#     service_name                           = "TeamUp"
#     timezone                               = "Asia/Seoul"
#     aws_region                             = "ap-northeast-2"
#     cloudwatch_log_group_retention_in_days = 5

#     #alb dns주소를 넣기 위한 route53 record name
#     route53_web_record = "sjna.xyz"

#     # 일반 사용자가 접속하는 URL(https포함)
#     web_url = "https://www.${local.route53_web_record}"
#     api_url = "https://${local.route53_web_record}"

#     web_api_path            = "${lower(local.service_name)}/api/web"
#     admin_path          = "${lower(local.service_name)}/admin"

#     #ecs
#     ami_id        = "ami-07704e83790d35a0d"
#     instance_type = "t3.micro"

#     # #s3 bucket
#     s3_bucket_name                  = "${lower(local.service_name)}-common-data"
#     s3_bucket_force_destroy_enable  = true

#     ecr_force_destroy_enable        = true

#     keystore_keyname = "teamup-key"

#     default_vpc_id  = "vpc-0c0078fd9f1552b2a"
#     private_subnets = [ "subnet-017adddb6a94630bc", "subnet-033244547b54d8a5f" ]
#     public_subnets  = [ "subnet-00c76c8bab5ee26d3", "subnet-010e36e1e0b856c88" ]
#     security_groups  = [ "sg-09d68618cd428d2a8" ]
# }

# data "terraform_remote_state" "common" {
#     backend = "s3"
#     config = {
#         bucket          = "teamup-terraform-backend"
#         key             = "terraform/teamup.tfstate"
#         region          = "ap-northeast-2"
#         dynamodb_table  = "teamup-common-terraform-backend"
#     }
# }

# #################################
# # 자동으로 설정되는 설정
# #################################
# locals {

#     ecs_web_cluster_name = upper("${local.service_name}-WEB-CLUSTER")

#     user_default_tags = {
#         SERVICE_NAME = local.service_name
#         IAC_TOOL     = "terraform"
#     }


#     # task에서 공통으로 사용하는 assume_role
#     common_task_assume_role_policy = jsonencode({
#         Version : "2012-10-17",
#         Statement : [{
#             Effect : "Allow",
#             Principal : {
#             Service : [
#                 "ecs-tasks.amazonaws.com",
#             ]
#             },
#             Action : "sts:AssumeRole"
#         }]
#     })


#     tag_specifications_resource_types = ["instance", "volume", "network-interface"] #"elastic-gpu"는 지정하면 안됨. ap-northeast-2에서는 지원안한다며 asg실패함. "spot-instances-request"도 asg실패
    
#     ## FQDN에서 호스트 부분이 'www'인 경우, rule 사용 
#     use_www_rule = startswith(local.web_url, "http://www") || startswith(local.web_url, "https://www") || startswith(local.web_url, "www")
    
#     # 정규표현식 패턴 (프로토콜을 제거해서 hostname 만을 가져옵니다.)
#     protocol_patterns = "/(http|https)?:///"

#     # 프로토콜을 제거한 호스트 이름
#     hostname = replace(local.web_url, local.protocol_patterns, "")

#     # heapdump를 보관할 s3의 디렉터리
#     heapdump_dir = "heapdump"

#     # ECS task role postfix 규칙
#     task_role_postfix = "ecsTaskRole"
# }

# terraform {
#     required_providers {
#         aws = {
#         source  = "hashicorp/aws"
#         version = "~> 4.0"
#         }
#     }


#     # TODO: 첫 실행에서는 주석 처리하고 실행
#     backend "s3" {
#         bucket         = "teamup-terraform-backend"
#         key            = "terraform/ecs/teamup.tfstate"
#         region         = "ap-northeast-2"
#         dynamodb_table = "teamup-common-terraform-backend"
#     }

# }


# provider "aws" {
#     region  = local.aws_region


#     default_tags {
#         tags = local.user_default_tags
#     }
# }


# ###############################################
# # ECR
# ###############################################
# resource "aws_ecr_repository" "api-ecr" {
#     name                 = "${lower(local.service_name)}.server" # ECR 리포지토리의 이름을 설정하세요
#     image_tag_mutability = "MUTABLE"
#     force_delete         = local.ecr_force_destroy_enable
#     image_scanning_configuration {
#         scan_on_push = true
#     }
# }

# ###############################################
# # ECS
# ###############################################

# resource "aws_ecs_cluster" "ecs_cluster" {
#     name = local.ecs_web_cluster_name

#     setting {
#         name  = "containerInsights"
#         value = var.enable_container_insights ? "enabled" : "disabled"
#     }
# }


# resource "aws_ecs_cluster_capacity_providers" "ecs_cp_mapping" {
#     cluster_name = aws_ecs_cluster.ecs_cluster.name

#     capacity_providers = [
#         aws_ecs_capacity_provider.ecs_cp.name
#     ]

#     default_capacity_provider_strategy {
#         base              = 1
#         weight            = 100
#         capacity_provider = aws_ecs_capacity_provider.ecs_cp.name
#     }
    
# }

# resource "aws_launch_template" "ecs_launch_template" {
#     name = "${local.service_name}-launch-template"


#     image_id        = local.ami_id
#     instance_type   = local.instance_type

#     vpc_security_group_ids = local.security_groups

#     #launch template을 수정할 경우 default version도 같이 수정되도록 함
#     update_default_version = true

#     #아래 내용을 추가해주어야 ecs화면의 container instance목록에 표시됨
#     user_data = base64encode(templatefile("launch_template_user_data.tftpl", { ecs_cluster_name = aws_ecs_cluster.ecs_cluster.name, zabbix_server="192.168.0.115" }))

#     iam_instance_profile {
#         name = aws_iam_instance_profile.ecsContainerInstanceRole_profile.name
#     }

#     #ec2가 autoscaling될 때 해당 ec2에 자동으로 tag를 지정
#     dynamic "tag_specifications" {
#         for_each = local.tag_specifications_resource_types
#         content {
#             resource_type = tag_specifications.value

#             tags = merge(local.user_default_tags, { Name = local.service_name })
#         }
#     }

# }



# resource "aws_autoscaling_group" "ecs_asg" {
#     name = "${local.service_name}-ecs-asg" #name을 붙이지 않으면 random하게 이름이 만들어짐(ex: terraform-20230608083143614900000001)
#     vpc_zone_identifier = local.private_subnets

#     desired_capacity = var.asg_desired_size
#     min_size         = 1
#     max_size         = var.asg_max_size

#     protect_from_scale_in = true
    
#     launch_template {
#         id      = aws_launch_template.ecs_launch_template.id
#         version = "$Latest"
#     }

#     # terraform plan하면 tag가 다르다는 메시지 나와서 설정함
#     tag {
#         key                 = "AmazonECSManaged"
#         value               = ""
#         propagate_at_launch = true
#     }

#     lifecycle {
#         ignore_changes = [desired_capacity] #실행할 때 desired_capacity값 때문에 change발생. desired_capacity는 자동변경되는 것이므로 무시하도록 설정
#     }
# }

# resource "aws_ecs_capacity_provider" "ecs_cp" {
#     name = "${local.service_name}-ecs-cp"

#     auto_scaling_group_provider {
#         auto_scaling_group_arn = aws_autoscaling_group.ecs_asg.arn

#         managed_scaling {
#             maximum_scaling_step_size = 1000
#             minimum_scaling_step_size = 1
#             status                    = "ENABLED"
#             target_capacity           = 100
#         }
#     }
# }


# ###############################################
# # IAM
# ###############################################

# #ecs agent가 실행할 때 사용할 role
# resource "aws_iam_role" "ecsTaskExecutionRole" {
#     name = "${local.service_name}-ecsTaskExecutionRole"

#     managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]

#     assume_role_policy = local.common_task_assume_role_policy
# }



# resource "aws_iam_instance_profile" "ecsContainerInstanceRole_profile" {
#     name = "${local.service_name}-ecsContainerInstanceRole"
#     role = aws_iam_role.ecsContainerInstanceRole.name
# }


# # container instance(EC2)가 실행할 때 사용할 role
# resource "aws_iam_role" "ecsContainerInstanceRole" {
#     name = "${local.service_name}-ecsContainerInstanceRole"

#     managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"]

#     assume_role_policy = jsonencode(merge(
#         jsondecode(local.common_task_assume_role_policy),
#         {
#             "Statement" : [
#                 for stmt in jsondecode(local.common_task_assume_role_policy).Statement : merge(
#                     stmt,
#                     {
#                         "Principal" : {
#                             "Service" : [
#                                 "ecs-tasks.amazonaws.com",
#                                 "ec2.amazonaws.com"
#                             ]
#                         }
#                     }
#                 )
#             ]
#         }
#     ))
# }

# #이메일 전송 policy
# resource "aws_iam_policy" "email_send_policy" {
#     name = "${local.service_name}-email-send-policy"

#     policy = jsonencode({
#         "Version" : "2012-10-17",
#         "Statement" : [{
#             "Effect" : "Allow",
#             "Action" : [
#                 "ses:SendEmail",
#                 "ses:SendRawEmail"
#             ],
#             "Resource" : "arn:aws:ses:ap-northeast-2:${var.aws_account_id}:identity/${var.ses_sender}"
#         }]
#     })
# }

# # heapdump policy (필요한 곳에 arn을 추가하여 사용)
# resource "aws_iam_policy" "heapdump" {
#     name = "${local.service_name}-heapdump-write-only-policy"

#     policy = jsonencode({
#         Version = "2012-10-17"
#         Statement = [{
#             Effect = "Allow"
#             Action = [
#                 "s3:PutObject",
#             ]
#             Resource = "arn:aws:s3:::${aws_s3_bucket.s3bucket.id}/${local.heapdump_dir}/*"
#         }]
#     })
# }

# resource "aws_db_instance" "teamup_main_db" {
#     allocated_storage = 20
#     allow_major_version_upgrade = false
#     apply_immediately = false
#     auto_minor_version_upgrade = true
#     availability_zone = "ap-northeast-2b"
#     ca_cert_identifier = "rds-ca-rsa2048-g1"
#     db_subnet_group_name = "default-vpc-0c0078fd9f1552b2a"
#     customer_owned_ip_enabled = false
#     engine = "mariadb"
#     engine_version = "10.11.6"
#     iam_database_authentication_enabled = false
#     identifier = "teamup-main"
#     instance_class = "db.t3.micro"
#     license_model = "general-public-license"
#     multi_az = false
#     network_type = "IPV4"
#     option_group_name = "default:mariadb-10-11"
#     parameter_group_name = "default.mariadb10.11"
#     username = var.main_db_username
#     password = var.main_db_password
#     port = 3306
#     publicly_accessible = false
#     skip_final_snapshot = true
#     storage_type = "gp2"
#     vpc_security_group_ids = local.security_groups
# }

# resource "aws_s3_bucket" "s3bucket" {
#     bucket        = local.s3_bucket_name
#     force_destroy = local.s3_bucket_force_destroy_enable
# }


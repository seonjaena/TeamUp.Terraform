locals {
    web_api_server_name                                  = "web-api-server"
    web_api_server_family                                = "${local.service_name}-${local.web_api_server_name}-td"
    web_api_server_ecr_image_addr                        = "107896592142.dkr.ecr.ap-northeast-2.amazonaws.com/teamup.server:0.0.1-SNAPSHOT-TEAM-1"
    web_api_server_awslogs_group                         = "/ecs/${local.web_api_server_family}"
    web_api_server_memory                                = 450
    web_api_server_cpu                                   = 1024
    web_api_server_init_ram_percent                      = "25.0"
    web_api_server_max_ram_percent                       = "25.0"
    web_api_server_task_desired_count                    = 2
}

resource "aws_ecs_task_definition" "web_api_server" {
    family = local.web_api_server_family
    container_definitions = jsonencode([
        {
            "name" : "${local.web_api_server_name}",
            "image" : "${local.web_api_server_ecr_image_addr}",
            "cpu" : 0,
            "portMappings" : [
                {
                    "name" : "${local.web_api_server_name}-8080-tcp",
                    "containerPort" : 8080,
                    "hostPort" : 0,
                    "protocol" : "tcp",
                    "appProtocol" : "http"
                }
            ],
            "essential" : true,
            "environment" : [
                {
                    "name" : "DB_HOST",
                    "value" : "${var.main_db_host}"
                },
                {
                    "name" : "DB_PORT",
                    "value" : "${var.main_db_port}"
                },
                {
                    "name" : "DB_NAME",
                    "value" : "${var.main_db_name}"
                },
                {
                    "name" : "DB_USERNAME",
                    "value" : "${var.main_db_username}"
                },
                {
                    "name" : "DB_PASSWORD",
                    "value" : "${var.main_db_password}"
                },
                {
                    "name" : "JWT_SECRET_KEY",
                    "value" : "${var.jwt_secret_key}"
                },
                {
                    "name" : "SMS_KEY",
                    "value" : "${var.cool_sms_key}"
                },
                {
                    "name" : "SES_SEND_EMAIL",
                    "value" : "${var.ses_sender}"
                }
            
            ],
            "logConfiguration" : {
                "logDriver" : "awslogs",
                "options" : {
                    "awslogs-create-group" : "true",
                    "awslogs-group" : "${local.web_api_server_awslogs_group}",
                    "awslogs-region" : "${local.aws_region}",
                    "awslogs-stream-prefix" : "ecs"
                }
            },
            "healthCheck" : {
                "command" : [
                    "CMD-SHELL",
                    "[ $(curl --silent http://localhost:8080/${local.web_api_path}/common/health-check -o /dev/null -w \"%%{http_code}\") -eq 200 ] || exit 1"
                ],
                "interval" : 60,
                "timeout" : 10,
                "retries" : 3,
                "startPeriod" : 150
            }
        }
  ])
    cpu    = local.web_api_server_cpu
    memory = local.web_api_server_memory
    runtime_platform {
        cpu_architecture        = "X86_64"
        operating_system_family = "LINUX"
    }
    task_role_arn            = aws_iam_role.web_api_server.arn
    execution_role_arn       = aws_iam_role.ecsTaskExecutionRole.arn
    network_mode             = "bridge"
    requires_compatibilities = ["EC2"]
    skip_destroy             = true

    depends_on = [
        aws_db_instance.teamup_main_db
    ]
}

resource "aws_ecs_service" "api_web_server" {
    name                               = "${local.service_name}-${local.web_api_server_name}-svc"
    cluster                            = aws_ecs_cluster.ecs_cluster.arn
    task_definition                    = aws_ecs_task_definition.web_api_server.arn
    deployment_maximum_percent         = local.web_api_server_task_desired_count > 1 ? "100" : "200"
    deployment_minimum_healthy_percent = local.web_api_server_task_desired_count > 1 ? "50" : "100"
    desired_count                      = local.web_api_server_task_desired_count

    ordered_placement_strategy {
        field = "attribute:ecs.availability-zone"
        type  = "spread"
    }
    ordered_placement_strategy {
        field = "instanceId"
        type  = "spread"
    }
    deployment_circuit_breaker {
        enable   = true
        rollback = true
    }
    propagate_tags                    = "TASK_DEFINITION"
    enable_ecs_managed_tags           = true
    enable_execute_command            = true
    health_check_grace_period_seconds = 150
    wait_for_steady_state             = false
    load_balancer {
        container_name   = local.web_api_server_name
        container_port   = 8080
        target_group_arn = aws_lb_target_group.targetGroupApiWeb.arn
    }
    capacity_provider_strategy {
        capacity_provider = aws_ecs_capacity_provider.ecs_capacity_provider.name
        base              = 1
        weight            = 100
    }
    force_new_deployment = true
}

resource "aws_cloudwatch_log_group" "api_web_server" {
    name              = local.web_api_server_awslogs_group
    retention_in_days = local.cloudwatch_log_group_retention_in_days
}

resource "aws_iam_role" "web_api_server" {
    name                = "${local.service_name}-${local.web_api_server_name}-${local.task_role_postfix}"
    assume_role_policy  = local.common_task_assume_role_policy
    managed_policy_arns = compact([
        aws_iam_policy.web_api_server.arn, aws_iam_policy.email_send_policy.arn,
    ]) 
}

resource "aws_iam_policy" "web_api_server" {
    name = "${local.service_name}-${local.web_api_server_name}-iamPolicy"

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Effect = "Allow"
            Action = [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ]
            Resource = "arn:aws:s3:::${aws_s3_bucket.s3bucket.id}/*"
        },
        {
            Effect = "Allow"
            Action = [
                "s3:ListBucket"
            ]
            Resource = "arn:aws:s3:::${aws_s3_bucket.s3bucket.id}"
        }
        ]
    })
}

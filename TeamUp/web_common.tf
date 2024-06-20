## 사용자 접속 URL Route53 record 등록
resource "aws_route53_record" "web_record" {
  zone_id = data.terraform_remote_state.common.outputs.route53_hosted_zone_id
  name    = local.route53_web_record
  type    = "A"

  weighted_routing_policy {
    weight = 100
  }

  set_identifier = "was01"

  alias {
    name                   = aws_lb.applicationLoadBalancer.dns_name
    zone_id                = aws_lb.applicationLoadBalancer.zone_id
    evaluate_target_health = true
  }
}

// 인증서 생성
resource "aws_acm_certificate" "root_domain_cert" {
  domain_name = local.route53_web_record
  subject_alternative_names = [ "*.${local.route53_web_record}" ]
  key_algorithm = "RSA_2048"
  validation_method = "DNS"
}

# 위 생성된 인증서에 대한 검증을 Route53에 등록하여 검증
resource "aws_route53_record" "root_domain_cert_record" {
  for_each = {
    for dvo in aws_acm_certificate.root_domain_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  allow_overwrite = true # 이슈: 해당 설정이 없다면 동일한 CNAME에 대해서 두 개 이상 등록할 수 없음. 따라서 해당 설정을 true 적용 https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record#allow_overwrite
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 300
  type            = each.value.type
  zone_id         = data.terraform_remote_state.common.outputs.route53_hosted_zone_id
}


###############################################
# ALB
# 생성한 후 ALB DNS Name과 Domain 이름을 전달
# 생성된 인증서의 ARN을 https_cert_arn 변수에 담아서 사용
###############################################
resource "aws_lb" "applicationLoadBalancer" {
  idle_timeout       = 60
  ip_address_type    = "ipv4"
  load_balancer_type = "application"
  name               = lower("${local.service_name}-web-alb")
  security_groups    = [ aws_security_group.teamup_security_group.id, local.default_security_group ]
  subnets            = local.public_subnets
}

resource "aws_lb_target_group" "targetGroupApiWeb" {
    ip_address_type               = "ipv4"
    load_balancing_algorithm_type = "round_robin"
    name                          = lower("${local.service_name}-api-web-tg")
    port                          = 8080
    protocol                      = "HTTP"
    vpc_id                        = local.default_vpc_id

    health_check {
      enabled             = true
      healthy_threshold   = 5
      interval            = 60
      matcher             = "200"
      path                = "/${local.web_api_path}/common/health-check"
      port                = "traffic-port"
      protocol            = "HTTP"
      timeout             = 10
      unhealthy_threshold = 5
    }

    stickiness {
      enabled = false
      type    = "lb_cookie"
    }

}

# ALB에 설정된 HTTPS 리스너 생성
resource "aws_lb_listener" "https" {
  certificate_arn   = aws_acm_certificate.root_domain_cert.arn
  load_balancer_arn = aws_lb.applicationLoadBalancer.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    order            = 1
    target_group_arn = aws_lb_target_group.targetGroupApiWeb.arn
    type             = "forward"
  }
}

# ALB에 설정된 HTTP 리스너 생성
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.applicationLoadBalancer.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    order = 1
    type  = "redirect"

    redirect {
      host        = "#{host}"
      path        = "/#{path}"
      port        = "443"
      protocol    = "HTTPS"
      query       = "#{query}"
      status_code = "HTTP_302"
    }
  }
}

# HTTPS 리스너에 Rule 추가 (/api/* 경로로 요청할 경우 빌드 서버로 이동)
resource "aws_lb_listener_rule" "https_api_server" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 1

  action {
    order            = 1
    target_group_arn = aws_lb_target_group.targetGroupApiWeb.arn
    type             = "forward"
  }

  condition {

    path_pattern {
      values = [
        "/${local.web_api_path}/*",
      ]
    }
  }
}
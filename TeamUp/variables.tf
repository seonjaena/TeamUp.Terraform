variable "aws_account_id" {
    type        = string
    default     = ""
    description = "AWS 계정 ID"
}

variable "asg_max_size" {
    type        = number
    default     = 1
    description = "asg의 최대 수를 지정합니다."
}

variable "asg_desired_size" {
    type        = number
    default     = 1
    description = "asg의 희망 수를 지정합니다."  
}

variable "enable_container_insights" {
    type        = bool
    description = "ECS에서 Container Insights를 사용할 것인지 여부"
    default     = false
}

variable "ses_sender" {
    type        = string
    description = "SES 이메일을 보내는 계정"
    default     = ""
}

variable "sns_alert_email" {
    type        = string
    description = "장애알람 이메일 보내는 계정"
    default     = ""
}

variable "main_db_host" {
    type        = string
    description = "메인 서비스 DB의 주소"
    default     = ""
}

variable "main_db_port" {
    type        = string
    description = "메인 서비스 DB의 port 번호"
    default     = ""
}

variable "main_db_name" {
    type        = string
    description = "메인 서비스 DB의 이름"
    default     = ""
}

variable "main_db_username" {
    type        = string
    description = "메인 서비스 DB의 계정"
    default     = ""
}

variable "main_db_password" {
    type        = string
    description = "메인 서비스 DB의 비밀번호"
    default     = ""
}

variable "jwt_secret_key" {
    type        = string
    description = "JWT의 비밀키"
    default     = ""
}

variable "sms_access_key" {
    type        = string
    description = "COOL SMS의 ACCESS Key"
    default     = ""
}

variable "sms_secret_key" {
    type        = string
    description = "COOL SMS의 SECRET Key"
    default     = ""
}

variable "sms_send_phone" {
    type        = string
    description = "SMS 보내는 전화번호"
    default     = ""
}

variable "front_base_url" {
    type        = string
    description = "프론트엔드의 기본 URL"
    default     = ""
}

variable "profile_image_temp_dir" {
    type        = string
    description = "프로필 이미지가 저장되는 임시 디렉터리"
    default     = ""
}

variable "profile_image_permanent_dir" {
    type        = string
    description = "프로필 이미지가 저장되는 디렉터리"
    default     = ""
}

variable "service_zone_id" {
    type        = string
    description = "서비스가 운영되는 지역의 ZONE ID"
    default     = ""
}

variable "home_ipv4" {
    type        = string
    description = "집 IPv4"
    default     = ""
}

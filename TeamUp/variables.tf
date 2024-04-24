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

variable "cool_sms_key" {
    type        = string
    description = "COOL SMS의 Key"
    default     = ""
}
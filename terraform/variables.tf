variable "region" { 
  type = string
  default = "us-east-1" 
  }
variable "name_prefix" { 
  type = string 
  default = "cac-demo" 
  }
variable "tags" {
  type = map(string)
  default = {
    Owner        = "Platform"
    Environment  = "Dev"
    System       = "ComplianceAsCode"
    DataClass    = "Internal"
  }
}

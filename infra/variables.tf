variable "apply_fixes" {
  description = "Feature flag to toggle security patches on or off. When false, the demo resources remain intentionally vulnerable."
  type        = bool
  default     = false
}

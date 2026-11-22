output "pages_project_name" {
  description = "Cloudflare Pages project name."
  value       = module.devsecops_gatekeeper_lab.pages_project_name
}

output "pages_subdomain" {
  description = "Default Cloudflare Pages subdomain."
  value       = module.devsecops_gatekeeper_lab.pages_subdomain
}

output "lab_url" {
  description = "Production standalone lab URL."
  value       = module.devsecops_gatekeeper_lab.lab_url
}

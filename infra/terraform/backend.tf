terraform {
  backend "gcs" {
    bucket = "0trust-dev-tfstate"
    prefix = "labs/devsecops-gatekeeper"
  }
}

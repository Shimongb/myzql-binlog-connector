-- DuckDB bootstrap for the S3 integration smoke.
--
-- Configures the AWS credential chain so subsequent `read_parquet('s3://...')`
-- queries authenticate using whatever provider is available in the
-- environment (env vars, profile files, IMDS, etc.). This script is
-- loaded via `duckdb -init s3_bootstrap.sql` from the integration test.
--
-- The connector uses STS-vended creds via `x-amz-security-token` for the
-- write path; reading from DuckDB uses the same creds via the
-- `credential_chain` provider. Both pick up `AWS_ACCESS_KEY_ID` /
-- `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` / `AWS_REGION` from the
-- environment.

CREATE OR REPLACE SECRET myzql_smoke_secret (
    TYPE s3,
    PROVIDER credential_chain
);

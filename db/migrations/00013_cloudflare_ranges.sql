-- +goose Up
-- Deployment owns authenticated Cloudflare network cache and expiry evidence.
CREATE TABLE deployment_cloudflare(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),generation text NOT NULL,body jsonb NOT NULL);
-- +goose Down
DROP TABLE deployment_cloudflare;

-- +goose Up
-- deployment owns target runtime bindings, counters and the durable generation
-- dirty marker. The singleton also fences network-free final activation reads.
CREATE TABLE deployment_generation(id boolean PRIMARY KEY DEFAULT true CHECK(id),generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),dirty boolean NOT NULL DEFAULT false,queued_at timestamptz NOT NULL DEFAULT '-infinity');
INSERT INTO deployment_generation(id) VALUES(true);
CREATE TABLE deployment_target_runtime(binding text PRIMARY KEY CHECK(length(binding)=64),body jsonb NOT NULL,sequence bigint NOT NULL DEFAULT 0 CHECK(sequence>=0),checked_at timestamptz);
-- +goose Down
DROP TABLE deployment_target_runtime,deployment_generation;

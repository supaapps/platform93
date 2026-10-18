-- +goose Up
CREATE TABLE billing_subject_closures (
 application_id UUID NOT NULL REFERENCES applications(id),
 subject_type TEXT NOT NULL CHECK(subject_type IN ('user','workspace')),
 subject_id UUID NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(application_id,subject_type,subject_id)
);
-- +goose Down
DROP TABLE billing_subject_closures;

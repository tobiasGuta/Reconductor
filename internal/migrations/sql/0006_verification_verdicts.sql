ALTER TABLE verification_results
    ADD COLUMN evidence_verdict TEXT NOT NULL DEFAULT 'inconclusive'
        CHECK (evidence_verdict IN ('observed','not_observed','inconclusive'));

ALTER TABLE verification_results
    ADD COLUMN impact_verdict TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK (impact_verdict IN ('unreviewed','confirmed','rejected'));

UPDATE verification_results
SET evidence_verdict = 'not_observed',
    impact_verdict = 'rejected'
WHERE verdict = 'rejected';

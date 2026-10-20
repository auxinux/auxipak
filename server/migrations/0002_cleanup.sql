-- Nettoyage des éléments révoqués ou terminés (AuxiPak 1.0.3).
--
-- « purged » : version révoquée dont les fichiers ont été supprimés ; elle
-- n'apparaît plus dans l'interface mais reste dans revocations.json pour que
-- les clients continuent de la refuser.
ALTER TABLE releases DROP CONSTRAINT releases_state_check;
ALTER TABLE releases ADD CONSTRAINT releases_state_check
    CHECK (state IN ('published', 'unpublished', 'revoked', 'purged'));

-- Supprimer un jeton ou une demande ne doit pas être bloqué par l'historique.
ALTER TABLE submissions DROP CONSTRAINT submissions_token_id_fkey;
ALTER TABLE submissions ADD CONSTRAINT submissions_token_id_fkey
    FOREIGN KEY (token_id) REFERENCES api_tokens(id) ON DELETE SET NULL;
ALTER TABLE releases DROP CONSTRAINT releases_submission_id_fkey;
ALTER TABLE releases ADD CONSTRAINT releases_submission_id_fkey
    FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE SET NULL;

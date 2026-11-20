-- хранит учебную копию транзакции непосредственно перед имитацией атаки
CREATE TABLE IF NOT EXISTS attack_backups (
    transaction_id BIGINT PRIMARY KEY REFERENCES transactions(transaction_id) ON DELETE CASCADE,
    employee_name VARCHAR(150) NOT NULL,
    fingerprint_hash CHAR(64) NOT NULL,
    transaction_hash CHAR(64) NOT NULL,
    block_id BIGINT NOT NULL REFERENCES blocks(block_id),
    backed_up_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

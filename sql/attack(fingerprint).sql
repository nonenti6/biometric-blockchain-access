UPDATE transactions
SET fingerprint_hash = encode(
    digest(
        (SELECT fingerprint_template
         FROM employees
         WHERE employee_id = 2),
        'sha256'
    ),
    'hex'
)
WHERE transaction_id = 5;



SELECT transaction_id, employee_name, fingerprint_hash, transaction_hash
FROM transactions
WHERE transaction_id = 5;
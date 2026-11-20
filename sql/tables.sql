SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;

-- Сотрудники
SELECT * FROM employees;

-- Транзакции
SELECT * FROM transactions;

-- Блоки
SELECT * FROM blocks;

-- Транзакции внутри блоков
SELECT * FROM block_transactions;

-- Резервные копии после имитации атаки
SELECT * FROM attack_backups;
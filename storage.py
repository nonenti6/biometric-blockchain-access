"""PostgreSQL-операции. Для подключения нужна переменная DATABASE_URL."""
import os
from datetime import datetime, timezone
import psycopg
from psycopg.rows import dict_row
from core import ZERO_HASH, sha, transaction_hash, merkle, block_hash

class Storage:
    def __init__(self):
        url = os.environ.get('DATABASE_URL')
        if not url:
            raise RuntimeError('Укажите DATABASE_URL в файле .env')
        self.conn = psycopg.connect(url, row_factory=dict_row, autocommit=False)

    def employees(self):
        with self.conn.transaction():
            return self.conn.execute('SELECT employee_id, full_name, department, fingerprint_template FROM employees ORDER BY employee_id').fetchall()

    def transactions(self):
        with self.conn.transaction():
            return self.conn.execute('SELECT * FROM transactions ORDER BY transaction_id DESC LIMIT 200').fetchall()

    def blocks(self):
        with self.conn.transaction():
            return self.conn.execute('SELECT * FROM blocks ORDER BY block_id DESC').fetchall()

    def block_members(self, block_id): # транзакции конкретного блока
        with self.conn.transaction():
            return self.conn.execute('''SELECT bt.position_in_block, bt.recorded_transaction_hash, t.transaction_id, t.employee_name, t.passed_at
                FROM block_transactions bt JOIN transactions t USING(transaction_id)
                WHERE bt.block_id=%s ORDER BY bt.position_in_block''', (block_id,)).fetchall()

    def ensure_genesis(self):
        with self.conn.transaction():
            with self.conn.cursor() as cur:
                cur.execute('SELECT block_id FROM blocks ORDER BY block_id LIMIT 1 FOR UPDATE')
                if cur.fetchone():
                    return
                now = datetime.now(timezone.utc)
                root = ZERO_HASH
                h = block_hash(0, now, ZERO_HASH, root, 0)
                cur.execute('INSERT INTO blocks(block_id, created_at, previous_hash, merkle_root, block_hash, transactions_count) VALUES (0,%s,%s,%s,%s,0)', (now, ZERO_HASH, root, h))

    def scan(self, fingerprint: bytes):
        """получаем тестовый биометрический шаблон и ищет точное совпадение в таблице"""
        with self.conn.transaction(): # поиск сотрудника
            employee = self.conn.execute('SELECT employee_id, full_name, fingerprint_template FROM employees WHERE fingerprint_template=%s', (fingerprint,)).fetchone()
            if not employee:
                return None
            now = datetime.now(timezone.utc)
            fp_hash = sha(bytes(fingerprint))
            with self.conn.cursor() as cur: # создание записи в таблице transactions
                cur.execute('''INSERT INTO transactions(employee_id, employee_name, fingerprint_hash, passed_at, transaction_hash)
                               VALUES (%s,%s,%s,%s,%s) RETURNING transaction_id''',
                            (employee['employee_id'], employee['full_name'], fp_hash, now, ZERO_HASH))
                tx_id = cur.fetchone()['transaction_id'] # получение ID новой транзакции
                h = transaction_hash(tx_id, employee['employee_id'], employee['full_name'], fp_hash, now) # хэш этой транзакции
                cur.execute('UPDATE transactions SET transaction_hash=%s WHERE transaction_id=%s', (h, tx_id)) #0хэш на вычисленный хэш меняем
            return tx_id

    def form_block(self):
        """Одна транзакция БД: создаёт блок только для корректных ожидающих записей."""
        with self.conn.transaction():
            with self.conn.cursor() as cur:
                # Сериализуем операции формирования блоков в одном экземпляре БД.
                cur.execute('SELECT pg_advisory_xact_lock(743291)') #блокировака postgresql, чтоб не было одновременного формирования блоков несколькими командами
                cur.execute('SELECT * FROM transactions WHERE block_id IS NULL ORDER BY transaction_id FOR UPDATE')
                pending = cur.fetchall() # сохраняем результат в pending
                if not pending:
                    return None
                for tx in pending: #перебираем каждую ожидающую транзакцию
                    expected = transaction_hash(tx['transaction_id'], tx['employee_id'], tx['employee_name'], tx['fingerprint_hash'], tx['passed_at'])
                    if expected != tx['transaction_hash'].strip():
                        raise ValueError(f'Нарушена целостность ожидающей транзакции №{tx["transaction_id"]}')
                cur.execute('SELECT * FROM blocks ORDER BY block_id DESC LIMIT 1 FOR UPDATE') # получение предыдущего блока
                last = cur.fetchone()
                index = int(last['block_id']) + 1
                prev = last['block_hash'].strip()
                hashes = [tx['transaction_hash'].strip() for tx in pending] #список хэшей всех ожидающих транзакций
                root = merkle(hashes)
                now = datetime.now(timezone.utc)
                h = block_hash(index, now, prev, root, len(pending))
                cur.execute('INSERT INTO blocks(block_id,created_at,previous_hash,merkle_root,block_hash,transactions_count) VALUES(%s,%s,%s,%s,%s,%s)', (index, now, prev, root, h, len(pending))) # сохранение блока в PostgreSQL
                for position, tx in enumerate(pending): #привязка транзакций к блоку (block_transactions)
                    cur.execute('INSERT INTO block_transactions(block_id,transaction_id,position_in_block,recorded_transaction_hash) VALUES(%s,%s,%s,%s)', (index, tx['transaction_id'], position, hashes[position]))
                    cur.execute('UPDATE transactions SET block_id=%s WHERE transaction_id=%s', (index, tx['transaction_id']))
                return index, len(pending)

    def verify(self):
        """Проверяет записи, привязки, корни Меркла, хэши блоков и связи."""
        problems = []
        with self.conn.transaction():
            with self.conn.cursor() as cur:
                cur.execute('SELECT * FROM blocks ORDER BY block_id')
                blocks = cur.fetchall()
                cur.execute('SELECT * FROM transactions ORDER BY transaction_id')
                txs = cur.fetchall()
                cur.execute('SELECT * FROM block_transactions ORDER BY block_id,position_in_block')
                members = cur.fetchall()
                tx_by_id = {t['transaction_id']: t for t in txs} # ключ — номер транзакции, а значение — сама транзакция
                # block_ids = {b['block_id'] for b in blocks}
                member_by_tx = {}
                for m in members:
                    member_by_tx.setdefault(m['transaction_id'], []).append(m)
                for tx in txs:
                    expected = transaction_hash(tx['transaction_id'], tx['employee_id'], tx['employee_name'], tx['fingerprint_hash'], tx['passed_at'])
                    if expected != tx['transaction_hash'].strip():
                        problems.append(f'Транзакция №{tx["transaction_id"]}: изменены данные или хэш')
                    linked = member_by_tx.get(tx['transaction_id'], [])
                    if tx['block_id'] is None and linked:
                        problems.append(f'Транзакция №{tx["transaction_id"]}: есть связь с блоком при статусе PENDING')
                    if tx['block_id'] is not None and (len(linked) != 1 or linked[0]['block_id'] != tx['block_id']):
                        problems.append(f'Транзакция №{tx["transaction_id"]}: нарушена привязка к блоку')
                for m in members:
                    tx = tx_by_id.get(m['transaction_id'])
                    if not tx:
                        problems.append(f'Связь с отсутствующей транзакцией №{m["transaction_id"]}')
                    elif m['recorded_transaction_hash'].strip() != tx['transaction_hash'].strip():
                        problems.append(f'Транзакция №{m["transaction_id"]}: хэш отличается от записанного в блоке')
                if not blocks or blocks[0]['block_id'] != 0:
                    problems.append('Отсутствует генезис-блок')
                previous = ZERO_HASH
                for idx, b in enumerate(blocks):
                    bid = b['block_id']
                    if bid != idx:
                        problems.append(f'Блок №{bid}: нарушена последовательность номеров')
                    if b['previous_hash'].strip() != previous:
                        problems.append(f'Блок №{bid}: неверный previous_hash')
                    own = [m for m in members if m['block_id'] == bid] # берем транзакции, которые принадлежат именно этому блоку bid
                    if [m['position_in_block'] for m in own] != list(range(len(own))):
                        problems.append(f'Блок №{bid}: неверный порядок транзакций')
                    if b['transactions_count'] != len(own):
                        problems.append(f'Блок №{bid}: неверное количество транзакций')
                    if b['merkle_root'].strip() != merkle([m['recorded_transaction_hash'].strip() for m in own]):
                        problems.append(f'Блок №{bid}: не совпадает Merkle Root')
                    calculated = block_hash(bid, b['created_at'], b['previous_hash'], b['merkle_root'], b['transactions_count'])
                    if calculated != b['block_hash'].strip():
                        problems.append(f'Блок №{bid}: не совпадает хэш блока')
                    previous = b['block_hash'].strip()
                return len(blocks), len(txs), problems

    def attack_backups(self):
        with self.conn.transaction():
            return self.conn.execute("SELECT transaction_id FROM attack_backups ORDER BY transaction_id").fetchall()

    def restore(self, tx_id):
        # Восстанавливает только транзакции, сохранённые ДО учебной атаки.
        with self.conn.transaction():
            with self.conn.cursor() as cur:
                cur.execute('SELECT * FROM attack_backups WHERE transaction_id=%s FOR UPDATE', (tx_id,))
                backup = cur.fetchone()
                if backup is None:
                    raise ValueError('Для этой транзакции нет резервной копии до атаки. Ранее изменённые данные автоматически восстановить нельзя.')
                cur.execute('SELECT * FROM transactions WHERE transaction_id=%s FOR UPDATE', (tx_id,))
                current = cur.fetchone()
                if not current or current['block_id'] != backup['block_id']:
                    raise ValueError('Транзакция отсутствует или её связь с блоком изменена.')
                cur.execute('''UPDATE transactions SET employee_name=%s, fingerprint_hash=%s,
                    transaction_hash=%s WHERE transaction_id=%s''',
                    (backup['employee_name'], backup['fingerprint_hash'], backup['transaction_hash'], tx_id))
                cur.execute('DELETE FROM attack_backups WHERE transaction_id=%s', (tx_id,))

    def hash_diagnostics(self): # какие хэши перестали совпадать
        with self.conn.transaction():
            rows = self.conn.execute('''SELECT t.*, bt.recorded_transaction_hash, bt.block_id AS recorded_block_id
                FROM transactions t LEFT JOIN block_transactions bt ON bt.transaction_id=t.transaction_id
                ORDER BY t.transaction_id''').fetchall()
        result = []
        for tx in rows:
            actual = transaction_hash(tx['transaction_id'], tx['employee_id'], tx['employee_name'], # сейчас вычисляем
                                      tx['fingerprint_hash'], tx['passed_at'])
            current = tx['transaction_hash'].strip() #записанный в таблице transactions
            recorded = tx['recorded_transaction_hash'] #в block_transactions (блокчейн)
            recorded = recorded.strip() if recorded is not None else None
            if actual != current or (recorded is not None and current != recorded):
                result.append(dict(id=tx['transaction_id'], block_id=tx['block_id'],
                                   recorded=recorded, current=current, calculated=actual))
        return result

    def attack(self, tx_id, kind, new_value=None, recalc=False):
        """Преднамеренно меняет данные в PostgreSQL"""
        with self.conn.transaction():
            with self.conn.cursor() as cur:
                cur.execute('SELECT * FROM transactions WHERE transaction_id=%s FOR UPDATE', (tx_id,))
                tx = cur.fetchone() # получаем атакуемую транзакцию
                if not tx or tx['block_id'] is None:
                    raise ValueError('Выберите транзакцию, уже включённую в блок.')
                # сохраняем исходные поля один раз, перед первой атакой
                # если запись уже повреждена, не создаём ложную «чистую» копию
                recorded = cur.execute('SELECT recorded_transaction_hash FROM block_transactions WHERE transaction_id=%s', (tx_id,)).fetchone() # исходный хэш
                expected = transaction_hash(tx['transaction_id'], tx['employee_id'], tx['employee_name'], tx['fingerprint_hash'], tx['passed_at']) # пересчитанный хэш
                if (not recorded or expected != tx['transaction_hash'].strip() # если транзакция еще не в блоке, перерасчитанный хэш не совпадает, злоум изм хэш
                        or recorded['recorded_transaction_hash'].strip() != tx['transaction_hash'].strip()):
                    existing = cur.execute('SELECT 1 FROM attack_backups WHERE transaction_id=%s', (tx_id,)).fetchone() #проверяем существование копии
                    if not existing:
                        raise ValueError('Транзакция уже изменена, а исходной резервной копии нет. Новую атаку для неё выполнять нельзя.')
                else:
                    cur.execute('''INSERT INTO attack_backups
                        (transaction_id, employee_name, fingerprint_hash, transaction_hash, block_id)
                        VALUES (%s,%s,%s,%s,%s) ON CONFLICT (transaction_id) DO NOTHING''',
                        (tx_id, tx['employee_name'], tx['fingerprint_hash'], tx['transaction_hash'], tx['block_id']))
                if kind == 'name':
                    if not new_value or not new_value.strip():
                        raise ValueError('Введите новое имя.')
                    cur.execute('UPDATE transactions SET employee_name=%s WHERE transaction_id=%s', (new_value.strip(), tx_id)) # взлом
                    tx['employee_name'] = new_value.strip()
                elif kind == 'fingerprint':
                    cur.execute('SELECT fingerprint_template FROM employees WHERE employee_id=%s', (int(new_value),))
                    row = cur.fetchone()
                    if not row: #если row вернул None
                        raise ValueError('Сотрудник с таким ID не найден.')
                    new_fp_hash = sha(bytes(row['fingerprint_template']))
                    cur.execute('UPDATE transactions SET fingerprint_hash=%s WHERE transaction_id=%s', (new_fp_hash, tx_id)) # взлом
                    tx['fingerprint_hash'] = new_fp_hash
                else:
                    raise ValueError('Неизвестный тип атаки.')
                if recalc:
                    h = transaction_hash(tx['transaction_id'], tx['employee_id'], tx['employee_name'], tx['fingerprint_hash'], tx['passed_at'])
                    cur.execute('UPDATE transactions SET transaction_hash=%s WHERE transaction_id=%s', (h, tx_id)) # взлом

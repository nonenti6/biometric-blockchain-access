import hashlib
import json
from datetime import timezone

ZERO_HASH = '0' * 64

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical(data: dict) -> bytes:
    """Канонический JSON: UTF-8, сортировка ключей, компактные разделители."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')

# в sha входят поля:
def tx_payload(tx_id, employee_id, name, fingerprint_hash, passed_at):
    return dict(transaction_id=int(tx_id), employee_id=int(employee_id), employee_name=name,
                fingerprint_hash=fingerprint_hash.strip(), passed_at=passed_at.astimezone(timezone.utc).isoformat(timespec='microseconds'))

# считаем хэш
def transaction_hash(tx_id, employee_id, name, fingerprint_hash, passed_at):
    return sha(canonical(tx_payload(tx_id, employee_id, name, fingerprint_hash, passed_at)))

def merkle(hashes):
    if not hashes: # пустой
        return ZERO_HASH
    level = [bytes.fromhex(h.strip()) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)] # digest() результат в байтовом виде
    return level[0].hex()

def block_hash(block_id, created_at, previous_hash, merkle_root, count):
    payload = dict(block_id=int(block_id), created_at=created_at.astimezone(timezone.utc).isoformat(timespec='microseconds'),
                   previous_hash=previous_hash.strip(), merkle_root=merkle_root.strip(), transactions_count=int(count))
    return sha(canonical(payload))

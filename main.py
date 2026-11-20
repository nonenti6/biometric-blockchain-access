"""Tkinter-приложение: демонстрационная система контроля доступа с блокчейном."""
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from pathlib import Path
from core import sha
from storage import Storage

INTERVAL_SECONDS = 60

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Биометрический блокчейн — контроль проходов')
        self.geometry('1100x740')
        self.minsize(940, 620)
        self.db = Storage()
        self.db.ensure_genesis()
        self.seconds_left = INTERVAL_SECONDS
        self.status = tk.StringVar(value='Система запущена')
        self.timer = tk.StringVar(value='До следующего блока: 01:00')
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill='both', expand=True, padx=12, pady=12)
        self._employees_tab()
        self._transactions_tab()
        self._blocks_tab()
        self._integrity_tab()
        self._attack_tab()
        footer = ttk.Frame(self)
        footer.pack(fill='x', padx=12, pady=(0, 12))
        ttk.Label(footer, textvariable=self.timer).pack(side='left')
        ttk.Label(footer, textvariable=self.status).pack(side='right')
        self.refresh()
        self.verify(show_success=False)
        self.after(1000, self.tick)

    def tree(self, parent, cols, widths=None):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True, padx=12, pady=10)
        table = ttk.Treeview(frame, columns=cols, show='headings', height=13)
        for i, c in enumerate(cols):
            table.heading(c, text=c)
            table.column(c, width=(widths or {}).get(c, 150), stretch=True)
        sb = ttk.Scrollbar(frame, orient='vertical', command=table.yview)
        table.configure(yscrollcommand=sb.set)
        table.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')
        return table

    def _employees_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text='Сканер и сотрудники')
        ttk.Label(tab, text='Имитация сканера: выберите тестовый отпечаток сотрудника. Совпадение байтов означает успешный проход.', wraplength=950).pack(anchor='w', padx=12, pady=12)
        self.employee_tree = self.tree(tab, ('ID', 'ФИО', 'Отдел', 'SHA-256 отпечатка'))
        actions = ttk.Frame(tab)
        actions.pack(fill='x', padx=12, pady=8)
        ttk.Button(actions, text='Сканировать выбранный отпечаток', command=self.scan_selected).pack(side='left', padx=4)
        ttk.Button(actions, text='Сканировать неизвестный отпечаток', command=self.scan_unknown).pack(side='left', padx=4)
        ttk.Button(actions, text='Обновить', command=self.refresh).pack(side='left', padx=4)

    def _transactions_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text='Транзакции')
        ttk.Label(tab, text='Каждый успешный проход — отдельная транзакция. PENDING означает ожидание блока.').pack(anchor='w', padx=12, pady=10)
        self.tx_tree = self.tree(tab, ('ID', 'Сотрудник', 'Время прохода', 'Блок', 'Хэш транзакции'))
        ttk.Button(tab, text='Обновить', command=self.refresh).pack(anchor='w', padx=12, pady=8)

    def _blocks_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text='Блокчейн')
        ttk.Label(tab, text='Блоки формируются автоматически раз в минуту, если есть ожидающие транзакции.').pack(anchor='w', padx=12, pady=10)
        self.block_tree = self.tree(tab, ('Блок', 'Создан', 'Транзакций', 'Хэш блока'))
        self.block_tree.bind('<<TreeviewSelect>>', self.show_block)
        self.block_details = tk.Text(tab, height=11, wrap='word')
        # Подробности скрыты до выбора блока.
        self.block_details.configure(state='disabled')
        self.block_refresh_button = ttk.Button(tab, text='Обновить', command=self.refresh)
        self.block_refresh_button.pack(anchor='w', padx=12, pady=8)

    def _integrity_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text='Проверка целостности')
        ttk.Label(tab, text='Проверяются транзакции, связи, дерево Меркла и хэши блоков. Автоматически — каждую минуту.').pack(anchor='w', padx=12, pady=12)
        ttk.Button(tab, text='Проверить сейчас', command=self.verify).pack(anchor='w', padx=12, pady=8)
        self.integrity_text = tk.Text(tab, height=22, wrap='word')
        self.integrity_text.pack(fill='both', expand=True, padx=12, pady=10)
        self.integrity_text.tag_configure('alert', foreground='#a00000')
        self.integrity_text.tag_configure('ok', foreground='#006b30')
        self.integrity_text.tag_configure('hash', foreground='#243b65', font=('Consolas', 10))

    def _attack_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text='Имитация атаки')
        ttk.Label(tab, text='внимание: атака действительно изменяет данные PostgreSQL.', foreground='#9b2500').pack(anchor='w', padx=12, pady=14)
        box = ttk.Frame(tab)
        box.pack(anchor='w', padx=12)
        ttk.Label(box, text='Транзакция (из сформированного блока):').grid(row=0, column=0, sticky='w', pady=6)
        self.attack_tx = ttk.Combobox(box, state='readonly', width=65)
        self.attack_tx.grid(row=0, column=1, pady=6)
        self.attack_tx_ids = {}
        ttk.Label(box, text='Тип изменения:').grid(row=1, column=0, sticky='w', pady=6)
        self.attack_kind = ttk.Combobox(box, state='readonly', values=('ФИО', 'Отпечаток'), width=25)
        self.attack_kind.current(0)
        self.attack_kind.grid(row=1, column=1, pady=6)
        ttk.Label(box, text='Новое ФИО или ID другого сотрудника:').grid(row=2, column=0, sticky='w', pady=6)
        self.attack_value = ttk.Entry(box, width=28)
        self.attack_value.grid(row=2, column=1, pady=6)
        self.recalc = tk.BooleanVar(value=True)
        ttk.Checkbutton(box, text='Пересчитать также хэш транзакции', variable=self.recalc).grid(row=3, column=0, columnspan=2, sticky='w', pady=8)
        ttk.Button(box, text='Выполнить подмену', command=self.attack).grid(row=4, column=0, sticky='w', pady=10)
        ttk.Button(box, text='Восстановить транзакцию', command=self.restore_attack).grid(row=4, column=1, sticky='w', pady=10)
        ttk.Label(tab, text='Восстановление доступно для атак, сделанных после установки обновления. Блоки не пересчитываются.', wraplength=900).pack(anchor='w', padx=12, pady=14)

    def refresh(self):
        self.employee_cache = {str(e['employee_id']): e for e in self.db.employees()}
        # При обновлении списка скрываем подробности предыдущего выбора.
        self.block_details.pack_forget()
        for table in (self.employee_tree, self.tx_tree, self.block_tree):
            for item in table.get_children():
                table.delete(item)
        for e in self.employee_cache.values():
            self.employee_tree.insert('', 'end', iid=str(e['employee_id']), values=(e['employee_id'], e['full_name'], e['department'], sha(bytes(e['fingerprint_template']))))
        attack_options = []
        attack_ids = {}
        for t in self.db.transactions():
            if t['block_id'] is not None:
                label = (f"№{t['transaction_id']} — {t['employee_name']} — "
                         f"{t['passed_at'].strftime('%Y-%m-%d %H:%M:%S')} — Блок {t['block_id']}")
                attack_options.append(label)
                attack_ids[label] = t['transaction_id']
            self.tx_tree.insert('', 'end', values=(t['transaction_id'], t['employee_name'], t['passed_at'].strftime('%Y-%m-%d %H:%M:%S'), t['block_id'] if t['block_id'] is not None else 'PENDING', t['transaction_hash'].strip()))
        previous_selection = self.attack_tx.get()
        self.attack_tx_ids = attack_ids
        self.attack_tx['values'] = attack_options
        if previous_selection in attack_ids:
            self.attack_tx.set(previous_selection)
        elif attack_options:
            self.attack_tx.current(0)
        else:
            self.attack_tx.set('')
        for b in self.db.blocks():
            self.block_tree.insert('', 'end', iid=str(b['block_id']), values=(b['block_id'], b['created_at'].strftime('%Y-%m-%d %H:%M:%S'), b['transactions_count'], b['block_hash'].strip()))

    def scan_selected(self):
        chosen = self.employee_tree.selection()
        if not chosen:
            messagebox.showinfo('Сканер', 'Сначала выберите сотрудника в таблице.')
            return
        employee = self.employee_cache[chosen[0]]
        self._scan(bytes(employee['fingerprint_template']))

    def scan_unknown(self):
        self._scan(b'unknown-fingerprint-for-demo')

    def _scan(self, data):
        try:
            tx_id = self.db.scan(data)
            if tx_id is None:
                self.status.set('Доступ запрещён: отпечаток не найден')
                messagebox.showwarning('Сканер', 'Доступ запрещён. Неизвестный отпечаток. Транзакция не создаётся.')
            else:
                self.status.set(f'Доступ разрешён. Транзакция №{tx_id} ожидает блока')
                messagebox.showinfo('Сканер', f'Доступ разрешён. Создана транзакция №{tx_id}.')
            self.refresh()
        except Exception as exc:
            self.error(exc)

    def show_block(self, event=None):
        selected = self.block_tree.selection()
        if not selected:
            return
        bid = int(selected[0])
        b = next((x for x in self.db.blocks() if x['block_id'] == bid), None)
        if b is None:
            return
        members = self.db.block_members(bid)
        # Размещаем подробности перед кнопкой обновления только после выбора блока.
        self.block_details.pack(fill='x', padx=12, pady=8, before=self.block_refresh_button)
        text = (f'БЛОК №{bid}\nСоздан: {b["created_at"]}\nPrevious hash: {b["previous_hash"].strip()}\n'
                f'Merkle root: {b["merkle_root"].strip()}\nBlock hash: {b["block_hash"].strip()}\n'
                f'Транзакций: {len(members)}\n\n')
        text += '\n'.join(f'{m["position_in_block"] + 1}. TX {m["transaction_id"]} — {m["employee_name"]} — {m["recorded_transaction_hash"].strip()}' for m in members)
        self.block_details.configure(state='normal')
        self.block_details.delete('1.0', 'end')
        self.block_details.insert('end', text)
        self.block_details.configure(state='disabled')

    def verify(self, show_success=True):
        try:
            nblocks, ntx, issues = self.db.verify()
            self.integrity_text.delete('1.0', 'end')
            self.integrity_text.insert('end', f'Проверено блоков: {nblocks}\nПроверено транзакций: {ntx}\n\n')
            if issues:
                self.integrity_text.insert('end', 'ОБНАРУЖЕНО НАРУШЕНИЕ ЦЕЛОСТНОСТИ!\n\n', 'alert')
                self.integrity_text.insert('end', '\n'.join('• ' + x for x in issues), 'alert')
                details = self.db.hash_diagnostics()
                if details:
                    self.integrity_text.insert('end', '\n\nСРАВНЕНИЕ SHA-256 (64 символа):\n')
                    for d in details:
                        self.integrity_text.insert('end', f'\nТранзакция №{d["id"]}, блок №{d["block_id"]}:\n')
                        self.integrity_text.insert('end', f'  Исходный хэш транзакции:       {d["recorded"] or "нет записи в блоке"}\n', 'hash')
                        self.integrity_text.insert('end', f'  Пересчитанный хэш транзакции:   {d["calculated"]}\n', 'hash')
                        self.integrity_text.insert('end', f'  Измененный (злоумышленником) хэш транзакции:  {d["current"]}\n', 'hash')
                        if d['recorded'] is not None:
                            self.integrity_text.insert(
                                'end',
                                f'  Результат: {"ХЭШИ СОВПАДАЮТ" if d["recorded"] == d["calculated"] else "ХЭШИ НЕ СОВПАДАЮТ"}\n'
                            )
                self.integrity_text.insert('end', '\nФОРМИРОВАНИЕ БЛОКОВ ПРИОСТАНОВЛЕНО. Новые транзакции остаются PENDING.\n', 'alert')
                self.status.set(f'АТАКА / НАРУШЕНИЕ ЦЕЛОСТНОСТИ: {len(issues)} проблем')
                # Не показываем всплывающее окно каждую минуту; красный статус остаётся видимым.
            else:
                self.integrity_text.insert('end', 'ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНА\nИзменений не обнаружено.', 'ok')
                self.status.set('Целостность подтверждена')
                if show_success:
                    messagebox.showinfo('Проверка', 'Целостность подтверждена.')
            return not issues
        except Exception as exc:
            self.error(exc)
            return False

    def attack(self):
        try:
            selected = self.attack_tx.get()
            if selected not in self.attack_tx_ids:
                messagebox.showinfo('Имитация атаки', 'Выберите транзакцию из списка. Сначала должен сформироваться блок.')
                return
            tx_id = self.attack_tx_ids[selected]
            kind = 'name' if self.attack_kind.get() == 'ФИО' else 'fingerprint'
            value = self.attack_value.get()
            if not messagebox.askyesno('Подтверждение', 'Изменить данные в PostgreSQL? Это демонстрационная атака.'):
                return
            self.db.attack(tx_id, kind, value, self.recalc.get())
            self.refresh()
            self.verify(show_success=False)
            self.tabs.select(3)
        except Exception as exc:
            self.error(exc)

    def restore_attack(self):
        try:
            selected = self.attack_tx.get()
            if selected not in self.attack_tx_ids:
                messagebox.showinfo('Восстановление', 'Выберите транзакцию из списка.')
                return
            tx_id = self.attack_tx_ids[selected]
            if not messagebox.askyesno('Восстановление', f'Восстановить транзакцию №{tx_id} из резервной копии до атаки?'):
                return
            self.db.restore(tx_id)
            self.refresh()
            good = self.verify(show_success=False)
            self.tabs.select(3)
            if good:
                messagebox.showinfo('Восстановление', 'Целостность подтверждена. Создание блоков возобновится на следующем минутном интервале.')
            else:
                messagebox.showwarning('Восстановление', 'Транзакция восстановлена, но остаются другие нарушения целостности.')
        except Exception as exc:
            self.error(exc)

    def tick(self):
        self.seconds_left -= 1
        if self.seconds_left <= 0:
            self.seconds_left = INTERVAL_SECONDS
            try:
                # Не добавляем блок поверх уже обнаруженного нарушения.
                if self.verify(show_success=False):
                    result = self.db.form_block()
                    if result:
                        self.status.set(f'Сформирован блок №{result[0]}, транзакций: {result[1]}')
                    self.refresh()
                    self.verify(show_success=False)
            except Exception as exc:
                self.error(exc)
        self.timer.set(f'До следующего блока: {self.seconds_left // 60:02d}:{self.seconds_left % 60:02d}')
        self.after(1000, self.tick)

    def error(self, exc):
        self.status.set('Ошибка: ' + str(exc))
        messagebox.showerror('Ошибка', str(exc))

if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).with_name('.env'))
    try:
        app = App()
        app.mainloop()
    except Exception as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror('Ошибка запуска', str(exc))
        root.destroy()

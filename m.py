import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import random
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("密码管理器")
        self.root.geometry("1000x600")
        
        # 加密相关初始化
        self.key = None
        self.setup_encryption()
        
        # 初始化数据库
        self.conn = sqlite3.connect('passwords.db')
        self.create_table()
        
        # 创建界面组件
        self.create_widgets()
        self.load_data()

    def setup_encryption(self):
        """设置加密密钥"""
        try:
            with open("secret.key", "rb") as key_file:
                self.key = key_file.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open("secret.key", "wb") as key_file:
                key_file.write(self.key)
        
        self.cipher_suite = Fernet(self.key)

    def encrypt_password(self, password):
        """加密密码"""
        return self.cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """解密密码"""
        return self.cipher_suite.decrypt(encrypted_password.encode()).decode()

    def create_table(self):
        """创建数据库表"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                url TEXT,
                notes TEXT
            )
        ''')
        self.conn.commit()

    def create_widgets(self):
        """创建界面组件"""
        # 顶部操作栏
        top_frame = ttk.Frame(self.root)
        top_frame.pack(pady=10, fill=tk.X)
        
        ttk.Button(top_frame, text="新增", command=self.add_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="编辑", command=self.edit_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="删除", command=self.delete_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="生成密码", command=self.generate_password_dialog).pack(side=tk.LEFT, padx=5)
        
        # 搜索栏
        search_frame = ttk.Frame(self.root)
        search_frame.pack(pady=5, fill=tk.X)
        
        self.search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_var, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="搜索", command=self.search_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="显示全部", command=self.load_data).pack(side=tk.LEFT, padx=5)
        
        # 数据表格
        columns = ("ID", "网站/应用", "用户名", "密码", "网址", "备注")
        self.tree = ttk.Treeview(
            self.root, 
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # 设置列属性
        self.tree.heading("ID", text="ID")
        self.tree.heading("网站/应用", text="网站/应用")
        self.tree.heading("用户名", text="用户名")
        self.tree.heading("密码", text="密码")
        self.tree.heading("网址", text="网址")
        self.tree.heading("备注", text="备注")
        
        self.tree.column("ID", width=50, anchor="center")
        self.tree.column("网站/应用", width=150)
        self.tree.column("用户名", width=150)
        self.tree.column("密码", width=200)
        self.tree.column("网址", width=200)
        self.tree.column("备注", width=250)
        
        # 添加右键菜单
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # 状态栏
        self.status = ttk.Label(self.root, relief=tk.SUNKEN)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def load_data(self, search_query=None):
        """加载/刷新数据"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        cursor = self.conn.cursor()
        if search_query:
            cursor.execute('''
                SELECT * FROM passwords 
                WHERE website LIKE ? OR username LIKE ? OR url LIKE ? OR notes LIKE ?
            ''', (f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"))
        else:
            cursor.execute('SELECT * FROM passwords ORDER BY website')
        
        for row in cursor.fetchall():
            decrypted_password = self.decrypt_password(row[3])
            display_password = "*" * 12  # 默认显示星号
            self.tree.insert("", tk.END, values=(
                row[0], 
                row[1], 
                row[2], 
                display_password, 
                row[4], 
                row[5]
            ), tags=(decrypted_password,))  # 存储解密后的密码在tag中

    def get_selected_id(self):
        selected = self.tree.selection()
        if selected:
            return self.tree.item(selected[0])['values'][0]
        return None

    def add_password(self):
        dialog = PasswordDialog(
            self.root, 
            title="新增密码条目",
            on_submit=lambda data: self.save_password(data)
        )

    def edit_password(self):
        selected_id = self.get_selected_id()
        if selected_id:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM passwords WHERE id=?', (selected_id,))
            password_data = cursor.fetchone()
            
            decrypted_password = self.decrypt_password(password_data[3])
            
            dialog = PasswordDialog(
                self.root,
                title="编辑密码条目",
                initial_data={
                    "website": password_data[1],
                    "username": password_data[2],
                    "password": decrypted_password,
                    "url": password_data[4],
                    "notes": password_data[5]
                },
                on_submit=lambda data: self.update_password(selected_id, data)
            )
        else:
            messagebox.showwarning("提示", "请先选择要编辑的条目")

    def delete_password(self):
        selected_id = self.get_selected_id()
        if selected_id:
            if messagebox.askyesno("确认删除", "确定要删除该密码条目吗？"):
                cursor = self.conn.cursor()
                cursor.execute('DELETE FROM passwords WHERE id=?', (selected_id,))
                self.conn.commit()
                self.load_data()
        else:
            messagebox.showwarning("提示", "请先选择要删除的条目")

    def search_password(self):
        query = self.search_var.get()
        self.load_data(query)
        self.status.config(text=f"搜索到 {len(self.tree.get_children())} 条结果")

    def save_password(self, data):
        encrypted_password = self.encrypt_password(data['password'])
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (website, username, encrypted_password, url, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            data['website'],
            data['username'],
            encrypted_password,
            data['url'],
            data['notes']
        ))
        self.conn.commit()
        self.load_data()
        self.status.config(text="密码保存成功")

    def update_password(self, password_id, data):
        encrypted_password = self.encrypt_password(data['password'])
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE passwords 
            SET website=?, username=?, encrypted_password=?, url=?, notes=?
            WHERE id=?
        ''', (
            data['website'],
            data['username'],
            encrypted_password,
            data['url'],
            data['notes'],
            password_id
        ))
        self.conn.commit()
        self.load_data()
        self.status.config(text="密码更新成功")

    def generate_password_dialog(self):
        """生成密码对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("生成随机密码")
        
        length_var = tk.IntVar(value=16)
        use_upper = tk.BooleanVar(value=True)
        use_digits = tk.BooleanVar(value=True)
        use_symbols = tk.BooleanVar(value=True)
        
        ttk.Label(dialog, text="密码长度：").grid(row=0, column=0, padx=5, pady=5)
        ttk.Spinbox(dialog, from_=8, to=32, textvariable=length_var).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Checkbutton(dialog, text="包含大写字母", variable=use_upper).grid(row=1, column=0, columnspan=2, sticky=tk.W)
        ttk.Checkbutton(dialog, text="包含数字", variable=use_digits).grid(row=2, column=0, columnspan=2, sticky=tk.W)
        ttk.Checkbutton(dialog, text="包含特殊符号", variable=use_symbols).grid(row=3, column=0, columnspan=2, sticky=tk.W)
        
        generated_password = tk.StringVar()
        ttk.Entry(dialog, textvariable=generated_password, width=25).grid(row=4, column=0, padx=5, pady=5)
        ttk.Button(dialog, text="生成", command=lambda: self.generate_password(
            length_var.get(),
            use_upper.get(),
            use_digits.get(),
            use_symbols.get(),
            generated_password
        )).grid(row=4, column=1, padx=5, pady=5)
        
        ttk.Button(dialog, text="使用此密码", command=lambda: self.use_generated_password(generated_password.get(), dialog)).grid(row=5, columnspan=2)

    def generate_password(self, length, use_upper, use_digits, use_symbols, password_var):
        """生成随机密码"""
        chars = string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += string.punctuation
        
        if len(chars) == 0:
            messagebox.showwarning("错误", "至少选择一种字符类型")
            return
        
        password = ''.join(random.choice(chars) for _ in range(length))
        password_var.set(password)

    def use_generated_password(self, password, dialog):
        """使用生成的密码"""
        if password:
            dialog.destroy()
            self.add_password()
            # 这里需要将生成的密码传递到新增对话框，实际实现可能需要修改对话框类

    def show_context_menu(self, event):
        """显示右键菜单"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="复制密码", command=self.copy_password)
        menu.add_command(label="显示密码", command=self.reveal_password)
        menu.add_command(label="打开网址", command=self.open_url)
        menu.tk_popup(event.x_root, event.y_root)

    def copy_password(self):
        """复制密码到剪贴板"""
        selected = self.tree.selection()
        if selected:
            decrypted_password = self.tree.item(selected[0], "tags")[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(decrypted_password)
            self.status.config(text="密码已复制到剪贴板")

    def reveal_password(self):
        """显示密码"""
        selected = self.tree.selection()
        if selected:
            decrypted_password = self.tree.item(selected[0], "tags")[0]
            self.tree.set(selected[0], "密码", decrypted_password)
            self.root.after(3000, lambda: self.tree.set(selected[0], "密码", "*"*12))  # 3秒后隐藏

    def open_url(self):
        """打开网址"""
        selected = self.tree.selection()
        if selected:
            url = self.tree.set(selected[0], "网址")
            if url.startswith(('http://', 'https://')):
                import webbrowser
                webbrowser.open(url)
            else:
                messagebox.showwarning("提示", "无效的网址格式")

class PasswordDialog(tk.Toplevel):
    """密码输入对话框"""
    def __init__(self, parent, title, initial_data=None, on_submit=None):
        super().__init__(parent)
        self.title(title)
        self.on_submit = on_submit
        
        initial_data = initial_data or {
            "website": "",
            "username": "",
            "password": "",
            "url": "",
            "notes": ""
        }
        
        # 创建表单组件
        ttk.Label(self, text="网站/应用：").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.website_var = tk.StringVar(value=initial_data['website'])
        ttk.Entry(self, textvariable=self.website_var).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(self, text="用户名：").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.username_var = tk.StringVar(value=initial_data['username'])
        ttk.Entry(self, textvariable=self.username_var).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(self, text="密码：").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.password_var = tk.StringVar(value=initial_data['password'])
        self.password_entry = ttk.Entry(self, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Button(self, text="显示", command=self.toggle_password_visibility).grid(row=2, column=2)
        
        ttk.Label(self, text="网址：").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.url_var = tk.StringVar(value=initial_data['url'])
        ttk.Entry(self, textvariable=self.url_var).grid(row=3, column=1, padx=5, pady=5)
        
        ttk.Label(self, text="备注：").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.notes_var = tk.StringVar(value=initial_data['notes'])
        ttk.Entry(self, textvariable=self.notes_var).grid(row=4, column=1, padx=5, pady=5)
        
        # 操作按钮
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=5, columnspan=3, pady=10)
        
        ttk.Button(btn_frame, text="提交", command=self.submit).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)

    def toggle_password_visibility(self):
        """切换密码可见性"""
        current_show = self.password_entry.cget("show")
        self.password_entry.config(show="" if current_show else "*")

    def submit(self):
        """提交表单"""
        data = {
            "website": self.website_var.get().strip(),
            "username": self.username_var.get().strip(),
            "password": self.password_var.get().strip(),
            "url": self.url_var.get().strip(),
            "notes": self.notes_var.get().strip()
        }
        
        if not data['website']:
            messagebox.showwarning("错误", "网站/应用名称不能为空")
            return
        
        if not data['username']:
            messagebox.showwarning("错误", "用户名不能为空")
            return
            
        if not data['password']:
            messagebox.showwarning("错误", "密码不能为空")
            return
            
        if self.on_submit:
            self.on_submit(data)
            self.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
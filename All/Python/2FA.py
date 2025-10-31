import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import os
import time
import base64
import hmac
import hashlib
import struct
import datetime
import pyperclip
from PIL import Image, ImageTk, ImageDraw, ImageFont
import math
import sys
import ctypes

# 配置文件路径
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".2fa_verifier_config.json")

def load_no_remind_setting():
    """加载'下次不提醒'的设置"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get("no_remind", False)
    except:
        pass
    return False

def save_no_remind_setting(value):
    """保存'下次不提醒'的设置"""
    try:
        config = {"no_remind": value}
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
    except:
        pass

def is_admin():
    """检查当前是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_data_file_path():
    """获取数据文件路径"""
    try:
        # 始终使用用户目录，避免权限问题
        data_dir = os.path.join(os.path.expanduser("~"), ".2fa_verifier")
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, "verifiers.json")
    except Exception as e:
        print(f"获取数据文件路径失败: {e}")
        # 备用方案：使用当前目录
        return "verifiers.json"

class TOTPGenerator:
    """TOTP生成器类"""
    
    @staticmethod
    def base32_decode(secret):
        """Base32解码"""
        try:
            # 移除空格和填充字符
            secret = secret.upper().replace(' ', '').replace('=', '')
            base32_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
            
            # 检查所有字符是否有效
            for char in secret:
                if char not in base32_chars:
                    raise ValueError(f"Invalid Base32 character: {char}")
            
            # 填充到8的倍数
            padding = 8 - (len(secret) % 8)
            if padding != 8:
                secret += 'A' * padding  # 使用A作为填充字符
            
            bits = ''
            for c in secret:
                bits += format(base32_chars.index(c), '05b')
            
            # 将位转换为字节
            result = bytearray()
            for i in range(0, len(bits), 8):
                byte = bits[i:i+8]
                if len(byte) == 8:
                    result.append(int(byte, 2))
            
            return bytes(result)
        except Exception as e:
            print(f"Base32解码错误: {e}")
            raise
    
    @staticmethod
    def generate_totp(secret, digits=6, time_step=30):
        """生成TOTP代码"""
        try:
            key = TOTPGenerator.base32_decode(secret)
            
            # 计算时间步数
            time_counter = int(time.time()) // time_step
            
            # 将时间计数器转换为字节
            time_bytes = struct.pack('>Q', time_counter)
            
            # 计算HMAC-SHA1
            hmac_hash = hmac.new(key, time_bytes, hashlib.sha1).digest()
            
            # 动态截取
            offset = hmac_hash[-1] & 0x0F
            binary = ((hmac_hash[offset] & 0x7F) << 24) | \
                     ((hmac_hash[offset + 1] & 0xFF) << 16) | \
                     ((hmac_hash[offset + 2] & 0xFF) << 8) | \
                     (hmac_hash[offset + 3] & 0xFF)
            
            # 生成指定位数的代码
            code = binary % (10 ** digits)
            return str(code).zfill(digits)
        except Exception as e:
            print(f"TOTP生成错误: {e}")
            return "ERROR"

class CircularProgressBar(tk.Canvas):
    """圆形进度条"""
    
    def __init__(self, parent, size=120, progress=0, **kwargs):
        super().__init__(parent, width=size, height=size, highlightthickness=0, **kwargs)
        self.size = size
        self.progress = progress
        self.draw()
    
    def draw(self):
        self.delete("all")
        width = self.size
        height = self.size
        radius = min(width, height) / 2 - 5
        
        # 绘制背景圆
        self.create_oval(5, 5, width-5, height-5, outline="#f0f0f0", width=8)
        
        # 绘制进度圆弧
        extent = 360 * self.progress / 100
        self.create_arc(5, 5, width-5, height-5, start=90, extent=-extent, 
                       outline="#1a1a1a", width=8, style="arc")
        
        # 绘制中心文本
        seconds_left = 30 - (int(time.time()) % 30)
        self.create_text(width/2, height/2, text=f"{seconds_left}s", 
                        font=("SF Mono", 16, "bold"), fill="#1a1a1a")
    
    def update_progress(self, progress):
        self.progress = progress
        self.draw()

class VerifierCard(tk.Frame):
    """验证器卡片"""
    
    def __init__(self, parent, name, secret, index, delete_callback, copy_callback, main_root):
        super().__init__(parent, bg="white", highlightbackground="#e5e5e5", 
                         highlightthickness=1, padx=20, pady=20)
        
        self.name = name
        self.secret = secret
        self.index = index
        self.delete_callback = delete_callback
        self.copy_callback = copy_callback
        self.main_root = main_root
        
        # 创建布局
        self.setup_ui()
        
        # 初始更新
        self.update_code()
    
    def setup_ui(self):
        """设置UI"""
        # 顶部区域 - 名称和删除按钮
        top_frame = tk.Frame(self, bg="white")
        top_frame.pack(fill=tk.X, pady=(0, 15))
        
        name_label = tk.Label(top_frame, text=self.name, font=("Segoe UI", 14), 
                            bg="white", fg="#1a1a1a")
        name_label.pack(side=tk.LEFT)
        
        delete_btn = tk.Button(top_frame, text="删除", font=("Segoe UI", 10),
                              bg="white", fg="#999", bd=1, relief=tk.SOLID,
                              activebackground="#f5f5f5", activeforeground="#1a1a1a",
                              command=self.delete)
        delete_btn.pack(side=tk.RIGHT)
        
        # 验证码显示
        self.code_label = tk.Label(self, text="------", font=("SF Mono", 32, "bold"),
                                  bg="white", fg="#1a1a1a")
        self.code_label.pack(pady=10)
        
        # 进度条
        self.progress_bar = CircularProgressBar(self, size=80)
        self.progress_bar.pack(pady=10)
        
        # 复制按钮
        self.copy_btn = tk.Button(self, text="复制验证码", font=("Segoe UI", 12),
                            bg="white", fg="#1a1a1a", bd=1, relief=tk.SOLID,
                            activebackground="#f5f5f5", activeforeground="#1a1a1a",
                            command=self.copy_code)
        self.copy_btn.pack(fill=tk.X, pady=(10, 0))
    
    def update_code(self):
        """更新验证码"""
        try:
            code = TOTPGenerator.generate_totp(self.secret)
            self.code_label.config(text=code)
            
            # 更新进度条
            seconds_left = 30 - (int(time.time()) % 30)
            progress = (seconds_left / 30) * 100
            self.progress_bar.update_progress(progress)
            
            # 继续定时更新
            self.after(1000, self.update_code)
        except Exception as e:
            print(f"更新验证码错误: {e}")
            self.code_label.config(text="ERROR")
            self.after(1000, self.update_code)
    
    def delete(self):
        """删除验证器"""
        if messagebox.askyesno("确认", "确定要删除这个验证器吗？"):
            self.delete_callback(self.index)
    
    def copy_code(self):
        """复制验证码"""
        try:
            code = self.code_label.cget("text")
            if code != "ERROR" and code != "------":
                pyperclip.copy(code)
                # 临时改变按钮文本
                self.copy_btn.config(text="已复制 ✓", bg="#1a1a1a", fg="white")
                self.after(2000, lambda: self.copy_btn.config(text="复制验证码", bg="white", fg="#1a1a1a"))
        except Exception as e:
            messagebox.showerror("错误", f"复制失败: {e}")

class TwoFactorAuthApp:
    """2FA验证器主应用"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("2FA验证器")
        self.root.geometry("800x600")
        self.root.minsize(600, 500)
        
        # 设置DPI感知
        self.setup_dpi()
        
        # 设置应用图标
        self.set_app_icon()
        
        # 获取数据文件路径
        self.data_file = get_data_file_path()
        
        # 加载验证器数据
        self.verifiers = self.load_verifiers()
        
        # 设置UI
        self.setup_ui()
        
        # 渲染验证器列表
        self.render_verifiers()
        
        # 更新统计信息
        self.update_stats()
    
    def setup_dpi(self):
        """设置DPI感知"""
        try:
            if sys.platform == "win32":
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except:
            pass
        
        # 设置缩放因子
        try:
            self.scale_factor = self.root.winfo_fpixels('1i') / 96
        except:
            self.scale_factor = 1.0
        
        # 调整窗口大小
        if self.scale_factor > 1.0:
            width = int(800 * self.scale_factor)
            height = int(600 * self.scale_factor)
            self.root.geometry(f"{width}x{height}")
    
    def set_app_icon(self):
        """设置应用图标"""
        try:
            # 创建一个简单的图标
            img = Image.new('RGBA', (64, 64), color=(255, 255, 255, 0))
            draw = ImageDraw.Draw(img)
            
            # 绘制一个简单的2FA图标
            draw.ellipse((8, 8, 56, 56), fill=(26, 26, 26))
            
            # 尝试使用系统字体
            try:
                font = ImageFont.truetype("arial.ttf", 20)
            except:
                try:
                    font = ImageFont.truetype("Arial", 20)
                except:
                    font = ImageFont.load_default()
            
            draw.text((32, 32), "2FA", fill=(255, 255, 255), anchor="mm", font=font)
            
            # 转换为Tkinter可用的格式
            icon = ImageTk.PhotoImage(img)
            self.root.iconphoto(True, icon)
        except Exception as e:
            print(f"设置图标失败: {e}")
    
    def setup_ui(self):
        """设置UI"""
        # 主容器
        main_container = tk.Frame(self.root, bg="#f5f5f5")
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 左侧面板
        left_panel = tk.Frame(main_container, bg="white", highlightbackground="#e5e5e5", 
                             highlightthickness=1, padx=30, pady=30)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # 标题
        title = tk.Label(left_panel, text="2FA验证器", font=("Segoe UI", 24, "normal"),
                        bg="white", fg="#1a1a1a")
        title.pack(pady=(0, 30))
        
        # 权限状态提示
        admin_status = "管理员模式" if is_admin() else "普通模式"
        admin_color = "green" if is_admin() else "orange"
        admin_label = tk.Label(left_panel, text=f"✓ {admin_status}", font=("Segoe UI", 10),
                              bg="white", fg=admin_color, anchor="w")
        admin_label.pack(fill=tk.X, pady=(0, 10))
        
        # 数据路径提示
        path_label = tk.Label(left_panel, text=f"数据位置: {self.data_file}", font=("Segoe UI", 8),
                             bg="white", fg="#999", anchor="w")
        path_label.pack(fill=tk.X, pady=(0, 10))
        
        # 添加验证器表单
        form_frame = tk.Frame(left_panel, bg="white")
        form_frame.pack(fill=tk.X, pady=(0, 30))
        
        # 账户名称输入
        name_label = tk.Label(form_frame, text="账户名称", font=("Segoe UI", 12),
                             bg="white", fg="#4a4a4a", anchor="w")
        name_label.pack(fill=tk.X, pady=(0, 5))
        
        self.name_entry = tk.Entry(form_frame, font=("Segoe UI", 14), bd=1, relief=tk.SOLID,
                                  bg="#fafafa", fg="#1a1a1a")
        self.name_entry.pack(fill=tk.X, pady=(0, 15))
        self.name_entry.insert(0, "例如: GitHub")
        self.name_entry.bind("<FocusIn>", self.on_name_focus_in)
        self.name_entry.bind("<FocusOut>", self.on_name_focus_out)
        
        # 密钥输入
        key_label = tk.Label(form_frame, text="密钥", font=("Segoe UI", 12),
                            bg="white", fg="#4a4a4a", anchor="w")
        key_label.pack(fill=tk.X, pady=(0, 5))
        
        self.key_entry = tk.Entry(form_frame, font=("Segoe UI", 14), bd=1, relief=tk.SOLID,
                                 bg="#fafafa", fg="#1a1a1a")
        self.key_entry.pack(fill=tk.X, pady=(0, 15))
        self.key_entry.insert(0, "输入2FA密钥")
        self.key_entry.bind("<FocusIn>", self.on_key_focus_in)
        self.key_entry.bind("<FocusOut>", self.on_key_focus_out)
        
        # 添加按钮
        add_btn = tk.Button(form_frame, text="添加验证器", font=("Segoe UI", 14),
                           bg="#1a1a1a", fg="white", bd=0, relief=tk.FLAT,
                           activebackground="#000", activeforeground="white",
                           command=self.add_verifier)
        add_btn.pack(fill=tk.X, pady=(10, 0))
        
        # 验证器列表容器
        list_container = tk.Frame(left_panel, bg="white")
        list_container.pack(fill=tk.BOTH, expand=True)
        
        # 验证器列表标题
        list_title = tk.Label(list_container, text="我的验证器", font=("Segoe UI", 16),
                             bg="white", fg="#1a1a1a", anchor="w")
        list_title.pack(fill=tk.X, pady=(0, 15))
        
        # 创建滚动框架
        self.canvas = tk.Canvas(list_container, bg="white", highlightthickness=0)
        scrollbar = tk.Scrollbar(list_container, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="white")
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 右侧面板
        right_panel = tk.Frame(main_container, bg="white", highlightbackground="#e5e5e5", 
                              highlightthickness=1, padx=20, pady=20, width=200)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        right_panel.pack_propagate(False)
        
        # 统计信息
        stats_frame = tk.Frame(right_panel, bg="#fafafa", padx=15, pady=15)
        stats_frame.pack(fill=tk.X, pady=(0, 20))
        
        stats_title = tk.Label(stats_frame, text="统计信息", font=("Segoe UI", 14),
                              bg="#fafafa", fg="#1a1a1a", anchor="w")
        stats_title.pack(fill=tk.X, pady=(0, 10))
        
        # 验证器总数
        count_frame = tk.Frame(stats_frame, bg="#fafafa")
        count_frame.pack(fill=tk.X, pady=5)
        
        count_label = tk.Label(count_frame, text="验证器总数", font=("Segoe UI", 10),
                              bg="#fafafa", fg="#666", anchor="w")
        count_label.pack(side=tk.LEFT)
        
        self.count_value = tk.Label(count_frame, text="0", font=("Segoe UI", 12, "bold"),
                                    bg="#fafafa", fg="#1a1a1a", anchor="e")
        self.count_value.pack(side=tk.RIGHT)
        
        # 当前时间
        time_frame = tk.Frame(stats_frame, bg="#fafafa")
        time_frame.pack(fill=tk.X, pady=5)
        
        time_label = tk.Label(time_frame, text="当前时间", font=("Segoe UI", 10),
                             bg="#fafafa", fg="#666", anchor="w")
        time_label.pack(side=tk.LEFT)
        
        self.time_value = tk.Label(time_frame, text="--:--", font=("Segoe UI", 12, "bold"),
                                  bg="#fafafa", fg="#1a1a1a", anchor="e")
        self.time_value.pack(side=tk.RIGHT)
        
        # 快速操作
        actions_title = tk.Label(right_panel, text="快速操作", font=("Segoe UI", 14),
                               bg="white", fg="#1a1a1a", anchor="w")
        actions_title.pack(fill=tk.X, pady=(0, 10))
        
        # 导出按钮
        export_btn = tk.Button(right_panel, text="导出数据", font=("Segoe UI", 12),
                               bg="#f5f5f5", fg="#1a1a1a", bd=1, relief=tk.SOLID,
                               activebackground="#1a1a1a", activeforeground="white",
                               command=self.export_data)
        export_btn.pack(fill=tk.X, pady=(0, 10))
        
        # 导入按钮
        import_btn = tk.Button(right_panel, text="导入数据", font=("Segoe UI", 12),
                               bg="#f5f5f5", fg="#1a1a1a", bd=1, relief=tk.SOLID,
                               activebackground="#1a1a1a", activeforeground="white",
                               command=self.import_data)
        import_btn.pack(fill=tk.X, pady=(0, 10))
        
        # 清空按钮
        clear_btn = tk.Button(right_panel, text="清空所有", font=("Segoe UI", 12),
                             bg="#f5f5f5", fg="#1a1a1a", bd=1, relief=tk.SOLID,
                             activebackground="#1a1a1a", activeforeground="white",
                             command=self.clear_all)
        clear_btn.pack(fill=tk.X)
    
    def on_name_focus_in(self, event):
        if self.name_entry.get() == "例如: GitHub":
            self.name_entry.delete(0, tk.END)
            self.name_entry.config(fg="#1a1a1a")
    
    def on_name_focus_out(self, event):
        if self.name_entry.get() == "":
            self.name_entry.insert(0, "例如: GitHub")
            self.name_entry.config(fg="#999")
    
    def on_key_focus_in(self, event):
        if self.key_entry.get() == "输入2FA密钥":
            self.key_entry.delete(0, tk.END)
            self.key_entry.config(fg="#1a1a1a")
    
    def on_key_focus_out(self, event):
        if self.key_entry.get() == "":
            self.key_entry.insert(0, "输入2FA密钥")
            self.key_entry.config(fg="#999")
    
    def load_verifiers(self):
        """从文件加载验证器数据"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"加载数据失败: {e}")
            messagebox.showwarning("警告", f"加载数据失败: {e}\n将使用空数据列表。")
        return []
    
    def save_verifiers(self):
        """保存验证器数据到文件"""
        try:
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(self.verifiers, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"保存数据失败: {e}")
            messagebox.showerror("错误", f"保存数据失败: {e}\n请检查文件权限或磁盘空间。")
            return False
    
    def render_verifiers(self):
        """渲染验证器列表"""
        # 清空现有列表
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        if not self.verifiers:
            # 显示空状态
            empty_label = tk.Label(self.scrollable_frame, text="暂无验证器\n请在上方添加您的第一个验证器",
                                  font=("Segoe UI", 12), bg="white", fg="#999", justify=tk.CENTER)
            empty_label.pack(expand=True, fill=tk.BOTH)
            return
        
        # 创建验证器卡片
        for i, verifier in enumerate(self.verifiers):
            card = VerifierCard(
                self.scrollable_frame,
                verifier["name"],
                verifier["key"],
                i,
                self.delete_verifier,
                lambda code=None: None,
                self.root
            )
            card.pack(fill=tk.X, pady=(0, 15))
    
    def add_verifier(self):
        """添加新验证器"""
        name = self.name_entry.get().strip()
        key = self.key_entry.get().strip()
        
        if not name or name == "例如: GitHub":
            messagebox.showwarning("提示", "请输入账户名称")
            return
        
        if not key or key == "输入2FA密钥":
            messagebox.showwarning("提示", "请输入2FA密钥")
            return
        
        # 验证密钥格式
        try:
            TOTPGenerator.base32_decode(key)
        except Exception as e:
            messagebox.showerror("错误", f"无效的2FA密钥格式: {e}")
            return
        
        # 添加到列表
        self.verifiers.append({"name": name, "key": key})
        
        # 保存数据
        if self.save_verifiers():
            # 重新渲染列表
            self.render_verifiers()
            
            # 更新统计信息
            self.update_stats()
            
            # 清空输入框
            self.name_entry.delete(0, tk.END)
            self.key_entry.delete(0, tk.END)
            self.on_name_focus_out(None)
            self.on_key_focus_out(None)
    
    def delete_verifier(self, index):
        """删除验证器"""
        if 0 <= index < len(self.verifiers):
            self.verifiers.pop(index)
            if self.save_verifiers():
                self.render_verifiers()
                self.update_stats()
    
    def update_stats(self):
        """更新统计信息"""
        # 更新验证器数量
        self.count_value.config(text=str(len(self.verifiers)))
        
        # 更新当前时间
        now = datetime.datetime.now()
        time_str = now.strftime("%H:%M:%S")
        self.time_value.config(text=time_str)
        
        # 继续定时更新
        self.root.after(1000, self.update_stats)
    
    def export_data(self):
        """导出数据"""
        if not self.verifiers:
            messagebox.showinfo("提示", "没有数据可导出")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")],
            initialfile=f"2fa-backup-{datetime.date.today().isoformat()}.json"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.verifiers, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("成功", "数据导出成功")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {e}")
    
    def import_data(self):
        """导入数据"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    imported_data = json.load(f)
                
                if not isinstance(imported_data, list):
                    messagebox.showerror("错误", "无效的数据格式")
                    return
                
                # 验证导入的数据
                for item in imported_data:
                    if not isinstance(item, dict) or 'name' not in item or 'key' not in item:
                        messagebox.showerror("错误", "数据格式不正确")
                        return
                
                if messagebox.askyesno("确认", f"将导入 {len(imported_data)} 个验证器，这会覆盖现有数据。确定继续吗？"):
                    self.verifiers = imported_data
                    if self.save_verifiers():
                        self.render_verifiers()
                        self.update_stats()
                        messagebox.showinfo("成功", "数据导入成功")
            except Exception as e:
                messagebox.showerror("错误", f"导入失败: {e}")
    
    def clear_all(self):
        """清空所有数据"""
        if not self.verifiers:
            messagebox.showinfo("提示", "没有数据可清空")
            return
        
        if messagebox.askyesno("确认", "确定要清空所有验证器数据吗？此操作不可恢复！"):
            self.verifiers = []
            if self.save_verifiers():
                self.render_verifiers()
                self.update_stats()
                messagebox.showinfo("成功", "所有数据已清空")

def main():
    """主函数"""
    # 不再自动请求管理员权限，避免循环重启
    print("启动2FA验证器...")
    
    root = tk.Tk()
    app = TwoFactorAuthApp(root)
    
    # 显示启动成功信息
    print("2FA验证器已成功启动")
    
    root.mainloop()

if __name__ == "__main__":
    main()
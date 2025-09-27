import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import ftplib
import os
import threading
from datetime import datetime
import socket

class SimpleFTPClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple FTP Client - Connect to Honeypot")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')

        # FTP connection
        self.ftp = None
        self.connected = False

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 10))

        self.create_widgets()

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Title
        title_label = ttk.Label(main_frame, text="🔒 Simple FTP Client", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=4, pady=(0, 20))

        # Connection frame
        conn_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        conn_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))

        # Host
        ttk.Label(conn_frame, text="FTP Server:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.host_var = tk.StringVar(value="127.0.0.1")  # Default to local IP
        self.host_entry = ttk.Entry(conn_frame, textvariable=self.host_var, width=20)
        self.host_entry.grid(row=0, column=1, padx=(0, 10))

        # Port
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.port_var = tk.StringVar(value="2121")  # Default honeypot port
        self.port_entry = ttk.Entry(conn_frame, textvariable=self.port_var, width=10)
        self.port_entry.grid(row=0, column=3)

        # Username
        ttk.Label(conn_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.user_var = tk.StringVar(value="")
        self.user_entry = ttk.Entry(conn_frame, textvariable=self.user_var, width=20)
        self.user_entry.grid(row=1, column=1, padx=(0, 10), pady=(5, 0))

        # Password
        ttk.Label(conn_frame, text="Password:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.pass_var = tk.StringVar(value="")
        self.pass_entry = ttk.Entry(conn_frame, textvariable=self.pass_var, show="*", width=15)
        self.pass_entry.grid(row=1, column=3, pady=(5, 0))

        # Connect button
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=2, column=0, columnspan=4, pady=(10, 0))

        # Status
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, style='Status.TLabel')
        self.status_label.grid(row=2, column=0, columnspan=4, pady=(5, 10))

        # File operations frame
        file_frame = ttk.LabelFrame(main_frame, text="File Operations", padding="10")
        file_frame.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        # Buttons frame
        btn_frame = ttk.Frame(file_frame)
        btn_frame.grid(row=0, column=0, columnspan=2, pady=(0, 10))

        self.list_btn = ttk.Button(btn_frame, text="📁 List Files", command=self.list_files, state='disabled')
        self.list_btn.grid(row=0, column=0, padx=(0, 5))

        self.upload_btn = ttk.Button(btn_frame, text="⬆️ Upload File", command=self.upload_file, state='disabled')
        self.upload_btn.grid(row=0, column=1, padx=5)

        self.download_btn = ttk.Button(btn_frame, text="⬇️ Download File", command=self.download_file, state='disabled')
        self.download_btn.grid(row=0, column=2, padx=5)

        self.mkdir_btn = ttk.Button(btn_frame, text="📂 Create Dir", command=self.create_directory, state='disabled')
        self.mkdir_btn.grid(row=0, column=3, padx=5)

        # File list
        ttk.Label(file_frame, text="Remote Files:").grid(row=1, column=0, sticky=tk.W)

        # Listbox with scrollbar
        list_frame = ttk.Frame(file_frame)
        list_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 10))

        self.file_listbox = tk.Listbox(list_frame, height=8)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
        self.file_listbox.configure(yscrollcommand=scrollbar.set)

        self.file_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Test buttons (for honeypot testing)
        test_frame = ttk.LabelFrame(main_frame, text="Honeypot Testing", padding="10")
        test_frame.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))

        test_btn1 = ttk.Button(test_frame, text="🔓 Try Admin Login", command=self.test_admin_login)
        test_btn1.grid(row=0, column=0, padx=(0, 5))

        test_btn2 = ttk.Button(test_frame, text="👤 Try Anonymous", command=self.test_anonymous)
        test_btn2.grid(row=0, column=1, padx=5)

        test_btn3 = ttk.Button(test_frame, text="🕵️ Try Multiple Fails", command=self.test_multiple_fails)
        test_btn3.grid(row=0, column=2, padx=5)

        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        main_frame.rowconfigure(4, weight=1)

        file_frame.columnconfigure(0, weight=1)
        file_frame.rowconfigure(2, weight=1)

        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        # Initial log message
        self.log("Simple FTP Client started")
        self.log("Ready to connect to FTP honeypot")

    def log(self, message):
        """Add message to log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
        self.root.update()

    def toggle_connection(self):
        """Connect or disconnect from FTP server"""
        if self.connected:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        """Connect to FTP server"""
        try:
            host = self.host_var.get().strip()
            port = int(self.port_var.get().strip())
            username = self.user_var.get().strip()
            password = self.pass_var.get()

            if not host:
                messagebox.showerror("Error", "Please enter FTP server address")
                return

            self.log(f"Connecting to {host}:{port}...")
            self.status_var.set("Connecting...")

            # Create FTP connection in separate thread
            thread = threading.Thread(target=self._connect_thread, args=(host, port, username, password))
            thread.daemon = True
            thread.start()

        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
        except Exception as e:
            self.log(f"Connection error: {str(e)}")
            messagebox.showerror("Connection Error", str(e))

    def _connect_thread(self, host, port, username, password):
        """Connect to FTP server in separate thread"""
        try:
            self.ftp = ftplib.FTP()
            self.ftp.connect(host, port, timeout=10)

            self.log(f"Connected to {host}:{port}")
            self.log(f"Logging in as {username}...")

            self.ftp.login(username, password)

            # Success
            self.connected = True
            self.root.after(0, self._connection_success)

        except ftplib.error_perm as e:
            self.root.after(0, lambda: self._connection_failed(f"Login failed: {str(e)}"))
        except socket.timeout:
            self.root.after(0, lambda: self._connection_failed("Connection timeout"))
        except Exception as e:
            self.root.after(0, lambda: self._connection_failed(f"Connection error: {str(e)}"))

    def _connection_success(self):
        """Handle successful connection"""
        self.log("✅ Login successful!")
        self.status_var.set("Connected")
        self.connect_btn.configure(text="Disconnect")

        # Enable buttons
        self.list_btn.configure(state='normal')
        self.upload_btn.configure(state='normal')
        self.download_btn.configure(state='normal')
        self.mkdir_btn.configure(state='normal')

        # Auto-list files
        self.list_files()

    def _connection_failed(self, error_msg):
        """Handle connection failure"""
        self.log(f"❌ {error_msg}")
        self.status_var.set("Disconnected")
        if self.ftp:
            try:
                self.ftp.quit()
            except:
                pass
            self.ftp = None

    def disconnect(self):
        """Disconnect from FTP server"""
        try:
            if self.ftp:
                self.ftp.quit()
                self.log("Disconnected from server")

            self.connected = False
            self.ftp = None
            self.status_var.set("Disconnected")
            self.connect_btn.configure(text="Connect")

            # Disable buttons
            self.list_btn.configure(state='disabled')
            self.upload_btn.configure(state='disabled')
            self.download_btn.configure(state='disabled')
            self.mkdir_btn.configure(state='disabled')

            # Clear file list
            self.file_listbox.delete(0, tk.END)

        except Exception as e:
            self.log(f"Disconnect error: {str(e)}")

    def list_files(self):
        """List files in current directory"""
        if not self.connected:
            return

        try:
            self.log("Listing remote files...")
            files = []
            self.ftp.dir(files.append)

            # Clear and populate listbox
            self.file_listbox.delete(0, tk.END)

            if not files:
                self.file_listbox.insert(tk.END, "(empty directory)")
                self.log("Directory is empty")
            else:
                for file_info in files:
                    self.file_listbox.insert(tk.END, file_info)
                self.log(f"Listed {len(files)} items")

        except Exception as e:
            self.log(f"List files error: {str(e)}")
            messagebox.showerror("Error", f"Failed to list files: {str(e)}")

    def upload_file(self):
        """Upload file to FTP server"""
        if not self.connected:
            return

        try:
            filename = filedialog.askopenfilename(title="Select file to upload")
            if not filename:
                return

            basename = os.path.basename(filename)
            self.log(f"Uploading {basename}...")

            with open(filename, 'rb') as f:
                self.ftp.storbinary(f'STOR {basename}', f)

            self.log(f"✅ Upload completed: {basename}")
            self.list_files()  # Refresh file list

        except Exception as e:
            self.log(f"Upload error: {str(e)}")
            messagebox.showerror("Upload Error", str(e))

    def download_file(self):
        """Download selected file"""
        if not self.connected:
            return

        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file to download")
            return

        try:
            file_info = self.file_listbox.get(selection[0])
            # Extract filename from file info (last part)
            filename = file_info.split()[-1]

            # Choose save location
            save_path = filedialog.asksaveasfilename(
                title="Save file as",
                initialvalue=filename
            )

            if not save_path:
                return

            self.log(f"Downloading {filename}...")

            with open(save_path, 'wb') as f:
                self.ftp.retrbinary(f'RETR {filename}', f.write)

            self.log(f"✅ Download completed: {filename}")

        except Exception as e:
            self.log(f"Download error: {str(e)}")
            messagebox.showerror("Download Error", str(e))

    def create_directory(self):
        """Create new directory"""
        if not self.connected:
            return

        dirname = tk.simpledialog.askstring("Create Directory", "Enter directory name:")
        if not dirname:
            return

        try:
            self.ftp.mkd(dirname)
            self.log(f"✅ Created directory: {dirname}")
            self.list_files()  # Refresh file list

        except Exception as e:
            self.log(f"Create directory error: {str(e)}")
            messagebox.showerror("Error", f"Failed to create directory: {str(e)}")

    # Testing functions for honeypot
    def test_admin_login(self):
        """Test admin login (likely to be flagged)"""
        self.host_var.set(self.host_var.get())
        self.user_var.set("admin")
        self.pass_var.set("admin123")
        self.log("🔓 Testing admin credentials...")
        self.connect()

    def test_anonymous(self):
        """Test anonymous login"""
        self.user_var.set("anonymous")
        self.pass_var.set("anonymous@example.com")
        self.log("👤 Testing anonymous login...")
        self.connect()

    def test_multiple_fails(self):
        """Test multiple failed logins (definitely suspicious)"""
        self.log("🕵️ Testing multiple failed logins (will trigger honeypot)...")

        failed_attempts = [
            ("admin", "password123"),
            ("root", "toor"),
            ("administrator", "admin"),
            ("guest", "guest"),
            ("ftp", "ftp")
        ]

        for username, password in failed_attempts:
            self.user_var.set(username)
            self.pass_var.set(password)
            self.log(f"Trying {username}:{password}")

            # Attempt connection (will likely fail)
            try:
                if self.ftp:
                    self.ftp.quit()

                self.ftp = ftplib.FTP()
                host = self.host_var.get().strip()
                port = int(self.port_var.get().strip())

                self.ftp.connect(host, port, timeout=5)
                self.ftp.login(username, password)
                self.log(f"✅ Success with {username}")
                break

            except Exception as e:
                self.log(f"❌ Failed: {username} - {str(e)}")
                if self.ftp:
                    try:
                        self.ftp.quit()
                    except:
                        pass
                    self.ftp = None

        self.log("Multiple login test completed - check honeypot logs!")

if __name__ == "__main__":
    # Add dialog import
    import tkinter.simpledialog

    root = tk.Tk()
    app = SimpleFTPClient(root)

    # Center window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f'+{x}+{y}')

    root.mainloop()

# -*- coding: utf-8 -*-

import ctypes
import ctypes.wintypes
import os
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk


user32 = ctypes.windll.user32
user32.GetMessageExtraInfo.restype = ctypes.wintypes.LPARAM
ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong


class MOUSEINPUT(ctypes.Structure):
	_fields_ = (
		("dx", ctypes.c_long),
		("dy", ctypes.c_long),
		("mouseData", ctypes.wintypes.DWORD),
		("dwFlags", ctypes.wintypes.DWORD),
		("time", ctypes.wintypes.DWORD),
		("dwExtraInfo", ULONG_PTR),
	)


class INPUT(ctypes.Structure):
	class _INPUT_UNION(ctypes.Union):
		_fields_ = (("mi", MOUSEINPUT),)

	_anonymous_ = ("union",)
	_fields_ = (
		("type", ctypes.wintypes.DWORD),
		("union", _INPUT_UNION),
	)


SendInput = user32.SendInput
SendInput.argtypes = (
	ctypes.wintypes.UINT,
	ctypes.POINTER(INPUT),
	ctypes.c_int,
)
SendInput.restype = ctypes.wintypes.UINT


INPUT_MOUSE = 0
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004


EnumWindowsProc = ctypes.WINFUNCTYPE(
	ctypes.c_bool,
	ctypes.wintypes.HWND,
	ctypes.wintypes.LPARAM,
)


def _list_windows():
	windows = []
	current_pid = os.getpid()

	def callback(hwnd, lparam):
		if not user32.IsWindowVisible(hwnd):
			return True

		length = user32.GetWindowTextLengthW(hwnd)
		if length == 0:
			return True

		buffer = ctypes.create_unicode_buffer(length + 1)
		user32.GetWindowTextW(hwnd, buffer, length + 1)
		title = buffer.value.strip()
		if not title:
			return True

		pid = ctypes.wintypes.DWORD()
		user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
		if pid.value == current_pid:
			return True

		windows.append((title, hwnd, pid.value))
		return True

	user32.EnumWindows(EnumWindowsProc(callback), 0)
	windows.sort(key=lambda item: item[0].lower())
	return windows


def _is_window(hwnd):
	return bool(user32.IsWindow(hwnd))


def _click_input(flag):
	extra_info = user32.GetMessageExtraInfo()
	mi = MOUSEINPUT(0, 0, 0, flag, 0, extra_info)
	inp = INPUT()
	inp.type = INPUT_MOUSE
	inp.mi = mi
	if SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT)) == 0:
		raise ctypes.WinError()


def _click_once():
	_click_input(MOUSEEVENTF_LEFTDOWN)
	_click_input(MOUSEEVENTF_LEFTUP)


class AutoClickerApp:
	def __init__(self, root: tk.Tk):
		self.root = root
		self.root.title("Windows 连点器")
		self.root.resizable(False, False)

		self.window_map = {}
		self.window_var = tk.StringVar()
		self.interval_var = tk.StringVar(value="0.05")
		self.status_var = tk.StringVar(value="未开始")

		self.target_hwnd = None
		self.click_thread = None
		self.stop_event = threading.Event()

		self._build_ui()
		self.refresh_windows()
		self.root.protocol("WM_DELETE_WINDOW", self.on_close)

	def _build_ui(self):
		padding = {"padx": 12, "pady": 6}

		ttk.Label(self.root, text="目标窗口").grid(row=0, column=0, sticky="w", **padding)
		self.window_box = ttk.Combobox(
			self.root,
			textvariable=self.window_var,
			state="readonly",
			width=70,
		)
		self.window_box.grid(row=0, column=1, sticky="we", **padding)

		ttk.Button(self.root, text="刷新", command=self.refresh_windows).grid(
			row=0, column=2, sticky="e", **padding
		)

		ttk.Label(self.root, text="间隔秒数").grid(row=1, column=0, sticky="w", **padding)
		ttk.Entry(self.root, textvariable=self.interval_var, width=15).grid(
			row=1, column=1, sticky="w", **padding
		)

		self.start_btn = ttk.Button(self.root, text="开始", command=self.start_clicking)
		self.start_btn.grid(row=2, column=0, sticky="we", **padding)

		self.stop_btn = ttk.Button(self.root, text="停止", command=self.stop_clicking, state="disabled")
		self.stop_btn.grid(row=2, column=1, sticky="w", **padding)

		ttk.Label(self.root, textvariable=self.status_var).grid(
			row=3, column=0, columnspan=3, sticky="w", padx=12, pady=(6, 12)
		)

	def refresh_windows(self):
		windows = _list_windows()
		self.window_map = {}
		labels = []
		for title, hwnd, pid in windows:
			label = f"{title} (PID {pid}, HWND 0x{hwnd:08X})"
			self.window_map[label] = hwnd
			labels.append(label)

		current_selection = self.window_var.get()
		self.window_box["values"] = labels

		if current_selection in self.window_map:
			self.window_var.set(current_selection)
		elif labels:
			self.window_var.set(labels[0])
		else:
			self.window_var.set("")

	def start_clicking(self):
		if self.click_thread and self.click_thread.is_alive():
			messagebox.showinfo("提示", "连点已在运行。")
			return

		selection = self.window_var.get()
		if selection not in self.window_map:
			messagebox.showerror("错误", "请先选择目标窗口。")
			return

		hwnd = self.window_map[selection]
		if not _is_window(hwnd):
			messagebox.showerror("错误", "目标窗口无效，请刷新窗口列表。")
			self.refresh_windows()
			return

		try:
			interval = float(self.interval_var.get())
		except ValueError:
			messagebox.showerror("错误", "间隔必须是数字。")
			return

		if interval <= 0:
			messagebox.showerror("错误", "间隔必须大于 0。")
			return

		self.target_hwnd = hwnd
		self.stop_event.clear()
		self.click_thread = threading.Thread(
			target=self._click_loop,
			args=(max(0.001, interval),),
			daemon=True,
		)
		self.click_thread.start()
		self._update_running_state(True, "连点中（仅当前台生效）")

	def stop_clicking(self, status_msg="已停止"):
		self.stop_event.set()
		thread = self.click_thread
		if thread and thread.is_alive() and threading.current_thread() is not thread:
			thread.join()

		self.click_thread = None
		self._update_running_state(False, status_msg)

	def _click_loop(self, interval: float):
		while not self.stop_event.is_set():
			if not _is_window(self.target_hwnd):
				self.stop_event.set()
				self._request_ui_stop("目标窗口已关闭，自动停止。")
				return

			if user32.GetForegroundWindow() == self.target_hwnd:
				try:
					_click_once()
				except OSError as exc:
					self.stop_event.set()
					self._request_ui_stop(f"发送点击失败：{exc}")
					return
				if self.stop_event.wait(interval):
					return
			else:
				if self.stop_event.wait(0.2):
					return

	def _request_ui_stop(self, status_msg: str):
		self.root.after(0, lambda: self.stop_clicking(status_msg))

	def _update_running_state(self, running: bool, status: str):
		self.status_var.set(status)
		self.start_btn.config(state="disabled" if running else "normal")
		self.stop_btn.config(state="normal" if running else "disabled")

	def on_close(self):
		self.stop_clicking()
		self.root.destroy()


def main():
	root = tk.Tk()
	AutoClickerApp(root)
	root.mainloop()


if __name__ == "__main__":
	main()


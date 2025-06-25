import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
import json
import os
import requests
import webview

# =========================
# CONFIGURAÇÕES
# =========================
API_URL = "http://127.0.0.1:3000"  # Endereço do seu backend
SENHA_TECNICA = "senhaTecnica123"
ARQUIVO_ATIVADO = "ativado.json"

# =========================
# FUNÇÕES
# =========================

def salvar_ativacao(chave):
    with open(ARQUIVO_ATIVADO, 'w') as f:
        json.dump({"chave": chave}, f)

def ativado():
    return os.path.exists(ARQUIVO_ATIVADO)

def validar_chave(chave):
    try:
        response = requests.post(f"{API_URL}/api/ativar_cliente", json={"chave": chave})
        return response.status_code == 200
    except Exception as e:
        print("Erro na validação:", e)
        return False

def abrir_sistema():
    webview.create_window("Taipan One", url=API_URL, fullscreen=True)

# =========================
# JANELAS
# =========================

def janela_ativacao(root):
    root.withdraw()
    ativ_win = ttk.Toplevel()
    ativ_win.title("Ativação do Cliente")
    ativ_win.geometry("400x250")
    ativ_win.resizable(False, False)

    ttk.Label(ativ_win, text="Chave de Ativação", font=("Segoe UI", 12)).pack(pady=(30, 10))
    entrada_chave = ttk.Entry(ativ_win, width=30, font=("Segoe UI", 11))
    entrada_chave.pack(pady=5)

    def ativar():
        chave = entrada_chave.get().strip()
        if validar_chave(chave):
            salvar_ativacao(chave)
            ativ_win.destroy()
            abrir_sistema()
        else:
            messagebox.showerror("Erro", "Chave inválida ou conexão falhou.")

    ttk.Button(ativ_win, text="Ativar Sistema", bootstyle="primary", command=ativar).pack(pady=20)

def janela_login_tecnico():
    app = ttk.Window(themename="darkly")
    app.title("Launcher Técnico - Taipan One")
    app.geometry("400x250")
    app.resizable(False, False)

    frame = ttk.Frame(app, padding=20)
    frame.pack(expand=True)

    ttk.Label(frame, text="Senha Técnica", font=("Segoe UI", 12)).pack(pady=(10, 5))
    senha_entry = ttk.Entry(frame, width=30, show='*', font=("Segoe UI", 11))
    senha_entry.pack(pady=5)

    def verificar_senha():
        if senha_entry.get() == SENHA_TECNICA:
            app.destroy()
            janela_ativacao(app)
        else:
            messagebox.showerror("Erro", "Senha técnica incorreta.")

    ttk.Button(frame, text="Entrar", bootstyle="primary", command=verificar_senha).pack(pady=20)

    app.mainloop()

# =========================
# INÍCIO
# =========================

if __name__ == "__main__":
    if ativado():
        abrir_sistema()
    else:
        janela_login_tecnico()

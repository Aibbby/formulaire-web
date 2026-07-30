# -*- coding: utf-8 -*-
"""
Outil JWE local
- Chiffrement : RSA-OAEP-256 + A256GCM
- Déchiffrement : RSA-OAEP-256 + A256GCM

Dépendance requise :
    cryptography

Installation si nécessaire :
    python -m pip install cryptography
"""

import base64
import json
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Dépendance manquante",
        "Le module « cryptography » n'est pas installé.\n\n"
        "Commande d'installation :\n"
        "python -m pip install cryptography"
    )
    root.destroy()
    raise SystemExit(1)


APP_TITLE = "Outil JWE – Chiffrement et déchiffrement"
DEFAULT_HEADER = {
    "alg": "RSA-OAEP-256",
    "enc": "A256GCM",
    "kid": "api-sds-pnh-pnr-jwe-jws"
}
DEFAULT_PAYLOAD = {
    "pan": "4990093581497111",
    "expDate": "1026",
    "expDateFormat": "MMYY"
}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    value = value.strip()
    padding_length = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + ("=" * padding_length))


def compact_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")


def load_public_rsa_key(path: str):
    try:
        data = Path(path).read_bytes()
        key = serialization.load_pem_public_key(data)
    except Exception as exc:
        raise ValueError(f"Impossible de lire la clé publique PEM :\n{exc}") from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Le fichier sélectionné ne contient pas une clé publique RSA.")
    return key


def load_private_rsa_key(path: str, parent):
    data = Path(path).read_bytes()

    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        password = simpledialog.askstring(
            "Mot de passe",
            "La clé privée est protégée.\nSaisissez son mot de passe :",
            show="*",
            parent=parent
        )
        if password is None:
            raise ValueError("Chargement de la clé privée annulé.")
        try:
            key = serialization.load_pem_private_key(
                data,
                password=password.encode("utf-8")
            )
        except Exception as exc:
            raise ValueError(f"Impossible de déverrouiller la clé privée :\n{exc}") from exc
    except Exception as exc:
        raise ValueError(f"Impossible de lire la clé privée PEM :\n{exc}") from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Le fichier sélectionné ne contient pas une clé privée RSA.")
    return key


def encrypt_jwe(public_key_path: str, header_text: str, payload_text: str) -> str:
    try:
        header = json.loads(header_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Header JSON invalide : ligne {exc.lineno}, colonne {exc.colno}.") from exc

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Payload JSON invalide : ligne {exc.lineno}, colonne {exc.colno}.") from exc

    if not isinstance(header, dict):
        raise ValueError("Le header doit être un objet JSON.")

    if header.get("alg") != "RSA-OAEP-256":
        raise ValueError('Le header doit contenir "alg": "RSA-OAEP-256".')

    if header.get("enc") != "A256GCM":
        raise ValueError('Le header doit contenir "enc": "A256GCM".')

    public_key = load_public_rsa_key(public_key_path)

    protected_header = b64url_encode(compact_json(header))
    aad = protected_header.encode("ascii")

    content_encryption_key = os.urandom(32)
    iv = os.urandom(12)

    encrypted_key = public_key.encrypt(
        content_encryption_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(content_encryption_key)
    ciphertext_and_tag = aesgcm.encrypt(iv, compact_json(payload), aad)
    ciphertext = ciphertext_and_tag[:-16]
    authentication_tag = ciphertext_and_tag[-16:]

    return ".".join([
        protected_header,
        b64url_encode(encrypted_key),
        b64url_encode(iv),
        b64url_encode(ciphertext),
        b64url_encode(authentication_tag)
    ])


def decrypt_jwe(private_key_path: str, token: str, parent):
    parts = token.strip().split(".")
    if len(parts) != 5:
        raise ValueError(
            "Le JWE compact doit contenir exactement 5 parties séparées par des points."
        )

    protected_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts

    try:
        header = json.loads(b64url_decode(protected_b64).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Header JWE illisible ou invalide :\n{exc}") from exc

    if header.get("alg") != "RSA-OAEP-256":
        raise ValueError(
            f'Algorithme non pris en charge : {header.get("alg")!r}. '
            'Seul "RSA-OAEP-256" est accepté.'
        )

    if header.get("enc") != "A256GCM":
        raise ValueError(
            f'Chiffrement non pris en charge : {header.get("enc")!r}. '
            'Seul "A256GCM" est accepté.'
        )

    private_key = load_private_rsa_key(private_key_path, parent)

    try:
        encrypted_key = b64url_decode(encrypted_key_b64)
        iv = b64url_decode(iv_b64)
        ciphertext = b64url_decode(ciphertext_b64)
        authentication_tag = b64url_decode(tag_b64)
    except Exception as exc:
        raise ValueError(f"Une partie du JWE n'est pas en Base64URL valide :\n{exc}") from exc

    try:
        content_encryption_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as exc:
        raise ValueError(
            "Échec du déchiffrement de la clé AES.\n"
            "La clé privée ne correspond peut-être pas à la clé publique utilisée."
        ) from exc

    aesgcm = AESGCM(content_encryption_key)
    aad = protected_b64.encode("ascii")

    try:
        plaintext = aesgcm.decrypt(
            iv,
            ciphertext + authentication_tag,
            aad
        )
    except InvalidTag as exc:
        raise ValueError(
            "Échec de l'authentification A256GCM.\n"
            "Le JWE est altéré, incomplet ou associé à une autre clé."
        ) from exc

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception:
        payload = plaintext.decode("utf-8", errors="replace")

    return header, payload


class JweApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1060x760")
        self.minsize(900, 650)

        self._configure_style()
        self._build_ui()

    def _configure_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TNotebook.Tab", padding=(18, 10), font=("Segoe UI", 10, "bold"))
        style.configure("TButton", padding=(10, 7), font=("Segoe UI", 10))
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 9))

    def _build_ui(self):
        top = ttk.Frame(self, padding=(16, 14, 16, 8))
        top.pack(fill="x")

        ttk.Label(top, text=APP_TITLE, style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            top,
            text="Traitement entièrement local – RSA-OAEP-256 / A256GCM",
            style="Status.TLabel"
        ).pack(anchor="w", pady=(3, 0))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=16, pady=(4, 16))

        self.encrypt_tab = ttk.Frame(notebook, padding=14)
        self.decrypt_tab = ttk.Frame(notebook, padding=14)

        notebook.add(self.encrypt_tab, text="1. Chiffrer un JWE")
        notebook.add(self.decrypt_tab, text="2. Déchiffrer un JWE")

        self._build_encrypt_tab()
        self._build_decrypt_tab()

    @staticmethod
    def _text_widget(parent, height=8, wrap="word"):
        return tk.Text(
            parent,
            height=height,
            wrap=wrap,
            font=("Consolas", 10),
            undo=True,
            relief="solid",
            borderwidth=1
        )

    @staticmethod
    def _set_text(widget, value):
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    @staticmethod
    def _get_text(widget):
        return widget.get("1.0", "end-1c").strip()

    def _file_row(self, parent, label, variable, command):
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=(0, 10))
        ttk.Label(frame, text=label, width=21).pack(side="left")
        ttk.Entry(frame, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(frame, text="Parcourir…", command=command).pack(side="left")

    def _build_encrypt_tab(self):
        self.public_key_path = tk.StringVar()

        self._file_row(
            self.encrypt_tab,
            "Clé publique PEM :",
            self.public_key_path,
            self.select_public_key
        )

        ttk.Label(self.encrypt_tab, text="Header protégé JSON :").pack(anchor="w")
        self.header_input = self._text_widget(self.encrypt_tab, height=6)
        self.header_input.pack(fill="x", pady=(4, 10))
        self._set_text(
            self.header_input,
            json.dumps(DEFAULT_HEADER, indent=2, ensure_ascii=False)
        )

        ttk.Label(self.encrypt_tab, text="Payload JSON :").pack(anchor="w")
        self.payload_input = self._text_widget(self.encrypt_tab, height=9)
        self.payload_input.pack(fill="x", pady=(4, 10))
        self._set_text(
            self.payload_input,
            json.dumps(DEFAULT_PAYLOAD, indent=2, ensure_ascii=False)
        )

        buttons = ttk.Frame(self.encrypt_tab)
        buttons.pack(fill="x", pady=(0, 10))
        ttk.Button(buttons, text="Chiffrer", command=self.encrypt_action).pack(side="left")
        ttk.Button(buttons, text="Formater les JSON", command=self.format_encrypt_json).pack(side="left", padx=8)
        ttk.Button(buttons, text="Effacer le résultat", command=lambda: self._set_text(self.jwe_output, "")).pack(side="left")

        result_header = ttk.Frame(self.encrypt_tab)
        result_header.pack(fill="x")
        ttk.Label(result_header, text="JWE compact :").pack(side="left")
        ttk.Button(result_header, text="Copier", command=lambda: self.copy_text(self.jwe_output)).pack(side="right")

        self.jwe_output = self._text_widget(self.encrypt_tab, height=10, wrap="char")
        self.jwe_output.pack(fill="both", expand=True, pady=(4, 0))

    def _build_decrypt_tab(self):
        self.private_key_path = tk.StringVar()

        self._file_row(
            self.decrypt_tab,
            "Clé privée PEM :",
            self.private_key_path,
            self.select_private_key
        )

        input_header = ttk.Frame(self.decrypt_tab)
        input_header.pack(fill="x")
        ttk.Label(input_header, text="JWE compact :").pack(side="left")
        ttk.Button(input_header, text="Coller", command=lambda: self.paste_into(self.jwe_input)).pack(side="right")

        self.jwe_input = self._text_widget(self.decrypt_tab, height=9, wrap="char")
        self.jwe_input.pack(fill="x", pady=(4, 10))

        buttons = ttk.Frame(self.decrypt_tab)
        buttons.pack(fill="x", pady=(0, 10))
        ttk.Button(buttons, text="Déchiffrer", command=self.decrypt_action).pack(side="left")
        ttk.Button(
            buttons,
            text="Effacer",
            command=self.clear_decrypt
        ).pack(side="left", padx=8)

        paned = ttk.Panedwindow(self.decrypt_tab, orient="horizontal")
        paned.pack(fill="both", expand=True)

        header_frame = ttk.Labelframe(paned, text="Header décodé", padding=8)
        payload_frame = ttk.Labelframe(paned, text="Payload déchiffré", padding=8)
        paned.add(header_frame, weight=1)
        paned.add(payload_frame, weight=2)

        self.header_output = self._text_widget(header_frame, height=14)
        self.header_output.pack(fill="both", expand=True)

        self.payload_output = self._text_widget(payload_frame, height=14)
        self.payload_output.pack(fill="both", expand=True)

        footer = ttk.Frame(self.decrypt_tab)
        footer.pack(fill="x", pady=(8, 0))
        ttk.Button(
            footer,
            text="Copier le payload",
            command=lambda: self.copy_text(self.payload_output)
        ).pack(side="right")

    def select_public_key(self):
        path = filedialog.askopenfilename(
            title="Sélectionner la clé publique RSA",
            filetypes=[("Fichiers PEM", "*.pem"), ("Tous les fichiers", "*.*")]
        )
        if path:
            self.public_key_path.set(path)

    def select_private_key(self):
        path = filedialog.askopenfilename(
            title="Sélectionner la clé privée RSA",
            filetypes=[("Fichiers PEM", "*.pem"), ("Tous les fichiers", "*.*")]
        )
        if path:
            self.private_key_path.set(path)

    def encrypt_action(self):
        path = self.public_key_path.get().strip()
        if not path:
            messagebox.showwarning("Clé manquante", "Sélectionnez une clé publique PEM.")
            return

        try:
            token = encrypt_jwe(
                path,
                self._get_text(self.header_input),
                self._get_text(self.payload_input)
            )
        except Exception as exc:
            messagebox.showerror("Échec du chiffrement", str(exc))
            return

        self._set_text(self.jwe_output, token)
        messagebox.showinfo("Chiffrement terminé", "Le JWE a été généré.")

    def decrypt_action(self):
        path = self.private_key_path.get().strip()
        if not path:
            messagebox.showwarning("Clé manquante", "Sélectionnez une clé privée PEM.")
            return

        token = self._get_text(self.jwe_input)
        if not token:
            messagebox.showwarning("JWE manquant", "Collez ou saisissez un JWE compact.")
            return

        try:
            header, payload = decrypt_jwe(path, token, self)
        except Exception as exc:
            messagebox.showerror("Échec du déchiffrement", str(exc))
            return

        self._set_text(
            self.header_output,
            json.dumps(header, indent=2, ensure_ascii=False)
        )
        if isinstance(payload, (dict, list)):
            payload_text = json.dumps(payload, indent=2, ensure_ascii=False)
        else:
            payload_text = str(payload)
        self._set_text(self.payload_output, payload_text)

    def format_encrypt_json(self):
        try:
            header = json.loads(self._get_text(self.header_input))
            payload = json.loads(self._get_text(self.payload_input))
        except json.JSONDecodeError as exc:
            messagebox.showerror(
                "JSON invalide",
                f"Erreur ligne {exc.lineno}, colonne {exc.colno} :\n{exc.msg}"
            )
            return

        self._set_text(self.header_input, json.dumps(header, indent=2, ensure_ascii=False))
        self._set_text(self.payload_input, json.dumps(payload, indent=2, ensure_ascii=False))

    def clear_decrypt(self):
        self._set_text(self.jwe_input, "")
        self._set_text(self.header_output, "")
        self._set_text(self.payload_output, "")

    def copy_text(self, widget):
        value = self._get_text(widget)
        if not value:
            messagebox.showwarning("Rien à copier", "La zone est vide.")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update()
        messagebox.showinfo("Copié", "Le contenu a été copié dans le presse-papiers.")

    def paste_into(self, widget):
        try:
            value = self.clipboard_get()
        except tk.TclError:
            messagebox.showwarning("Presse-papiers vide", "Aucun texte n'est disponible.")
            return
        self._set_text(widget, value)


if __name__ == "__main__":
    app = JweApp()
    app.mainloop()

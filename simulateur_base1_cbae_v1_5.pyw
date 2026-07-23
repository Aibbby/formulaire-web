import csv
import re
from pathlib import Path
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk


# ============================================================
#  Parseur ISO 8583 BASE I
#  Bibliothèque standard uniquement
# ============================================================

@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: str                 # "fixed" ou "var"
    encoding: str             # "bcd", "ebcdic", "binary"
    length: int | None = None # chiffres pour BCD, octets sinon
    length_bytes: int = 0     # taille du préfixe binaire
    length_unit: str = "bytes"  # "bytes" ou "digits"


BASE1_FIELDS: dict[int, FieldSpec] = {
    2:   FieldSpec("Primary Account Number", "var", "bcd",
                   length_bytes=1, length_unit="digits"),
    3:   FieldSpec("Processing Code", "fixed", "bcd", length=6),
    4:   FieldSpec("Amount, Transaction", "fixed", "bcd", length=12),
    6:   FieldSpec("Amount, Cardholder Billing", "fixed", "bcd", length=12),
    7:   FieldSpec("Transmission Date and Time", "fixed", "bcd", length=10),
    10:  FieldSpec("Conversion Rate, Cardholder Billing", "fixed", "bcd", length=8),
    11:  FieldSpec("Systems Trace Audit Number", "fixed", "bcd", length=6),
    14:  FieldSpec("Date, Expiration", "fixed", "bcd", length=4),
    15:  FieldSpec("Date, Settlement", "fixed", "bcd", length=4),
    18:  FieldSpec("Merchant Type", "fixed", "bcd", length=4),
    19:  FieldSpec("Acquiring Institution Country Code", "fixed", "bcd", length=3),
    22:  FieldSpec("Point of Service Entry Mode", "fixed", "bcd", length=3),
    25:  FieldSpec("Point of Service Condition Code", "fixed", "bcd", length=2),
    32:  FieldSpec("Acquiring Institution Identification Code", "var", "bcd",
                   length_bytes=1, length_unit="digits"),
    37:  FieldSpec("Retrieval Reference Number", "fixed", "ebcdic", length=12),
    39:  FieldSpec("Response Code", "fixed", "ebcdic", length=2),
    42:  FieldSpec("Card Acceptor Identification Code", "fixed", "ebcdic", length=15),
    43:  FieldSpec("Card Acceptor Name / Location", "fixed", "ebcdic", length=40),
    44:  FieldSpec("Additional Response Data", "var", "ebcdic",
                   length_bytes=1, length_unit="bytes"),
    49:  FieldSpec("Currency Code, Transaction", "fixed", "bcd", length=3),
    51:  FieldSpec("Currency Code, Cardholder Billing", "fixed", "bcd", length=3),
    56:  FieldSpec("Payment Account Reference Data", "var", "binary",
                   length_bytes=1, length_unit="bytes"),
    60:  FieldSpec("Additional POS Information", "var", "binary",
                   length_bytes=1, length_unit="bytes"),
    62:  FieldSpec("Custom Payment Service Fields", "var", "binary",
                   length_bytes=1, length_unit="bytes"),
    63:  FieldSpec("SMS or VIP Private-Use Fields", "var", "binary",
                   length_bytes=1, length_unit="bytes"),
    70:  FieldSpec("Network Management Information Code", "fixed", "bcd", length=3),
    120: FieldSpec("Auxiliary Transaction Data", "var", "binary",
                   length_bytes=2, length_unit="bytes"),
    123: FieldSpec("Verification & Token Data", "var", "binary",
                   length_bytes=1, length_unit="bytes"),
    125: FieldSpec("Supporting Information", "var", "binary",
                   length_bytes=1, length_unit="bytes"),
    126: FieldSpec("Visa Private-Use Fields", "var", "binary",
                   length_bytes=1, length_unit="bytes"),
}


def clean_hex(text: str) -> bytes:
    value = re.sub(r"\s+", "", text)
    if not value:
        raise ValueError("La zone d'entrée est vide.")
    if not re.fullmatch(r"[0-9A-Fa-f]+", value):
        raise ValueError(
            "La trame doit contenir uniquement des caractères hexadécimaux "
            "et des espaces ou retours à la ligne."
        )
    if len(value) % 2:
        raise ValueError("La trame contient un nombre impair de caractères hexadécimaux.")
    return bytes.fromhex(value)


def bcd_to_digits(data: bytes, digit_count: int) -> str:
    digits = "".join(f"{byte:02X}" for byte in data)
    # Pour les longueurs impaires BASE I, le demi-octet de remplissage est à gauche.
    if len(digits) > digit_count:
        digits = digits[-digit_count:]
    if not re.fullmatch(r"\d*", digits):
        raise ValueError(f"BCD invalide : {data.hex(' ').upper()}")
    return digits


def decode_ebcdic(data: bytes) -> str:
    # CP500 est courant dans les environnements internationaux.
    # Pour les chiffres et lettres vus dans les exemples, CP500 et CP037 concordent.
    for codec in ("cp500", "cp037"):
        try:
            return data.decode(codec)
        except UnicodeDecodeError:
            continue
    return data.hex(" ").upper()


def bitmap_fields(bitmap: bytes, first_field_number: int) -> list[int]:
    fields: list[int] = []
    for byte_index, byte_value in enumerate(bitmap):
        for bit_index in range(8):
            if byte_value & (0x80 >> bit_index):
                fields.append(first_field_number + byte_index * 8 + bit_index)
    return fields


def read_exact(data: bytes, pos: int, count: int, label: str) -> tuple[bytes, int]:
    end = pos + count
    if end > len(data):
        raise ValueError(
            f"Trame incomplète pendant la lecture de {label} : "
            f"{count} octet(s) attendu(s) à l'offset {pos}, "
            f"{len(data) - pos} disponible(s)."
        )
    return data[pos:end], end


def parse_dataset_tlv(data: bytes) -> str:
    """
    Résumé prudent des datasets Visa observés :
      Dataset ID : 1 octet
      Longueur   : 2 octets big-endian
      TLV        : tag 1 octet, longueur 1 octet, valeur
    Si la structure n'est pas cohérente, la valeur brute est conservée.
    """
    if len(data) < 3:
        return data.hex(" ").upper()

    out: list[str] = []
    pos = 0

    try:
        while pos < len(data):
            if pos + 3 > len(data):
                raise ValueError
            dataset_id = data[pos]
            dataset_len = int.from_bytes(data[pos + 1:pos + 3], "big")
            pos += 3
            dataset_end = pos + dataset_len
            if dataset_end > len(data):
                raise ValueError

            items: list[str] = []
            while pos < dataset_end:
                if pos + 2 > dataset_end:
                    raise ValueError
                tag = data[pos]
                item_len = data[pos + 1]
                pos += 2
                value = data[pos:pos + item_len]
                if len(value) != item_len or pos + item_len > dataset_end:
                    raise ValueError
                pos += item_len

                text = decode_ebcdic(value).rstrip()
                printable = all(ch.isprintable() for ch in text)
                shown = text if printable and text else value.hex().upper()
                items.append(f"{tag:02X}={shown}")

            out.append(f"Dataset {dataset_id:02X} [{', '.join(items)}]")

        return " | ".join(out)
    except ValueError:
        return data.hex(" ").upper()


def format_special_field(field_no: int, raw: bytes, decoded: str) -> str:
    if field_no == 43 and len(decoded) == 40:
        name = decoded[:25].rstrip()
        city = decoded[25:38].rstrip()
        country = decoded[38:40].rstrip()
        return f"Nom={name!r} ; Ville={city!r} ; Pays={country!r}"

    if field_no in (56, 123, 125):
        return parse_dataset_tlv(raw)

    if field_no == 60:
        return f"{raw.hex(' ').upper()}  (BCD: {''.join(f'{b:02X}' for b in raw)})"

    if field_no in (62, 63, 126):
        return raw.hex(" ").upper()

    return decoded


def parse_base1(message: bytes) -> dict:
    pos = 0
    result: dict = {"rows": []}

    # Header BASE I
    if len(message) < 24:
        raise ValueError("La trame est trop courte pour contenir le header BASE I et le MTI.")

    header_length = message[0]
    if header_length != 22:
        raise ValueError(
            f"Header BASE I non reconnu : H01 vaut {header_length}, 22 attendu."
        )

    header, pos = read_exact(message, pos, 22, "header BASE I")
    declared_length = int.from_bytes(header[3:5], "big")

    result["header"] = {
        "H01": header[0],
        "H02": header[1],
        "H03": header[2],
        "H04": declared_length,
        "H05": header[5:8].hex().upper(),
        "H06": header[8:11].hex().upper(),
        "H07": header[11],
        "H08": header[12:14].hex().upper(),
        "H09": header[14:17].hex().upper(),
        "H10": header[17],
        "H11": header[18:21].hex().upper(),
        "H12": header[21],
    }

    if declared_length != len(message):
        result["length_warning"] = (
            f"H04 annonce {declared_length} octets, "
            f"mais la trame fournie en contient {len(message)}."
        )

    mti_raw, pos = read_exact(message, pos, 2, "MTI")
    mti = bcd_to_digits(mti_raw, 4)
    result["mti"] = mti
    result["mti_raw"] = mti_raw.hex(" ").upper()

    primary_offset = pos
    primary, pos = read_exact(message, pos, 8, "bitmap primaire")
    present = bitmap_fields(primary, 1)

    secondary = None
    if 1 in present:
        secondary_offset = pos
        secondary, pos = read_exact(message, pos, 8, "bitmap secondaire")
        present.extend(bitmap_fields(secondary, 65))
        # Le bit 65 annoncerait un bitmap tertiaire, non géré ici.
        if 65 in present:
            raise ValueError("Bitmap tertiaire détecté : il n'est pas encore pris en charge.")
    else:
        secondary_offset = None

    fields = sorted(field for field in present if field not in (1, 65))
    result["primary_bitmap"] = primary.hex(" ").upper()
    result["primary_offset"] = primary_offset
    result["secondary_bitmap"] = secondary.hex(" ").upper() if secondary else ""
    result["secondary_offset"] = secondary_offset
    result["present_fields"] = fields

    for field_no in fields:
        spec = BASE1_FIELDS.get(field_no)
        if spec is None:
            raise ValueError(
                f"Le champ DE{field_no:03d} est présent dans le bitmap, "
                f"mais sa définition n'est pas encore configurée. "
                f"Arrêt à l'offset {pos}."
            )

        field_start = pos
        prefix = b""

        if spec.kind == "var":
            prefix, pos = read_exact(
                message, pos, spec.length_bytes, f"préfixe de longueur DE{field_no:03d}"
            )
            logical_length = int.from_bytes(prefix, "big")
        else:
            if spec.length is None:
                raise ValueError(f"Définition incomplète pour DE{field_no:03d}.")
            logical_length = spec.length

        if spec.encoding == "bcd":
            digit_count = logical_length
            byte_count = (digit_count + 1) // 2
            raw, pos = read_exact(message, pos, byte_count, f"DE{field_no:03d}")
            decoded = bcd_to_digits(raw, digit_count)

        elif spec.encoding == "ebcdic":
            byte_count = logical_length
            raw, pos = read_exact(message, pos, byte_count, f"DE{field_no:03d}")
            decoded = decode_ebcdic(raw)

        elif spec.encoding == "binary":
            if spec.length_unit != "bytes":
                raise ValueError(f"Unité non prise en charge pour DE{field_no:03d}.")
            byte_count = logical_length
            raw, pos = read_exact(message, pos, byte_count, f"DE{field_no:03d}")
            decoded = raw.hex(" ").upper()

        else:
            raise ValueError(f"Encodage inconnu pour DE{field_no:03d}.")

        display_value = format_special_field(field_no, raw, decoded)

        result["rows"].append({
            "field": field_no,
            "name": spec.name,
            "offset": field_start,
            "end": pos,
            "prefix": prefix.hex(" ").upper(),
            "raw": raw.hex(" ").upper(),
            "value": display_value.rstrip() if isinstance(display_value, str) else display_value,
        })

    result["end_offset"] = pos
    result["remaining"] = message[pos:]
    return result



# ============================================================
#  Simulateur TCP BASE I + parseur graphique
# ============================================================

import datetime
import json
import socket
import threading


APP_NAME = "Simulateur BASE I & CBAE"
APP_SUBTITLE = "Parseur de messages ISO8583"
APP_VERSION = "1.5"

DEFAULT_HOST = "NXLIASM012"
DEFAULT_PORT = 22201

DEFAULT_CALL_POINTS = {
    "PNH": {"host": "NXLIASM012", "port": 22201},
    "PNR": {"host": "NXLIASM012", "port": 22201},
}

# Trame 0100 fonctionnelle fournie par l'utilisateur.
# Les 4 premiers octets correspondent au framing TCP :
#   longueur du payload sur 2 octets + 0000.
TEMPLATE_0100_FRAME = bytes.fromhex("""
00 FE 00 00
16 01 02 00 FE 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 01 00
F6 66 64 81 08 20 A0 16
00 00 00 00 00 00 00 24
10 49 90 09 35 81 49 71
11 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
07 23 13 00 45 05 65 59
57 00 48 55 26 10 07 07
60 12 02 50 00 00 51 06
49 75 72 F6 F1 F9 F6 F1
F3 F0 F0 F4 F8 F5 F5 E3
D6 D2 40 C1 C3 E3 40 40
40 40 40 40 40 40 40 40
40 40 40 40 40 40 40 40
D7 81 99 89 A2 40 40 40
40 40 40 40 40 C6 D9 09
78 09 78 06 00 00 00 40
00 00 10 40 00 00 00 00
00 00 00 01 26 19 65 37
45 00 01 07 A0 00 00 00
02 37 00 3B 68 00 38 03
0B F4 F0 F0 F1 F0 F0 F3
F0 F2 F7 F3 05 12 F8 F8
F8 F8 F2 F4 F0 F7 F0 F7
F1 F1 F2 F8 F8 F4 F5 F6
0B 12 F8 F8 F8 F8 F2 F4
F0 F7 F0 F7 F1 F1 F2 F8
F8 F4 F5 F6 08 01 C1 0E
00 40 00 00 00 00 00 00
F0 F0 40 40 40 40
""")


def digits_to_bcd(value: str) -> bytes:
    if not value.isdigit():
        raise ValueError("La valeur BCD doit contenir uniquement des chiffres.")
    if len(value) % 2:
        value = "0" + value
    return bytes.fromhex(value)


def make_tcp_frame(payload: bytes) -> bytes:
    if len(payload) > 65535:
        raise ValueError("Le payload est trop long pour le préfixe TCP sur 2 octets.")
    return len(payload).to_bytes(2, "big") + b"\x00\x00" + payload


def field_raw_bounds(parsed: dict, field_no: int) -> tuple[int, int]:
    for row in parsed["rows"]:
        if row["field"] == field_no:
            prefix_size = len(bytes.fromhex(row["prefix"])) if row["prefix"] else 0
            raw_start = row["offset"] + prefix_size
            raw_end = row["end"]
            return raw_start, raw_end
    raise ValueError(f"Le champ DE{field_no:03d} n'est pas présent dans la trame modèle.")


def build_0100_frame(pan: str, expiry_yymm: str) -> bytes:
    pan = re.sub(r"\s+", "", pan)
    expiry_yymm = re.sub(r"[\s/.-]+", "", expiry_yymm)

    if not re.fullmatch(r"\d{16}", pan):
        raise ValueError(
            "Pour cette première version, le PAN doit contenir exactement 16 chiffres."
        )
    if not re.fullmatch(r"\d{4}", expiry_yymm):
        raise ValueError("La date d'expiration doit être saisie au format AAMM, par exemple 2906.")

    month = int(expiry_yymm[2:4])
    if month < 1 or month > 12:
        raise ValueError("Le mois de la date d'expiration doit être compris entre 01 et 12.")

    frame = bytearray(TEMPLATE_0100_FRAME)
    payload = bytes(frame[4:])
    parsed = parse_base1(payload)

    pan_start, pan_end = field_raw_bounds(parsed, 2)
    exp_start, exp_end = field_raw_bounds(parsed, 14)

    pan_bcd = digits_to_bcd(pan)
    expiry_bcd = digits_to_bcd(expiry_yymm)

    if len(pan_bcd) != pan_end - pan_start:
        raise ValueError("La longueur du PAN ne correspond pas à celle de la trame modèle.")
    if len(expiry_bcd) != exp_end - exp_start:
        raise ValueError("La longueur de la date d'expiration est incorrecte.")

    payload_mutable = bytearray(payload)
    payload_mutable[pan_start:pan_end] = pan_bcd
    payload_mutable[exp_start:exp_end] = expiry_bcd

    # H04 est recalculé même si la longueur ne change pas.
    payload_mutable[3:5] = len(payload_mutable).to_bytes(2, "big")
    return make_tcp_frame(bytes(payload_mutable))


def get_field_raw(parsed: dict, field_no: int) -> bytes:
    for row in parsed["rows"]:
        if row["field"] == field_no:
            return bytes.fromhex(row["raw"])
    raise ValueError(f"DE{field_no:03d} absent du message reçu.")


def calculate_rrn_part_from_stan(stan_digits: str) -> str:
    """
    Reprise à l'identique de la règle du code utilisateur :
      base 4791 + STAN, résultat sur 6 chiffres.
    """
    value_stan = int(stan_digits)
    return f"{4791 + value_stan:06d}"


def build_0810_frame(parsed_0800: dict) -> bytes:
    if parsed_0800["mti"] != "0800":
        raise ValueError("Le message fourni n'est pas un 0800.")

    de7 = get_field_raw(parsed_0800, 7)
    de11 = get_field_raw(parsed_0800, 11)
    de70 = get_field_raw(parsed_0800, 70)

    stan_digits = bcd_to_digits(de11, 6)

    # Règle conservée depuis le code initial.
    rrn_prefix = "6196"
    hour_minus_one = (datetime.datetime.now() - datetime.timedelta(hours=1)).strftime("%H")
    rrn = rrn_prefix + hour_minus_one + calculate_rrn_part_from_stan(stan_digits)
    rrn_ebcdic = rrn.encode("cp500")

    header = bytes.fromhex(
        "16 01 02 00 40 "
        "00 00 00 "
        "00 00 00 "
        "00 "
        "00 00 "
        "00 00 00 "
        "00 "
        "00 00 00 "
        "00"
    )
    mti = bytes.fromhex("08 10")
    bitmap_primary = bytes.fromhex("82 20 00 00 0A 00 00 00")
    bitmap_secondary = bytes.fromhex("04 00 00 00 00 00 00 00")
    response_code = "00".encode("cp500")

    payload = (
        header
        + mti
        + bitmap_primary
        + bitmap_secondary
        + de7
        + de11
        + rrn_ebcdic
        + response_code
        + de70
    )

    if len(payload) != 64:
        raise ValueError(f"Le 0810 généré fait {len(payload)} octets au lieu de 64.")

    return make_tcp_frame(payload)


class TcpFrameDecoder:
    """
    Décode un flux TCP où chaque message est précédé de :
      - 2 octets : longueur du payload en big-endian
      - 2 octets : réservés, normalement 0000

    Le buffer gère :
      - un message reçu en plusieurs recv()
      - plusieurs messages reçus dans un seul recv()
    """

    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[tuple[bytes, bytes]]:
        self.buffer.extend(data)
        frames: list[tuple[bytes, bytes]] = []

        while True:
            if len(self.buffer) < 4:
                break

            payload_length = int.from_bytes(self.buffer[0:2], "big")
            reserved = bytes(self.buffer[2:4])

            # Protection contre une désynchronisation.
            if payload_length < 24 or payload_length > 65535:
                sync = self.buffer.find(b"\x16\x01\x02")
                if sync == -1:
                    # On conserve les 2 derniers octets, au cas où le motif
                    # commencerait à la fin du prochain paquet.
                    if len(self.buffer) > 2:
                        del self.buffer[:-2]
                    break

                if sync >= 4:
                    del self.buffer[:sync - 4]
                    continue

                raise ValueError("Flux TCP désynchronisé : préfixe de longueur invalide.")

            full_length = 4 + payload_length
            if len(self.buffer) < full_length:
                break

            frame = bytes(self.buffer[:full_length])
            del self.buffer[:full_length]

            payload = frame[4:]
            if reserved != b"\x00\x00":
                # Le message reste exploitable ; l'information sera journalisée.
                pass

            frames.append((frame, payload))

        return frames


class AppSimulateurBase1(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} - {APP_SUBTITLE} - V{APP_VERSION}")
        self.geometry("1240x840")
        self.minsize(1000, 680)
        self.configure(bg="#EEF2F7")

        self.client_socket: socket.socket | None = None
        self.network_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.send_lock = threading.Lock()
        self.frame_decoder = TcpFrameDecoder()
        self.count_0800 = 0
        self.count_0810 = 0
        self.count_0100 = 0
        self.count_0110 = 0

        self.call_points = self.load_call_points()
        self.listen_points = self.load_listen_points()

        self.call_point_var = tk.StringVar(value="PNH")
        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar()

        self.cbae_listen_point_var = tk.StringVar(value="PNH")
        self.cbae_host_var = tk.StringVar()
        self.cbae_port_var = tk.StringVar()

        self.pan_var = tk.StringVar()
        self.expiry_var = tk.StringVar()
        self.status_var = tk.StringVar(value="● Déconnecté | BASE I")
        self.counter_var = tk.StringVar(
            value="RX : 0800=0  0110=0    |    TX : 0810=0  0100=0"
        )
        self.connection_started_at = None
        self.connection_duration_var = tk.StringVar(value="")
        self.active_mode = "BASE I"
        self.cards_file_path = Path(__file__).resolve().parent / "referentiel_cartes.csv"
        self.cards: list[dict[str, str]] = []
        self.last_selected_pan = ""

        self._configure_styles()
        self._build_ui()
        self.apply_selected_call_point()
        self.apply_selected_listen_point()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.reload_cards_reference(show_message=False)
        self.log(
            "Simulateur prêt. Saisissez librement le PAN et la date AAMM, "
            "ou choisissez une carte dans le référentiel."
        )

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", font=("Segoe UI", 10))
        style.configure("TFrame", background="#EEF2F7")
        style.configure("TLabel", background="#EEF2F7", foreground="#263238")
        style.configure(
            "TLabelframe",
            background="#F8FAFC",
            bordercolor="#CBD5E1",
            relief="solid",
            borderwidth=1,
        )
        style.configure(
            "TLabelframe.Label",
            background="#EEF2F7",
            foreground="#1E3A5F",
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "TNotebook",
            background="#EEF2F7",
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            padding=(14, 8),
            font=("Segoe UI", 9),
            background="#D9E1EA",
            foreground="#334155",
        )
        style.map(
            "TNotebook.Tab",
            padding=[("selected", (20, 10)), ("active", (16, 9))],
            font=[("selected", ("Segoe UI", 10, "bold")),
                  ("active", ("Segoe UI", 9, "bold"))],
            background=[("selected", "#FFFFFF"), ("active", "#E8EEF6")],
            foreground=[("selected", "#0B5FA5")],
        )
        style.configure(
            "Treeview",
            rowheight=26,
            background="#FFFFFF",
            fieldbackground="#FFFFFF",
            foreground="#263238",
            bordercolor="#CBD5E1",
        )
        style.configure(
            "Treeview.Heading",
            background="#DCE8F5",
            foreground="#173B5E",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map("Treeview", background=[("selected", "#CCE4FA")])
        style.configure("TEntry", fieldbackground="#FFFFFF")
        style.configure("TCombobox", fieldbackground="#FFFFFF")
        style.configure(
            "Soft.TButton",
            padding=(11, 7),
            font=("Segoe UI", 10, "bold"),
        )

    # --------------------------------------------------------
    # Interface
    # --------------------------------------------------------

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg="#2F6FA5", height=58)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text=f"{APP_NAME} - {APP_SUBTITLE} - V{APP_VERSION}",
            bg="#2F6FA5",
            fg="white",
            font=("Segoe UI", 15, "bold"),
        ).pack(side="left", padx=20)

        self.header_status_label = tk.Label(
            header,
            textvariable=self.status_var,
            bg="#2F6FA5",
            fg="#D7E3ED",
            font=("Segoe UI", 10, "bold"),
        )
        self.header_status_label.pack(side="right", padx=22)

        separator = tk.Frame(self, bg="#D6DEE7", height=1)
        separator.pack(fill="x")

        notebook = ttk.Notebook(self)
        self.main_notebook = notebook
        notebook.pack(fill="both", expand=True, padx=12, pady=(12, 6))

        self.server_tab = ttk.Frame(notebook, padding=10)
        self.cbae_tab = ttk.Frame(notebook, padding=10)
        self.parser_tab = ttk.Frame(notebook, padding=10)
        self.call_points_tab = ttk.Frame(notebook, padding=10)

        notebook.add(self.server_tab, text="BASE I")
        notebook.add(self.cbae_tab, text="CBAE")
        notebook.add(self.parser_tab, text="Parser ISO8583")
        notebook.add(self.call_points_tab, text="Configuration")

        self._build_server_tab()
        self._build_cbae_tab()
        self._build_parser_tab()
        self._build_call_points_tab()

        notebook.bind("<<NotebookTabChanged>>", self.on_main_tab_changed)

        footer = tk.Frame(self, bg="#DCE5EE", height=30)
        footer.pack(fill="x")
        footer.pack_propagate(False)

        tk.Label(
            footer,
            textvariable=self.connection_duration_var,
            bg="#DCE5EE",
            fg="#607D8B",
            font=("Segoe UI", 9),
        ).pack(side="right", padx=(0, 14))

        tk.Label(
            footer,
            textvariable=self.counter_var,
            bg="#DCE5EE",
            fg="#40566B",
            font=("Consolas", 9, "bold"),
        ).pack(side="right", padx=14)

        tk.Label(
            footer,
            text=f"{APP_NAME} - V{APP_VERSION}",
            bg="#DCE5EE",
            fg="#607D8B",
            font=("Segoe UI", 9),
        ).pack(side="left", padx=14)

    def _build_server_tab(self) -> None:
        connection = ttk.LabelFrame(self.server_tab, text="Connexion TCP", padding=10)
        connection.pack(fill="x")

        ttk.Label(connection, text="Point d'appel :").grid(row=0, column=0, sticky="w")

        self.call_point_combo = ttk.Combobox(
            connection,
            textvariable=self.call_point_var,
            values=("PNH", "PNR"),
            state="readonly",
            width=8,
        )
        self.call_point_combo.grid(row=0, column=1, padx=(5, 15), sticky="w")
        self.call_point_combo.bind("<<ComboboxSelected>>", self.on_call_point_selected)

        ttk.Label(connection, text="Serveur :").grid(row=0, column=2, sticky="w")
        self.host_entry = ttk.Entry(connection, textvariable=self.host_var, width=28)
        self.host_entry.grid(row=0, column=3, padx=(5, 15), sticky="w")

        ttk.Label(connection, text="Port :").grid(row=0, column=4, sticky="w")
        self.port_entry = ttk.Entry(connection, textvariable=self.port_var, width=9)
        self.port_entry.grid(row=0, column=5, padx=(5, 15), sticky="w")

        self.connect_button = tk.Button(
            connection,
            text="Connexion",
            command=self.start_connection,
            bg="#F8FAFC",
            fg="#1F2937",
            activebackground="#E8EEF6",
            activeforeground="#1F2937",
            disabledforeground="#D1D5DB",
            relief="solid",
            bd=1,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=13,
            pady=6,
        )
        self.connect_button.grid(row=0, column=6, padx=5)

        self.disconnect_button = tk.Button(
            connection,
            text="Déconnexion",
            command=self.disconnect,
            state="disabled",
            bg="#F8FAFC",
            fg="#1F2937",
            activebackground="#FDECEC",
            activeforeground="#1F2937",
            disabledforeground="#D1D5DB",
            relief="solid",
            bd=1,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=13,
            pady=6,
        )
        self.disconnect_button.grid(row=0, column=7, padx=5)


        authorization = ttk.LabelFrame(
            self.server_tab, text="Message d'autorisation 0100", padding=10
        )
        authorization.pack(fill="x", pady=(10, 10))

        ttk.Label(authorization, text="PAN (16 chiffres) :").grid(
            row=0, column=0, sticky="w"
        )
        self.pan_entry = tk.Entry(
            authorization,
            textvariable=self.pan_var,
            width=21,
            bg="#FFF9E6",
            fg="#263238",
            insertbackground="#263238",
            relief="solid",
            bd=1,
            font=("Consolas", 10),
        )
        self.pan_entry.grid(row=0, column=1, padx=(5, 16), ipady=3, sticky="w")

        ttk.Label(authorization, text="Expiration AAMM :").grid(
            row=0, column=2, sticky="w"
        )
        self.expiry_entry = tk.Entry(
            authorization,
            textvariable=self.expiry_var,
            width=8,
            bg="#EDF7FF",
            fg="#263238",
            insertbackground="#263238",
            relief="solid",
            bd=1,
            font=("Consolas", 10),
        )
        self.expiry_entry.grid(row=0, column=3, padx=(5, 16), ipady=3, sticky="w")

        self.choose_card_button = tk.Button(
            authorization,
            text="Choisir une carte",
            command=self.open_card_selector,
            bg="#F8FAFC",
            fg="#1F2937",
            activebackground="#E8EEF6",
            activeforeground="#1F2937",
            relief="solid",
            bd=1,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=6,
        )
        self.choose_card_button.grid(row=0, column=4, padx=(0, 8))

        self.send_0100_button = tk.Button(
            authorization,
            text="Envoyer 0100",
            command=self.trigger_send_0100,
            state="disabled",
            bg="#F8FAFC",
            fg="#1F2937",
            activebackground="#E8F2FB",
            activeforeground="#1F2937",
            disabledforeground="#D1D5DB",
            relief="solid",
            bd=1,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=14,
            pady=6,
        )
        self.send_0100_button.grid(row=0, column=5, padx=5)

        console_frame = ttk.LabelFrame(self.server_tab, text="Journal réseau", padding=5)
        console_frame.pack(fill="both", expand=True)

        self.console = tk.Text(
            console_frame,
            bg="#101820",
            fg="#D7E3ED",
            insertbackground="white",
            font=("Consolas", 10),
            state="disabled",
            wrap="none",
        )
        console_y = ttk.Scrollbar(console_frame, orient="vertical", command=self.console.yview)
        console_x = ttk.Scrollbar(console_frame, orient="horizontal", command=self.console.xview)
        self.console.configure(yscrollcommand=console_y.set, xscrollcommand=console_x.set)
        self.console.tag_configure("time", foreground="#78909C")
        self.console.tag_configure("rx", foreground="#4FC3F7")
        self.console.tag_configure("tx", foreground="#81C784")
        self.console.tag_configure("success", foreground="#69F0AE")
        self.console.tag_configure("warning", foreground="#FFD166")
        self.console.tag_configure("error", foreground="#FF6B6B")
        self.console.tag_configure("info", foreground="#D7E3ED")
        self.console.tag_configure("raw", foreground="#B0BEC5")

        self.console.grid(row=0, column=0, sticky="nsew")
        console_y.grid(row=0, column=1, sticky="ns")
        console_x.grid(row=1, column=0, sticky="ew")
        console_frame.rowconfigure(0, weight=1)
        console_frame.columnconfigure(0, weight=1)

    def _build_cbae_tab(self) -> None:
        connection = ttk.LabelFrame(
            self.cbae_tab,
            text="Point d'écoute CBAE",
            padding=10,
        )
        connection.pack(fill="x", pady=(0, 10))

        ttk.Label(connection, text="Point d'écoute :").grid(
            row=0, column=0, sticky="w"
        )

        self.cbae_listen_combo = ttk.Combobox(
            connection,
            textvariable=self.cbae_listen_point_var,
            values=("PNH", "PNR"),
            state="readonly",
            width=8,
        )
        self.cbae_listen_combo.grid(
            row=0, column=1, padx=(5, 15), sticky="w"
        )
        self.cbae_listen_combo.bind(
            "<<ComboboxSelected>>",
            self.on_listen_point_selected,
        )

        ttk.Label(connection, text="Serveur :").grid(
            row=0, column=2, sticky="w"
        )
        self.cbae_host_entry = ttk.Entry(
            connection,
            textvariable=self.cbae_host_var,
            width=28,
            state="readonly",
        )
        self.cbae_host_entry.grid(
            row=0, column=3, padx=(5, 15), sticky="w"
        )

        ttk.Label(connection, text="Port :").grid(
            row=0, column=4, sticky="w"
        )
        self.cbae_port_entry = ttk.Entry(
            connection,
            textvariable=self.cbae_port_var,
            width=9,
            state="readonly",
        )
        self.cbae_port_entry.grid(
            row=0, column=5, padx=(5, 15), sticky="w"
        )

        ttk.Label(
            self.cbae_tab,
            text="La gestion réseau CBAE sera ajoutée ultérieurement.",
            font=("Segoe UI", 11, "italic"),
        ).pack(anchor="w", pady=(8, 0))

    def _build_parser_tab(self) -> None:
        ttk.Label(
            self.parser_tab,
            text="Collez une trame BASE I avec ou sans préfixe TCP :",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")

        self.parser_input = tk.Text(
            self.parser_tab, height=7, wrap="word", font=("Consolas", 10)
        )
        self.parser_input.pack(fill="x", pady=(5, 6))

        actions = ttk.Frame(self.parser_tab)
        actions.pack(fill="x", pady=(0, 6))
        tk.Button(
            actions, text="Coller", command=self.paste_parser,
            bg="#F8FAFC", fg="#1F2937", activebackground="#E8EEF6",
            activeforeground="#1F2937", relief="solid", bd=1, cursor="hand2",
            font=("Segoe UI", 10, "bold"), padx=12, pady=6
        ).pack(side="left")

        tk.Button(
            actions, text="Décoder", command=self.decode_parser_input,
            bg="#F8FAFC", fg="#1F2937", activebackground="#E8F2FB",
            activeforeground="#1F2937", relief="solid", bd=1, cursor="hand2",
            font=("Segoe UI", 10, "bold"), padx=12, pady=6
        ).pack(side="left", padx=6)

        tk.Button(
            actions, text="Effacer", command=self.clear_parser,
            bg="#F8FAFC", fg="#1F2937", activebackground="#FFF3E6",
            activeforeground="#1F2937", relief="solid", bd=1, cursor="hand2",
            font=("Segoe UI", 10, "bold"), padx=12, pady=6
        ).pack(side="left")

        columns = ("field", "name", "offset", "prefix", "raw", "value")
        self.parser_tree = ttk.Treeview(
            self.parser_tab, columns=columns, show="headings", height=16
        )
        labels = {
            "field": "Champ",
            "name": "Nom",
            "offset": "Offsets",
            "prefix": "Préfixe",
            "raw": "Données brutes",
            "value": "Valeur décodée",
        }
        widths = {
            "field": 70,
            "name": 250,
            "offset": 90,
            "prefix": 85,
            "raw": 310,
            "value": 350,
        }
        for col in columns:
            self.parser_tree.heading(col, text=labels[col])
            self.parser_tree.column(col, width=widths[col], anchor="w")

        tree_frame = ttk.Frame(self.parser_tab)
        tree_frame.pack(fill="both", expand=True)
        tree_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.parser_tree.yview)
        tree_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.parser_tree.xview)
        self.parser_tree.configure(yscrollcommand=tree_y.set, xscrollcommand=tree_x.set)
        self.parser_tree.tag_configure("even", background="#FFFFFF")
        self.parser_tree.tag_configure("odd", background="#F3F7FB")
        self.parser_tree.grid(in_=tree_frame, row=0, column=0, sticky="nsew")
        tree_y.grid(row=0, column=1, sticky="ns")
        tree_x.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

    def get_call_points_config_path(self) -> Path:
        return Path(__file__).resolve().with_name("points_appel_base1.json")

    def load_call_points(self) -> dict:
        config = {
            name: {"host": values["host"], "port": values["port"]}
            for name, values in DEFAULT_CALL_POINTS.items()
        }

        config_path = self.get_call_points_config_path()
        if not config_path.exists():
            return config

        try:
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            for name in ("PNH", "PNR"):
                values = loaded.get(name, {})
                host = str(values.get("host", config[name]["host"])).strip()
                port = int(values.get("port", config[name]["port"]))

                if host and 1 <= port <= 65535:
                    config[name] = {"host": host, "port": port}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass

        return config

    def apply_selected_call_point(self) -> None:
        name = self.call_point_var.get()
        values = self.call_points.get(name)
        if values is None:
            return

        self.host_var.set(values["host"])
        self.port_var.set(str(values["port"]))

    def on_call_point_selected(self, _event=None) -> None:
        self.apply_selected_call_point()
        self.refresh_header_status()

    def _build_call_points_tab(self) -> None:
        ttk.Label(
            self.call_points_tab,
            text="Configuration des points réseau",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        config_notebook = ttk.Notebook(self.call_points_tab)
        config_notebook.pack(fill="both", expand=True)

        call_frame = ttk.Frame(config_notebook, padding=12)
        listen_frame = ttk.Frame(config_notebook, padding=12)
        cards_frame = ttk.Frame(config_notebook, padding=12)

        config_notebook.add(call_frame, text="Points d'appel")
        config_notebook.add(listen_frame, text="Points d'écoute")
        config_notebook.add(cards_frame, text="Référentiel cartes")

        cards_box = ttk.LabelFrame(
            cards_frame,
            text="Fichier des cartes",
            padding=12,
        )
        cards_box.pack(fill="x")

        ttk.Label(
            cards_box,
            text="Fichier utilisé : referentiel_cartes.csv",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            cards_box,
            text=(
                "Le fichier doit être placé dans le même dossier que l'application. "
                "Colonnes : Favori, Libellé, PAN, Carte encodée, DateExp, Environnement, Code banque, Nom de la banque."
            ),
            wraplength=760,
        ).pack(anchor="w", pady=(6, 10))

        self.cards_reference_status_var = tk.StringVar(
            value="Référentiel non chargé"
        )
        ttk.Label(
            cards_box,
            textvariable=self.cards_reference_status_var,
        ).pack(anchor="w", pady=(0, 10))

        tk.Button(
            cards_box,
            text="Actualiser le référentiel",
            command=self.reload_cards_reference,
            bg="#F8FAFC",
            fg="#1F2937",
            activebackground="#E8EEF6",
            activeforeground="#1F2937",
            relief="solid",
            bd=1,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=15,
            pady=6,
        ).pack(anchor="w")

        # -----------------------------
        # Points d'appel BASE I
        # -----------------------------
        ttk.Label(
            call_frame,
            text="Points d'appel BASE I",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        call_box = ttk.LabelFrame(
            call_frame,
            text="Configuration PNH / PNR",
            padding=12,
        )
        call_box.pack(fill="x")

        ttk.Label(call_box, text="Nom").grid(row=0, column=0, padx=6, pady=5)
        ttk.Label(call_box, text="Serveur").grid(row=0, column=1, padx=6, pady=5)
        ttk.Label(call_box, text="Port").grid(row=0, column=2, padx=6, pady=5)

        self.call_point_host_vars = {}
        self.call_point_port_vars = {}

        for row_index, name in enumerate(("PNH", "PNR"), start=1):
            values = self.call_points[name]

            host_var = tk.StringVar(value=values["host"])
            port_var = tk.StringVar(value=str(values["port"]))

            self.call_point_host_vars[name] = host_var
            self.call_point_port_vars[name] = port_var

            ttk.Label(
                call_box,
                text=name,
                font=("Segoe UI", 10, "bold"),
            ).grid(row=row_index, column=0, padx=6, pady=7, sticky="w")

            ttk.Entry(
                call_box,
                textvariable=host_var,
                width=35,
            ).grid(row=row_index, column=1, padx=6, pady=7, sticky="w")

            ttk.Entry(
                call_box,
                textvariable=port_var,
                width=10,
            ).grid(row=row_index, column=2, padx=6, pady=7, sticky="w")

        tk.Button(
            call_box,
            text="Enregistrer les points d'appel",
            command=self.save_call_points,
            bg="#F8FAFC",
            fg="#1F2937",
            activebackground="#E8EEF6",
            activeforeground="#1F2937",
            relief="solid",
            bd=1,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=15,
            pady=6,
        ).grid(row=3, column=0, columnspan=3, pady=(14, 4))

        # -----------------------------
        # Points d'écoute CBAE
        # -----------------------------
        ttk.Label(
            listen_frame,
            text="Points d'écoute CBAE",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        listen_box = ttk.LabelFrame(
            listen_frame,
            text="Configuration PNH / PNR",
            padding=12,
        )
        listen_box.pack(fill="x")

        ttk.Label(listen_box, text="Nom").grid(row=0, column=0, padx=6, pady=5)
        ttk.Label(listen_box, text="Serveur").grid(row=0, column=1, padx=6, pady=5)
        ttk.Label(listen_box, text="Port").grid(row=0, column=2, padx=6, pady=5)

        self.listen_point_host_vars = {}
        self.listen_point_port_vars = {}

        for row_index, name in enumerate(("PNH", "PNR"), start=1):
            values = self.listen_points[name]

            host_var = tk.StringVar(value=values["host"])
            port_var = tk.StringVar(value=str(values["port"]))

            self.listen_point_host_vars[name] = host_var
            self.listen_point_port_vars[name] = port_var

            ttk.Label(
                listen_box,
                text=name,
                font=("Segoe UI", 10, "bold"),
            ).grid(row=row_index, column=0, padx=6, pady=7, sticky="w")

            ttk.Entry(
                listen_box,
                textvariable=host_var,
                width=35,
            ).grid(row=row_index, column=1, padx=6, pady=7, sticky="w")

            ttk.Entry(
                listen_box,
                textvariable=port_var,
                width=10,
            ).grid(row=row_index, column=2, padx=6, pady=7, sticky="w")

        tk.Button(
            listen_box,
            text="Enregistrer les points d'écoute",
            command=self.save_listen_points,
            bg="#F8FAFC",
            fg="#1F2937",
            activebackground="#E8F2FB",
            activeforeground="#1F2937",
            relief="solid",
            bd=1,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=15,
            pady=6,
        ).grid(row=3, column=0, columnspan=3, pady=(14, 4))

    def get_listen_points_config_path(self) -> Path:
        return Path(__file__).resolve().with_name("points_ecoute_cbae.json")

    def load_listen_points(self) -> dict:
        config = {
            "PNH": {"host": "0.0.0.0", "port": 0},
            "PNR": {"host": "0.0.0.0", "port": 0},
        }

        config_path = self.get_listen_points_config_path()
        if not config_path.exists():
            return config

        try:
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            for name in ("PNH", "PNR"):
                values = loaded.get(name, {})
                host = str(values.get("host", config[name]["host"])).strip()
                port = int(values.get("port", config[name]["port"]))

                if host and 0 <= port <= 65535:
                    config[name] = {"host": host, "port": port}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass

        return config

    def apply_selected_listen_point(self) -> None:
        name = self.cbae_listen_point_var.get()
        values = self.listen_points.get(name)
        if values is None:
            return

        self.cbae_host_var.set(values["host"])
        self.cbae_port_var.set(str(values["port"]))

    def on_listen_point_selected(self, _event=None) -> None:
        self.apply_selected_listen_point()
        self.refresh_header_status()

    def save_listen_points(self) -> None:
        new_config = {}

        try:
            for name in ("PNH", "PNR"):
                host = self.listen_point_host_vars[name].get().strip()
                port_text = self.listen_point_port_vars[name].get().strip()

                if not host:
                    raise ValueError(
                        f"Le serveur du point d'écoute {name} est vide."
                    )

                try:
                    port = int(port_text)
                except ValueError as exc:
                    raise ValueError(
                        f"Le port du point d'écoute {name} doit être numérique."
                    ) from exc

                if not 0 <= port <= 65535:
                    raise ValueError(
                        f"Le port du point d'écoute {name} doit être compris entre 0 et 65535."
                    )

                new_config[name] = {"host": host, "port": port}

            self.listen_points = new_config

            self.get_listen_points_config_path().write_text(
                json.dumps(self.listen_points, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            self.apply_selected_listen_point()

            messagebox.showinfo(
                "Points d'écoute CBAE",
                "Les points d'écoute PNH et PNR ont été enregistrés.",
            )

        except Exception as exc:
            messagebox.showerror("Erreur de configuration", str(exc))

    def save_call_points(self) -> None:
        new_config = {}

        try:
            for name in ("PNH", "PNR"):
                host = self.call_point_host_vars[name].get().strip()
                port_text = self.call_point_port_vars[name].get().strip()

                if not host:
                    raise ValueError(f"Le serveur du point d'appel {name} est vide.")

                try:
                    port = int(port_text)
                except ValueError as exc:
                    raise ValueError(
                        f"Le port du point d'appel {name} doit être numérique."
                    ) from exc

                if not 1 <= port <= 65535:
                    raise ValueError(
                        f"Le port du point d'appel {name} doit être compris entre 1 et 65535."
                    )

                new_config[name] = {"host": host, "port": port}

            self.call_points = new_config

            self.get_call_points_config_path().write_text(
                json.dumps(self.call_points, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            self.apply_selected_call_point()

            messagebox.showinfo(
                "Points d'appel BASE I",
                "Les points d'appel PNH et PNR ont été enregistrés.",
            )

        except Exception as exc:
            messagebox.showerror("Erreur de configuration", str(exc))

    def on_main_tab_changed(self, _event=None) -> None:
        try:
            selected = self.main_notebook.select()
            tab_text = self.main_notebook.tab(selected, "text")
        except tk.TclError:
            return

        if tab_text == "CBAE":
            self.active_mode = "CBAE"
        elif tab_text == "BASE I":
            self.active_mode = "BASE I"

        self.refresh_header_status()

    def refresh_header_status(self) -> None:
        connected = self.client_socket is not None

        if connected:
            if self.active_mode == "CBAE":
                point = self.cbae_listen_point_var.get().strip() or "-"
                host = self.cbae_host_var.get().strip() or "-"
                port = self.cbae_port_var.get().strip() or "-"
            else:
                point = self.call_point_var.get().strip() or "-"
                host = self.host_var.get().strip() or "-"
                port = self.port_var.get().strip() or "-"

            self.status_var.set(
                f"● Connecté | {self.active_mode} | {point} | {host}:{port}"
            )
            self.header_status_label.configure(fg="#8CF0B5")
        else:
            self.status_var.set(f"● Déconnecté | {self.active_mode}")
            self.header_status_label.configure(fg="#D7E3ED")

    def update_connection_duration(self) -> None:
        if self.connection_started_at is None or self.client_socket is None:
            self.connection_duration_var.set("")
            return

        elapsed = datetime.datetime.now() - self.connection_started_at
        total_seconds = max(0, int(elapsed.total_seconds()))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        self.connection_duration_var.set(
            f"Connecté depuis {hours:02d}:{minutes:02d}:{seconds:02d}"
        )
        self.after(1000, self.update_connection_duration)

    # --------------------------------------------------------
    # Journal et état
    # --------------------------------------------------------

    def log(self, message: str) -> None:
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S] ")
        self.after(0, self._append_log, timestamp, message)

    def _log_tag(self, message: str) -> str:
        upper = message.upper()
        if "ERREUR" in upper or "IMPOSSIBLE" in upper or "NON PARSABLE" in upper:
            return "error"
        if "RX " in upper or upper.startswith("0800") or "0110 REÇU" in upper:
            return "rx"
        if "TX " in upper or "ENVOI" in upper:
            return "tx"
        if "CONNEXION ÉTABLIE" in upper or "APPROUV" in upper:
            return "success"
        if "FERMÉ" in upper or "TERMINÉE" in upper or "ATTENTE" in upper:
            return "warning"
        return "info"

    def _append_log(self, timestamp: str, message: str) -> None:
        self.console.configure(state="normal")
        self.console.insert("end", timestamp, "time")

        tag = self._log_tag(message)
        lines = message.splitlines() or [""]
        for index, line in enumerate(lines):
            line_tag = "raw" if "BRUT" in line.upper() else tag
            self.console.insert("end", line, line_tag)
            if index < len(lines) - 1:
                self.console.insert("end", "\n")

        self.console.insert("end", "\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    def update_counters(self) -> None:
        self.counter_var.set(
            f"RX : 0800={self.count_0800}  0110={self.count_0110}"
            f"    |    TX : 0810={self.count_0810}  0100={self.count_0100}"
        )

    def set_connected_ui(self, connected: bool) -> None:
        self.connect_button.configure(state="disabled" if connected else "normal")
        self.disconnect_button.configure(state="normal" if connected else "disabled")
        self.send_0100_button.configure(state="normal" if connected else "disabled")
        self.call_point_combo.configure(state="disabled" if connected else "readonly")
        self.host_entry.configure(state="disabled" if connected else "normal")
        self.port_entry.configure(state="disabled" if connected else "normal")

        if connected:
            self.connection_started_at = datetime.datetime.now()
            self.refresh_header_status()
            self.update_connection_duration()
        else:
            self.connection_started_at = None
            self.connection_duration_var.set("")
            self.refresh_header_status()

    # --------------------------------------------------------
    # Connexion TCP
    # --------------------------------------------------------

    def start_connection(self) -> None:
        if self.client_socket is not None:
            return

        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Port invalide", "Le port doit être compris entre 1 et 65535.")
            return

        if not host:
            messagebox.showerror("Serveur invalide", "Le nom du serveur est vide.")
            return

        self.connect_button.configure(state="disabled")
        self.stop_event.clear()
        self.frame_decoder = TcpFrameDecoder()
        self.network_thread = threading.Thread(
            target=self.network_loop, args=(host, port), daemon=True
        )
        self.network_thread.start()

    def network_loop(self, host: str, port: int) -> None:
        self.log(f"Connexion à {host}:{port}...")

        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8.0)
            sock.connect((host, port))
            sock.settimeout(1.0)
            self.client_socket = sock
            self.after(0, self.set_connected_ui, True)
            self.log("Connexion établie. Écoute permanente des messages entrants.")

            while not self.stop_event.is_set():
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        self.log("Le serveur a fermé la connexion.")
                        break

                    for frame, payload in self.frame_decoder.feed(chunk):
                        self.handle_received_frame(frame, payload)

                except socket.timeout:
                    continue

        except Exception as exc:
            if not self.stop_event.is_set():
                self.log(f"Erreur réseau : {exc}")

        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self.client_socket = None
            self.after(0, self.set_connected_ui, False)
            self.log("Session TCP terminée.")

    def disconnect(self) -> None:
        self.stop_event.set()
        sock = self.client_socket
        self.client_socket = None

        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

        self.set_connected_ui(False)

    def send_frame(self, frame: bytes) -> None:
        sock = self.client_socket
        if sock is None:
            raise ConnectionError("La socket n'est pas connectée.")

        with self.send_lock:
            sock.sendall(frame)

    # --------------------------------------------------------
    # Réception et réponses automatiques
    # --------------------------------------------------------

    def handle_received_frame(self, frame: bytes, payload: bytes) -> None:
        try:
            parsed = parse_base1(payload)
        except Exception as exc:
            self.log(
                f"Message reçu mais non parsable : {exc}\n"
                f"RX brut : {frame.hex(' ').upper()}"
            )
            return

        self.log(
            f"RX MTI {parsed['mti']} — {len(payload)} octets payload\n"
            f"RX brut : {frame.hex(' ').upper()}"
        )

        if parsed["mti"] == "0800":
            self.count_0800 += 1
            self.after(0, self.update_counters)
            try:
                de7 = bcd_to_digits(get_field_raw(parsed, 7), 10)
                de11 = bcd_to_digits(get_field_raw(parsed, 11), 6)
                de70 = bcd_to_digits(get_field_raw(parsed, 70), 3)
                self.log(
                    f"0800 n°{self.count_0800} : "
                    f"DE7={de7}, DE11={de11}, DE70={de70}"
                )

                response = build_0810_frame(parsed)
                self.send_frame(response)
                self.count_0810 += 1
                self.after(0, self.update_counters)
                self.log(
                    f"TX 0810 n°{self.count_0800} — champs DE7/DE11/DE70 repris en écho\n"
                    f"TX brut : {response.hex(' ').upper()}"
                )
            except Exception as exc:
                self.log(f"Impossible de répondre au 0800 : {exc}")

        elif parsed["mti"] == "0110":
            self.count_0110 += 1
            self.after(0, self.update_counters)
            response_code = ""
            try:
                response_code = next(
                    row["value"] for row in parsed["rows"] if row["field"] == 39
                )
            except StopIteration:
                pass

            if response_code:
                self.log(f"Réponse d'autorisation 0110 reçue — DE39={response_code}")
            else:
                self.log("Réponse d'autorisation 0110 reçue.")

            self.after(0, lambda: self.send_0100_button.configure(state="normal"))

        else:
            self.log(f"MTI {parsed['mti']} reçu : aucune réponse automatique configurée.")

    # --------------------------------------------------------
    # Envoi du 0100
    # --------------------------------------------------------

    @staticmethod
    def _normalize_card_header(value: str) -> str:
        value = value.strip().lower()
        replacements = {
            "é": "e", "è": "e", "ê": "e", "ë": "e",
            "à": "a", "â": "a", "ä": "a",
            "î": "i", "ï": "i",
            "ô": "o", "ö": "o",
            "ù": "u", "û": "u", "ü": "u",
            "ç": "c",
        }
        for source, target in replacements.items():
            value = value.replace(source, target)
        return re.sub(r"[^a-z0-9]", "", value)

    @staticmethod
    def _is_favorite_value(value: str) -> bool:
        return value.strip().casefold() in {
            "1", "oui", "o", "yes", "y", "true", "vrai", "x", "★", "*"
        }

    @staticmethod
    def _mask_pan(pan: str) -> str:
        """Affiche le PAN sous la forme 4970 10•• •••• 1234."""
        if len(pan) < 10:
            return pan

        visible_start = min(6, len(pan) - 4)
        masked = pan[:visible_start] + ("•" * (len(pan) - visible_start - 4)) + pan[-4:]
        return " ".join(masked[index:index + 4] for index in range(0, len(masked), 4))

    def _read_cards_file(self, path: Path) -> list[dict[str, str]]:
        try:
            raw = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            raw = path.read_text(encoding="cp1252")

        if not raw.strip():
            raise ValueError("Le fichier de cartes est vide.")

        sample = raw[:4096]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=";,\t")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = ";"

        rows = list(csv.reader(raw.splitlines(), delimiter=delimiter))
        rows = [row for row in rows if any(cell.strip() for cell in row)]
        if not rows:
            raise ValueError("Le fichier de cartes ne contient aucune ligne.")

        normalized_headers = [self._normalize_card_header(cell) for cell in rows[0]]
        aliases = {
            "favorite": {"favori", "favorite", "favourite", "etoile"},
            "label": {"libelle", "label", "nomcarte", "description"},
            "pan": {"pan", "numerocarte", "cardnumber"},
            "encoded_card": {
                "carteencodee", "carteencode", "encodedcard",
                "panencode", "panencodee", "encryptedcard", "encryptedpan"
            },
            "expiry": {
                "datexp", "dateexpiration", "expiration", "expiry",
                "expirydate", "exp", "aamm"
            },
            "environment": {
                "environnement", "environment", "env", "plateforme"
            },
            "bank_code": {"codebanque", "bankcode", "code"},
            "bank_name": {"nombanque", "banque", "bankname", "bank"},
        }

        def find_index(names: set[str]) -> int | None:
            for index, header in enumerate(normalized_headers):
                if header in names:
                    return index
            return None

        indexes = {name: find_index(values) for name, values in aliases.items()}
        has_header = indexes["pan"] is not None and indexes["expiry"] is not None

        if has_header:
            data_rows = rows[1:]
        else:
            # Format V1.5 sans en-tête :
            # Favori, Libellé, PAN, Carte encodée, DateExp,
            # Environnement, Code banque, Nom banque.
            data_rows = rows
            indexes = {
                "favorite": 0,
                "label": 1,
                "pan": 2,
                "encoded_card": 3,
                "expiry": 4,
                "environment": 5,
                "bank_code": 6,
                "bank_name": 7,
            }

        cards: list[dict[str, str]] = []
        for line_number, row in enumerate(data_rows, start=2 if has_header else 1):
            def cell(index: int | None) -> str:
                if index is None or index >= len(row):
                    return ""
                return row[index].strip()

            pan = re.sub(r"\s+", "", cell(indexes["pan"]))
            encoded_card = re.sub(r"\s+", "", cell(indexes["encoded_card"]))
            expiry = re.sub(r"[\s/.-]+", "", cell(indexes["expiry"]))
            environment = cell(indexes["environment"]).upper()
            favorite_raw = cell(indexes["favorite"])

            if not pan and not encoded_card and not expiry:
                continue
            if pan and (not pan.isdigit() or not (12 <= len(pan) <= 19)):
                continue
            if not pan and not encoded_card:
                continue
            if not (expiry.isdigit() and len(expiry) == 4):
                continue
            if environment not in {"", "PNH", "PNR"}:
                continue

            cards.append(
                {
                    "favorite": "1" if self._is_favorite_value(favorite_raw) else "0",
                    "label": cell(indexes["label"]),
                    "pan": pan,
                    "encoded_card": encoded_card,
                    "expiry": expiry,
                    "environment": environment,
                    "bank_code": cell(indexes["bank_code"]),
                    "bank_name": cell(indexes["bank_name"]),
                    "line_number": str(line_number),
                }
            )

        if not cards:
            raise ValueError(
                "Aucune ligne valide n'a été trouvée.\n\n"
                "Format attendu : Favori ; Libellé ; PAN ; Carte encodée ; "
                "DateExp ; Environnement ; Code banque ; Nom banque\n"
                "DateExp doit être au format AAMM et l'environnement PNH ou PNR."
            )

        return cards

    def reload_cards_reference(self, show_message: bool = True) -> bool:
        path = self.cards_file_path

        if not path.exists():
            self.cards = []
            if hasattr(self, "cards_reference_status_var"):
                self.cards_reference_status_var.set(
                    "Fichier introuvable : referentiel_cartes.csv"
                )
            self.log(
                "Référentiel cartes introuvable : "
                f"{path}"
            )
            if show_message:
                messagebox.showerror(
                    "Référentiel introuvable",
                    "Le fichier referentiel_cartes.csv est introuvable.\n\n"
                    "Placez-le dans le même dossier que l'application.",
                    parent=self,
                )
            return False

        try:
            self.cards = self._read_cards_file(path)
        except Exception as exc:
            self.cards = []
            if hasattr(self, "cards_reference_status_var"):
                self.cards_reference_status_var.set(
                    "Erreur de chargement du référentiel"
                )
            if show_message:
                messagebox.showerror(
                    "Référentiel invalide",
                    str(exc),
                    parent=self,
                )
            self.log(f"Erreur de chargement du référentiel cartes : {exc}")
            return False

        count = len(self.cards)
        if hasattr(self, "cards_reference_status_var"):
            self.cards_reference_status_var.set(
                f"{count} carte(s) chargée(s)"
            )
        self.log(
            f"Référentiel cartes chargé : {count} ligne(s) valide(s)."
        )
        if show_message:
            messagebox.showinfo(
                "Référentiel actualisé",
                f"{count} carte(s) chargée(s).",
                parent=self,
            )
        return True

    def open_card_selector(self) -> None:
        if not self.cards:
            if not self.reload_cards_reference(show_message=True):
                return

        self._show_card_selection_window(
            self.cards,
            self.cards_file_path,
        )

    def _show_card_selection_window(
        self,
        cards: list[dict[str, str]],
        path: Path,
    ) -> None:
        window = tk.Toplevel(self)
        window.title("Catalogue des cartes de test")
        window.geometry("1120x560")
        window.minsize(900, 420)
        window.transient(self)
        window.grab_set()

        top = ttk.Frame(window, padding=(12, 12, 12, 6))
        top.pack(fill="x")

        ttk.Label(
            top,
            text=f"Référentiel : {path.name}",
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=(0, 20))

        favorite_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top,
            text="★ Favoris uniquement",
            variable=favorite_only_var,
        ).grid(row=0, column=1, sticky="w", padx=(0, 20))

        environment_var = tk.StringVar(value="Tous")
        ttk.Label(top, text="Environnement :").grid(
            row=0, column=2, sticky="e", padx=(0, 6)
        )
        environment_combo = ttk.Combobox(
            top,
            textvariable=environment_var,
            values=("Tous", "PNH", "PNR"),
            state="readonly",
            width=8,
        )
        environment_combo.grid(row=0, column=3, sticky="w", padx=(0, 20))

        bank_names = sorted(
            {
                card["bank_name"].strip()
                for card in cards
                if card["bank_name"].strip()
            },
            key=str.casefold,
        )
        bank_var = tk.StringVar(value="Toutes les banques")
        ttk.Label(top, text="Banque :").grid(
            row=0, column=4, sticky="e", padx=(0, 6)
        )
        bank_combo = ttk.Combobox(
            top,
            textvariable=bank_var,
            values=["Toutes les banques"] + bank_names,
            state="readonly",
            width=23,
        )
        bank_combo.grid(row=0, column=5, sticky="w", padx=(0, 20))

        search_var = tk.StringVar()
        ttk.Label(top, text="Rechercher :").grid(
            row=0, column=6, sticky="e", padx=(0, 6)
        )
        search_entry = ttk.Entry(top, textvariable=search_var, width=24)
        search_entry.grid(row=0, column=7, sticky="ew")
        top.columnconfigure(7, weight=1)

        count_var = tk.StringVar()
        ttk.Label(
            window,
            textvariable=count_var,
            padding=(12, 0, 12, 4),
        ).pack(anchor="w")

        table_frame = ttk.Frame(window, padding=(12, 6))
        table_frame.pack(fill="both", expand=True)

        columns = (
            "favorite", "label", "pan", "encoded_card", "expiry",
            "environment", "bank_code", "bank_name"
        )
        card_tree_style = ttk.Style(window)
        card_tree_style.configure(
            "CardSelector.Treeview",
            foreground="black",
        )
        card_tree_style.map(
            "CardSelector.Treeview",
            foreground=[("selected", "black")],
        )

        tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="CardSelector.Treeview",
        )

        headings = {
            "favorite": "★",
            "label": "Libellé",
            "pan": "PAN",
            "encoded_card": "Carte encodée",
            "expiry": "DateExp",
            "environment": "Env.",
            "bank_code": "Code banque",
            "bank_name": "Nom de la banque",
        }
        widths = {
            "favorite": 45,
            "label": 220,
            "pan": 205,
            "encoded_card": 190,
            "expiry": 85,
            "environment": 70,
            "bank_code": 115,
            "bank_name": 230,
        }
        anchors = {
            "favorite": "center",
            "label": "w",
            "pan": "center",
            "encoded_card": "center",
            "expiry": "center",
            "environment": "center",
            "bank_code": "center",
            "bank_name": "w",
        }

        for name in columns:
            tree.column(
                name,
                width=widths[name],
                minwidth=40,
                anchor=anchors[name],
            )

        scrollbar_y = ttk.Scrollbar(
            table_frame, orient="vertical", command=tree.yview
        )
        scrollbar_x = ttk.Scrollbar(
            table_frame, orient="horizontal", command=tree.xview
        )
        tree.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set,
        )
        tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        sort_state = {"column": "", "reverse": False}
        displayed_cards: dict[str, dict[str, str]] = {}

        def filtered_cards() -> list[dict[str, str]]:
            query = search_var.get().strip().casefold()
            selected_bank = bank_var.get()
            selected_environment = environment_var.get()

            result = []
            for card in cards:
                if favorite_only_var.get() and card["favorite"] != "1":
                    continue
                if (
                    selected_environment != "Tous"
                    and card["environment"] != selected_environment
                ):
                    continue
                if (
                    selected_bank != "Toutes les banques"
                    and card["bank_name"] != selected_bank
                ):
                    continue

                haystack = " ".join(
                    (
                        card["label"],
                        card["pan"],
                        card["encoded_card"],
                        card["expiry"],
                        card["environment"],
                        card["bank_code"],
                        card["bank_name"],
                    )
                ).casefold()
                if query and query not in haystack:
                    continue
                result.append(card)

            column = sort_state["column"]
            if column:
                result.sort(
                    key=lambda card: card[column].casefold(),
                    reverse=sort_state["reverse"],
                )
            else:
                # Par défaut : favoris en premier, puis libellé et PAN.
                result.sort(
                    key=lambda card: (
                        card["favorite"] != "1",
                        card["label"].casefold(),
                        card["pan"] or card["encoded_card"],
                    )
                )
            return result

        def populate(*_args) -> None:
            current_pan = ""
            selection = tree.selection()
            if selection:
                current = displayed_cards.get(selection[0])
                if current:
                    current_pan = current["pan"] or current["encoded_card"]

            tree.delete(*tree.get_children())
            displayed_cards.clear()
            result = filtered_cards()
            selected_item = None

            for card in result:
                item_id = tree.insert(
                    "",
                    "end",
                    values=(
                        "★" if card["favorite"] == "1" else "",
                        card["label"],
                        self._mask_pan(card["pan"]) if card["pan"] else "À déchiffrer",
                        card["encoded_card"],
                        card["expiry"],
                        card["environment"],
                        card["bank_code"],
                        card["bank_name"],
                    ),
                )
                displayed_cards[item_id] = card
                card_identifier = card["pan"] or card["encoded_card"]
                if card_identifier in (current_pan, self.last_selected_pan):
                    selected_item = item_id

            count_var.set(
                f"{len(cards)} carte(s) dans le référentiel — "
                f"{len(result)} affichée(s)"
            )
            window.title(
                f"Catalogue des cartes de test — {len(result)} affichée(s)"
            )

            children = tree.get_children()
            if children:
                target = selected_item or children[0]
                tree.selection_set(target)
                tree.focus(target)
                tree.see(target)

        def sort_by(column: str) -> None:
            if sort_state["column"] == column:
                sort_state["reverse"] = not sort_state["reverse"]
            else:
                sort_state["column"] = column
                sort_state["reverse"] = False

            for name, title in headings.items():
                suffix = ""
                if name == column:
                    suffix = " ▼" if sort_state["reverse"] else " ▲"
                tree.heading(name, text=title + suffix)
            populate()

        for name, title in headings.items():
            tree.heading(
                name,
                text=title,
                command=lambda column=name: sort_by(column),
            )

        def validate_selection(_event=None) -> None:
            selection = tree.selection()
            if not selection:
                messagebox.showwarning(
                    "Aucune carte sélectionnée",
                    "Sélectionnez une ligne dans la liste.",
                    parent=window,
                )
                return

            card = displayed_cards.get(selection[0])
            if card is None:
                return

            if not card["pan"] and card["encoded_card"]:
                messagebox.showinfo(
                    "Carte encodée",
                    "Cette ligne ne contient pas encore de PAN en clair.\n\n"
                    "Le module de déchiffrement sera intégré ultérieurement.",
                    parent=window,
                )
                return

            self.pan_var.set(card["pan"])
            self.expiry_var.set(card["expiry"])
            self.last_selected_pan = card["pan"]

            environment = card["environment"]
            connection_warning = ""
            if environment in {"PNH", "PNR"}:
                previous_environment = self.call_point_var.get()
                self.call_point_var.set(environment)
                self.apply_selected_call_point()
                self.refresh_header_status()

                if (
                    self.client_socket is not None
                    and previous_environment != environment
                ):
                    connection_warning = (
                        "\n\nLa carte appartient à l'environnement "
                        f"{environment}, mais la connexion TCP actuelle reste ouverte "
                        f"sur {previous_environment}. Déconnectez-vous puis reconnectez-vous "
                        "avant d'envoyer le 0100."
                    )

            self.pan_entry.focus_set()
            self.pan_entry.icursor(tk.END)

            details = " - ".join(
                value for value in (
                    card["label"],
                    environment,
                    card["bank_code"],
                    card["bank_name"],
                )
                if value
            )
            suffix = f" ({details})" if details else ""
            self.log(
                f"Carte sélectionnée : PAN={card['pan']}, "
                f"expiration={card['expiry']}{suffix}."
            )
            window.destroy()

            if connection_warning:
                messagebox.showwarning(
                    "Reconnexion nécessaire",
                    connection_warning.strip(),
                    parent=self,
                )

        buttons = ttk.Frame(window, padding=(12, 6, 12, 12))
        buttons.pack(fill="x")

        ttk.Button(
            buttons,
            text="Annuler",
            command=window.destroy,
        ).pack(side="right", padx=(8, 0))

        ttk.Button(
            buttons,
            text="Utiliser cette carte",
            command=validate_selection,
        ).pack(side="right")

        search_var.trace_add("write", populate)
        bank_var.trace_add("write", populate)
        environment_var.trace_add("write", populate)
        favorite_only_var.trace_add("write", populate)

        tree.bind("<Double-1>", validate_selection)
        tree.bind("<Return>", validate_selection)
        window.bind("<Escape>", lambda _event: window.destroy())

        populate()
        search_entry.focus_set()

    def trigger_send_0100(self) -> None:
        if self.client_socket is None:
            messagebox.showerror("Non connecté", "Connectez-vous au serveur avant l'envoi.")
            return

        try:
            frame = build_0100_frame(self.pan_var.get(), self.expiry_var.get())
            parsed = parse_base1(frame[4:])
            de2 = next(row["value"] for row in parsed["rows"] if row["field"] == 2)
            de14 = next(row["value"] for row in parsed["rows"] if row["field"] == 14)
        except Exception as exc:
            messagebox.showerror("Trame 0100 invalide", str(exc))
            return

        self.send_0100_button.configure(state="disabled")
        threading.Thread(
            target=self._send_0100_worker,
            args=(frame, de2, de14),
            daemon=True,
        ).start()

    def _send_0100_worker(self, frame: bytes, pan: str, expiry: str) -> None:
        try:
            self.send_frame(frame)
            self.count_0100 += 1
            self.after(0, self.update_counters)
            self.log(
                f"TX MTI 0100 — PAN={pan}, expiration={expiry}\n"
                f"TX brut : {frame.hex(' ').upper()}\n"
                "En attente du message 0110."
            )
        except Exception as exc:
            self.log(f"Erreur pendant l'envoi du 0100 : {exc}")
            self.after(0, lambda: self.send_0100_button.configure(state="normal"))

    # --------------------------------------------------------
    # Onglet parseur manuel
    # --------------------------------------------------------

    def normalize_parser_payload(self, raw: bytes) -> bytes:
        if raw.startswith(b"\x16\x01\x02"):
            return raw

        if len(raw) >= 8 and raw[4:7] == b"\x16\x01\x02":
            announced = int.from_bytes(raw[0:2], "big")
            payload = raw[4:]
            if announced != len(payload):
                raise ValueError(
                    f"Le préfixe TCP annonce {announced} octets, "
                    f"mais le payload en contient {len(payload)}."
                )
            return payload

        raise ValueError(
            "Début de trame non reconnu. Le payload doit commencer par 16 01 02, "
            "ou être précédé du préfixe TCP de 4 octets."
        )

    def paste_parser(self) -> None:
        try:
            text = self.clipboard_get()
        except tk.TclError:
            messagebox.showwarning("Presse-papiers", "Aucun texte disponible.")
            return
        self.parser_input.delete("1.0", "end")
        self.parser_input.insert("1.0", text)

    def clear_parser(self) -> None:
        self.parser_input.delete("1.0", "end")
        for item in self.parser_tree.get_children():
            self.parser_tree.delete(item)

    def decode_parser_input(self) -> None:
        try:
            raw = clean_hex(self.parser_input.get("1.0", "end"))
            payload = self.normalize_parser_payload(raw)
            parsed = parse_base1(payload)
        except Exception as exc:
            messagebox.showerror("Erreur de décodage", str(exc))
            return

        for item in self.parser_tree.get_children():
            self.parser_tree.delete(item)

        for index, row in enumerate(parsed["rows"]):
            self.parser_tree.insert(
                "",
                "end",
                tags=("even" if index % 2 == 0 else "odd",),
                values=(
                    f"DE{row['field']:03d}",
                    row["name"],
                    f"{row['offset']}–{row['end'] - 1}",
                    row["prefix"],
                    row["raw"],
                    row["value"],
                ),
            )

    def on_close(self) -> None:
        try:
            self.disconnect()
        finally:
            self.destroy()


if __name__ == "__main__":
    app = AppSimulateurBase1()
    app.mainloop()

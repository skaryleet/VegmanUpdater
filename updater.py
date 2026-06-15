#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Утилита обновления прошивок BMC/UEFI сервера YADRO Vegman Rx20 (G1-3).

Платформа на базе OpenBMC. Утилита совмещает два API:
  * Redfish (HTTPS, Basic auth) — сбор информации, запуск SimpleUpdate, reset хоста;
  * legacy REST OpenBMC (/xyz/openbmc_project/..., HTTPS, cookie-сессия через /login)
    — отслеживание загруженного образа и управление активацией.

Только стандартная библиотека Python 3.9+. Без внешних зависимостей.
"""

import argparse
import base64
import http.cookiejar
import http.server
import json
import logging
import os
import shutil
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, Optional, Set

# --------------------------------------------------------------------------- #
# Константы
# --------------------------------------------------------------------------- #

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FIRMWARE_DIR = os.path.join(SCRIPT_DIR, "firmware")
BMC_SUBDIR = "bmc"
UEFI_SUBDIR = "uefi"

# Идентификаторы инвентаря прошивок Redfish
FW_INV_BIOS = "bios_active"
FW_INV_BMC = "bmc_active"

# Строки D-Bus OpenBMC (Software.*)
ACT_READY = "xyz.openbmc_project.Software.Activation.Activations.Ready"
ACT_ACTIVATING = "xyz.openbmc_project.Software.Activation.Activations.Activating"
ACT_ACTIVE = "xyz.openbmc_project.Software.Activation.Activations.Active"
ACT_FAILED = "xyz.openbmc_project.Software.Activation.Activations.Failed"
REQ_ACT_ACTIVE = "xyz.openbmc_project.Software.Activation.RequestedActivations.Active"
PURPOSE_BMC = "xyz.openbmc_project.Software.Version.VersionPurpose.BMC"
PURPOSE_HOST = "xyz.openbmc_project.Software.Version.VersionPurpose.Host"

log = logging.getLogger("updater")


class UpdaterError(Exception):
    """Управляемая ошибка процесса обновления (понятное сообщение оператору)."""


# --------------------------------------------------------------------------- #
# HTTP-обёртка над urllib (логирование + единая обработка)
# --------------------------------------------------------------------------- #

class HttpResult:
    def __init__(self, status: int, data, raw: str):
        self.status = status
        self.data = data       # распарсенный JSON (dict/list) либо None
        self.raw = raw         # тело ответа как текст


def _fmt_body(raw: str, limit: int = 800) -> str:
    if not raw:
        return ""
    body = raw if len(raw) <= limit else raw[:limit] + "...(truncated)"
    return " body=" + body.replace("\n", " ")


def http_request(opener, method, url, timeout, headers=None, body=None,
                 log_body=None) -> HttpResult:
    """Выполнить HTTP-запрос через переданный opener.

    Сетевые ошибки (URLError без кода, таймауты) пробрасываются наружу, чтобы
    вызывающий код мог обработать недоступность BMC (например, ребут при
    обновлении). HTTP-ответы (включая 4xx/5xx) возвращаются как HttpResult.
    Заголовки (в т.ч. Authorization) не логируются; секреты в теле редактируются
    через параметр log_body.
    """
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)

    shown = log_body if log_body is not None else (
        json.dumps(body, ensure_ascii=False) if body is not None else "")
    log.info("--> %s %s%s", method, url, (" body=" + shown) if shown else "")

    try:
        resp = opener.open(req, timeout=timeout)
        status = resp.getcode()
        raw = resp.read().decode("utf-8", "replace")
        resp.close()
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read().decode("utf-8", "replace")

    parsed = None
    if raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None

    log.info("<-- %s %s (%d)%s", method, url, status, _fmt_body(raw))
    return HttpResult(status, parsed, raw)


def make_ssl_context() -> ssl.SSLContext:
    """Контекст без проверки сертификата.

    На оборудовании используется CA, доверенный внутри ОС, но на части устройств
    встречаются ошибки применения сертификата, поэтому проверка отключается
    безусловно (по согласованию). Никаких TLS-флагов утилита не предоставляет.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    log.warning("TLS: проверка сертификата BMC отключена (так задумано)")
    return ctx


# --------------------------------------------------------------------------- #
# Redfish-клиент (Basic auth)
# --------------------------------------------------------------------------- #

class RedfishClient:
    def __init__(self, host, user, password, ssl_ctx, timeout=30):
        self.base = "https://%s" % host
        self.timeout = timeout
        token = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")
        self.headers = {"Authorization": "Basic " + token}
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx))

    def _req(self, method, path, body=None, log_body=None) -> HttpResult:
        return http_request(self.opener, method, self.base + path, self.timeout,
                            headers=self.headers, body=body, log_body=log_body)

    def get_system(self) -> dict:
        r = self._req("GET", "/redfish/v1/Systems/system")
        if r.status == 401:
            raise UpdaterError("Ошибка авторизации Redfish (401): проверьте --login/--password")
        if r.status != 200:
            raise UpdaterError("Не удалось получить /redfish/v1/Systems/system (HTTP %d)" % r.status)
        return r.data or {}

    def get_firmware_inventory(self, member) -> Optional[dict]:
        r = self._req("GET", "/redfish/v1/UpdateService/FirmwareInventory/%s" % member)
        if r.status != 200:
            log.warning("Инвентарь прошивки '%s' недоступен (HTTP %d)", member, r.status)
            return None
        return r.data

    def simple_update(self, image_uri) -> HttpResult:
        body = {"ImageURI": image_uri, "TransferProtocol": "HTTP"}
        r = self._req("POST",
                      "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate",
                      body=body)
        if r.status not in (200, 202):
            raise UpdaterError("SimpleUpdate отклонён (HTTP %d): %s" % (r.status, r.raw[:300]))
        return r

    def reset_system(self, reset_type) -> HttpResult:
        body = {"ResetType": reset_type}
        r = self._req("POST",
                      "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset",
                      body=body)
        if r.status not in (200, 202, 204):
            raise UpdaterError("Reset (%s) отклонён (HTTP %d): %s"
                               % (reset_type, r.status, r.raw[:300]))
        return r


# --------------------------------------------------------------------------- #
# Legacy REST OpenBMC-клиент (cookie-сессия)
# --------------------------------------------------------------------------- #

class OpenBmcRestClient:
    def __init__(self, host, user, password, ssl_ctx, timeout=30):
        self.base = "https://%s" % host
        self.user = user
        self.password = password
        self.timeout = timeout
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx),
            urllib.request.HTTPCookieProcessor(self.cookies))

    def login(self):
        body = {"data": [self.user, self.password]}
        r = http_request(self.opener, "POST", self.base + "/login", self.timeout,
                         body=body, log_body='{"data": ["%s", "***"]}' % self.user)
        ok = r.status == 200 and (not isinstance(r.data, dict) or r.data.get("status") == "ok")
        if not ok:
            raise UpdaterError("Логин в legacy REST не удался (HTTP %d): %s"
                               % (r.status, r.raw[:300]))
        log.info("Legacy REST: cookie-сессия установлена")

    def _get(self, path) -> HttpResult:
        return http_request(self.opener, "GET", self.base + path, self.timeout)

    def list_software(self) -> Set[str]:
        """Множество id software-объектов из /xyz/openbmc_project/software/."""
        r = self._get("/xyz/openbmc_project/software/")
        ids = set()  # type: Set[str]
        if r.status == 200 and isinstance(r.data, dict):
            for entry in r.data.get("data", []) or []:
                if isinstance(entry, str):
                    ids.add(entry.rstrip("/").rsplit("/", 1)[-1])
        return ids

    def get_software(self, sid) -> Optional[dict]:
        r = self._get("/xyz/openbmc_project/software/%s" % sid)
        if r.status == 200 and isinstance(r.data, dict):
            return r.data.get("data", {})
        return None

    def set_requested_activation(self, sid) -> HttpResult:
        url = self.base + "/xyz/openbmc_project/software/%s/attr/RequestedActivation" % sid
        r = http_request(self.opener, "PUT", url, self.timeout,
                         body={"data": REQ_ACT_ACTIVE})
        if r.status != 200:
            raise UpdaterError("Не удалось задать RequestedActivation для %s (HTTP %d): %s"
                               % (sid, r.status, r.raw[:300]))
        return r


def reconnect_rest(rest: OpenBmcRestClient) -> bool:
    try:
        rest.login()
        return True
    except (UpdaterError, urllib.error.URLError, OSError) as e:
        log.debug("Переподключение REST пока не удалось: %s", e)
        return False


# --------------------------------------------------------------------------- #
# HTTP-сервер раздачи образа (только выбранные файлы)
# --------------------------------------------------------------------------- #

class _FirmwareHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    served_files = {}  # type: Dict[str, str]   # переопределяется фабрикой

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        filepath = self.served_files.get(path)
        if not filepath or not os.path.isfile(filepath):
            self.send_error(404, "Not Found")
            log.warning("HTTP-сервер: 404 для %s от %s", self.path, self.client_address[0])
            return
        try:
            size = os.path.getsize(filepath)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Connection", "close")
            self.end_headers()
            with open(filepath, "rb") as f:
                shutil.copyfileobj(f, self.wfile)
            log.info("HTTP-сервер: отдан %s (%d байт) клиенту %s",
                     path, size, self.client_address[0])
        except (BrokenPipeError, ConnectionResetError) as e:
            log.warning("HTTP-сервер: соединение прервано при отдаче %s: %s", path, e)

    def log_message(self, fmt, *args):
        log.debug("HTTP-сервер: " + fmt, *args)


class FirmwareHttpServer:
    def __init__(self, bind_host, port, served_files):
        handler = type("BoundFirmwareHandler", (_FirmwareHandler,),
                       {"served_files": served_files})
        try:
            self.httpd = http.server.ThreadingHTTPServer((bind_host, port), handler)
        except PermissionError:
            raise UpdaterError("Нет прав на порт %d. Запустите от root (sudo) "
                               "или укажите непривилегированный --http-port." % port)
        except OSError as e:
            raise UpdaterError("Не удалось открыть порт %d: %s "
                               "(возможно, порт уже занят)." % (port, e))
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       name="fw-http", daemon=True)

    def start(self):
        self.thread.start()
        log.info("HTTP-сервер запущен на %s:%d", *self.httpd.server_address)

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.thread.join(timeout=5)
            log.info("HTTP-сервер остановлен")
        except Exception as e:  # noqa: BLE001 — финальная уборка не должна падать
            log.warning("Ошибка при остановке HTTP-сервера: %s", e)


# --------------------------------------------------------------------------- #
# Вспомогательные функции
# --------------------------------------------------------------------------- #

def detect_local_ip(host, port=443) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    except OSError as e:
        raise UpdaterError("Не удалось автоопределить локальный IP для ImageURI (%s). "
                           "Укажите его явно через --advertise-ip." % e)
    finally:
        s.close()


def resolve_image(subdir) -> str:
    d = os.path.join(FIRMWARE_DIR, subdir)
    if not os.path.isdir(d):
        raise UpdaterError("Каталог прошивки не найден: %s" % d)
    files = [f for f in sorted(os.listdir(d))
             if os.path.isfile(os.path.join(d, f)) and not f.startswith(".")]
    if not files:
        raise UpdaterError("В каталоге %s нет файла образа прошивки." % d)
    if len(files) > 1:
        raise UpdaterError("В каталоге %s более одного файла, ожидается ровно один образ: %s"
                           % (d, ", ".join(files)))
    return os.path.join(d, files[0])


# --------------------------------------------------------------------------- #
# Логика обновления одного компонента
# --------------------------------------------------------------------------- #

def wait_for_ready_image(rest, before_ids, expected_purpose, timeout) -> str:
    """Дождаться появления нового software-объекта в состоянии Ready с нужным Purpose."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            current = rest.list_software()
        except (urllib.error.URLError, OSError) as e:
            log.warning("Опрос списка software прерван (%s), повтор...", e)
            time.sleep(2)
            continue
        for sid in (current - before_ids):
            info = rest.get_software(sid)
            if not info:
                continue
            if info.get("Purpose") == expected_purpose and info.get("Activation") == ACT_READY:
                return sid
        time.sleep(2)
    raise UpdaterError("Таймаут ожидания готового образа (Purpose=%s) за %d c."
                       % (expected_purpose, timeout))


def wait_for_active(rest, sid, comp_name, timeout):
    """Опрос статуса активации раз в секунду до Activations.Active.

    Толерантно к обрывам связи: при обновлении BMC соединение может временно
    пропадать (ребут BMC) — ошибки сети не считаются фатальными, выполняется
    попытка переустановить cookie-сессию, опрос продолжается до таймаута.
    """
    deadline = time.time() + timeout
    last_progress = None
    while time.time() < deadline:
        try:
            info = rest.get_software(sid)
        except (urllib.error.URLError, OSError) as e:
            log.warning("%s: опрос активации прерван (%s) — возможно, BMC перезагружается, ждём...",
                        comp_name, e)
            reconnect_rest(rest)
            time.sleep(5)
            continue
        if info is None:
            time.sleep(1)
            continue
        activation = info.get("Activation", "")
        progress = info.get("Progress")
        if progress is not None and progress != last_progress:
            log.info("%s: прогресс активации %s%%", comp_name, progress)
            last_progress = progress
        if activation == ACT_ACTIVE:
            log.info("%s: активация завершена (Active)", comp_name)
            return
        if activation == ACT_FAILED:
            raise UpdaterError("%s: активация завершилась ошибкой (Failed)." % comp_name)
        time.sleep(1)
    raise UpdaterError("%s: таймаут ожидания состояния Active за %d c." % (comp_name, timeout))


def update_component(redfish, rest, comp_name, expected_purpose, image_path,
                     advertise_url, download_timeout, activation_timeout, dry_run):
    log.info("=== Обновление: %s ===", comp_name)
    image_name = os.path.basename(image_path)
    image_uri = "%s/%s" % (advertise_url, image_name)

    before_ids = rest.list_software()
    log.info("%s: software-объектов до запуска: %d", comp_name, len(before_ids))

    if dry_run:
        log.info("[dry-run] %s: пропуск SimpleUpdate/активации (ImageURI был бы %s)",
                 comp_name, image_uri)
        return

    redfish.simple_update(image_uri)
    log.info("%s: SimpleUpdate инициирован, ImageURI=%s", comp_name, image_uri)

    sid = wait_for_ready_image(rest, before_ids, expected_purpose, download_timeout)
    info = rest.get_software(sid) or {}
    log.info("%s: образ готов, id=%s, version=%s", comp_name, sid, info.get("Version"))

    rest.set_requested_activation(sid)
    log.info("%s: запрошена активация образа %s", comp_name, sid)

    wait_for_active(rest, sid, comp_name, activation_timeout)
    log.info("=== %s: обновление завершено ===", comp_name)


# --------------------------------------------------------------------------- #
# Сбор информации и сводка
# --------------------------------------------------------------------------- #

def collect_info(redfish) -> dict:
    info = {}
    sysd = redfish.get_system()
    info["PowerState"] = sysd.get("PowerState")
    info["SerialNumber"] = sysd.get("SerialNumber")
    info["Model"] = sysd.get("Model")
    info["Manufacturer"] = sysd.get("Manufacturer")
    info["Status"] = sysd.get("Status")
    info["MemorySummary"] = sysd.get("MemorySummary")
    info["ProcessorSummary"] = sysd.get("ProcessorSummary")
    bios = redfish.get_firmware_inventory(FW_INV_BIOS) or {}
    bmc = redfish.get_firmware_inventory(FW_INV_BMC) or {}
    info["bios_version"] = bios.get("Version")
    info["bios_status"] = bios.get("Status")
    info["bmc_version"] = bmc.get("Version")
    info["bmc_status"] = bmc.get("Status")
    return info


def _health(status) -> str:
    if isinstance(status, dict):
        return "State=%s Health=%s" % (status.get("State"), status.get("Health"))
    return str(status)


def print_summary(before, after):
    lines = []
    lines.append("")
    lines.append("=" * 64)
    lines.append("ИТОГОВАЯ СВОДКА")
    lines.append("=" * 64)
    lines.append("Сервер:        %s %s" % (after.get("Manufacturer") or before.get("Manufacturer") or "",
                                           after.get("Model") or before.get("Model") or ""))
    lines.append("SerialNumber:  %s" % (after.get("SerialNumber") or before.get("SerialNumber")))
    proc = after.get("ProcessorSummary") or {}
    mem = after.get("MemorySummary") or {}
    lines.append("CPU:           Count=%s Model=%s" % (proc.get("Count"), proc.get("Model")))
    lines.append("RAM:           TotalSystemMemoryGiB=%s" % (mem.get("TotalSystemMemoryGiB")))
    lines.append("Status:        %s" % _health(after.get("Status")))
    lines.append("PowerState:    %s -> %s" % (before.get("PowerState"), after.get("PowerState")))
    lines.append("-" * 64)
    lines.append("Прошивка   | Версия ДО                | Версия ПОСЛЕ")
    lines.append("-" * 64)
    lines.append("BMC        | %-24s | %s" % (before.get("bmc_version"), after.get("bmc_version")))
    lines.append("UEFI/BIOS  | %-24s | %s" % (before.get("bios_version"), after.get("bios_version")))
    lines.append("=" * 64)
    text = "\n".join(lines)
    # Выводим напрямую в stdout (читаемая сводка) и дублируем в лог-файл.
    print(text)
    log.info("Сводка по завершении:\n%s", text)


# --------------------------------------------------------------------------- #
# CLI / оркестрация
# --------------------------------------------------------------------------- #

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="updater.py",
        description="Обновление прошивок BMC/UEFI сервера YADRO Vegman Rx20 (G1-3).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--host", required=True, help="FQDN или IP-адрес BMC сервера.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true", help="Обновить и BMC, и UEFI.")
    g.add_argument("--bmc", action="store_true", help="Обновить только BMC.")
    g.add_argument("--uefi", action="store_true", help="Обновить только UEFI.")
    p.add_argument("--login", required=True, help="Имя пользователя BMC (например, admin).")
    p.add_argument("--password", required=True, help="Пароль пользователя BMC.")
    p.add_argument("--no-autoboot", action="store_true",
                   help="НЕ включать сервер после обновления (по умолчанию включается).")
    p.add_argument("--log-file", default="logs.txt", help="Путь к файлу журнала.")
    p.add_argument("--http-port", type=int, default=80,
                   help="Порт HTTP-сервера раздачи образа.")
    p.add_argument("--advertise-ip", default=None,
                   help="IP для ImageURI (адрес, по которому BMC скачает образ). "
                        "По умолчанию определяется автоматически.")
    p.add_argument("--download-timeout", type=int, default=600,
                   help="Таймаут ожидания готовности образа, c.")
    p.add_argument("--activation-timeout", type=int, default=1800,
                   help="Таймаут ожидания завершения активации, c.")
    p.add_argument("--dry-run", action="store_true",
                   help="Только сбор информации и раздача образа, без обновления и reset.")
    return p.parse_args(argv)


def setup_logging(log_file):
    log.setLevel(logging.DEBUG)
    log.handlers = []
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(ch)


def run(args) -> int:
    do_bmc = args.all or args.bmc
    do_uefi = args.all or args.uefi

    ssl_ctx = make_ssl_context()
    redfish = RedfishClient(args.host, args.login, args.password, ssl_ctx)

    # Шаг 3 (с правкой): сбор инфо «до» и проверка питания (сервер должен быть Off).
    log.info("Сбор информации о сервере (состояние «до»)...")
    before = collect_info(redfish)
    log.info("PowerState=%s, Serial=%s, BMC=%s, BIOS=%s",
             before.get("PowerState"), before.get("SerialNumber"),
             before.get("bmc_version"), before.get("bios_version"))
    if before.get("PowerState") != "Off":
        raise UpdaterError("Сервер должен быть ВЫКЛЮЧЕН перед обновлением "
                           "(PowerState=Off), сейчас: %s." % before.get("PowerState"))

    # Подготовка образов и адреса раздачи.
    served_files = {}  # type: Dict[str, str]
    bmc_image = uefi_image = None
    if do_bmc:
        bmc_image = resolve_image(BMC_SUBDIR)
        served_files["/" + os.path.basename(bmc_image)] = bmc_image
        log.info("Образ BMC: %s", bmc_image)
    if do_uefi:
        uefi_image = resolve_image(UEFI_SUBDIR)
        served_files["/" + os.path.basename(uefi_image)] = uefi_image
        log.info("Образ UEFI: %s", uefi_image)

    advertise_ip = args.advertise_ip or detect_local_ip(args.host)
    advertise_url = "http://%s:%d" % (advertise_ip, args.http_port)
    log.info("Адрес раздачи образа: %s", advertise_url)

    # Шаг 2: HTTP-сервер раздачи образа.
    server = FirmwareHttpServer("0.0.0.0", args.http_port, served_files)
    server.start()

    rest = OpenBmcRestClient(args.host, args.login, args.password, ssl_ctx)
    updated = False
    try:
        rest.login()

        # Шаг 4: BMC, затем шаг 5: UEFI.
        if do_bmc:
            update_component(redfish, rest, "BMC", PURPOSE_BMC, bmc_image,
                             advertise_url, args.download_timeout,
                             args.activation_timeout, args.dry_run)
            updated = updated or not args.dry_run
        if do_uefi:
            update_component(redfish, rest, "UEFI", PURPOSE_HOST, uefi_image,
                             advertise_url, args.download_timeout,
                             args.activation_timeout, args.dry_run)
            updated = updated or not args.dry_run

        # Шаг 6: включение сервера (если обновление выполнено и не задан --no-autoboot).
        if updated and not args.no_autoboot:
            log.info("Включение сервера (ResetType=On)...")
            redfish.reset_system("On")
        elif args.no_autoboot:
            log.info("Флаг --no-autoboot: сервер не включается.")

        # Шаг 8: сбор инфо «после» и сводка.
        log.info("Сбор информации о сервере (состояние «после»)...")
        after = collect_info(redfish)
        print_summary(before, after)
    finally:
        server.stop()

    return 0


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_logging(args.log_file)
    log.info("Запуск утилиты обновления прошивок YADRO Vegman Rx20. host=%s, режим=%s%s",
             args.host,
             "all" if args.all else ("bmc" if args.bmc else "uefi"),
             " [dry-run]" if args.dry_run else "")
    try:
        rc = run(args)
        log.info("Готово. Код возврата: %d", rc)
        return rc
    except UpdaterError as e:
        log.error("Ошибка: %s", e)
        return 2
    except KeyboardInterrupt:
        log.warning("Прервано пользователем (Ctrl+C).")
        return 130
    except Exception as e:  # noqa: BLE001 — логируем любую непредвиденную ошибку
        log.exception("Непредвиденная ошибка: %s", e)
        return 1
    finally:
        logging.shutdown()


if __name__ == "__main__":
    sys.exit(main())

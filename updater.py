#!/usr/bin/env python3
"""Утилита обновления прошивок BMC/UEFI сервера YADRO Vegman Rx20 (G1-3).

Платформа на базе OpenBMC. Утилита работает только по Redfish (HTTPS, Basic auth):
  * доставка образа — HTTP-push: POST бинарника образа в HttpPushUri
    (/redfish/v1/UpdateService, Content-Type: application/octet-stream); BMC принимает образ
    и активирует его, но НЕ перезагружается автоматически;
  * отслеживание установки — Redfish TaskService (опрос Task до Completed) с подтверждением
    по FirmwareInventory (смена версии активного образа);
  * завершение — включение хоста (ComputerSystem.Reset=On, если не задан --no-autoboot) и
    ОБЯЗАТЕЛЬНАЯ перезагрузка BMC (Manager.Reset) после его обновления: без ребута ломается
    провижининг ресурсов UEFI и обмен FRU-данными. При --all порядок: сначала UEFI, затем BMC.

Модель pull (SimpleUpdate с ImageURI) не используется: на этой платформе SimpleUpdate
принимает только TransferProtocol=TFTP, недоступный по сети (из BMC открыты только TCP
80/443/22, TFTP — это UDP/69). Поэтому образ заливается напрямую по уже доступному каналу
оператор→BMC (443). Локальный HTTP-сервер и обратный доступ BMC→оператор не нужны.

Только стандартная библиотека Python 3.9+. Без внешних зависимостей.
"""

import argparse
import base64
import http.client
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Optional

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

# Endpoint HTTP-push по умолчанию (фолбэк, если в UpdateService нет HttpPushUri)
DEFAULT_PUSH_URI = "/redfish/v1/UpdateService"

# Состояния Redfish Task
TASK_DONE = "Completed"
TASK_FAILED = ("Exception", "Killed", "Cancelled")
# всё остальное (New/Pending/Starting/Running/...) трактуем как «ещё идёт».

# Переходные сбои, ожидаемые при ребуте/инициализации BMC — НЕ фатальны. Включают
# http.client.HTTPException (BadStatusLine/IncompleteRead при обрыве на полузагруженном BMC),
# который НЕ является подклассом OSError/URLError и иначе всплыл бы как «Непредвиденная ошибка».
TRANSIENT_NET = (urllib.error.URLError, OSError, http.client.HTTPException)
# Транзиентные HTTP-коды (BMC поднялся, но ещё инициализируется) и 404 на исчезнувшей Task.
TRANSIENT_HTTP = (404, 500, 502, 503, 504)

# После Manager.Reset BMC уходит в перезагрузку не мгновенно (наблюдалась задержка ~30 c).
# Сколько ждём фактического ухода BMC в офлайн, прежде чем ждать его возврата.
BMC_REBOOT_SETTLE_TIMEOUT = 120

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

    Сетевые ошибки (URLError без кода, таймауты, connection refused) пробрасываются
    наружу, чтобы вызывающий код мог обработать недоступность BMC (например, ребут
    при обновлении). HTTP-ответы (включая 4xx/5xx) возвращаются как HttpResult.
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

    def get_system(self, retries=3, retry_delay=5) -> dict:
        """Получить ComputerSystem.

        Терпит кратковременные транзиентные сбои (5xx, обрывы связи) с несколькими повторами:
        сразу после возврата из ребута BMC может ещё «дёргаться» и отвечать 500/503, прежде
        чем стабилизируется. 401 (авторизация) — фатально сразу, повторять смысла нет.
        """
        last = ""
        for attempt in range(1, retries + 1):
            try:
                r = self._req("GET", "/redfish/v1/Systems/system")
            except TRANSIENT_NET as e:
                last = str(e)
                log.info("get_system: транзиентный сбой (%s), попытка %d/%d",
                         last, attempt, retries)
                if attempt < retries:
                    time.sleep(retry_delay)
                continue
            if r.status == 401:
                raise UpdaterError("Ошибка авторизации Redfish (401): проверьте --login/--password")
            if r.status == 200:
                return r.data or {}
            last = "HTTP %d" % r.status
            if r.status in TRANSIENT_HTTP:
                log.info("get_system: %s — BMC ещё инициализируется, попытка %d/%d",
                         last, attempt, retries)
                if attempt < retries:
                    time.sleep(retry_delay)
                continue
            raise UpdaterError("Не удалось получить /redfish/v1/Systems/system (%s)" % last)
        raise UpdaterError("Не удалось получить /redfish/v1/Systems/system (%s)" % last)

    def get_firmware_inventory(self, member) -> Optional[dict]:
        r = self._req("GET", "/redfish/v1/UpdateService/FirmwareInventory/%s" % member)
        if r.status != 200:
            log.warning("Инвентарь прошивки '%s' недоступен (HTTP %d)", member, r.status)
            return None
        return r.data

    def get_ethernet_interface(self, manager="bmc", iface="eth0") -> Optional[dict]:
        r = self._req("GET", "/redfish/v1/Managers/%s/EthernetInterfaces/%s" % (manager, iface))
        if r.status != 200:
            log.warning("EthernetInterface %s/%s недоступен (HTTP %d)", manager, iface, r.status)
            return None
        return r.data

    def get_update_service(self) -> str:
        """Вернуть HttpPushUri из /redfish/v1/UpdateService (фолбэк — стандартный путь)."""
        r = self._req("GET", "/redfish/v1/UpdateService")
        if r.status == 200 and isinstance(r.data, dict):
            uri = r.data.get("HttpPushUri")
            if uri:
                return uri
        log.warning("HttpPushUri не получен (HTTP %d) — используем %s", r.status, DEFAULT_PUSH_URI)
        return DEFAULT_PUSH_URI

    def push_image(self, push_uri, image_path, timeout) -> str:
        """Залить образ HTTP-push'ем в HttpPushUri, вернуть URI созданной Task.

        Образ стримится из файла с ЯВНЫМ Content-Length: иначе urllib переключится на
        Transfer-Encoding: chunked, который BMC может не принять. Тело в лог не пишется.
        """
        size = os.path.getsize(image_path)
        url = self.base + push_uri
        hdrs = dict(self.headers)
        hdrs["Content-Type"] = "application/octet-stream"
        hdrs["Content-Length"] = str(size)
        log.info("--> POST %s (%d байт, %s)", url, size, os.path.basename(image_path))

        with open(image_path, "rb") as f:
            req = urllib.request.Request(url, data=f, method="POST", headers=hdrs)
            try:
                resp = self.opener.open(req, timeout=timeout)
                status = resp.getcode()
                raw = resp.read().decode("utf-8", "replace")
                location = resp.headers.get("Location")
                resp.close()
            except urllib.error.HTTPError as e:
                status = e.code
                raw = e.read().decode("utf-8", "replace")
                location = e.headers.get("Location") if e.headers else None

        log.info("<-- POST %s (%d)%s", url, status, _fmt_body(raw))
        if status not in (200, 202):
            raise UpdaterError("HTTP-push отклонён (HTTP %d): %s" % (status, raw[:300]))

        task_uri = None
        if raw:
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                task_uri = parsed.get("@odata.id")
        if not task_uri and location:
            task_uri = location
        if not task_uri:
            raise UpdaterError("HTTP-push принят (HTTP %d), но в ответе нет ссылки на Task: %s"
                               % (status, raw[:300]))
        return task_uri

    def get_task(self, task_uri) -> HttpResult:
        # task_uri может быть путём (@odata.id) или абсолютным URL (Location).
        url = task_uri if task_uri.startswith("http") else self.base + task_uri
        return http_request(self.opener, "GET", url, self.timeout, headers=self.headers)

    def reset_system(self, reset_type) -> HttpResult:
        body = {"ResetType": reset_type}
        r = self._req("POST",
                      "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset",
                      body=body)
        if r.status not in (200, 202, 204):
            raise UpdaterError("Reset (%s) отклонён (HTTP %d): %s"
                               % (reset_type, r.status, r.raw[:300]))
        return r

    def reset_manager(self, reset_type="GracefulRestart") -> Optional[HttpResult]:
        """Перезагрузить BMC (Manager.Reset).

        BMC может закрыть соединение, начав перезагрузку раньше, чем отдаст ответ — это не
        ошибка, команда уже отправлена (TRANSIENT_NET трактуем как успешную инициацию).
        """
        body = {"ResetType": reset_type}
        try:
            r = self._req("POST",
                          "/redfish/v1/Managers/bmc/Actions/Manager.Reset",
                          body=body)
        except TRANSIENT_NET as e:
            log.info("BMC закрыл соединение при перезагрузке (%s) — reset инициирован", e)
            return None
        if r.status not in (200, 202, 204):
            raise UpdaterError("Перезагрузка BMC (Manager.Reset=%s) отклонена (HTTP %d): %s"
                               % (reset_type, r.status, r.raw[:300]))
        return r

    def wait_online(self, timeout, poll=5) -> dict:
        """Дождаться, пока BMC снова отвечает на Redfish.

        Терпимо к переходным сбоям при ребуте (connection refused, таймауты, обрывы —
        TRANSIENT_NET) и к HTTP 5xx (BMC поднялся, но ещё инициализируется). Возвращает
        System при 200.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = self._req("GET", "/redfish/v1/Systems/system")
            except TRANSIENT_NET as e:
                log.info("Ожидание доступности BMC (%s)...", e)
                time.sleep(poll)
                continue
            if r.status == 200:
                return r.data or {}
            log.info("BMC отвечает HTTP %d — идёт инициализация, ждём...", r.status)
            time.sleep(poll)
        raise UpdaterError("BMC не стал доступен по Redfish за %d c." % timeout)

    def wait_for_reboot(self, timeout, settle_timeout=BMC_REBOOT_SETTLE_TIMEOUT, poll=5) -> dict:
        """Дождаться полного цикла перезагрузки BMC: сначала ухода в офлайн, затем возврата.

        После Manager.Reset BMC уходит в перезагрузку не мгновенно (наблюдалась задержка ~30 c),
        поэтому обычный wait_online может застать ещё «живой» BMC, вернуться преждевременно — и
        тогда последующий сбор данных падает на 5xx уже начавшегося ребута. Поэтому сперва ждём,
        пока BMC перестанет нормально отвечать (ребут начался), и только затем — пока снова не
        поднимется (HTTP 200).
        """
        # Фаза 1: ждём фактического ухода BMC в перезагрузку (обрыв связи или не-200).
        log.info("Ожидание ухода BMC в перезагрузку (до %d c)...", settle_timeout)
        deadline = time.time() + settle_timeout
        went_down = False
        while time.time() < deadline:
            try:
                r = self._req("GET", "/redfish/v1/Systems/system")
            except TRANSIENT_NET as e:
                log.info("BMC начал перезагрузку (%s)", e)
                went_down = True
                break
            if r.status != 200:
                log.info("BMC начал перезагрузку (HTTP %d)", r.status)
                went_down = True
                break
            time.sleep(poll)
        if not went_down:
            log.warning("BMC не ушёл в офлайн за %d c — продолжаем ожидание готовности.",
                        settle_timeout)
        # Фаза 2: ждём стабильного возврата (HTTP 200).
        log.info("Ожидание возврата BMC в строй...")
        return self.wait_online(timeout, poll=poll)


# --------------------------------------------------------------------------- #
# Вспомогательные функции
# --------------------------------------------------------------------------- #

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


def _task_messages(task: dict) -> str:
    out = []
    for m in task.get("Messages") or []:
        if isinstance(m, dict):
            text = m.get("Message") or m.get("MessageId")
            if text:
                out.append(str(text))
    return "; ".join(out)


def _confirm_by_inventory(redfish, comp_name, inv_member, before_version) -> bool:
    """Подтвердить успех по смене версии активного образа в инвентаре Redfish.

    Нужен как фолбэк для BMC: при ApplyTime=Immediate контроллер уходит в ребут, и Task
    после перезагрузки уже недоступна, но новая прошивка уже активна.
    """
    if not before_version:
        return False
    try:
        inv = redfish.get_firmware_inventory(inv_member)
    except TRANSIENT_NET:
        return False
    version = (inv or {}).get("Version")
    if version and version != before_version:
        log.info("%s: успех подтверждён по инвентарю Redfish (Version=%s)", comp_name, version)
        return True
    return False


# --------------------------------------------------------------------------- #
# Логика обновления одного компонента
# --------------------------------------------------------------------------- #

def wait_for_update(redfish, task_uri, comp_name, inv_member, before_version, timeout):
    """Опрос Redfish Task до Completed.

    Толерантно к перезагрузке BMC: при обновлении BMC контроллер уходит в ребут —
    TRANSIENT_NET (включая connection refused и http.client.HTTPException) и транзиентные
    HTTP-коды (5xx, 404 на исчезнувшей задаче) не фатальны. После обрыва успех дополнительно
    подтверждается по версии активного образа в инвентаре Redfish.
    """
    deadline = time.time() + timeout
    last_pct = None
    saw_outage = False
    while time.time() < deadline:
        try:
            r = redfish.get_task(task_uri)
        except TRANSIENT_NET as e:
            saw_outage = True
            log.info("%s: BMC недоступен (%s) — вероятно, перезагрузка, ждём...", comp_name, e)
            if _confirm_by_inventory(redfish, comp_name, inv_member, before_version):
                return
            time.sleep(5)
            continue

        if r.status in TRANSIENT_HTTP:
            saw_outage = True
            log.info("%s: Task недоступна (HTTP %d) — BMC инициализируется/перезагрузка, ждём...",
                     comp_name, r.status)
            if _confirm_by_inventory(redfish, comp_name, inv_member, before_version):
                return
            time.sleep(5)
            continue

        task = r.data if isinstance(r.data, dict) else {}
        state = task.get("TaskState")
        pct = task.get("PercentComplete")
        if pct is not None and pct != last_pct:
            log.info("%s: прогресс задачи %s%%", comp_name, pct)
            last_pct = pct

        if state == TASK_DONE:
            log.info("%s: задача завершена (TaskState=Completed, TaskStatus=%s)",
                     comp_name, task.get("TaskStatus"))
            return
        if state in TASK_FAILED:
            msg = _task_messages(task)
            raise UpdaterError("%s: задача обновления завершилась со статусом %s%s"
                               % (comp_name, state, (": " + msg) if msg else ""))

        # Фолбэк: если успели увидеть обрыв, но задача снова доступна без явного финала —
        # подтверждаем по инвентарю (на случай быстрого ребута).
        if saw_outage and _confirm_by_inventory(redfish, comp_name, inv_member, before_version):
            return
        time.sleep(3)
    raise UpdaterError("%s: таймаут ожидания завершения обновления за %d c." % (comp_name, timeout))


def update_component(redfish, comp_name, inv_member, image_path, push_uri,
                     update_timeout, dry_run):
    log.info("=== Обновление: %s ===", comp_name)
    image_name = os.path.basename(image_path)
    before_version = (redfish.get_firmware_inventory(inv_member) or {}).get("Version")
    log.info("%s: текущая версия в инвентаре: %s", comp_name, before_version)

    if dry_run:
        log.info("[dry-run] %s: пропуск HTTP-push/активации (был бы залит %s в %s)",
                 comp_name, image_name, push_uri)
        return

    task_uri = redfish.push_image(push_uri, image_path, update_timeout)
    log.info("%s: HTTP-push инициирован, задача %s", comp_name, task_uri)

    wait_for_update(redfish, task_uri, comp_name, inv_member, before_version, update_timeout)
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
    eth = redfish.get_ethernet_interface() or {}
    info["fqdn"] = eth.get("FQDN") or eth.get("HostName")
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
    manufacturer = after.get("Manufacturer") or before.get("Manufacturer") or ""
    model = after.get("Model") or before.get("Model") or ""
    proc = after.get("ProcessorSummary") or {}
    mem = after.get("MemorySummary") or {}
    bmc_before, bmc_after = before.get("bmc_version"), after.get("bmc_version")
    bios_before, bios_after = before.get("bios_version"), after.get("bios_version")

    lines = [
        "",
        "=" * 64,
        "ИТОГОВАЯ СВОДКА",
        "=" * 64,
        "Сервер:        %s %s" % (manufacturer, model),
        "FQDN:          %s" % (after.get("fqdn") or before.get("fqdn")),
        "SerialNumber:  %s" % (after.get("SerialNumber") or before.get("SerialNumber")),
        "CPU:           Count=%s Model=%s" % (proc.get("Count"), proc.get("Model")),
        "RAM:           TotalSystemMemoryGiB=%s" % mem.get("TotalSystemMemoryGiB"),
        "Status:        %s" % _health(after.get("Status")),
        "PowerState:    %s -> %s" % (before.get("PowerState"), after.get("PowerState")),
        "-" * 64,
        "Прошивка   | Версия ДО                | Версия ПОСЛЕ",
        "-" * 64,
        "BMC        | %-24s | %s" % (bmc_before, bmc_after),
        "UEFI/BIOS  | %-24s | %s" % (bios_before, bios_after),
        "=" * 64,
    ]
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
    p.add_argument("--update-timeout", type=int, default=1800,
                   help="Таймаут заливки образа (HTTP-push) и его применения/подтверждения, c.")
    p.add_argument("--online-timeout", type=int, default=900,
                   help="Таймаут ожидания возврата BMC в строй после перезагрузки, c.")
    p.add_argument("--dry-run", action="store_true",
                   help="Только сбор информации; без HTTP-push и reset.")
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

    # Сбор инфо «до» и проверка питания (сервер должен быть Off).
    log.info("Сбор информации о сервере (состояние «до»)...")
    before = collect_info(redfish)
    log.info("PowerState=%s, Serial=%s, BMC=%s, BIOS=%s",
             before.get("PowerState"), before.get("SerialNumber"),
             before.get("bmc_version"), before.get("bios_version"))
    if before.get("PowerState") != "Off":
        raise UpdaterError("Сервер должен быть ВЫКЛЮЧЕН перед обновлением "
                           "(PowerState=Off), сейчас: %s." % before.get("PowerState"))

    # Подготовка образов.
    bmc_image = uefi_image = None
    if do_bmc:
        bmc_image = resolve_image(BMC_SUBDIR)
        log.info("Образ BMC: %s", bmc_image)
    if do_uefi:
        uefi_image = resolve_image(UEFI_SUBDIR)
        log.info("Образ UEFI: %s", uefi_image)

    push_uri = redfish.get_update_service()
    log.info("Endpoint HTTP-push: %s", push_uri)

    updated = False

    # Порядок: сначала UEFI, затем BMC. BMC при push активирует образ, но НЕ перезагружается
    # автоматически — ребут BMC выполняется явно в самом конце (см. ниже). Без него ломается
    # провижининг ресурсов UEFI и обмен FRU-данными, поэтому BMC обновляется последним.
    if do_uefi:
        update_component(redfish, "UEFI", FW_INV_BIOS, uefi_image, push_uri,
                         args.update_timeout, args.dry_run)
        updated = updated or not args.dry_run
    if do_bmc:
        update_component(redfish, "BMC", FW_INV_BMC, bmc_image, push_uri,
                         args.update_timeout, args.dry_run)
        updated = updated or not args.dry_run

    if not args.dry_run:
        # Включение сервера (если есть что включать и не задан --no-autoboot).
        if updated and not args.no_autoboot:
            log.info("Включение сервера (ResetType=On)...")
            redfish.reset_system("On")
        elif args.no_autoboot:
            log.info("Флаг --no-autoboot: сервер не включается.")

        # Обязательная перезагрузка BMC после его обновления: образ активирован, но без ребута
        # ломается провижининг UEFI и обмен FRU. Флаг --no-autoboot на это НЕ влияет — он
        # касается только включения хоста. Для --uefi (BMC не обновлялся) ребут не нужен.
        if do_bmc:
            log.info("Перезагрузка BMC (Manager.Reset=GracefulRestart)...")
            redfish.reset_manager("GracefulRestart")
            redfish.wait_for_reboot(args.online_timeout)

    # Диагностика: сбор инфо «после» и сводка.
    log.info("Сбор информации о сервере (состояние «после»)...")
    after = collect_info(redfish)
    print_summary(before, after)

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
    except TRANSIENT_NET as e:
        log.error("Сетевая ошибка (BMC недоступен): %s", e)
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

#!/usr/bin/env python3
import os
import sys
import subprocess
import base64
import re
import syslog
import argparse
import hashlib
import platform

# ==========================================
# Podkop Subscription Updater
# ==========================================

USER_AGENT = "Podkop-Subscription-Updater/1.0"
VALID_PROTOCOLS = ('vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hy2://', 'hysteria2://')
VALID_PTYPES = {'urltest', 'selector'}
VALID_ON_EMPTY = {'all', 'skip'}
VALID_MATCH_MODES = {'ifmatch', 'ifnotmatch'}
LINK_OPTIONS = (
    'list urltest_proxy_links',
    'list selector_proxy_links',
    'option connection_type',
    'option proxy_config_type',
)
CONFIG_RE = re.compile(r"^\s*config\s+\S+\s+['\"]?([a-zA-Z0-9_-]+)")

def setup_syslog():
    syslog.openlog("podkop-updater", syslog.LOG_PID, syslog.LOG_USER)

def log(level, msg):
    print(f"[{level}] {msg}")
    syslog_level = syslog.LOG_WARNING if level in ["ERROR", "WARN"] else syslog.LOG_INFO
    syslog.syslog(syslog_level, f"[{level}] {msg}")

def parse_args():
    parser = argparse.ArgumentParser(description="Обновление подписок для Podkop")
    parser.add_argument('--config', default='/etc/config/podkop', help='Путь к UCI конфигу podkop')
    parser.add_argument('--subs', default='/etc/config/podkop-subs', help='Путь к файлу подписок')
    parser.add_argument('--force', action='store_true', help='Принудительно перезаписать конфиг podkop и перезапустить сервис')
    return parser.parse_args()

def unquote(s):
    """URL-декодер (аналог urllib.unquote)"""
    if '%' not in s:
        return s

    res = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '%' and i + 2 < len(s):
            try:
                res.append(int(s[i+1:i+3], 16))
                i += 3
                continue
            except ValueError:
                pass

        res.extend(s[i].encode('utf-8'))
        i += 1

    return res.decode('utf-8', errors='replace')

def get_mac_address():
    interfaces = ['br-lan', 'eth0', 'eth1', 'lan']
    for iface in interfaces:
        path = f"/sys/class/net/{iface}/address"
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    mac = f.read().strip()
                    if mac and mac != '00:00:00:00:00:00':
                        return mac.replace(':', '').lower()
            except Exception:
                continue
    return "000000000000"

def get_device_model():
    paths = ['/tmp/sysinfo/model', '/proc/device-tree/model']
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    model = f.read().replace('\x00', '').strip()
                    if model:
                        return model
            except Exception:
                continue
    return "Generic OpenWrt Device"

def get_kernel_version():
    return platform.release()

def load_jobs(subs_path):
    if not os.path.exists(subs_path):
        log("ERROR", f"Файл подписок {subs_path} не найден")
        sys.exit(1)

    jobs = {}
    with open(subs_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = [p.strip() for p in line.split('::')]
            if len(parts) != 6:
                log("WARN", f"Строка {line_num}: неверный формат. Ожидается ровно 6 колонок через '::'. Пропуск.")
                continue

            sec_name, url, regex_pattern, match_mode, ptype, on_empty = parts
            sec_name = sec_name.lower()
            match_mode = match_mode.lower()
            ptype = ptype.lower()
            on_empty = on_empty.lower()

            if not sec_name or not url:
                log("WARN", f"Строка {line_num}: отсутствует имя секции или URL. Пропуск.")
                continue

            if match_mode not in VALID_MATCH_MODES:
                log("WARN", f"Строка {line_num}: недопустимый режим '{match_mode}'. Разрешены: {', '.join(VALID_MATCH_MODES)}. Пропуск.")
                continue

            if ptype not in VALID_PTYPES:
                log("WARN", f"Строка {line_num}: недопустимый тип '{ptype}'. Разрешены: {', '.join(VALID_PTYPES)}. Пропуск.")
                continue

            if on_empty not in VALID_ON_EMPTY:
                log("WARN", f"Строка {line_num}: недопустимое действие '{on_empty}'. Разрешены: {', '.join(VALID_ON_EMPTY)}. Пропуск.")
                continue

            regex = None
            if regex_pattern:
                try:
                    regex = re.compile(regex_pattern, re.IGNORECASE)
                except re.error as e:
                    log("WARN", f"Строка {line_num}: некорректное регулярное выражение '{regex_pattern}' ({e}). Пропуск.")
                    continue

            jobs[sec_name] = {
                'url': url,
                'regex': regex,
                'match_mode': match_mode,
                'ptype': ptype,
                'on_empty': on_empty,
                'links': []
            }
    
    return jobs

def fetch_links(jobs, hwid, device_model, kernel_ver):
    links_cache = {}

    for sec, job in jobs.items():
        log("DEBUG", f"--- Обработка секции: [{sec}] ---")
        url = job['url']
        
        try:
            if url in links_cache:
                links_raw = links_cache[url]
            else:
                cmd = ['wget', '-qO-', f'--user-agent={USER_AGENT}']

                cmd.extend(['--header', f'X-HWID: {hwid}'])
                cmd.extend(['--header', 'X-Device-OS: OpenWrt Linux'])
                cmd.extend(['--header', f'X-Device-Model: {device_model}'])
                cmd.extend(['--header', f'X-Ver-OS: {kernel_ver}'])

                cmd.append(url)

                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
                
                if result.returncode != 0 or not result.stdout:
                    log("ERROR", f"[{sec}]: Ошибка скачивания -> {result.stderr.strip() or 'Пустой ответ'}")
                    continue
                
                payload = result.stdout.strip()
                payload += '=' * (-len(payload) % 4)
                
                try:
                    decoded_text = base64.b64decode(payload).decode('utf-8')
                except Exception:
                    log("ERROR", f"[{sec}]: Ответ не является валидным Base64")
                    continue

                links_raw = [ln.strip() for ln in decoded_text.splitlines() if ln.strip().startswith(VALID_PROTOCOLS)]
                
                if not links_raw:
                    log("WARN", f"[{sec}]: Не найдено ссылок с поддерживаемыми протоколами.")
                    continue
                
                links_cache[url] = links_raw

            filtered_links = []
            for ln in links_raw:
                if job['regex']:
                    raw_tag = ln.split('#', 1)[1] if '#' in ln else ln
                    tag = unquote(raw_tag)

                    is_match = bool(job['regex'].search(tag))
                    if (job['match_mode'] == 'ifmatch' and is_match) or \
                       (job['match_mode'] == 'ifnotmatch' and not is_match):
                        filtered_links.append(ln)
                else:
                    filtered_links.append(ln)

            if not filtered_links:
                if job['on_empty'] == 'all':
                    log("INFO", f"[{sec}]: По фильтру пусто, используются все ссылки (on_empty=all).")
                    filtered_links = links_raw
                else:
                    log("INFO", f"[{sec}]: По фильтру пусто, секция пропущена (on_empty=skip).")
                    continue

            job['links'] = sorted(list(set(filtered_links)))
            log("INFO", f"[{sec}]: Успешно загружено ссылок: {len(job['links'])}")

        except subprocess.TimeoutExpired:
            log("ERROR", f"[{sec}]: Превышено время ожидания ответа сервера (15с).")
        except Exception as e:
            log("ERROR", f"[{sec}]: Непредвиденная ошибка -> {e}")

def update_uci_config(config_path, jobs):
    if not os.path.exists(config_path):
        log("ERROR", f"Конфиг {config_path} не найден. Настройте Podkop в интерфейсе.")
        sys.exit(1)

    with open(config_path, 'r', encoding='utf-8') as f:
        old_lines = f.readlines()

    out_lines = []
    current_sec = None
    found_sections = set()
    skip_multiline = False

    def flush_section(sec):
        if sec in jobs:
            ptype = jobs[sec]['ptype']
            out_lines.append(f"\toption connection_type 'proxy'\n")
            out_lines.append(f"\toption proxy_config_type '{ptype}'\n")
            for link in jobs[sec]['links']:
                link = link.replace("'", "'\\''") # экранирование кавычки в UCI
                out_lines.append(f"\tlist {ptype}_proxy_links '{link}'\n")

    for line in old_lines:
        m = CONFIG_RE.match(line)
        if m:
            flush_section(current_sec)

            current_sec = m.group(1).lower()
            if current_sec in jobs:
                found_sections.add(current_sec)

            out_lines.append(line)
            skip_multiline = False
            continue

        if current_sec in jobs:
            sline = line.strip()
            quotes = sline.replace("\\'", "").count("'") # без учета экранированных кавычек

            if skip_multiline:
                if quotes % 2 != 0:
                    skip_multiline = False
                continue

            if sline.startswith(LINK_OPTIONS + ('option proxy_string',)):
                if quotes % 2 != 0:
                    skip_multiline = True
                continue

        out_lines.append(line)

    flush_section(current_sec)

    for sec in jobs:
        if sec not in found_sections:
            log("WARN", f"Секция '{sec}' успешно скачана, но отсутствует в {config_path} (ожидается config proxy '{sec}')")

    new_content = "".join(out_lines)
    old_content = "".join(old_lines)

    return old_content, new_content

def links_state(text, jobs):
    """Набор строк со ссылками и их настройками в управляемых секциях (без учета порядка)"""
    state = set()
    sec = None
    for line in text.splitlines():
        m = CONFIG_RE.match(line)
        if m:
            sec = m.group(1).lower()
            continue

        line = line.strip()
        if sec in jobs and line.startswith(LINK_OPTIONS):
            line = re.sub(r'sid=[a-zA-Z0-9]+', '', line) # ignore dynamic sid
            line = re.sub(r"#[^']*", '', line)          # ignore link comments
            state.add((sec, line))
    return state

def write_config(path, content):
    """Атомарная запись: сначала во временный файл, затем подмена оригинала"""
    tmp = os.path.join(os.path.dirname(path), f".{os.path.basename(path)}.tmp")
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, os.stat(path).st_mode & 0o777)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise

def main():
    setup_syslog()
    args = parse_args()
    
    log("INFO", "=== ЗАПУСК ОБНОВЛЕНИЯ ПОДПИСОК ===")

    mac = get_mac_address()
    device_model = get_device_model()
    kernel_ver = get_kernel_version()    
    raw_hwid_str = f"{mac}{device_model}"
    hwid = hashlib.md5(raw_hwid_str.encode('utf-8')).hexdigest()[:16]
    log("INFO", f"Устройство: {device_model} (Ядро: {kernel_ver})")
    log("INFO", f"Сгенерирован X-HWID: {hwid}")
    
    jobs = load_jobs(args.subs)
    if not jobs:
        log("ERROR", "Не найдено ни одной валидной подписки. Выход.")
        sys.exit(1)

    fetch_links(jobs, hwid, device_model, kernel_ver)
    active_jobs = {sec: job for sec, job in jobs.items() if job['links']}

    old_content, new_content = update_uci_config(args.config, active_jobs)
    is_content_changed = links_state(old_content, active_jobs) != links_state(new_content, active_jobs)

    # Проверяем изменения, но учитываем флаг --force
    if not args.force and not is_content_changed:
        log("INFO", "Изменений не обнаружено. Перезапуск не требуется.")
    else:
        if args.force and not is_content_changed:
            log("INFO", "Изменений не обнаружено, но указан флаг --force. Принудительная перезапись и перезапуск...")
        else:
            log("INFO", "Применение обновлений и перезапуск Podkop...")

        try:
            write_config(args.config, new_content)
        except Exception as e:
            log("ERROR", f"Ошибка при сохранении конфига: {e}")
            sys.exit(1)

        os.system("/etc/init.d/podkop restart")
        log("INFO", "Успешно завершено.")

if __name__ == "__main__":
    main()

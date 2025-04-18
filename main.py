import argparse
import logging
import paramiko
import socket
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich import box
import re

# --- Настройка логгирования с категорией ---
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)
log_file = log_dir / "install.log"

class CategoryAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return f'[{self.extra["category"]}] {msg}', kwargs

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

base_logger = logging.getLogger("installer")
log_connect = CategoryAdapter(base_logger, {"category": "connect"})
log_install = CategoryAdapter(base_logger, {"category": "install"})
log_status = CategoryAdapter(base_logger, {"category": "status"})
log_error = CategoryAdapter(base_logger, {"category": "error"})

console = Console()

# --- Проверка доступности по порту ---
def is_ssh_open(host, port=22):
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except:
        return False

# --- Упрощенное подключение по ssh ---
def connect_ssh(host, key_path, user="root"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, username=user, key_filename=key_path, timeout=5)
        return ssh
    except Exception as e:
        log_connect.error(f"Не удалось подключиться к {host}: {e}")
        return None

# --- Получение простой метрики загрузки ---
def get_server_status(ssh):
    stdin, stdout, stderr = ssh.exec_command("grep 'cpu ' /proc/stat && free -m")
    cpu_line = stdout.readline()
    cpu_vals = list(map(int, cpu_line.strip().split()[1:]))
    idle_time = cpu_vals[3]
    total_time = sum(cpu_vals)
    cpu_usage = 100 * (1 - idle_time / total_time)

    mem_line = [line for line in stdout.readlines() if "Mem:" in line][0]
    mem_vals = list(map(int, mem_line.strip().split()[1:]))
    mem_usage = 100 * mem_vals[1] / mem_vals[0]
    return cpu_usage, mem_usage

# --- Определение дистрибутива Linux ---
def get_linux_distribution(ssh):
    stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release")
    output = stdout.read().decode()
    if "debian" in output.lower() or "ubuntu" in output.lower():
        return "debian"
    elif "almalinux" in output.lower() or "centos" in output.lower():
        return "alma"
    return None

def install_postgresql_debian(ssh):
    commands = [
        "sudo apt-get install -y lsb-release",
        "sudo sh -c 'echo \"deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main\" > /etc/apt/sources.list.d/pgdg.list'",
        "wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -",
        "sudo apt-get update",
        "locale",
        "export LC_CTYPE=ru_RU.UTF8",
        "export LC_COLLATE=ru_RU.UTF8",
        "locale -a | grep ru_RU",
        "sudo locale-gen ru_RU.UTF8",
        "sudo apt-get install -y postgresql-17",
        "sudo -u postgres psql -c 'SELECT version();'"
    ]
    execute_commands(ssh, commands)

# --- Установка PostgreSQL на AlmaLinux/CentOS ---
def install_postgresql_alma(ssh):
    commands = [
        "sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm",
        "sudo dnf install -y postgresql17-server",
        "sudo /usr/pgsql-17/bin/postgresql-17-setup initdb",
        "sudo systemctl enable postgresql-17",
        "sudo systemctl start postgresql-17",
    ]
    execute_commands(ssh, commands)

# --- Универсальная функция выполнения команд ---
def execute_commands(ssh, commands):
    for cmd in commands:
        log_install.info(f"Выполняется команда: {cmd}")
        console.print(f"[blue]→ {cmd}[/blue]")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_status = stdout.channel.recv_exit_status()

        if output.strip():
            console.print(f"[green]{output.strip()}[/green]")
            log_install.info(output.strip())
        if error.strip():
            console.print(f"[red]{error.strip()}[/red]")
            log_error.error(error.strip())

        if exit_status != 0:
            log_error.error(f"Команда завершилась с кодом {exit_status}")

# --- Настройка PostgreSQL для внешних соединений и пользователя student ---
def configure_postgresql_access(ssh, allowed_ip):
    commands = [
        # Разрешаем внешние подключения
        r"sudo sed -i 's/#listen_addresses = \'localhost\'/listen_addresses = \'*\'/g' /etc/postgresql/17/main/postgresql.conf"
        # Добавляем правило в pg_hba.conf для подключения пользователя student только с указанного IP
        f"echo \"host    all             student         {allowed_ip}/32         md5\" | sudo tee -a /etc/postgresql/17/main/pg_hba.conf || echo \"host    all             student         {allowed_ip}/32         md5\" | sudo tee -a /var/lib/pgsql/17/data/pg_hba.conf",

        # Создаём пользователя student (если не существует)
        "sudo -u postgres psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='student'\" | grep -q 1 || sudo -u postgres psql -c \"CREATE ROLE student LOGIN PASSWORD 'student';\"",

        # Перезапускаем PostgreSQL
        "sudo systemctl restart postgresql"
    ]
    execute_commands(ssh, commands)

# --- Проверка подключения пользователя student со второго сервера ---
def test_student_connection(host, key_path, db_host):
    ssh = connect_ssh(host, key_path)
    if not ssh:
        console.print(f"[red]Не удалось подключиться ко второму серверу ({host}) для теста подключения.[/red]")
        log_error.error(f"Проверка подключения student: SSH к {host} не удался")
        return

    test_cmd = f"psql -h {db_host} -U student -c 'SELECT 1;'"
    full_cmd = f"PGPASSWORD=student {test_cmd}"

    console.print(f"[cyan]Проверка подключения от пользователя student к {db_host} со второго сервера...[/cyan]")
    log_install.info(f"Проверка подключения student@{db_host} с {host}")

    stdin, stdout, stderr = ssh.exec_command(full_cmd)
    output = stdout.read().decode()
    error = stderr.read().decode()
    exit_code = stdout.channel.recv_exit_status()

    if exit_code == 0:
        console.print(f"[bold green]Проверка подключения прошла успешно:[/bold green]{output}")
        log_install.info("student SELECT 1 выполнено успешно")
    else:
        console.print(f"[bold red]Ошибка подключения или выполнения запроса:[/bold red]{error}")
        log_error.error(f"Ошибка подключения student: {error.strip()}")

    ssh.close()

# --- основной запуск ---
def main():
    parser = argparse.ArgumentParser(description="PostgreSQL Auto Installer")
    parser.add_argument("--hosts", required=True, help="Адреса серверов через запятую")
    parser.add_argument("--key", required=True, help="Путь к приватному SSH ключу")
    parser.add_argument("--quiet", action="store_true", help="Отключить приветствие")
    parser.add_argument("--debug", action="store_true", help="Включить отладочный вывод")
    args = parser.parse_args()

    if args.debug:
        base_logger.setLevel(logging.DEBUG)

    log_connect.info(f"Введены хосты: {args.hosts}")
    log_connect.info(f"Путь к ключу: {args.key}")

    if not args.quiet:
        console.print(Panel("[bold cyan]PostgreSQL Auto Installer[/bold cyan]\nВыбор наименее загруженного сервера и установка PostgreSQL", box=box.ROUNDED))

    hosts = args.hosts.split(",")
    key_path = args.key

    available_hosts = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
        task = progress.add_task("Проверка доступности хостов...", total=len(hosts))
        for host in hosts:
            if is_ssh_open(host):
                console.print(f"\n[green]{host} доступен по SSH[/green]")
                available_hosts.append(host)
                log_connect.info(f"{host} доступен по SSH")
            else:
                console.print(f"\n[red]{host} недоступен[/red]")
                log_connect.warning(f"{host} недоступен")
            progress.update(task, advance=1)

    if not available_hosts:
        console.print("[bold red]Нет доступных серверов. Завершение.[/bold red]")
        log_error.warning("Нет доступных серверов")
        return

    stats = {}
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
        task = progress.add_task("Получение статуса серверов...", total=len(available_hosts))
        for host in available_hosts:
            ssh = connect_ssh(host, key_path)
            if ssh:
                cpu, mem = get_server_status(ssh)
                stats[host] = cpu + mem
                console.print(f"\n[bold yellow]Статистика {host}:[/bold yellow] CPU: {cpu:.2f}%, RAM: {mem:.2f}%")
                log_status.info(f"{host} CPU: {cpu:.2f}%, RAM: {mem:.2f}%")
                ssh.close()
            progress.update(task, advance=1)

    target = min(stats, key=stats.get)
    log_status.info(f"Выбран сервер для установки: {target}")
    console.print(f"[bold cyan]Выбран сервер: {target}[/bold cyan]")
    ssh = connect_ssh(target, key_path)
    if ssh:
        distro = get_linux_distribution(ssh)
        console.print(f"[cyan]Установка PostgreSQL на {target} ({distro})...[/cyan]")
        log_install.info(f"Установка PostgreSQL на {target} ({distro})")
        try:
            if distro == "debian":
                install_postgresql_debian(ssh)
            elif distro == "alma":
                install_postgresql_alma(ssh)
            else:
                console.print("[red]Неизвестный дистрибутив. Установка невозможна.[/red]")
                log_error.error("Неизвестный дистрибутив")
                ssh.close()
                return

            # Конфигурация PostgreSQL доступа
            other_host = [h for h in hosts if h != target][0]
            console.print(f"[cyan]Настройка доступа для пользователя student с IP {other_host}...[/cyan]")
            log_install.info(f"Настройка доступа к PostgreSQL с {other_host}")
            configure_postgresql_access(ssh, other_host)

        except RuntimeError as e:
            console.print(f"[bold red]Ошибка: {e}[/bold red]")
            log_error.error(str(e))
        else:
            console.print("[bold green]Установка завершена успешно![/bold green]")
            log_install.info("Установка завершена успешно")
        ssh.close()

        # Проверка подключения student со второго сервера
        test_student_connection(other_host, key_path, target)

if __name__ =="__main__":
    main()
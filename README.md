#!/data/data/com.termux/files/usr/bin/bash

# ==============================================
# Termux交流社区单兵武器库
# 开发者：研发组组长星
# 版本：4.0 - 终极兼容版
# 最后更新：2024年
# ==============================================

# 颜色定义
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# 全局变量
TOOLS_DIR="$HOME/.termux-arsenal"
LOG_FILE="$TOOLS_DIR/arsenal.log"
INSTALL_LOG="$TOOLS_DIR/install.log"
BIN_DIR="$PREFIX/bin"
CONFIG_DIR="$TOOLS_DIR/config"

# 创建必要目录
mkdir -p "$TOOLS_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$TOOLS_DIR/downloads"
mkdir -p "$TOOLS_DIR/scripts"

# 日志系统
log_message() {
    local type=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $type in
        "INFO") echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$type] $message" >> "$LOG_FILE"
}

# 横幅显示
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                                  ║"
    echo "║  ████████╗███████╗██████╗ ███╗   ███╗██╗   ██╗██╗  ██╗                          ║"
    echo "║  ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║╚██╗ ██╔╝╚██╗██╔╝                          ║"
    echo "║     ██║   █████╗  ██████╔╝██╔████╔██║ ╚████╔╝  ╚███╔╝                           ║"
    echo "║     ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║  ╚██╔╝   ██╔██╗                           ║"
    echo "║     ██║   ███████╗██║  ██║██║ ╚═╝ ██║   ██║   ██╔╝ ██╗                          ║"
    echo "║     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝  ╚═╝                          ║"
    echo "║                                                                                  ║"
    echo "║                🛡️ TERMUX 单兵作战武器库 v4.0 🛡️                               ║"
    echo "║                     🔧 开发者：研发组组长星 🔧                                 ║"
    echo "║                     📅 $(date '+%Y-%m-%d %H:%M:%S') 📅                          ║"
    echo "║                                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  免责声明：本工具仅用于授权的安全测试和教育目的${NC}"
    echo -e "${YELLOW}⚠️  严禁用于非法活动，使用者需承担全部法律责任${NC}"
    echo ""
}

# 进度条显示
show_progress() {
    local current=$1
    local total=$2
    local message=$3
    local width=50
    local percent=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r${CYAN}[%3d%%]${NC} %s [" "$percent" "$message"
    printf "#%.0s" $(seq 1 $completed)
    printf " %.0s" $(seq 1 $remaining)
    printf "]"
    
    if [ $current -eq $total ]; then
        printf "\n"
    fi
}

# 检查命令是否存在
check_command() {
    command -v "$1" >/dev/null 2>&1
    return $?
}

# 检查并安装基础包
install_base_packages() {
    log_message "INFO" "开始安装基础系统包"
    
    local packages=(
        "python" "git" "wget" "curl" "proot" "tar" "zip" "unzip"
        "nano" "vim" "tree" "htop" "neofetch" "figlet" "toilet"
        "clang" "make" "cmake" "binutils" "pkg-config"
        "openssl" "openssh" "libffi" "libxml2" "libxslt"
        "zlib" "libjpeg-turbo" "libpng" "freetype"
    )
    
    local total=${#packages[@]}
    local current=0
    
    for pkg in "${packages[@]}"; do
        ((current++))
        show_progress $current $total "安装 $pkg"
        
        if ! pkg list-installed | grep -q "^$pkg/"; then
            pkg install -y "$pkg" >> "$INSTALL_LOG" 2>&1
            if [ $? -ne 0 ]; then
                log_message "WARN" "安装 $pkg 失败，跳过"
            fi
        fi
    done
    
    echo ""
    log_message "INFO" "基础包安装完成"
}

# 安装Python环境
setup_python_env() {
    log_message "INFO" "设置Python环境"
    
    # 创建虚拟环境
    if [ ! -d "$TOOLS_DIR/venv" ]; then
        python -m venv "$TOOLS_DIR/venv" >> "$INSTALL_LOG" 2>&1
    fi
    
    # 激活虚拟环境
    source "$TOOLS_DIR/venv/bin/activate"
    
    # 升级pip
    pip install --upgrade pip >> "$INSTALL_LOG" 2>&1
    
    # 安装Python基础包
    local py_packages=(
        "requests" "beautifulsoup4" "lxml" "html5lib"
        "urllib3" "certifi" "chardet" "idna"
        "colorama" "progress" "tabulate" "pyfiglet"
        "cryptography" "paramiko" "scapy" "pysocks"
        "dnspython" "ipaddress" "netifaces"
    )
    
    log_message "INFO" "安装Python包"
    for pkg in "${py_packages[@]}"; do
        pip install "$pkg" >> "$INSTALL_LOG" 2>&1
    done
    
    log_message "INFO" "Python环境设置完成"
}

# 安装Nmap
install_nmap() {
    log_message "INFO" "安装Nmap"
    
    if check_command nmap; then
        log_message "INFO" "Nmap已安装"
        return
    fi
    
    # Termux中的nmap包名可能是nmap
    if pkg install -y nmap >> "$INSTALL_LOG" 2>&1; then
        log_message "INFO" "Nmap安装成功"
    else
        log_message "WARN" "无法通过pkg安装Nmap"
        # 尝试从源码编译
        log_message "INFO" "尝试从源码编译Nmap"
        
        cd "$TOOLS_DIR/downloads"
        wget https://nmap.org/dist/nmap-7.94.tar.bz2 >> "$INSTALL_LOG" 2>&1
        tar xjf nmap-7.94.tar.bz2
        cd nmap-7.94
        ./configure --prefix="$PREFIX" >> "$INSTALL_LOG" 2>&1
        make >> "$INSTALL_LOG" 2>&1
        make install >> "$INSTALL_LOG" 2>&1
        
        if check_command nmap; then
            log_message "INFO" "Nmap编译安装成功"
        else
            log_message "ERROR" "Nmap安装失败"
        fi
    fi
}

# 安装SQLMap
install_sqlmap() {
    log_message "INFO" "安装SQLMap"
    
    if [ -d "$TOOLS_DIR/sqlmap" ]; then
        log_message "INFO" "SQLMap已存在，更新中..."
        cd "$TOOLS_DIR/sqlmap"
        git pull >> "$INSTALL_LOG" 2>&1
    else
        cd "$TOOLS_DIR"
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git >> "$INSTALL_LOG" 2>&1
    fi
    
    # 创建启动脚本
    cat > "$BIN_DIR/sqlmap" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$HOME/.termux-arsenal/sqlmap"
python sqlmap.py "$@"
EOF
    
    chmod +x "$BIN_DIR/sqlmap"
    log_message "INFO" "SQLMap安装完成"
}

# 安装信息收集工具
install_recon_tools() {
    log_message "INFO" "安装信息收集工具"
    
    local recon_tools=(
        "recon-ng https://github.com/lanmaster53/recon-ng"
        "theHarvester https://github.com/laramies/theHarvester"
        "Sublist3r https://github.com/aboul3la/Sublist3r"
        "dirsearch https://github.com/maurosoria/dirsearch"
        "EyeWitness https://github.com/FortyNorthSecurity/EyeWitness"
    )
    
    for tool_info in "${recon_tools[@]}"; do
        tool_name=$(echo "$tool_info" | awk '{print $1}')
        tool_url=$(echo "$tool_info" | awk '{print $2}')
        
        log_message "INFO" "安装 $tool_name"
        
        if [ -d "$TOOLS_DIR/$tool_name" ]; then
            cd "$TOOLS_DIR/$tool_name"
            git pull >> "$INSTALL_LOG" 2>&1
        else
            cd "$TOOLS_DIR"
            git clone --depth 1 "$tool_url" >> "$INSTALL_LOG" 2>&1
        fi
        
        # 安装Python依赖
        if [ -f "$TOOLS_DIR/$tool_name/requirements.txt" ]; then
            pip install -r "$TOOLS_DIR/$tool_name/requirements.txt" >> "$INSTALL_LOG" 2>&1
        fi
        
        # 创建启动脚本
        if [ -f "$TOOLS_DIR/$tool_name/${tool_name}.py" ]; then
            cat > "$BIN_DIR/$tool_name" << EOF
#!/data/data/com.termux/files/usr/bin/bash
cd "$TOOLS_DIR/$tool_name"
python ${tool_name}.py "\$@"
EOF
            chmod +x "$BIN_DIR/$tool_name"
        fi
    done
    
    log_message "INFO" "信息收集工具安装完成"
}

# 安装Web漏洞扫描工具
install_web_tools() {
    log_message "INFO" "安装Web漏洞扫描工具"
    
    local web_tools=(
        "XSStrike https://github.com/s0md3v/XSStrike"
        "nikto https://github.com/sullo/nikto"
        "wpscan https://github.com/wpscanteam/wpscan"
        "joomscan https://github.com/rezasp/joomscan"
        "drupwn https://github.com/immunIT/drupwn"
    )
    
    for tool_info in "${web_tools[@]}"; do
        tool_name=$(echo "$tool_info" | awk '{print $1}')
        tool_url=$(echo "$tool_info" | awk '{print $2}')
        
        log_message "INFO" "安装 $tool_name"
        
        cd "$TOOLS_DIR"
        git clone --depth 1 "$tool_url" >> "$INSTALL_LOG" 2>&1
        
        # 安装依赖
        if [ -f "$TOOLS_DIR/$tool_name/requirements.txt" ]; then
            pip install -r "$TOOLS_DIR/$tool_name/requirements.txt" >> "$INSTALL_LOG" 2>&1
        fi
    done
    
    log_message "INFO" "Web漏洞扫描工具安装完成"
}

# 安装密码工具
install_password_tools() {
    log_message "INFO" "安装密码工具"
    
    # 安装crunch
    if pkg install -y crunch >> "$INSTALL_LOG" 2>&1; then
        log_message "INFO" "Crunch安装成功"
    fi
    
    # 安装hashcat（尝试编译）
    log_message "INFO" "尝试安装Hashcat"
    cd "$TOOLS_DIR/downloads"
    wget https://github.com/hashcat/hashcat/archive/refs/tags/v6.2.6.tar.gz >> "$INSTALL_LOG" 2>&1
    tar xzf v6.2.6.tar.gz
    cd hashcat-6.2.6
    make >> "$INSTALL_LOG" 2>&1
    make install >> "$INSTALL_LOG" 2>&1
    
    # 创建密码字典
    create_password_lists
    
    log_message "INFO" "密码工具安装完成"
}

# 创建密码字典
create_password_lists() {
    log_message "INFO" "创建常用密码字典"
    
    local wordlists_dir="$TOOLS_DIR/wordlists"
    mkdir -p "$wordlists_dir"
    
    # 常见密码列表
    cat > "$wordlists_dir/common_passwords.txt" << 'EOF'
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
1234567890
michael
654321
superman
1qaz2wsx
7777777
121212
000000
qazwsx
123qwe
killer
trustno1
jordan
jennifer
zxcvbnm
asdfgh
hunter
buster
soccer
harley
batman
andrew
tigger
sunshine
iloveyou
2000
charlie
robert
thomas
hockey
ranger
daniel
starwars
klaster
112233
george
computer
michelle
jessica
pepper
1111
zxcvbn
555555
11111111
131313
freedom
777777
pass
maggie
159753
aaaaaa
ginger
princess
joshua
cheese
amanda
summer
love
ashley
nicole
chelsea
biteme
matthew
access
yankees
987654321
dallas
austin
thunder
taylor
matrix
mobilemail
mom
monitor
monitoring
montana
moon
moscow
EOF

    # 用户名列表
    cat > "$wordlists_dir/usernames.txt" << 'EOF'
admin
root
user
administrator
test
guest
info
adm
mysql
user1
administrator
oracle
ftp
pi
git
postgres
tomcat
weblogic
boss
manager
system
sysadmin
webadmin
webmaster
admin123
adminadmin
superadmin
superuser
support
tech
it
dev
developer
demo
backup
dbadmin
testuser
test123
user123
useradmin
web
www
www-data
apache
nginx
redis
mongodb
elastic
kibana
grafana
prometheus
jenkins
ansible
docker
kubernetes
ubuntu
centos
debian
ec2-user
aws
azure
gcp
cloud
alpine
EOF

    log_message "INFO" "密码字典创建完成"
}

# 安装无线工具（Termux有限支持）
install_wireless_tools() {
    log_message "INFO" "安装无线工具"
    
    # Termux API 提供基本WiFi功能
    if pkg install -y termux-api >> "$INSTALL_LOG" 2>&1; then
        log_message "INFO" "Termux API安装成功"
    fi
    
    # 安装网络工具
    local net_tools=("net-tools" "iproute2" "dnsutils" "netcat")
    for tool in "${net_tools[@]}"; do
        pkg install -y "$tool" >> "$INSTALL_LOG" 2>&1
    done
    
    log_message "INFO" "无线工具安装完成"
}

# 创建自定义工具脚本
create_custom_tools() {
    log_message "INFO" "创建自定义工具脚本"
    
    # 1. 端口扫描器
    cat > "$TOOLS_DIR/scripts/port_scanner.py" << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore

init(autoreset=True)

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return port, True
    except:
        pass
    return port, False

def main():
    parser = argparse.ArgumentParser(description='多线程端口扫描器')
    parser.add_argument('host', help='目标主机')
    parser.add_argument('-p', '--ports', default='1-1024', help='端口范围 (默认: 1-1024)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='线程数')
    
    args = parser.parse_args()
    
    if '-' in args.ports:
        start_port, end_port = map(int, args.ports.split('-'))
        ports = range(start_port, end_port + 1)
    else:
        ports = [int(p) for p in args.ports.split(',')]
    
    print(f"{Fore.CYAN}[*] 开始扫描 {args.host}")
    print(f"{Fore.CYAN}[*] 端口范围: {args.ports}")
    print(f"{Fore.CYAN}[*] 使用线程: {args.threads}")
    print("-" * 50)
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_port, args.host, port) for port in ports]
        
        for future in futures:
            port, is_open = future.result()
            if is_open:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "未知"
                print(f"{Fore.GREEN}[+] 端口 {port} 开放 ({service})")
                open_ports.append((port, service))
    
    print("-" * 50)
    print(f"{Fore.YELLOW}[*] 扫描完成")
    print(f"{Fore.YELLOW}[*] 开放端口: {len(open_ports)} 个")
    
    if open_ports:
        print(f"{Fore.YELLOW}[*] 列表:")
        for port, service in open_ports:
            print(f"    {port}/tcp - {service}")

if __name__ == "__main__":
    main()
EOF

    chmod +x "$TOOLS_DIR/scripts/port_scanner.py"
    
    # 2. 子域名枚举器
    cat > "$TOOLS_DIR/scripts/subdomain_enum.py" << 'EOF'
#!/usr/bin/env python3
import requests
import dns.resolver
import concurrent.futures
import argparse
from colorama import init, Fore

init(autoreset=True)

common_subdomains = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
    'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'admin', 'blog',
    'shop', 'api', 'dev', 'test', 'staging', 'mobile', 'm', 'app', 'apps',
    'web', 'support', 'help', 'cdn', 'static', 'media', 'img', 'images',
    'js', 'css', 'login', 'secure', 'portal', 'wiki', 'forum', 'forums',
    'download', 'downloads', 'upload', 'uploads', 'video', 'videos',
    'music', 'photo', 'photos', 'search', 'secure', 'ssl', 'vpn',
    'remote', 'server', 'servers', 'ns', 'dns', 'mx', 'imap', 'pop3',
    'ssh', 'git', 'svn', 'redis', 'mysql', 'mariadb', 'postgres', 'mongodb',
    'elasticsearch', 'kibana', 'grafana', 'prometheus', 'jenkins',
    'docker', 'kubernetes', 'aws', 'azure', 'gcp', 'cloud'
]

def check_subdomain(domain, subdomain):
    full_domain = f"{subdomain}.{domain}"
    
    # 方法1: DNS查询
    try:
        dns.resolver.resolve(full_domain, 'A')
        return full_domain, "DNS"
    except:
        pass
    
    # 方法2: HTTP请求
    for scheme in ['http://', 'https://']:
        url = f"{scheme}{full_domain}"
        try:
            response = requests.get(url, timeout=3, verify=False)
            if response.status_code < 400:
                return full_domain, f"HTTP {response.status_code}"
        except:
            pass
    
    return None, None

def main():
    parser = argparse.ArgumentParser(description='子域名枚举工具')
    parser.add_argument('domain', help='目标域名')
    parser.add_argument('-t', '--threads', type=int, default=50, help='线程数')
    parser.add_argument('-o', '--output', help='输出文件')
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}[*] 开始枚举 {args.domain} 的子域名")
    print(f"{Fore.CYAN}[*] 使用 {args.threads} 个线程")
    print("-" * 50)
    
    found_subdomains = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_subdomain, args.domain, sub): sub for sub in common_subdomains}
        
        for future in concurrent.futures.as_completed(futures):
            subdomain = futures[future]
            try:
                result, method = future.result()
                if result:
                    print(f"{Fore.GREEN}[+] {result} ({method})")
                    found_subdomains.append((result, method))
            except Exception as e:
                print(f"{Fore.RED}[-] 检查 {subdomain} 时出错: {e}")
    
    print("-" * 50)
    print(f"{Fore.YELLOW}[*] 扫描完成")
    print(f"{Fore.YELLOW}[*] 发现子域名: {len(found_subdomains)} 个")
    
    if args.output and found_subdomains:
        with open(args.output, 'w') as f:
            for subdomain, method in found_subdomains:
                f.write(f"{subdomain}\n")
        print(f"{Fore.YELLOW}[*] 结果已保存到: {args.output}")

if __name__ == "__main__":
    main()
EOF

    chmod +x "$TOOLS_DIR/scripts/subdomain_enum.py"
    
    # 3. Web目录扫描器
    cat > "$TOOLS_DIR/scripts/dir_scanner.py" << 'EOF'
#!/usr/bin/env python3
import requests
import concurrent.futures
import argparse
from urllib.parse import urljoin
from colorama import init, Fore

init(autoreset=True)

common_directories = [
    'admin', 'administrator', 'wp-admin', 'wp-login.php', 'login', 'auth',
    'dashboard', 'control', 'manage', 'manager', 'sysadmin', 'system',
    'user', 'users', 'account', 'accounts', 'profile', 'profiles',
    'api', 'api/v1', 'api/v2', 'rest', 'rest/api', 'graphql',
    'backup', 'backups', 'backup.zip', 'backup.tar.gz', 'backup.sql',
    'config', 'configuration', 'conf', 'settings', 'setup', 'install',
    'phpmyadmin', 'mysql', 'pma', 'db', 'database', 'dba',
    'test', 'testing', 'demo', 'stage', 'staging', 'dev', 'development',
    'cgi-bin', 'cgi', 'scripts', 'script', 'js', 'javascript',
    'css', 'style', 'styles', 'images', 'img', 'pics', 'photos',
    'uploads', 'upload', 'downloads', 'download', 'files', 'file',
    'doc', 'docs', 'document', 'documents', 'manual', 'manuals',
    'help', 'faq', 'faqs', 'support', 'contact', 'about', 'info',
    'blog', 'news', 'articles', 'posts', 'forum', 'forums', 'board',
    'shop', 'store', 'cart', 'checkout', 'payment', 'payments',
    'search', 'find', 'query', 'results', 'result',
    'robots.txt', 'sitemap.xml', 'sitemap', 'sitemap_index.xml',
    '.git', '.svn', '.hg', '.env', '.htaccess', '.htpasswd',
    'crossdomain.xml', 'clientaccesspolicy.xml', 'security.txt',
    'LICENSE', 'license.txt', 'README', 'readme.txt', 'CHANGELOG'
]

def check_directory(base_url, directory):
    url = urljoin(base_url, directory)
    
    try:
        response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
        
        if response.status_code == 200:
            return url, f"200 OK"
        elif response.status_code == 301 or response.status_code == 302:
            return url, f"{response.status_code} Redirect"
        elif response.status_code == 403:
            return url, f"403 Forbidden"
        elif response.status_code == 500:
            return url, f"500 Server Error"
        elif response.status_code == 401:
            return url, f"401 Unauthorized"
    except requests.RequestException:
        return None, None
    
    return None, None

def main():
    parser = argparse.ArgumentParser(description='Web目录扫描器')
    parser.add_argument('url', help='目标URL')
    parser.add_argument('-t', '--threads', type=int, default=20, help='线程数')
    parser.add_argument('-o', '--output', help='输出文件')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    
    print(f"{Fore.CYAN}[*] 开始扫描: {args.url}")
    print(f"{Fore.CYAN}[*] 使用 {args.threads} 个线程")
    print("-" * 50)
    
    found_directories = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_directory, args.url, dir): dir for dir in common_directories}
        
        for future in concurrent.futures.as_completed(futures):
            directory = futures[future]
            try:
                url, status = future.result()
                if url:
                    if "200 OK" in status:
                        print(f"{Fore.GREEN}[+] {url} ({status})")
                    elif "403" in status:
                        print(f"{Fore.YELLOW}[+] {url} ({status})")
                    elif "401" in status:
                        print(f"{Fore.YELLOW}[+] {url} ({status})")
                    else:
                        print(f"{Fore.BLUE}[+] {url} ({status})")
                    found_directories.append((url, status))
            except Exception as e:
                print(f"{Fore.RED}[-] 检查 {directory} 时出错: {e}")
    
    print("-" * 50)
    print(f"{Fore.YELLOW}[*] 扫描完成")
    print(f"{Fore.YELLOW}[*] 发现目录/文件: {len(found_directories)} 个")
    
    if args.output and found_directories:
        with open(args.output, 'w') as f:
            for url, status in found_directories:
                f.write(f"{url} - {status}\n")
        print(f"{Fore.YELLOW}[*] 结果已保存到: {args.output}")

if __name__ == "__main__":
    main()
EOF

    chmod +x "$TOOLS_DIR/scripts/dir_scanner.py"
    
    # 创建启动脚本
    for script in port_scanner subdomain_enum dir_scanner; do
        cat > "$BIN_DIR/termux-$script" << EOF
#!/data/data/com.termux/files/usr/bin/bash
python "$TOOLS_DIR/scripts/${script}.py" "\$@"
EOF
        chmod +x "$BIN_DIR/termux-$script"
    done
    
    log_message "INFO" "自定义工具脚本创建完成"
}

# 主安装函数
install_all() {
    show_banner
    
    log_message "INFO" "开始安装Termux武器库"
    echo ""
    
    # 记录开始时间
    start_time=$(date +%s)
    
    # 执行安装步骤
    install_base_packages
    setup_python_env
    install_nmap
    install_sqlmap
    install_recon_tools
    install_web_tools
    install_password_tools
    install_wireless_tools
    create_custom_tools
    
    # 计算安装时间
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    log_message "INFO" "安装完成！耗时: ${duration}秒"
    
    # 显示安装总结
    show_installation_summary
}

# 显示安装总结
show_installation_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🎉 安装完成！可用工具列表：${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${YELLOW}🔧 系统工具：${NC}"
    echo "  nmap          - 网络扫描器"
    echo "  sqlmap        - SQL注入工具"
    echo "  crunch        - 密码字典生成器"
    echo ""
    
    echo -e "${YELLOW}🔍 信息收集：${NC}"
    echo "  termux-port-scanner   - 端口扫描器"
    echo "  termux-subdomain-enum - 子域名枚举器"
    echo "  termux-dir-scanner    - 目录扫描器"
    echo "  recon-ng             - 侦察框架"
    echo "  theHarvester         - 信息收集工具"
    echo ""
    
    echo -e "${YELLOW}🛡️ Web安全：${NC}"
    echo "  XSStrike     - XSS扫描器"
    echo "  nikto        - Web漏洞扫描器"
    echo "  wpscan       - WordPress扫描器"
    echo "  dirsearch    - Web路径扫描器"
    echo ""
    
    echo -e "${YELLOW}🔐 密码工具：${NC}"
    echo "  密码字典位置: $TOOLS_DIR/wordlists/"
    echo ""
    
    echo -e "${YELLOW}📁 重要目录：${NC}"
    echo "  工具目录: $TOOLS_DIR"
    echo "  脚本目录: $TOOLS_DIR/scripts"
    echo "  字典目录: $TOOLS_DIR/wordlists"
    echo "  日志文件: $LOG_FILE"
    echo ""
    
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}💡 使用方法：${NC}"
    echo "  运行任何工具: termux-<工具名> [参数]"
    echo "  例如: termux-port-scanner example.com"
    echo ""
    echo -e "${RED}⚠️  重要提醒：${NC}"
    echo "  1. 仅用于授权的安全测试"
    echo "  2. 遵守当地法律法规"
    echo "  3. 不要用于非法入侵"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    
    read -p "按回车键继续..."
}

# 快速扫描功能
quick_scan() {
    show_banner
    
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🚀 快速扫描模式${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    read -p "请输入目标域名或IP: " target
    
    if [ -z "$target" ]; then
        log_message "ERROR" "目标不能为空"
        return
    fi
    
    echo ""
    echo -e "${YELLOW}[1/3] 正在扫描开放端口...${NC}"
    python "$TOOLS_DIR/scripts/port_scanner.py" "$target" -p "1-1000" -t 50
    
    echo ""
    echo -e "${YELLOW}[2/3] 正在枚举子域名...${NC}"
    python "$TOOLS_DIR/scripts/subdomain_enum.py" "$target" -t 30
    
    echo ""
    echo -e "${YELLOW}[3/3] 正在扫描Web目录...${NC}"
    python "$TOOLS_DIR/scripts/dir_scanner.py" "http://$target" -t 20
    
    echo ""
    echo -e "${GREEN}✅ 快速扫描完成${NC}"
    read -p "按回车键返回主菜单..."
}

# 工具管理菜单
tool_manager() {
    while true; do
        show_banner
        
        echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}🛠️  工具管理${NC}"
        echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "1. 更新所有工具"
        echo "2. 清理缓存文件"
        echo "3. 查看工具状态"
        echo "4. 重新创建工具脚本"
        echo "5. 返回主菜单"
        echo ""
        
        read -p "请选择操作 [1-5]: " choice
        
        case $choice in
            1)
                log_message "INFO" "开始更新工具"
                source "$TOOLS_DIR/venv/bin/activate"
                
                # 更新Git工具
                for dir in "$TOOLS_DIR"/*/; do
                    if [ -d "$dir/.git" ]; then
                        cd "$dir"
                        git pull >> "$INSTALL_LOG" 2>&1
                        log_message "INFO" "更新 $(basename "$dir")"
                    fi
                done
                
                # 更新Python包
                pip list --outdated | grep -v "^Package" | awk '{print $1}' | xargs -r pip install --upgrade
                
                log_message "INFO" "工具更新完成"
                read -p "按回车键继续..."
                ;;
            2)
                log_message "INFO" "清理缓存文件"
                rm -rf "$TOOLS_DIR/downloads/"*
                rm -rf /tmp/*
                pip cache purge
                log_message "INFO" "缓存清理完成"
                read -p "按回车键继续..."
                ;;
            3)
                show_banner
                echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
                echo -e "${GREEN}📊 工具状态${NC}"
                echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
                echo ""
                
                # 检查工具状态
                tools=(
                    "nmap" "sqlmap" "python" "git" "wget" "curl"
                )
                
                for tool in "${tools[@]}"; do
                    if check_command "$tool"; then
                        echo -e "${GREEN}✓${NC} $tool"
                    else
                        echo -e "${RED}✗${NC} $tool"
                    fi
                done
                
                echo ""
                echo -e "${YELLOW}自定义工具：${NC}"
                custom_tools=(
                    "port_scanner.py" "subdomain_enum.py" "dir_scanner.py"
                )
                
                for tool in "${custom_tools[@]}"; do
                    if [ -f "$TOOLS_DIR/scripts/$tool" ]; then
                        echo -e "${GREEN}✓${NC} $tool"
                    else
                        echo -e "${RED}✗${NC} $tool"
                    fi
                done
                
                echo ""
                read -p "按回车键继续..."
                ;;
            4)
                log_message "INFO" "重新创建工具脚本"
                create_custom_tools
                log_message "INFO" "工具脚本创建完成"
                read -p "按回车键继续..."
                ;;
            5)
                return
                ;;
            *)
                log_message "ERROR" "无效选择"
                ;;
        esac
    done
}

# 主菜单
main_menu() {
    while true; do
        show_banner
        
        echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}🏠 主菜单${NC}"
        echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "1. 🚀 一键安装武器库"
        echo "2. 🔍 快速目标扫描"
        echo "3. 🛠️  工具管理"
        echo "4. 📖 使用教程"
        echo "5. 🗑️  清理卸载"
        echo "6. 🚪 退出"
        echo ""
        
        read -p "请选择操作 [1-6]: " choice
        
        case $choice in
            1)
                install_all
                ;;
            2)
                quick_scan
                ;;
            3)
                tool_manager
                ;;
            4)
                show_tutorial
                ;;
            5)
                uninstall
                ;;
            6)
                log_message "INFO" "退出武器库"
                echo -e "${GREEN}感谢使用！再见！👋${NC}"
                exit 0
                ;;
            *)
                log_message "ERROR" "无效选择，请重新输入"
                sleep 2
                ;;
        esac
    done
}

# 使用教程
show_tutorial() {
    show_banner
    
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}📖 使用教程${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${YELLOW}1. 基本扫描命令：${NC}"
    echo "  termux-port-scanner example.com"
    echo "  termux-subdomain-enum example.com"
    echo "  termux-dir-scanner http://example.com"
    echo ""
    
    echo -e "${YELLOW}2. SQLMap使用：${NC}"
    echo "  sqlmap -u \"http://example.com?id=1\" --batch"
    echo "  sqlmap -u \"http://example.com\" --forms --batch"
    echo ""
    
    echo -e "${YELLOW}3. Nmap常用命令：${NC}"
    echo "  nmap -sS -sV -O target.com"
    echo "  nmap -p 1-1000 target.com"
    echo "  nmap -A -T4 target.com"
    echo ""
    
    echo -e "${YELLOW}4. 信息收集：${NC}"
    echo "  recon-ng"
    echo "  theHarvester -d example.com -b google"
    echo ""
    
    echo -e "${YELLOW}5. 密码攻击：${NC}"
    echo "  crunch 6 8 abc123 -o passwords.txt"
    echo "  使用字典: $TOOLS_DIR/wordlists/"
    echo ""
    
    echo -e "${YELLOW}6. 实用技巧：${NC}"
    echo "  • 使用 -h 查看工具帮助"
    echo "  • 保存结果: 添加 -o output.txt"
    echo "  • 多线程: 使用 -t 参数"
    echo ""
    
    echo -e "${RED}⚠️  重要安全提醒：${NC}"
    echo "  • 仅测试自己拥有权限的系统"
    echo "  • 获取书面授权证明"
    echo "  • 遵守当地法律法规"
    echo "  • 不要攻击未授权的目标"
    echo ""
    
    read -p "按回车键返回主菜单..."
}

# 清理卸载
uninstall() {
    show_banner
    
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}🗑️  清理卸载${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}警告：这将删除所有安装的工具和配置！${NC}"
    echo ""
    echo "选择卸载级别："
    echo "1. 轻度清理（仅删除工具文件）"
    echo "2. 完全卸载（删除所有文件和配置）"
    echo "3. 取消"
    echo ""
    
    read -p "请选择 [1-3]: " choice
    
    case $choice in
        1)
            echo -e "${YELLOW}[+] 执行轻度清理...${NC}"
            rm -rf "$TOOLS_DIR"
            log_message "INFO" "轻度清理完成"
            echo -e "${GREEN}✅ 清理完成${NC}"
            ;;
        2)
            echo -e "${YELLOW}[+] 执行完全卸载...${NC}"
            rm -rf "$TOOLS_DIR"
            # 移除自定义命令
            for cmd in termux-port-scanner termux-subdomain-enum termux-dir-scanner; do
                rm -f "$BIN_DIR/$cmd"
            done
            log_message "INFO" "完全卸载完成"
            echo -e "${GREEN}✅ 卸载完成${NC}"
            ;;
        3)
            echo -e "${YELLOW}[+] 取消卸载${NC}"
            return
            ;;
        *)
            log_message "ERROR" "无效选择"
            ;;
    esac
    
    read -p "按回车键返回主菜单..."
}

# 初始化检查
init_check() {
    # 检查是否在Termux中运行
    if [ ! -d "/data/data/com.termux" ]; then
        echo -e "${RED}错误：本脚本只能在Termux环境中运行！${NC}"
        exit 1
    fi
    
    # 检查存储权限
    if [ ! -w "$HOME" ]; then
        echo -e "${RED}错误：没有写入权限，请检查存储权限${NC}"
        exit 1
    fi
    
    # 检查网络连接
    if ! ping -c 1 -W 2 google.com >/dev/null 2>&1; then
        echo -e "${YELLOW}警告：网络连接可能有问题，某些功能可能无法使用${NC}"
        sleep 2
    fi
    
    log_message "INFO" "Termux武器库启动"
}

# 主程序入口
echo -e "${GREEN}[+] 启动Termux交流社区单兵武器库 v4.0${NC}"
echo -e "${GREEN}[+] 开发者：研发组组长星${NC}"
echo ""

init_check
main_menu

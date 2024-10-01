#!/bin/bash

function isRoot() {
  if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
  fi
}

function setVariables() {
  ADGUARD_PORT=8080
  X_UI_PORT=8081
  X_UI_RNDSTR=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")

  read -rp "Enter hostname: " -e -i "$(hostname)" HOSTNAME
  read -rp "Enter username: " -e -i "john" USERNAME
  read -rp "Adguard Home. Enter domain: " -e -i "dns.$HOSTNAME" DOMAIN_ADGUARD
  read -rp "Adguard Home. Enter password: " ADGUARD_PASS
  read -rp "3X UI panel. Enter domain: " -e -i "3x.$HOSTNAME" DOMAIN_3X_UI
  read -rp "3X UI panel. Enter password: " X_UI_PASS
  read -rp "3X UI panel. Enter path: " -e -i "$X_UI_RNDSTR" X_UI_RNDSTR

  RANDOM_PORT=$(shuf -i49152-65535 -n1)
  until [[ ${VLESS_PORT} =~ ^[0-9]+$ ]] && [ "${VLESS_PORT}" -ge 1 ] && [ "${VLESS_PORT}" -le 65535 ]; do
    read -rp "3X UI VLESS. Enter connection port [1-65535]: " -e -i "${RANDOM_PORT}" VLESS_PORT
  done

  CONFIG_IPV6=0
  read -rp "Disable IPv6? (y/n): " -e -i "y" answer
  if [ "$answer" != "y" ]; then
    CONFIG_IPV6=1
  fi

  SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
  if [[ -z ${SERVER_PUB_IP} ]]; then
    if [ "$CONFIG_IPV6" -eq 0 ]; then
      echo 'IPv4 is not detected. Exit'
      exit
    fi

    # Detect public IPv6 address
    SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
  fi

  if [ "$CONFIG_IPV6" -eq 0 ]; then
    until [[ ${SERVER_PUB_IP} =~ ^([0-9]{1,3}\.){3} ]]; do
      read -rp "IPv4 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP
    done
  else
    read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP
  fi

  SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
  until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
    read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
  done

  until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
    read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
  done

  until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
    read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
  done

  if [ "$CONFIG_IPV6" -eq 1 ]; then
    until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
      read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
    done
  fi

  RANDOM_PORT=$(shuf -i49152-65535 -n1)
  until [[ ${SERVER_WG_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_WG_PORT}" -ge 1 ] && [ "${SERVER_WG_PORT}" -le 65535 ]; do
    read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_WG_PORT
  done

  until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
    read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
  done

  until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
    read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
    if [[ ${CLIENT_DNS_2} == "" ]]; then
      CLIENT_DNS_2="${CLIENT_DNS_1}"
    fi
  done

  until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
    echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
    ALLOWED_IPS_DEFAULT="0.0.0.0/0,::/0"
    if [ "$CONFIG_IPV6" -eq 0 ]; then
      ALLOWED_IPS_DEFAULT="0.0.0.0/0"
    fi

    read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i $ALLOWED_IPS_DEFAULT ALLOWED_IPS
    if [[ ${ALLOWED_IPS} == "" ]]; then
      ALLOWED_IPS=$ALLOWED_IPS_DEFAULT
    fi
  done

  VPN_PREFIX_V4=$(echo "$SERVER_WG_IPV4" | sed 's/\.[0-9]\+$//').0
  read -rp "SSH. Allow root login from IP: " -e -i "$SERVER_PUB_IP,$VPN_PREFIX_V4/24,127.0.0.1" SSH_ALLOW_IP

  read -rp "Fail2Ban. Ignore IP: " -e -i "$SERVER_PUB_IP $VPN_PREFIX_V4/24 127.0.0.1" FAIL2BAN_IGNORE_IP

  echo ""
}

function mainInstall() {
  echo "Install apt packages..."

  rm -rf /usr/share/keyrings/gierens.gpg
  rm -rf /etc/apt/sources.list.d/gierens.list
  rm -rf /usr/share/keyrings/nginx-archive-keyring.gpg
  rm -rf /etc/apt/sources.list.d/nginx.list
  rm -rf /etc/apt/preferences.d/99nginx

  apt update
  apt upgrade -y
  apt install -y gpg curl wget gnupg2 ca-certificates lsb-release ubuntu-keyring

  # eza
  curl https://raw.githubusercontent.com/eza-community/eza/main/deb.asc | gpg --dearmor | tee /usr/share/keyrings/gierens.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/gierens.gpg] http://deb.gierens.de stable main" | tee /etc/apt/sources.list.d/gierens.list

  #nginx
  curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
  echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | tee /etc/apt/preferences.d/99nginx

  apt update
  apt install -y nano \
    bash-completion \
    mc \
    zsh \
    nftables \
    htop \
    git \
    eza \
    bat \
    nginx \
    fail2ban \
    lsof \
    apache2-utils \
    python3 \
    python3-venv \
    libaugeas0 \
    cron \
    rsyslog

  #Remove snapd
  if dpkg -l | grep -q snapd; then
    if [ "$(snap list 2>/dev/null | wc -l)" -gt 1 ]; then
      echo "Remove all snap apps..."
      snap list | awk '!/^Name|^core|^bare|^snapd/ {print $1}' | xargs -I {} snap remove --purge {}
      snap remove --purge bare
      snap remove --purge core20
      snap remove --purge core22
      snap remove --purge core24
      snap remove --purge snapd
    fi

    echo "Remove snapd app..."
    apt remove -y snapd
    rm -rf /var/snap
    rm -rf /var/lib/snapd
    rm -rf /root/snap
  fi

  echo ""
  echo "Configuring nano..."
  echo "set autoindent
set brackets \"\"')>]}\"
set constantshow
set historylog
set indicator
set linenumbers
set locking
set minibar
set stateflags
set tabsize 4

set titlecolor bold,white,blue
set promptcolor lightwhite,grey
set statuscolor bold,white,green
set errorcolor bold,white,red
set spotlightcolor black,lightyellow
set selectedcolor lightwhite,magenta
set stripecolor ,yellow
set scrollercolor cyan
set numbercolor cyan
set keycolor cyan
set functioncolor green

include \"/usr/share/nano/*.nanorc\"
bind Sh-M-T \"{execute}|xsel -ib{enter}{undo}\" main

bind ^X cut main
bind ^C copy main
bind ^V paste all
bind ^Q exit all
bind ^S savefile main
bind ^W writeout main
bind ^O insert main
bind ^H help all
bind ^H exit help
bind ^F whereis all
bind ^G findnext all
bind ^B wherewas all
bind ^D findprevious all
bind ^R replace main
unbind ^U all
unbind ^N main
unbind ^Y all
unbind M-J main
unbind M-T main
bind ^A mark main
bind ^P location main
bind ^T gotoline main
bind ^T gotodir browser
bind ^T cutrestoffile execute
bind ^L linter execute
bind ^E execute main
bind ^K \"{mark}{end}{zap}\" main
bind ^U \"{mark}{home}{zap}\" main
bind ^Z undo main
bind ^Y redo main
" >/etc/nanorc

  echo "set titlecolor bold,white,magenta
set promptcolor black,yellow
set statuscolor bold,white,magenta
set errorcolor bold,white,red
set spotlightcolor black,orange
set selectedcolor lightwhite,cyan
set stripecolor ,yellow
set scrollercolor magenta
set numbercolor magenta
set keycolor lightmagenta
set functioncolor magenta
" >/root/.nanorc

  echo "net.ipv4.ip_forward = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr" >/etc/sysctl.d/10-vpn.conf

  echo $HOSTNAME >/etc/hostname

  echo ""
  echo "Config sshd..."
  sed -i 's/#\?\(PermitRootLogin\s*\).*$/\1 no/' /etc/ssh/sshd_config
  sed -i 's/#\?\(PasswordAuthentication\s*\).*$/\1 no/' /etc/ssh/sshd_config
  sed -i 's/#\?\(TCPKeepAlive\s*\).*$/\1 yes/' /etc/ssh/sshd_config

  echo "Match Address $SSH_ALLOW_IP
  PermitRootLogin yes
  PasswordAuthentication yes" >/etc/ssh/sshd_config.d/allow_ip.conf

  echo ""
}

function swapConfig {
  echo "Set swap config..."
  if swapon --show | grep -q '^'; then
    echo "Swap is configured"
    swapon --show
    return
  fi

  read -rp "Enter swap size: " -e -i 2G SWAP_SIZE

  fallocate -l $SWAP_SIZE /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

  echo 'vm.swappiness=10
vm.vfs_cache_pressure = 50' >/etc/sysctl.d/10-swap.conf

  swapon --show

  echo ""
}

function userConfig {
  echo "Creating user: $USERNAME..."
  if id "$USERNAME" &>/dev/null; then
    return
  fi

  adduser --gecos "" $USERNAME
  sed -i "/root[\s\t]*ALL/a $USERNAME ALL=(ALL:ALL) ALL" /etc/sudoers
  sed -i '/%admin/s/^/#/' /etc/sudoers
  sed -i '/%sudo/s/^/#/' /etc/sudoers

  mkdir -p /root/.ssh
  cp -r /root/.ssh /home/$USERNAME/
  chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh/
  chmod -R 600 /home/$USERNAME/.ssh/

  echo ""

  read -n1 -r -p "Press any key to continue..."
}

function zshConfig {
  echo "Set zsh config..."

  rm -rf /root/.zshrc
  rm -rf /root/.oh-my-zsh
  rm -rf /home/$USERNAME/.zshrc
  rm -rf /home/$USERNAME/.oh-my-zsh
  apt remove fzf
  rm -rf /usr/bin/fzf
  rm -rf /usr/bin/fzf-preview.sh
  rm -rf /usr/bin/fzf-tmux
  rm -rf /root/.fzf

  sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
  git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-/root/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
  git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-/root/.oh-my-zsh/custom}/plugins/zsh-autosuggestions

  sed -i 's/^ZSH_THEME=".*"/ZSH_THEME="dst"/' /root/.zshrc
  sed -i '/^plugins=(/c\plugins=(git zsh-syntax-highlighting zsh-autosuggestions)' /root/.zshrc

  usermod -s /usr/bin/zsh root

  git clone --depth 1 https://github.com/junegunn/fzf.git /root/.fzf
  /root/.fzf/install --bin
  ln -s /root/.fzf/bin/fzf /usr/bin/fzf
  ln -s /root/.fzf/bin/fzf-preview.sh /usr/bin/fzf-preview.sh
  ln -s /root/.fzf/bin/fzf-tmux /usr/bin/fzf-tmux

  echo "export EDITOR='nano'

alias ls='ls -a --color=auto --group-directories-first'
alias ll='eza -lga --group-directories-first'
alias diff='diff --color=auto'
alias grep='grep --color=auto'
alias dmesg='dmesg --color=always'
alias cat='batcat -pp'


## History file configuration
[ -z \"\$HISTFILE\" ] && HISTFILE=\"\$HOME/.zsh_history\"
HISTSIZE=500000
SAVEHIST=500000

## History command configuration
setopt extended_history       # record timestamp of command in HISTFILE
setopt hist_expire_dups_first # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt hist_ignore_dups       # ignore duplicated commands history list
setopt hist_ignore_space      # ignore commands that start with space
setopt hist_verify            # show command with history expansion to user before running it
setopt inc_append_history     # add commands to HISTFILE in order of execution
setopt share_history          # share command history data

source <(fzf --zsh)
" >>/root/.zshrc

  usermod -s /usr/bin/zsh $USERNAME
  cp /root/.zshrc /home/$USERNAME/.zshrc
  cp -r /root/.oh-my-zsh/ /home/$USERNAME/
  chown $USERNAME:$USERNAME /home/$USERNAME/.zshrc
  chown -R $USERNAME:$USERNAME /home/$USERNAME/.oh-my-zsh

  echo ""
}

function disableIpv6() {
  if [ "$CONFIG_IPV6" -eq 0 ]; then
    return
  fi

  echo 'net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1' >/etc/sysctl.d/10-disable_ipv6.conf

  sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT=/ { /ipv6.disable=1/! s/"$/ ipv6.disable=1"/ }' /etc/default/grub
  sed -i '/^GRUB_CMDLINE_LINUX=/ { /ipv6.disable=1/! s/"$/ ipv6.disable=1"/ }' /etc/default/grub

  update-grub

  echo ""
}

function adguardInstall() {
  echo "Install Adguard Home..."

  curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -u
  curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -c beta

  mkdir -p /etc/systemd/resolved.conf.d

  echo '[Resolve]
DNS=127.0.0.1
DNSStubListener=no' >/etc/systemd/resolved.conf.d/adguardhome.conf

  rm -rf /etc/resolv.conf
  ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
  sed -i 's/^DNS=[0-9. ]*/DNS=127.0.0.1/' /etc/systemd/resolved.conf
  systemctl reload-or-restart systemd-resolved
  systemctl enable systemd-resolved

  echo -p "Adguard Home user: $USERNAME"
  ADGUARD_HASH=$(htpasswd -B -C 10 -n -b $USERNAME $ADGUARD_PASS | awk -F':' '{print $2}')

  echo "http:
  pprof:
    port: 6060
    enabled: false
  address: 0.0.0.0:$ADGUARD_PORT
  session_ttl: 720h
users:
  - name: $USERNAME
    password: $ADGUARD_HASH
auth_attempts: 5
block_auth_min: 15
http_proxy: \"\"
language: \"\"
theme: auto
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: false
  ratelimit: 500
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist: []
  refuse_any: true
  upstream_dns:
    - https://1.1.1.1/dns-query
    - https://1.0.0.1/dns-query
    - https://8.8.8.8/dns-query
    - https://8.8.4.4/dns-query
  upstream_dns_file: \"\"
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  fallback_dns: []
  upstream_mode: load_balance
  fastest_timeout: 1s
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
  trusted_proxies:
    - 127.0.0.0/8
    - ::1/128
  cache_size: 104857600
  cache_ttl_min: 0
  cache_ttl_max: 0
  cache_optimistic: false
  bogus_nxdomain: []
  aaaa_disabled: true
  enable_dnssec: true
  edns_client_subnet:
    custom_ip: \"\"
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  ipset: []
  ipset_file: \"\"
  bootstrap_prefer_ipv6: false
  upstream_timeout: 10s
  private_networks: []
  use_private_ptr_resolvers: true
  local_ptr_upstreams: []
  use_dns64: false
  dns64_prefixes: []
  serve_http3: false
  use_http3_upstreams: false
  serve_plain_dns: true
  hostsfile_enabled: true
tls:
  enabled: true
  server_name: $DOMAIN_ADGUARD
  force_https: false
  port_https: 8443
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  dnscrypt_config_file: \"\"
  allow_unencrypted_doh: true
  certificate_chain: \"\"
  private_key: \"\"
  certificate_path: /etc/letsencrypt/live/$DOMAIN_ADGUARD/fullchain.pem
  private_key_path: /etc/letsencrypt/live/$DOMAIN_ADGUARD/privkey.pem
  strict_sni_check: false
querylog:
  dir_path: \"\"
  ignored: []
  interval: 720h
  size_memory: 1000
  enabled: false
  file_enabled: true
statistics:
  dir_path: \"\"
  ignored: []
  interval: 720h
  enabled: true
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://schakal.ru/hosts/hosts_mail_fb.txt
    name: schakal
    id: 1724655739
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt
    name: WindowsSpyBlocker - Hosts spy rules
    id: 1724655740
  - enabled: true
    url: https://raw.githubusercontent.com/Kittyskj/FreeFromMi/main/hosts_ads_tracking
    name: FreeFromMi
    id: 1724655741
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
  interface_name: \"\"
  local_domain_name: lan
  dhcpv4:
    gateway_ip: \"\"
    subnet_mask: \"\"
    range_start: \"\"
    range_end: \"\"
    lease_duration: 86400
    icmp_timeout_msec: 1000
    options: []
  dhcpv6:
    range_start: \"\"
    lease_duration: 86400
    ra_slaac_only: false
    ra_allow_slaac: false
filtering:
  blocking_ipv4: \"\"
  blocking_ipv6: \"\"
  blocked_services:
    schedule:
      time_zone: Local
    ids: []
  protection_disabled_until: null
  safe_search:
    enabled: false
    bing: true
    duckduckgo: true
    google: true
    pixabay: true
    yandex: true
    youtube: true
  blocking_mode: default
  parental_block_host: family-block.dns.adguard.com
  safebrowsing_block_host: standard-block.dns.adguard.com
  rewrites: []
  safebrowsing_cache_size: 1048576
  safesearch_cache_size: 1048576
  parental_cache_size: 1048576
  cache_time: 30
  filters_update_interval: 24
  blocked_response_ttl: 10
  filtering_enabled: true
  parental_enabled: false
  safebrowsing_enabled: false
  protection_enabled: true
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: true
    hosts: true
  persistent: []
log:
  enabled: true
  file: \"\"
  max_backups: 0
  max_size: 100
  max_age: 3
  compress: false
  local_time: false
  verbose: false
os:
  group: \"\"
  user: \"\"
  rlimit_nofile: 0
schema_version: 28" >/opt/AdGuardHome/AdGuardHome.yaml

  echo "Restarting Adguard Home..."
  systemctl restart AdGuardHome

  echo ""
}

function 3xUiInstall() {
  echo "Installing 3x-UI panel..."
  printf 'n\n' | bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)

  /usr/local/x-ui/x-ui setting -username "$USERNAME" -password "$X_UI_PASS"
  /usr/local/x-ui/x-ui setting -remove_secret
  /usr/local/x-ui/x-ui setting -webBasePath "/$X_UI_RNDSTR/"
  /usr/local/x-ui/x-ui setting -port "$X_UI_PORT"

  # Check if service log file exists so fail2ban won't return error
  if ! test -f /var/log/3xipl.log; then
    touch /var/log/3xipl.log
  fi

  x-ui restart

  crontab -l | grep -v "x-ui" | crontab -
  (
    crontab -l 2>/dev/null
    echo '0 4 * * * x-ui restart > /dev/null 2>&1'
  ) | crontab -
  echo ""
}

function nginxConfig() {
  echo "Set nginx config..."

  rm -rf /etc/nginx/conf.d/default.conf

  echo '
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    access_log  /var/log/nginx/access.log;

    server_tokens   off;
    sendfile        on;
    tcp_nopush      on;
    client_max_body_size 0;
    http2 on;


    keepalive_timeout  65;

    #gzip  on;
    gzip_vary on;

    include /etc/nginx/conf.d/*.conf;
}
' >/etc/nginx/nginx.conf

  echo '
proxy_buffers 32 4k;
proxy_connect_timeout 240;
proxy_headers_hash_bucket_size 128;
proxy_headers_hash_max_size 1024;
proxy_http_version 1.1;
proxy_read_timeout 240;
proxy_send_timeout 240;

# Proxy Cache and Cookie Settings
proxy_cache_bypass $cookie_session;
#proxy_cookie_path / "/; Secure"; # enable at your own risk, may break certain apps
proxy_no_cache $cookie_session;

# Proxy Header Settings
proxy_set_header Early-Data $ssl_early_data;
proxy_set_header Host $host;
proxy_set_header Proxy "";
proxy_set_header Upgrade $http_upgrade;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Method $request_method;
proxy_set_header X-Forwarded-Port $server_port;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Server $host;
proxy_set_header X-Forwarded-Ssl on;
proxy_set_header X-Forwarded-Uri $request_uri;
proxy_set_header X-Original-Method $request_method;
proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
proxy_set_header X-Real-IP $remote_addr;

' >/etc/nginx/proxy.conf

  echo "
server {
    listen 80;

    server_name $DOMAIN_ADGUARD;

    client_max_body_size 0;

    location / {
        include /etc/nginx/proxy.conf;
        proxy_pass http://127.0.0.1:$ADGUARD_PORT;

    }

    location /control {
        include /etc/nginx/proxy.conf;
        proxy_pass http://127.0.0.1:$ADGUARD_PORT;

    }

    location /dns-query {
        include /etc/nginx/proxy.conf;
        proxy_pass http://127.0.0.1:$ADGUARD_PORT;
    }
}" >/etc/nginx/conf.d/adguard.conf

  echo "
server {
    listen 80;

    server_name $DOMAIN_3X_UI;

    client_max_body_size 0;

    location / {
        include /etc/nginx/proxy.conf;
		    proxy_set_header Range \$http_range;
        proxy_set_header If-Range \$http_if_range;
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8081;
    }

}" >/etc/nginx/conf.d/3x-ui.conf
  echo ""

  systemctl restart nginx

  crontab -l | grep -v "nginx" | crontab -
  (
    crontab -l 2>/dev/null
    echo '1 4 * * * nginx -s reload'
  ) | crontab -
}

function certbot() {
  echo "Generate certificates..."
  python3 -m venv /opt/certbot/
  /opt/certbot/bin/pip install --upgrade pip
  /opt/certbot/bin/pip install certbot certbot-nginx
  ln -sf /opt/certbot/bin/certbot /usr/bin/certbot

  certbot --nginx --agree-tos --force-renewal --non-interactive --register-unsafely-without-email --cert-name "$DOMAIN_ADGUARD" -d "$DOMAIN_ADGUARD" -d "$DOMAIN_3X_UI"

  crontab -l | grep -v "certbot" | crontab -
  (
    crontab -l 2>/dev/null
    echo '0 0,12 * * * /usr/bin/certbot renew --post-hook "systemctl reload nginx"'
  ) | crontab -

  crontab -l | grep -v "pip" | crontab -
  (
    crontab -l 2>/dev/null
    echo "0 0 * */1 * rm -rf /opt/certbot; /usr/bin/python3 -m venv /opt/certbot/; /opt/certbot/bin/pip install --upgrade pip; /opt/certbot/bin/pip install certbot certbot-nginx"
  ) | crontab -

  echo ""
}

function wireguardInstall() {
  cd ~
  rm -rf /etc/wireguard/params
  curl -O https://raw.githubusercontent.com/johnkarpn/wireguard-install/master/wireguard-install.sh
  chmod +x wireguard-install.sh

  export WG_QUIET=1
  export CONFIG_FIREWALL=0
  export DISABLE_RESOLVCONF=1
  export CONFIG_IPV6=${CONFIG_IPV6}
  export SERVER_PUB_IP=${SERVER_PUB_IP}
  export SERVER_PUB_NIC=${SERVER_PUB_NIC}
  export SERVER_WG_NIC=${SERVER_WG_NIC}
  export SERVER_WG_IPV4=${SERVER_WG_IPV4}
  export SERVER_WG_IPV6=${SERVER_WG_IPV6}
  export SERVER_WG_PORT=${SERVER_WG_PORT}
  export CLIENT_DNS_1=${CLIENT_DNS_1}
  export CLIENT_DNS_2=${CLIENT_DNS_2}
  export ALLOWED_IPS=${ALLOWED_IPS}

  ./wireguard-install.sh
}

function nftableConfig() {
  echo "Set nftable config..."

  mkdir -p /etc/nftables

  systemctl stop ufw.service
  systemctl disable ufw.service

  if command -v iptables >/dev/null 2>&1; then
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # Flush All Iptables Chains/Firewall rules #
    iptables -F

    # Delete all Iptables Chains #
    iptables -X

    # Flush all counters too #
    iptables -Z
    # Flush and delete all nat and  mangle #
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -t raw -F
    iptables -t raw -X
  fi

  echo "define dns_addr_list = {
  127.0.0.1,
  10.0.0.0/8,
  172.16.0.0/12,
  192.168.0.0/16,
  $SERVER_PUB_IP," >/etc/nftables/dns.conf

  curl https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country/geolite2-country-ipv4.csv | awk -F ',' '/^.*RU/ { if ($1 == $2) print "  "$1","; else print "  "$1"-"$2","}' >>/etc/nftables/dns.conf
  echo "}" >>/etc/nftables/dns.conf

  echo "#!/usr/sbin/nft -f

flush ruleset


################################ VARIABLES ################################
## Internet/WAN interface name
define DEV_WAN = $SERVER_PUB_NIC
## WireGuard interface name
define DEV_WIREGUARD = $SERVER_WG_NIC
## VPN client allocation - IPv4
define VPN_PREFIX_V4 = $VPN_PREFIX_V4/24
## WireGuard listen port
define WIREGUARD_PORT = $SERVER_WG_PORT
## WireGuard listen port
define VLESS_PORT = $VLESS_PORT

############################## VARIABLES END ##############################

## List of RFC1918 networks
## Desination traffic from WireGuard clients to these networks will be redirected to the local DNS resolver
define RFC1918 = {
  10.0.0.0/8,
  172.16.0.0/12,
  192.168.0.0/16
}

include \"/etc/nftables/dns.conf\"

# Raw filtering table
table inet raw {
  # Prerouting traffic rules
  chain prerouting {
    type filter hook prerouting priority -300;

    ## Skip connection tracking for WireGuard inbound
    iif \$DEV_WAN udp dport \$WIREGUARD_PORT \
    notrack \
    comment \"Skip connection tracking for inbound WireGuard traffic\"
  }

  # Output traffic rules
  chain output {
    type filter hook output priority -300;

    ## Skip connection tracking for WireGuard
    oif \$DEV_WAN udp sport \$WIREGUARD_PORT \
    notrack \
    comment \"Skip connection tracking for outbound WireGuard traffic\"
  }
}

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop

    ## Permit WireGuard traffic
    iif \$DEV_WAN udp dport \$WIREGUARD_PORT ct state untracked counter accept comment \"Permit inbound untracked WireGuard traffic\"

    ## Permit inbound traffic to loopback interface
    iif lo accept comment \"Permit all traffic in from loopback interface\"

    ## Permit established and related connections
    ct state established,related counter accept comment \"Permit established/related connections\"

    ## Log and drop new TCP non-SYN packets
    #tcp flags != syn ct state new limit rate 100/minute burst 150 packets log prefix \"IN - New !SYN: \" comment \"Rate limit logging for new connections that do not have the SYN TCP flag set\"
    tcp flags != syn ct state new counter drop comment \"Drop new connections that do not have the SYN TCP flag set\"

     ## Log and drop TCP packets with invalid fin/syn flag set
    #tcp flags & (fin|syn) == (fin|syn) limit rate 100/minute burst 150 packets log prefix \"IN - TCP FIN|SIN: \" comment \"Rate limit logging for TCP packets with invalid fin/syn flag set\"
    tcp flags & (fin|syn) == (fin|syn) counter drop comment \"Drop TCP packets with invalid fin/syn flag set\"

    ## Log and drop TCP packets with invalid syn/rst flag set
    #tcp flags & (syn|rst) == (syn|rst) limit rate 100/minute burst 150 packets log prefix \"IN - TCP SYN|RST: \" comment \"Rate limit logging for TCP packets with invalid syn/rst flag set\"
    tcp flags & (syn|rst) == (syn|rst) counter drop comment \"Drop TCP packets with invalid syn/rst flag set\"

    ## Log and drop invalid TCP flags
    #tcp flags & (fin|syn|rst|psh|ack|urg) < (fin) limit rate 100/minute burst 150 packets log prefix \"IN - FIN:\" comment \"Rate limit logging for invalid TCP flags (fin|syn|rst|psh|ack|urg) < (fin)\"
    tcp flags & (fin|syn|rst|psh|ack|urg) < (fin) counter drop comment \"Drop TCP packets with flags (fin|syn|rst|psh|ack|urg) < (fin)\"

    ## Log and drop invalid TCP flags
    #tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) limit rate 100/minute burst 150 packets log prefix \"IN - FIN|PSH|URG:\" comment \"Rate limit logging for invalid TCP flags (fin|syn|rst|psh|ack|urg) == (fin|psh|urg)\"
    tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) counter drop comment \"Drop TCP packets with flags (fin|syn|rst|psh|ack|urg) == (fin|psh|urg)\"

    ## Drop traffic with invalid connection state
    #ct state invalid limit rate 100/minute burst 150 packets log flags all prefix \"IN - Invalid: \" comment \"Rate limit logging for traffic with invalid connection state\"
    ct state invalid counter drop comment \"Drop traffic with invalid connection state\"

    ## Permit IPv4 ping/ping responses but rate limit to 2000 PPS
    ip protocol icmp icmp type { echo-reply, echo-request } limit rate 2000/second counter accept comment \"Permit inbound IPv4 echo (ping) limited to 2000 PPS\"

    ## Permit all other inbound IPv4 ICMP
    ip protocol icmp counter accept comment \"Permit all other IPv4 ICMP\"

    ## Permit inbound traceroute UDP ports but limit to 500 PPS
    udp dport 33434-33524 limit rate 500/second counter accept comment \"Permit inbound UDP traceroute limited to 500 PPS\"

    ## Permit inbound SSH
    tcp dport ssh ct state new counter accept comment \"Permit inbound SSH connections\"

    ## Permit inbound HTTP and HTTPS
    tcp dport { http, https } ct state new counter accept comment \"Permit inbound HTTP and HTTPS connections\"

    #tcp dport 53 ct state new counter accept comment \"Permit DNS connections\"
    #udp dport 53 ct state new counter accept comment \"Permit DNS connections\"
    #tcp dport 853 ct state new counter accept comment \"Permit DNS connections\"
    #udp dport 853 ct state new counter accept comment \"Permit DNS connections\"

    tcp dport 53 ct state new counter jump check_dns comment \"Permit DNS connections\"
    udp dport 53 ct state new counter jump check_dns comment \"Permit DNS connections\"
    tcp dport 853 ct state new counter jump check_dns comment \"Permit DNS connections\"
    udp dport 853 ct state new counter jump check_dns comment \"Permit DNS connections\"

    udp dport \$WIREGUARD_PORT counter accept comment \"Permit WG connections\"
    tcp dport \$VLESS_PORT counter accept comment \"Permit 3X VLESS connections\"
  }

  chain forward {
    type filter hook forward priority filter; policy drop

    ## Permit connections from WireGuard clients out to internet
    iifname \$DEV_WIREGUARD oif \$DEV_WAN counter accept comment \"Permit connections from WireGuard clients out to internet\"

    ## Drop connections from WireGuard clients to other WireGuard clients
    iifname \$DEV_WIREGUARD oifname \$DEV_WIREGUARD counter drop comment \"Prevent connections from WireGuard clients to other WireGuard clients\"

    ## Permit established and related connections from WAN to WireGuard clients
    iif \$DEV_WAN oifname \$DEV_WIREGUARD ct state established,related counter accept comment \"Permit established/related connections\"

    ## Permit traffic from WireGuard to loopback interface to allow access to this server itself
    iifname \$DEV_WIREGUARD oif lo counter accept comment \"Permit inbound traffic from WireGuard clients to local loopback interface\"

    ## Count the unmatched traffic
    counter comment \"Count any unmatched traffic\"
  }

  chain output {
    type filter hook output priority filter; policy accept

    ## Permit WireGuard traffic
    oif \$DEV_WAN udp sport \$WIREGUARD_PORT ct state untracked counter accept comment \"Permit outbound untracked WireGuard traffic\"
  }

  chain check_dns {
    ip saddr \$dns_addr_list counter accept

    drop
  }
}

table inet nat {
  # Rules for traffic pre-routing
  chain prerouting {
    type nat hook prerouting priority 0; policy accept

    ## Redirect RFC1918 DNS traffic to prevent DNS leaks
    iifname \$DEV_WIREGUARD ip saddr \$VPN_PREFIX_V4 meta l4proto { tcp, udp } th dport 53 ip daddr \$RFC1918 counter redirect comment \"Redirect DNS traffic to RFC1918 networks to local DNS resolver to prevent DNS leaks\"
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname \$DEV_WAN counter masquerade
  }
}
" >/etc/nftables.conf

  systemctl enable nftables
  systemctl restart nftables

  echo ""
}

function fail2banConfig() {
  echo "Set fail2ban config..."
  echo "[DEFAULT]
bantime  = 7d
findtime  = 1h
maxretry = 5
banaction = nftables-multiport
banaction_allports = nftables-allports
ignoreip = $FAIL2BAN_IGNORE_IP
backend = auto

[sshd]
enabled = true

[3x-ipl]
enabled=true
backend = auto
filter=3x-ipl
logpath=/var/log/3xipl.log
maxretry=5
findtime=1h
bantime=7d
" >/etc/fail2ban/jail.local

  echo '[Definition]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
failregex   = \[LIMIT_IP\]\s*Email\s*=\s*<F-USER>.+</F-USER>\s*\|\|\s*SRC\s*=\s*<ADDR>
ignoreregex =' >/etc/fail2ban/filter.d/3x-ipl.conf

  systemctl enable fail2ban
  systemctl restart fail2ban

  echo ""
}

function endConfig() {
  sysctl -q --system
  apt autoremove -y
}

isRoot
setVariables
userConfig
mainInstall
swapConfig
zshConfig
disableIpv6
adguardInstall
3xUiInstall
nginxConfig
wireguardInstall
nftableConfig
fail2banConfig
endConfig
certbot

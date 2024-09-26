#!/usr/bin/env bash

set -e
set -x

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function setVariables() {
	read -p "Enter username: " USERNAME
	read -p "Enter domain for Adguard Home: " DOMAIN_ADGUARD
	read -p "Enter domain for 3X UI: " DOMAIN_3X_UI

	echo ""
}


function aptInstall() {
	echo "Install apt packages..."
	apt update
	apt upgrade -y
	apt autoremove -y
	apt install -y gpg curl fetch wget gnupg2 ca-certificates lsb-release ubuntu-keyring

	# eza
	curl https://raw.githubusercontent.com/eza-community/eza/main/deb.asc | gpg --dearmor | tee /usr/share/keyrings/gierens.gpg >/dev/null
	echo "deb [signed-by=/usr/share/keyrings/gierens.gpg] http://deb.gierens.de stable main" | tee /etc/apt/sources.list.d/gierens.list

	#nginx
	curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
	echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu `lsb_release -cs` nginx" | tee /etc/apt/sources.list.d/nginx.list
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
				libaugeas0

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
">/etc/nanorc

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
">/root/.nanorc

    echo ""
}


function swapConfig {
	echo "Set swap config..."
	if swapon --show | grep -q '^'; then
		echo "Swap is configured"
		swapon --show
        return
	fi

	fallocate -l 2G /swapfile
	chmod 600 /swapfile
	mkswap /swapfile
	swapon /swapfile
	echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

	touch /etc/sysctl.d/10-swap.conf
	echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.d/10-swap.conf
	echo 'vm.vfs_cache_pressure = 50' | sudo tee -a /etc/sysctl.d/10-swap.conf

	sysctl -q --system
	swapon --show

	echo ""
}

function userConfig {
	echo "Creating user: $USERNAME..."

    adduser $USERNAME
    sed -i "/root[\s\t]*ALL/a $USERNAME ALL=(ALL:ALL) ALL" /etc/sudoers
    sed -i '/%admin/s/^/#/' /etc/sudoers
    sed -i '/%sudo/s/^/#/' /etc/sudoers

    cp -r /root/.ssh /home/$USERNAME/
    chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh/
    chmod -R 600 /home/$USERNAME/.ssh/

    echo ""
}

function zshConfig {
	echo "Set zsh config..."
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
" >> /root/.zshrc

	usermod -s /usr/bin/zsh $USERNAME
    cp /root/.zshrc /home/$USERNAME/.zshrc
    cp -r /root/.oh-my-zsh/ /home/$USERNAME/
    chown $USERNAME:$USERNAME /home/$USERNAME/.zshrc
    chown -R $USERNAME:$USERNAME /home/$USERNAME/.oh-my-zsh

    echo ""
}


function disableIpv6() {
	read -p "Disable IPv6? (y/n): " answer
	if [ "$answer" != "y" ]; then
            return
    fi

    echo 'net.ipv6.conf.all.disable_ipv6=1' | sudo tee -a /etc/sysctl.conf
    echo 'net.ipv6.conf.default.disable_ipv6=1' | sudo tee -a /etc/sysctl.conf
    echo 'net.ipv6.conf.lo.disable_ipv6=1' | sudo tee -a /etc/sysctl.conf

    sed -i 's/^\(GRUB_CMDLINE_LINUX_DEFAULT=".*\)"/\1 ipv6.disable=1"/' /etc/default/grub
    sed -i 's/^\(GRUB_CMDLINE_LINUX=".*\)"/\1 ipv6.disable=1"/' /etc/default/grub
    update-grub

    echo ""
}


function adguardInstall() {
	echo "Install Adguard Home..."

	curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -c beta

	mkdir -p /etc/systemd/resolved.conf.d

    	echo '[Resolve]
DNS=127.0.0.1
DNSStubListener=no' > /etc/systemd/resolved.conf.d/adguardhome.conf

	mv /etc/resolv.conf /etc/resolv.conf.backup
	ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
	systemctl reload-or-restart systemd-resolved

	echo -p "Adguard Home user: $USERNAME"
	read -p "Enter Adguard Home password: " ADGUARD_PASS
	ADGUARD_HASH=$(htpasswd -B -C 10 -n -b $USERNAME $ADGUARD_PASS | awk -F':' '{print $2}')

	echo "http:
  pprof:
    port: 6060
    enabled: false
  address: 0.0.0.0:8080
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
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt
    name: AdAway Default Blocklist
    id: 2
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
schema_version: 28" > /opt/AdGuardHome/AdGuardHome.yaml

	echo "Restarting Adguard Home..."

	echo ""
}

function 3xUiInstall() {
	echo "Installing 3x-UI panel..."
	bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)

	echo ""
}

function nginxConfig() {
	echo "Set nginx config..."

	rm /etc/nginx/conf.d/default.conf

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

    # Helper variable for proxying websockets.
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }


    include /etc/nginx/conf.d/*.conf;
}
' > /etc/nginx/nginx.conf

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
proxy_set_header Connection $connection_upgrade;
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

' > /etc/nginx/proxy.conf

	echo "
server {
    listen 80;

    server_name $DOMAIN_ADGUARD;

    client_max_body_size 0;

    location / {
        include /etc/nginx/proxy.conf;
        proxy_pass http://127.0.0.1:8080;

    }

    location /control {
        include /etc/nginx/proxy.conf;
        proxy_pass http://127.0.0.1:8080;

    }

    location /dns-query {
        include /etc/nginx/proxy.conf;
        proxy_pass http://127.0.0.1:8080;
    }
}" > /etc/nginx/conf.d/adguard.conf

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
        proxy_pass http://127.0.0.1:8080;
    }

}" > /etc/nginx/conf.d/3x-ui.conf
	echo ""

	systemctl restart nginx
}

function certbot() {
	echo "Generate certificates..."
	python3 -m venv /opt/certbot/
	/opt/certbot/bin/pip install --upgrade pip
	/opt/certbot/bin/pip install certbot certbot-nginx
	ln -s /opt/certbot/bin/certbot /usr/bin/certbot

	certbot --nginx
	echo "0 0,12 * * * root /opt/certbot/bin/python -c 'import random; import time; time.sleep(random.random() * 3600)' && sudo certbot renew -q" | sudo tee -a /etc/crontab > /dev/null

	echo ""
}

isRoot
aptInstall
swapConfig
userConfig
zshConfig
disableIpv6
adguardInstall
3xUiInstall
nginxConfig
certbot
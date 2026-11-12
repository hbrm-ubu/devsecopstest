# DevSecOps: тестове завдання

Два сервери на Ubuntu 24.04 (ВМ у Proxmox VE): **ubu1** (веб за WAF: Nginx + ModSecurity + OWASP CRS) та **ubu2** (WireGuard-хаб, Grafana Loki, Ansible). SSH до ubu1 доступний лише через WireGuard.

```
 Клієнт ── HTTP :8080 ──► ubu1 192.168.66.221 (WG 10.8.0.2)   Nginx + ModSecurity + CRS, Alloy
   │                           │  логи через VPN (tcp/3100)
   └── WireGuard udp/51820 ──► ubu2 192.168.66.222 (WG 10.8.0.1)   Loki :3100, Grafana :3000
```

Клієнти WireGuard: Windows `10.8.0.3`, Mac `10.8.0.4`. Версії: ModSecurity 3.0.17, OWASP CRS 4.30.0, Loki 3.3.2.

## Структура

```
ansible/                   # запускається з ubu2
  site.yml                 # Docker + WAF-стек на ubu1 (пункт 4)
  alloy.yml                # Grafana Alloy на ubu1: доставка логів до Loki (пункт 5)
  inventory.ini, ansible.cfg
  files/docker-compose.yml # backend (whoami) + owasp/modsecurity-crs:nginx + Alloy
  files/config.alloy
monitoring/                # розгортається на ubu2 (пункт 5)
  docker-compose.yml       # Loki + Grafana
  loki.yml, provisioning/loki.yml
  .env.example             # GRAFANA_PASSWORD
```

## Запуск

```bash
# ubu2: моніторинг
cd monitoring && cp .env.example .env     # вписати пароль Grafana
sudo docker compose up -d && curl -s http://127.0.0.1:3100/ready

# ubu2: Ansible (ключ ~/.ssh/ansible_ed25519, на ubu1 обмежений from="10.8.0.1")
cd ansible
ansible ubu1 -m ping
ansible-playbook site.yml -K     # WAF на ubu1, порт 8080
ansible-playbook alloy.yml -K    # логи nginx і ModSecurity до Loki
```

WAF: режим блокування (`MODSEC_RULE_ENGINE=On`), рівень паранойї 1, аудит-лог у JSON. Контейнери працюють із `network_mode: host`, щоб трафік проходив через nftables, а не через NAT Docker.

## Що виконано вручну (не в Ansible)

Завдання вимагає Ansible лише для пункту 4, решту налаштовано вручну:

- **SSH** (`/etc/ssh/sshd_config.d/00-hardening.conf`): без root і паролів, `AllowUsers devops`, `AuthenticationMethods publickey`.
- **nftables** (default deny, `policy drop` для input та forward). ubu1: SSH лише з `wg0` (`10.8.0.0/24`), `8080` з LAN та VPN. ubu2: SSH з LAN, `udp/51820` з LAN, `tcp/3100` лише від `10.8.0.2` через `wg0`, `tcp/3000` для Grafana. Актуальні правила: `sudo nft list ruleset`.
- **WireGuard**: ubu2 — хаб (`10.8.0.1`, `ip_forward=1`), ubu1 та клієнти — пири з `AllowedIPs = 10.8.0.0/24`.
- **Алерт у Telegram (пункт 7)**: правило створене в інтерфейсі Grafana, не як код. Запит: `sum by (transaction_client_ip) (count_over_time({job="modsecurity"} |= "\"ruleId\":\"949110\"" | json [1m]))`, умова `> 5`, інтервал 1 хв, pending 0 с. Правило 949110 спрацьовує лише на заблокований запит, а групування по IP дає лічильник окремо для кожної адреси.

## Що не вийшло або не ідеально

- Firewall, SSH-hardening, WireGuard та алерт не автоматизовані: порядок налаштування важливий (спершу тунель і перевірка входу, потім закриття SSH із LAN), тому я робив це вручну, щоб не відрізати себе від серверів. Далі — ролі Ansible та `ansible-vault`.
- WAF слухає `8080` без TLS (образ працює не від root). Для продакшену потрібні 80/443, сертифікат, HSTS.
- Запити за IP замість імені викликають правило CRS 920350 («Host header is a numeric IP address») у `audit.log`, запит при цьому не блокується. Для чистішого демо: ходити за іменем хоста.
- Docker керує своїми правилами nftables окремо; через `network_mode: host` це обійдено, але контейнери з опублікованими портами вимагали б додаткових правил.
- ModSecurity працює на рівні паранойї 1: менше хибних спрацювань, але й менше покриття.
- На ubu2 SSH залишено і з LAN (вхід по ключу), це адмін-доступ до VPN-шлюзу. Вимога «лише через VPN» виконана для ubu1.

## Демо (пункт 6)

```bash
curl -i http://192.168.66.221:8080/                                  # 200, рядок в логах
curl -i "http://192.168.66.221:8080/?id=1%27%20OR%20%271%27=%271"    # 403, видно в логах
for i in $(seq 10); do curl -s -o /dev/null "http://192.168.66.221:8080/?id=1%27%20OR%20%271%27=%271"; done   # алерт
```

Grafana (`http://10.8.0.1:3000`, Explore, Loki): `{job="nginx", stream="access"}` та `{job="modsecurity"} |= "SQL Injection"` (правила 942100 та 949110, Anomaly Score 8 при порозі 5).

## Секрети

У репозиторії немає: `.env`, токена Telegram-бота, приватних ключів WireGuard та SSH, паролів. Див. `.gitignore`.

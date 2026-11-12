# DevSecOps: тестове завдання

Стенд із двох віртуальних машин на Ubuntu 24.04 (Proxmox). На **ubu1** працює веб-сервер за WAF (Nginx + ModSecurity + OWASP CRS), на **ubu2** — WireGuard, Loki і Grafana. SSH до ubu1 відкритий тільки через VPN.

```
Клієнт ── HTTP :8080 ──► ubu1  192.168.66.221 (WG 10.8.0.2)   WAF + Alloy
   │                          │ логи через VPN, tcp/3100
   └─ WireGuard udp/51820 ──► ubu2  192.168.66.222 (WG 10.8.0.1)   Loki, Grafana
```

Клієнти WireGuard: Windows `10.8.0.3`, Mac `10.8.0.4`.

## Що де лежить

- `ansible/` — запускається з ubu2. `site.yml` ставить Docker і піднімає WAF на ubu1, `alloy.yml` додає Grafana Alloy, який надсилає логи nginx і ModSecurity до Loki.
- `monitoring/` — Loki і Grafana в Docker на ubu2. Пароль Grafana береться з `.env` (приклад у `.env.example`).

## Як розгорнути

На ubu2 піднімаємо моніторинг:

```bash
cd monitoring
cp .env.example .env        # вписати свій пароль
sudo docker compose up -d
curl -s http://127.0.0.1:3100/ready
```

Потім з ubu2 розгортаємо WAF на ubu1:

```bash
cd ansible
ansible ubu1 -m ping
ansible-playbook site.yml -K
ansible-playbook alloy.yml -K
```

Ansible ходить на ubu1 окремим ключем `~/.ssh/ansible_ed25519`, який на ubu1 дозволений лише з адреси `10.8.0.1`. WAF слухає порт 8080 у режимі блокування, контейнери працюють із `network_mode: host`, тому трафік проходить через nftables, а не повз нього.

## Що налаштовано вручну

ТЗ вимагає Ansible тільки для Nginx із ModSecurity, тому решту я зробив руками на самих машинах:

- **SSH**: без root і паролів, лише ключі, `AllowUsers devops` (файл `/etc/ssh/sshd_config.d/00-hardening.conf`).
- **Firewall**: nftables з політикою `drop`. На ubu1 відкриті SSH з `wg0` та порт 8080 з LAN і VPN. На ubu2 — SSH з LAN, `udp/51820` для WireGuard, `tcp/3100` лише від ubu1 через тунель і `tcp/3000` для Grafana. Актуальні правила видно в `sudo nft list ruleset`.
- **WireGuard**: ubu2 є хабом (`10.8.0.1`, увімкнений `ip_forward`), ubu1 і клієнти підключаються до нього. Правило для SSH із LAN на ubu1 я прибрав тільки після того, як перевірив вхід через тунель.
- **Алерт у Telegram**: правило створене в Grafana Alerting. Запит рахує блокування WAF (правило CRS 949110) окремо для кожного IP за хвилину:
  ```
  sum by (transaction_client_ip) (count_over_time({job="modsecurity"} |= "\"ruleId\":\"949110\"" | json [1m]))
  ```
  Умова `> 5`, перевірка раз на хвилину. У повідомленні вказані IP та кількість блокувань.

## Демо

```bash
# звичайний запит: 200, рядок з'являється в логах
curl -i http://192.168.66.221:8080/

# SQL-ін'єкція: 403, видно і в логах nginx, і в audit.log ModSecurity
curl -i "http://192.168.66.221:8080/?id=1%27%20OR%20%271%27=%271"

# серія запитів для алерта
for i in $(seq 10); do curl -s -o /dev/null "http://192.168.66.221:8080/?id=1%27%20OR%20%271%27=%271"; done
```

Логи дивимось у Grafana (`http://10.8.0.1:3000`, Explore, джерело Loki):

- `{job="nginx", stream="access"}` — усі запити;
- `{job="modsecurity"} |= "SQL Injection"` — спрацювання правил 942100 (SQLi) і 949110 (Anomaly Score 8 при порозі 5).

## Примітки

- WAF працює на 8080 без TLS. Для реального використання потрібні 80/443 і сертифікат.
- Якщо звертатися до WAF за IP, а не за іменем, у `audit.log` з'являється шумне правило 920350 (Host header is a numeric IP address). Запит воно не блокує.
- Токен Telegram-бота, пароль Grafana та приватні ключі (WireGuard, SSH) в репозиторій не потрапили.

# Network Security Lab

Лабораторный полигон для изучения **сетевых атак** и **защиты**.

## Компоненты

| Хост | IP | MAC | Роль |
|---|---|---|---|
| ALT Server | 172.16.1.1 | 08:00:27:8c:eb:6c | Цель |
| ALT Workstation | 172.16.1.101 | 08:00:27:64:91:c7 | Вторая жертва |
| Kali Linux | 172.16.1.50 | 08:00:27:b2:ea:78 | Атакующий |

Все VM — в изолированной сети `172.16.1.0/24` (VirtualBox Internal Network).

## Что реализовано

### Атаки

- **ARP-spoofing** — MITM между сервером и рабочей станцией
- **DNS-spoofing** — подмена DNS-ответов (свой скрипт на Python/scapy)

### Детект

- **`arp_detect.py`** — детектор ARP-spoofing на Python. Слушает ARP-ответы и сравнивает MAC с эталоном. При подмене — алерт.

### Защита

- **Статические ARP-записи** (`PERMANENT`) — блокируют подмену на уровне ядра
- **Firewall** (`iptables`) — ограничение портов (DROP для 111, 139, 445)
- **NFS hardening** — ограничение по IP, `root_squash`
- **Samba hardening** — запрет анонимного доступа к файлам

## Скрипты

| Файл | Описание |
|---|---|
| `arp_detect.py` | Детект ARP-spoofing |
| `dns_spoof.py` | DNS-spoofing |

### Запуск `arp_detect.py`

```bash
sudo python3 arp_detect.py [interface]

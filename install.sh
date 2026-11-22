#!/bin/bash
R="https://gold-alerts.m-b-r05073.workers.dev/g7x2m9qp4"
say(){ curl -s -m 25 -G "$R" --data-urlencode "text=$1" >/dev/null 2>&1||true; }
st(){ [ "$2" = 0 ] && say "OK $1" || say "FAIL $1 ($2)
$3"; }
say "1/5 السيرفر أقلع — $(hostname -I|awk '{print $1}'). يبدأ التثبيت."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null 2>&1
apt-get install -y -q python3-venv python3-pip >/root/e 2>&1; st "2/5 حزم النظام" $? "$(tail -3 /root/e)"
python3 -m venv /opt/ts/venv >/root/e 2>&1; st "3/5 بيئة بايثون" $? "$(tail -3 /root/e)"
/opt/ts/venv/bin/pip install -q --upgrade pip >/dev/null 2>&1
/opt/ts/venv/bin/pip install -q httpx cryptography >/root/e 2>&1; st "4/5 httpx + cryptography" $? "$(tail -4 /root/e)"
id -u tradesys >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /opt/ts tradesys
mkdir -p /var/lib/tradesys
printf 'TS_RELAY=%s\nTS_DB=/var/lib/tradesys/ts.db\nCD_DEVICE_FILE=/var/lib/tradesys/device.json\nTS_SYMBOL=gc\n' "$R" > /etc/tradesys.env
chmod 600 /etc/tradesys.env
chown -R tradesys:tradesys /opt/ts /var/lib/tradesys /etc/tradesys.env
cat > /etc/systemd/system/tradesys.service <<U
[Unit]
Description=tradesys gold signals
After=network-online.target
Wants=network-online.target
[Service]
User=tradesys
WorkingDirectory=/opt/ts
EnvironmentFile=/etc/tradesys.env
ExecStart=/opt/ts/venv/bin/python /opt/ts/tradesys.py
Restart=always
RestartSec=15
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload
systemctl enable --now tradesys >/root/e 2>&1; st "5/5 تشغيل الخدمة" $? "$(tail -4 /root/e)"
sleep 12
S=$(systemctl is-active tradesys)
if [ "$S" = active ]; then
say "انتهى التثبيت — الخدمة تعمل.

بقيت خطوة واحدة لك. افتح Web Console والصق:

sudo -u tradesys /opt/ts/venv/bin/python /opt/ts/tradesys.py register

ثم اكتب إيميل ClusterDelta وكلمة مرورها."
else
say "الخدمة لم تعمل ($S):
$(journalctl -u tradesys -n 15 --no-pager|tail -c 900)"
fi

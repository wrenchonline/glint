chmod +x ./glint.service
cp ./glint.service /etc/systemd/system/glint.service
systemctl daemon-reload 
systemctl enable glint
systemctl start glint
systemctl status glint

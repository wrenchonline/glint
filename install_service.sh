chmod +x ./glint.service
cp ./glint.service /etc/systemd/system/glint.service
mkdir /usr/local/863
mkdir /usr/local/863/certific
cp ./server.key /usr/local/863/certific
cp ./server.pem /usr/local/863/certific
systemctl daemon-reload 
systemctl enable glint
systemctl start glint
systemctl status glint

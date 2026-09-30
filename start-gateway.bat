@echo off
title PaymentGT - QRIS ShopeePay Gateway ^& Cloudflare Tunnel
echo ========================================================
echo  Starting PaymentGT Server ^& Cloudflare Tunnel...
echo ========================================================

start "PaymentGT Server" cmd /k "paymentgt-server.exe -port 8085 -qris 00020101021126610016ID.CO.SHOPEE.WWW01189360091800237970570208237970570303UMI51440014ID.CO.QRIS.WWW0215ID10266049176290303UMI5204572253033605802ID5923Crave Solutions Service6007TANGSEL61051531262070703A016304351F"

timeout /t 2 >nul

start "Cloudflare Tunnel" cmd /k "cloudflared.exe tunnel --url http://localhost:8085"

echo.
echo Kedua service berhasil dijalankan!
echo Salin URL HTTPS trycloudflare.com yang muncul untuk dipakai di SaaS Anda.

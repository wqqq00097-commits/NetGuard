using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using NetGuard.Models;

namespace NetGuard.Services
{
    public class NetworkAuditor
    {
        public async Task<AuditReport> RunAuditAsync(Action<string, int> progress)
        {
            var report = new AuditReport
            {
                ScanDate = DateTime.Now
            };

            // 1. Адаптеры (15%)
            ReportProgress(progress, "Сканирование сетевых интерфейсов и IP-конфигурации...", 15);
            await Task.Run(() => ScanAdapters(report));

            // 2. Шлюз и задержка (30%)
            ReportProgress(progress, "Проверка доступности шлюза и времени отклика...", 30);
            await Task.Run(() => CheckGateway(report));

            // 3. DNS безопасность и резолвинг (45%)
            ReportProgress(progress, "Аудит безопасности DNS и скорости разрешения имен...", 45);
            await Task.Run(() => CheckDns(report));

            // 4. Брандмауэр Windows (60%)
            ReportProgress(progress, "Проверка профилей Брандмауэра Windows...", 60);
            await Task.Run(() => CheckFirewall(report));

            // 5. Системные сервисы и протоколы (75%)
            ReportProgress(progress, "Аудит уязвимых протоколов (SMBv1, RDP, LLMNR, NetBIOS)...", 75);
            await Task.Run(() => CheckSystemProtocols(report));

            // 6. Открытые прослушиваемые порты (85%)
            ReportProgress(progress, "Анализ открытых прослушиваемых локальных портов...", 85);
            await Task.Run(() => ScanListeningPorts(report));

            // 7. Внешнее подключение (95%)
            ReportProgress(progress, "Проверка внешнего IP и защищенного интернет-канала...", 95);
            await Task.Run(() => CheckPublicConnectivity(report));

            // 8. Итоговый скоринг (100%)
            ReportProgress(progress, "Формирование отчета безопасности и рекомендаций...", 100);
            CalculateScore(report);

            return report;
        }

        private void ReportProgress(Action<string, int> progress, string message, int pct)
        {
            if (progress != null)
            {
                progress(message, pct);
            }
        }

        private void ScanAdapters(AuditReport report)
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces)
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    var ipProps = ni.GetIPProperties();
                    var ipv4Addr = ipProps.UnicastAddresses
                        .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);

                    var gateway = ipProps.GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);

                    var dnsList = ipProps.DnsAddresses
                        .Where(d => d.AddressFamily == AddressFamily.InterNetwork)
                        .Select(d => d.ToString())
                        .ToList();

                    var item = new AdapterItem
                    {
                        Name = ni.Name,
                        Description = ni.Description,
                        InterfaceType = ni.NetworkInterfaceType.ToString(),
                        Status = ni.OperationalStatus == OperationalStatus.Up ? "Подключено" : "Отключено",
                        IsActive = ni.OperationalStatus == OperationalStatus.Up && ipv4Addr != null,
                        IPv4Address = ipv4Addr != null ? ipv4Addr.Address.ToString() : "—",
                        SubnetMask = ipv4Addr != null && ipv4Addr.IPv4Mask != null ? ipv4Addr.IPv4Mask.ToString() : "—",
                        Gateway = gateway != null ? gateway.Address.ToString() : "—",
                        DnsServers = dnsList.Count > 0 ? string.Join(", ", dnsList) : "Авто (DHCP)",
                        MacAddress = string.Join(":", Enumerable.Range(0, 6).Select(i => ni.GetPhysicalAddress().GetAddressBytes().Length > i ? ni.GetPhysicalAddress().GetAddressBytes()[i].ToString("X2") : "00")),
                        Speed = (ni.Speed / 1000000) > 0 ? string.Format("{0} Мбит/с", ni.Speed / 1000000) : "—"
                    };

                    report.Adapters.Add(item);

                    if (item.IsActive && string.IsNullOrEmpty(report.ActiveAdapterName))
                    {
                        report.ActiveAdapterName = item.Name + " (" + item.IPv4Address + ")";
                        if (gateway != null)
                            report.DefaultGateway = gateway.Address.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                report.SecurityChecks.Add(new SecurityItem
                {
                    Title = "Адаптеры сети",
                    Category = "Интерфейсы",
                    Severity = SecuritySeverity.Warning,
                    StatusValue = "Ошибка чтения",
                    Description = "Не удалось полностью опросить сетевые адаптеры: " + ex.Message
                });
            }
        }

        private void CheckGateway(AuditReport report)
        {
            if (string.IsNullOrEmpty(report.DefaultGateway) || report.DefaultGateway == "—")
            {
                report.GatewayPing = "Не задан";
                report.SecurityChecks.Add(new SecurityItem
                {
                    Title = "Основной шлюз сети",
                    Category = "Маршрутизация",
                    Severity = SecuritySeverity.Warning,
                    StatusValue = "Отсутствует",
                    Description = "Основной шлюз не обнаружен. Сеть может быть изолирована или работать через мост/прокси.",
                    Recommendation = "Проверьте сетевой кабель или подключение к Wi-Fi роутеру."
                });
                return;
            }

            try
            {
                using (var ping = new Ping())
                {
                    var reply = ping.Send(report.DefaultGateway, 1500);
                    if (reply.Status == IPStatus.Success)
                    {
                        report.GatewayPing = string.Format("{0} мс", reply.RoundtripTime);
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Доступность основного шлюза (" + report.DefaultGateway + ")",
                            Category = "Маршрутизация",
                            Severity = reply.RoundtripTime < 15 ? SecuritySeverity.Safe : SecuritySeverity.Warning,
                            StatusValue = string.Format("Отклик {0} мс", reply.RoundtripTime),
                            Description = "Шлюз локальной сети доступен и стабильно отвечает на ICMP-запросы.",
                            Recommendation = reply.RoundtripTime >= 15 ? "Повышенная задержка до роутера (проверьте качество сигнала Wi-Fi)." : "Настройки маршрутизации в норме."
                        });
                    }
                    else
                    {
                        report.GatewayPing = "Нет ответа";
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Отклик основного шлюза (" + report.DefaultGateway + ")",
                            Category = "Маршрутизация",
                            Severity = SecuritySeverity.Warning,
                            StatusValue = "ICMP заблокирован или таймаут",
                            Description = "Шлюз не ответил на пинг. Возможно, на роутере отключен ответ на ICMP (это норма для безопасности) либо связь нестабильна.",
                            Recommendation = "Если интернет работает исправно, роутер просто скрывает пинг для защиты."
                        });
                    }
                }
            }
            catch (Exception)
            {
                report.GatewayPing = "Ошибка";
            }
        }

        private void CheckDns(AuditReport report)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                var entries = Dns.GetHostAddresses("google.com");
                sw.Stop();

                report.DnsResponseTime = string.Format("{0} мс", sw.ElapsedMilliseconds);

                var activeAdapter = report.Adapters.FirstOrDefault(a => a.IsActive);
                string dnsInfo = activeAdapter != null ? activeAdapter.DnsServers : "—";

                bool isPublicSecureDns = dnsInfo.Contains("1.1.1.1") || dnsInfo.Contains("8.8.8.8") || dnsInfo.Contains("9.9.9.9") || dnsInfo.Contains("1.0.0.1") || dnsInfo.Contains("8.8.4.4");

                report.SecurityChecks.Add(new SecurityItem
                {
                    Title = "Разрешение имен DNS (google.com)",
                    Category = "DNS",
                    Severity = sw.ElapsedMilliseconds < 150 ? SecuritySeverity.Safe : SecuritySeverity.Warning,
                    StatusValue = string.Format("{0} мс ({1})", sw.ElapsedMilliseconds, entries.Length > 0 ? entries[0].ToString() : "OK"),
                    Description = string.Format("DNS серверы: {0}. Разрешение имен функционирует без сбоев.", dnsInfo),
                    Recommendation = isPublicSecureDns ? "Используется защищенный публичный DNS провайдер." : "Рекомендуется настроить DoH (DNS over HTTPS) или серверы Cloudflare (1.1.1.1) / Quad9 (9.9.9.9) для защиты от перехвата трафика провайдером.",
                    FixCommand = "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses ('1.1.1.1','1.0.0.1')"
                });
            }
            catch (Exception ex)
            {
                report.DnsResponseTime = "Сбой";
                report.SecurityChecks.Add(new SecurityItem
                {
                    Title = "DNS резолвер",
                    Category = "DNS",
                    Severity = SecuritySeverity.Critical,
                    StatusValue = "Сбой разрешения",
                    Description = "Не удалось разрешить публичное имя хоста: " + ex.Message,
                    Recommendation = "Проверьте настройки DNS в свойствах сетевого подключения."
                });
            }

            // Проверка файла hosts на вредоносные перенаправления
            CheckHostsFile(report);
        }

        private void CheckHostsFile(AuditReport report)
        {
            try
            {
                string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                if (File.Exists(hostsPath))
                {
                    var lines = File.ReadAllLines(hostsPath)
                        .Select(l => l.Trim())
                        .Where(l => !string.IsNullOrEmpty(l) && !l.StartsWith("#"))
                        .ToList();

                    if (lines.Count == 0 || (lines.Count <= 2 && lines.All(l => l.Contains("localhost") || l.Contains("::1"))))
                    {
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Целостность файла hosts",
                            Category = "Система и DNS",
                            Severity = SecuritySeverity.Safe,
                            StatusValue = "Чист (нет модификаций)",
                            Description = "Файл hosts содержит только стандартные локальные записи. Подмена доменов не обнаружена.",
                            Recommendation = "Действий не требуется."
                        });
                    }
                    else
                    {
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Файл hosts содержит кастомные записи",
                            Category = "Система и DNS",
                            Severity = SecuritySeverity.Warning,
                            StatusValue = string.Format("{0} активных записей", lines.Count),
                            Description = "Обнаружены пользовательские перенаправления в файле hosts. Убедитесь, что они добавлены вами, а не вредоносным ПО.",
                            Recommendation = "Проверьте файл " + hostsPath + " в блокноте."
                        });
                    }
                }
            }
            catch
            {
                // Игнорируем ошибки доступа
            }
        }

        private void CheckFirewall(AuditReport report)
        {
            try
            {
                bool domainOn = CheckFirewallProfile("DomainProfile");
                bool privateOn = CheckFirewallProfile("StandardProfile");
                bool publicOn = CheckFirewallProfile("PublicProfile");

                if (domainOn && privateOn && publicOn)
                {
                    report.SecurityChecks.Add(new SecurityItem
                    {
                        Title = "Брандмауэр Windows (Windows Firewall)",
                        Category = "Брандмауэр",
                        Severity = SecuritySeverity.Safe,
                        StatusValue = "Все профили активны (100%)",
                        Description = "Брандмауэр защищает входящий трафик для Доменного, Частного и Общедоступного профилей.",
                        Recommendation = "Защита сетевого периметра Windows работает в штатном режиме."
                    });
                }
                else
                {
                    var disabled = new List<string>();
                    if (!domainOn) disabled.Add("Доменный");
                    if (!privateOn) disabled.Add("Частный");
                    if (!publicOn) disabled.Add("Общедоступный");

                    report.SecurityChecks.Add(new SecurityItem
                    {
                        Title = "Брандмауэр Windows частично отключен",
                        Category = "Брандмауэр",
                        Severity = !publicOn ? SecuritySeverity.Critical : SecuritySeverity.Warning,
                        StatusValue = "Отключен: " + string.Join(", ", disabled),
                        Description = "Отключение брандмауэра оставляет компьютер уязвимым для сканирования портов и эксплойтов в локальной сети.",
                        Recommendation = "Включите брандмауэр для всех профилей через панель управления или PowerShell.",
                        FixCommand = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
                    });
                }
            }
            catch (Exception ex)
            {
                report.SecurityChecks.Add(new SecurityItem
                {
                    Title = "Брандмауэр Windows",
                    Category = "Брандмауэр",
                    Severity = SecuritySeverity.Warning,
                    StatusValue = "Ошибка проверки",
                    Description = "Не удалось прочитать параметры брандмауэра: " + ex.Message
                });
            }
        }

        private bool CheckFirewallProfile(string profileKey)
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + profileKey))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("EnableFirewall");
                        if (val != null)
                        {
                            return Convert.ToInt32(val) == 1;
                        }
                    }
                }
            }
            catch { }
            return true;
        }

        private void CheckSystemProtocols(AuditReport report)
        {
            // 1. SMBv1 (WannaCry vector)
            try
            {
                bool smb1Enabled = false;
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("SMB1");
                        if (val != null && Convert.ToInt32(val) == 1)
                        {
                            smb1Enabled = true;
                        }
                    }
                }

                if (smb1Enabled)
                {
                    report.SecurityChecks.Add(new SecurityItem
                    {
                        Title = "Устаревший протокол SMBv1 активен",
                        Category = "Уязвимые службы",
                        Severity = SecuritySeverity.Critical,
                        StatusValue = "ВКЛЮЧЕН (Критическая угроза)",
                        Description = "Протокол SMBv1 содержит критические уязвимости удаленного выполнения кода (EternalBlue / WannaCry).",
                        Recommendation = "Немедленно отключите SMBv1 в компонентах Windows.",
                        FixCommand = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
                    });
                }
                else
                {
                    report.SecurityChecks.Add(new SecurityItem
                    {
                        Title = "Протокол общего доступа SMBv1",
                        Category = "Уязвимые службы",
                        Severity = SecuritySeverity.Safe,
                        StatusValue = "Отключен / Не используется",
                        Description = "Устаревший протокол SMBv1 деактивирован. Защита от классических сетевых червей активна.",
                        Recommendation = "Действий не требуется."
                    });
                }
            }
            catch { }

            // 2. Remote Desktop (RDP)
            try
            {
                bool rdpEnabled = false;
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("fDenyTSConnections");
                        if (val != null && Convert.ToInt32(val) == 0)
                        {
                            rdpEnabled = true;
                        }
                    }
                }

                if (rdpEnabled)
                {
                    bool nlaEnabled = false;
                    using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"))
                    {
                        if (key != null)
                        {
                            var val = key.GetValue("UserAuthentication");
                            if (val != null && Convert.ToInt32(val) == 1)
                            {
                                nlaEnabled = true;
                            }
                        }
                    }

                    if (!nlaEnabled)
                    {
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Удаленный рабочий стол (RDP) без NLA",
                            Category = "Удаленный доступ",
                            Severity = SecuritySeverity.Critical,
                            StatusValue = "RDP ВКЛЮЧЕН БЕЗ NLA",
                            Description = "RDP включен без проверки подлинности на уровне сети (NLA). Злоумышленники в LAN могут попытаться подобрать пароль или вызвать сбой.",
                            Recommendation = "Включите NLA или отключите RDP, если он не нужен для работы.",
                            FixCommand = "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1"
                        });
                    }
                    else
                    {
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Удаленный рабочий стол (RDP)",
                            Category = "Удаленный доступ",
                            Severity = SecuritySeverity.Warning,
                            StatusValue = "Включен (с защитой NLA)",
                            Description = "Порт 3389 активен. NLA защищает от прямых неавторизованных подключений.",
                            Recommendation = "Если удаленный доступ не используется постоянно, отключите его для минимизации площади атаки.",
                            FixCommand = "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1"
                        });
                    }
                }
                else
                {
                    report.SecurityChecks.Add(new SecurityItem
                    {
                        Title = "Удаленный рабочий стол (RDP)",
                        Category = "Удаленный доступ",
                        Severity = SecuritySeverity.Safe,
                        StatusValue = "Отключен",
                        Description = "Входящие подключения Remote Desktop запрещены. Порт 3389 закрыт.",
                        Recommendation = "Действий не требуется."
                    });
                }
            }
            catch { }

            // 3. LLMNR Multicast Resolution
            try
            {
                bool llmnrDisabled = false;
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("EnableMulticast");
                        if (val != null && Convert.ToInt32(val) == 0)
                        {
                            llmnrDisabled = true;
                        }
                    }
                }

                if (llmnrDisabled)
                {
                    report.SecurityChecks.Add(new SecurityItem
                    {
                        Title = "Разрешение имен LLMNR",
                        Category = "Сетевые протоколы",
                        Severity = SecuritySeverity.Safe,
                        StatusValue = "Отключено политикой",
                        Description = "Широковещательный протокол LLMNR отключен. Система защищена от спуфинга Responder в локальной сети.",
                        Recommendation = "Действий не требуется."
                    });
                }
                else
                {
                    report.SecurityChecks.Add(new SecurityItem
                    {
                        Title = "Протокол LLMNR (Link-Local Multicast)",
                        Category = "Сетевые протоколы",
                        Severity = SecuritySeverity.Warning,
                        StatusValue = "Активен по умолчанию",
                        Description = "LLMNR передает широковещательные запросы в локальной сети. В публичных сетях атакующий может перехватить NTLM-хэши через Responder.",
                        Recommendation = "Рекомендуется отключить LLMNR через групповую политику или реестр.",
                        FixCommand = "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force"
                    });
                }
            }
            catch { }

            // 4. Remote Registry
            try
            {
                using (var sc = new ServiceController("RemoteRegistry"))
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Служба удаленного реестра (RemoteRegistry)",
                            Category = "Системные службы",
                            Severity = SecuritySeverity.Warning,
                            StatusValue = "Работает",
                            Description = "Служба позволяет удаленным пользователям изменять настройки реестра на данном компьютере.",
                            Recommendation = "Остановите и отключите службу RemoteRegistry.",
                            FixCommand = "Stop-Service -Name RemoteRegistry; Set-Service -Name RemoteRegistry -StartupType Disabled"
                        });
                    }
                    else
                    {
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Служба удаленного реестра (RemoteRegistry)",
                            Category = "Системные службы",
                            Severity = SecuritySeverity.Safe,
                            StatusValue = "Остановлена / Отключена",
                            Description = "Удаленное редактирование реестра по сети заблокировано.",
                            Recommendation = "Действий не требуется."
                        });
                    }
                }
            }
            catch { }
        }

        private void ScanListeningPorts(AuditReport report)
        {
            try
            {
                var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
                var distinctPorts = listeners
                    .GroupBy(l => new { l.Address, l.Port })
                    .Select(g => g.First())
                    .OrderBy(l => l.Port)
                    .ToList();

                foreach (var ep in distinctPorts)
                {
                    bool isLAN = ep.Address.ToString() == "0.0.0.0" || ep.Address.ToString() == "::";
                    string service = GetServiceName(ep.Port);
                    string risk = "Низкий";
                    string details = isLAN ? "Слушает на всех сетевых интерфейсах (0.0.0.0). Доступен из локальной сети." : "Слушает только локальный адрес (127.0.0.1 / localhost). Вне компьютера недоступен.";

                    if (isLAN)
                    {
                        if (ep.Port == 21 || ep.Port == 23)
                        {
                            risk = "Высокий";
                            details = "Критически небезопасный протокол без шифрования открыт для всех в сети!";
                        }
                        else if (ep.Port == 445 || ep.Port == 135 || ep.Port == 139)
                        {
                            risk = "Средний";
                            details = "Служба Windows RPC/SMB слушает на всех интерфейсах. Ограничьте правилами брандмауэра в публичных сетях.";
                        }
                        else if (ep.Port == 3389)
                        {
                            risk = "Средний";
                            details = "Порт RDP слушает на всех интерфейсах.";
                        }
                        else if (ep.Port == 80 || ep.Port == 8080)
                        {
                            risk = "Средний";
                            details = "HTTP веб-сервер без обязательного SSL/TLS шифрования.";
                        }
                    }

                    report.OpenPorts.Add(new PortItem
                    {
                        Port = ep.Port,
                        Protocol = "TCP",
                        LocalAddress = ep.Address.ToString(),
                        ServiceName = service,
                        RiskLevel = risk,
                        IsExposedToLAN = isLAN,
                        Details = details
                    });
                }
            }
            catch (Exception)
            {
                // Ошибка сбора портов
            }
        }

        private string GetServiceName(int port)
        {
            switch (port)
            {
                case 21: return "FTP (Передача файлов)";
                case 22: return "SSH (Удаленная оболочка)";
                case 23: return "Telnet (Нешифрованный терминал)";
                case 25: return "SMTP (Почта)";
                case 53: return "DNS (Служба имен)";
                case 80: return "HTTP (Веб-сервер)";
                case 135: return "MS-RPC (Endpoint Mapper)";
                case 139: return "NetBIOS Session Service";
                case 443: return "HTTPS (Безопасный веб)";
                case 445: return "Microsoft-DS (SMB общий доступ)";
                case 5037: return "ADB (Android Debug Bridge)";
                case 11434: return "Ollama (Локальный AI сервер)";
                case 3389: return "RDP (Удаленный рабочий стол)";
                case 5985: return "WinRM HTTP";
                case 5986: return "WinRM HTTPS";
                case 8080: return "HTTP Proxy / Web Alt";
                default:
                    if (port >= 49152) return "Динамический порт Windows RPC";
                    return "Пользовательская служба";
            }
        }

        private void CheckPublicConnectivity(AuditReport report)
        {
            try
            {
                using (var client = new WebClient())
                {
                    client.Headers.Add("User-Agent", "NetGuard-Security-Auditor/1.0");
                    client.Encoding = Encoding.UTF8;
                    // Таймаут на загрузку внешнего IP
                    string ip = client.DownloadString("https://api.ipify.org").Trim();
                    if (!string.IsNullOrEmpty(ip) && ip.Length < 45)
                    {
                        report.PublicIP = ip;
                        report.SecurityChecks.Add(new SecurityItem
                        {
                            Title = "Внешний шлюз в сеть Интернет",
                            Category = "Внешний периметр",
                            Severity = SecuritySeverity.Safe,
                            StatusValue = "Публичный IP: " + ip,
                            Description = "Прямой защищенный доступ в Интернет через провайдера активен. HTTPS стек работает корректно.",
                            Recommendation = "Действий не требуется."
                        });
                    }
                    else
                    {
                        report.PublicIP = "Не определен";
                    }
                }
            }
            catch
            {
                report.PublicIP = "Офлайн / Недоступен";
                report.SecurityChecks.Add(new SecurityItem
                {
                    Title = "Внешний периметр Интернет",
                    Category = "Внешний периметр",
                    Severity = SecuritySeverity.Warning,
                    StatusValue = "Не удалось запросить публичный IP",
                    Description = "Возможно, соединение работает через закрытый корпоративный прокси или внешний доступ заблокирован.",
                    Recommendation = "Проверьте параметры прокси-сервера в параметрах Windows."
                });
            }
        }

        private void CalculateScore(AuditReport report)
        {
            int baseScore = 100;
            int passed = 0;
            int warnings = 0;
            int critical = 0;

            foreach (var check in report.SecurityChecks)
            {
                if (check.Severity == SecuritySeverity.Safe)
                    passed++;
                else if (check.Severity == SecuritySeverity.Warning)
                {
                    warnings++;
                    baseScore -= 10;
                }
                else if (check.Severity == SecuritySeverity.Critical)
                {
                    critical++;
                    baseScore -= 25;
                }
            }

            // Штраф за открытые на 0.0.0.0 высокорисковые порты
            int exposedHighRiskPorts = report.OpenPorts.Count(p => p.RiskLevel == "Высокий" && p.IsExposedToLAN);
            baseScore -= (exposedHighRiskPorts * 15);

            int finalScore = Math.Max(10, Math.Min(100, baseScore));

            report.TotalChecks = report.SecurityChecks.Count;
            report.PassedCount = passed;
            report.WarningCount = warnings;
            report.CriticalCount = critical;
            report.SecurityScore = finalScore;

            if (finalScore >= 85)
            {
                report.SecurityRating = "ВЫСОКИЙ УРОВЕНЬ ЗАЩИТЫ";
                report.ScoreSummary = "Конфигурация сети и системные параметры Windows надежно защищены от базовых и сетевых угроз.";
            }
            else if (finalScore >= 60)
            {
                report.SecurityRating = "СРЕДНИЙ (ТРЕБУЕТСЯ ВНИМАНИЕ)";
                report.ScoreSummary = "Обнаружены потенциальные уязвимости или небезопасные сетевые службы. Рекомендуется применить советы ниже.";
            }
            else
            {
                report.SecurityRating = "КРИТИЧЕСКИЙ РИСК";
                report.ScoreSummary = "Обнаружены серьезные бреши в безопасности сети (отключен брандмауэр, активен SMBv1 или уязвимый RDP).";
            }
        }
    }
}

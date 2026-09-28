using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using NetGuard.Models;
using NetGuard.Services;

namespace NetGuard
{
    public partial class MainWindow : Window
    {
        private readonly NetworkAuditor _auditor;
        private AuditReport _latestReport;

        public MainWindow()
        {
            InitializeComponent();
            _auditor = new NetworkAuditor();

            // Автозапуск первого сканирования при открытии
            Loaded += async (s, e) =>
            {
                await StartAuditAsync();
            };
        }

        private async void BtnScan_Click(object sender, RoutedEventArgs e)
        {
            await StartAuditAsync();
        }

        private async Task StartAuditAsync()
        {
            btnScan.IsEnabled = false;
            panelProgress.Visibility = Visibility.Visible;
            pbScan.Value = 0;
            txtFooterStatus.Text = "Выполняется аудит параметров сети и безопасности Windows...";

            try
            {
                _latestReport = await _auditor.RunAuditAsync((msg, pct) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        txtProgressStatus.Text = msg;
                        pbScan.Value = pct;
                    });
                });

                UpdateUiWithReport(_latestReport);
                txtFooterStatus.Text = string.Format("Аудит завершен в {0:HH:mm:ss}. Оценка: {1}/100 ({2})",
                    _latestReport.ScanDate, _latestReport.SecurityScore, _latestReport.SecurityRating);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Произошла ошибка при выполнении аудита: " + ex.Message,
                    "Ошибка NetGuard", MessageBoxButton.OK, MessageBoxImage.Error);
                txtFooterStatus.Text = "Ошибка аудита: " + ex.Message;
            }
            finally
            {
                panelProgress.Visibility = Visibility.Collapsed;
                btnScan.IsEnabled = true;
            }
        }

        private void UpdateUiWithReport(AuditReport report)
        {
            // Скоринг
            txtScore.Text = report.SecurityScore.ToString();
            txtRatingBadge.Text = report.SecurityRating;
            txtScoreSummary.Text = report.ScoreSummary;

            // Цвета рейтинга
            if (report.SecurityScore >= 85)
            {
                txtScore.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#76D499"));
                borderRatingBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#133624"));
                txtRatingBadge.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#76D499"));
            }
            else if (report.SecurityScore >= 60)
            {
                txtScore.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFD066"));
                borderRatingBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3E2D0E"));
                txtRatingBadge.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFD066"));
            }
            else
            {
                txtScore.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF8D80"));
                borderRatingBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#441A1A"));
                txtRatingBadge.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF8D80"));
            }

            // Метрики
            txtGatewayInfo.Text = !string.IsNullOrEmpty(report.DefaultGateway) ? report.DefaultGateway : "Не задан";
            txtGatewayPing.Text = "Пинг: " + report.GatewayPing;

            txtDnsInfo.Text = "Проверка google.com";
            txtDnsLatency.Text = "Отклик: " + report.DnsResponseTime;

            txtPublicIP.Text = report.PublicIP;
            txtActiveAdapter.Text = !string.IsNullOrEmpty(report.ActiveAdapterName) ? report.ActiveAdapterName : "Не обнаружен";

            // Счетчики
            txtTotalChecks.Text = report.TotalChecks.ToString();
            txtPassedChecks.Text = report.PassedCount.ToString();
            txtIssueChecks.Text = (report.WarningCount + report.CriticalCount).ToString();

            // Списки
            icOverviewSummary.ItemsSource = report.SecurityChecks.Take(5).ToList();
            icSecurityChecks.ItemsSource = report.SecurityChecks;
            icPorts.ItemsSource = report.OpenPorts;
            icAdapters.ItemsSource = report.Adapters;

            // Рекомендации (только те, где есть FixCommand или статус не Safe)
            var recommendations = report.SecurityChecks
                .Where(c => c.Severity != SecuritySeverity.Safe && !string.IsNullOrEmpty(c.Recommendation))
                .ToList();

            if (recommendations.Count == 0)
            {
                recommendations = report.SecurityChecks.Where(c => !string.IsNullOrEmpty(c.Recommendation)).ToList();
            }

            icFixRecommendations.ItemsSource = recommendations;
        }

        private void Tab_Checked(object sender, RoutedEventArgs e)
        {
            if (viewOverview == null || viewSecurity == null || viewPorts == null || viewAdapters == null || viewFixes == null)
                return;

            viewOverview.Visibility = Visibility.Collapsed;
            viewSecurity.Visibility = Visibility.Collapsed;
            viewPorts.Visibility = Visibility.Collapsed;
            viewAdapters.Visibility = Visibility.Collapsed;
            viewFixes.Visibility = Visibility.Collapsed;

            if (tabOverview.IsChecked == true)
                viewOverview.Visibility = Visibility.Visible;
            else if (tabSecurity.IsChecked == true)
                viewSecurity.Visibility = Visibility.Visible;
            else if (tabPorts.IsChecked == true)
                viewPorts.Visibility = Visibility.Visible;
            else if (tabAdapters.IsChecked == true)
                viewAdapters.Visibility = Visibility.Visible;
            else if (tabFixes.IsChecked == true)
                viewFixes.Visibility = Visibility.Visible;
        }

        private void BtnCopyFix_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as Button;
            if (btn != null && btn.Tag != null)
            {
                string cmd = btn.Tag.ToString();
                Clipboard.SetText(cmd);
                MessageBox.Show("Команда скопирована в буфер обмена:\n\n" + cmd + "\n\nЗапустите PowerShell от имени администратора и вставьте команду.",
                    "Команда скопирована", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            if (_latestReport == null)
            {
                MessageBox.Show("Сначала выполните аудит сети.", "NetGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Текстовый отчет (*.txt)|*.txt|JSON отчет (*.json)|*.json",
                FileName = string.Format("NetGuard_Audit_Report_{0:yyyyMMdd_HHmmss}", DateTime.Now),
                Title = "Сохранить отчет аудита сети"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    string content;
                    if (dialog.FilterIndex == 2)
                    {
                        content = GenerateJsonReport(_latestReport);
                    }
                    else
                    {
                        content = GenerateTextReport(_latestReport);
                    }

                    File.WriteAllText(dialog.FileName, content);
                    MessageBox.Show("Отчет успешно сохранен в файл:\n" + dialog.FileName,
                        "Отчет экспортирован", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Ошибка при сохранении отчета: " + ex.Message,
                        "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private string GenerateTextReport(AuditReport r)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("================================================================================");
            sb.AppendLine("                 NETGUARD - ОТЧЕТ АУДИТА БЕЗОПАСНОСТИ СЕТИ                     ");
            sb.AppendLine("================================================================================");
            sb.AppendLine(string.Format("Дата проверки: {0:yyyy-MM-dd HH:mm:ss}", r.ScanDate));
            sb.AppendLine(string.Format("Оценка безопасности: {0} / 100 ({1})", r.SecurityScore, r.SecurityRating));
            sb.AppendLine(string.Format("Внешний IP: {0}", r.PublicIP));
            sb.AppendLine(string.Format("Шлюз: {0} (Пинг: {1})", r.DefaultGateway, r.GatewayPing));
            sb.AppendLine(string.Format("DNS задержка: {0}", r.DnsResponseTime));
            sb.AppendLine();
            sb.AppendLine("--- СТАТИСТИКА ПРОВЕРОК ---");
            sb.AppendLine(string.Format("Всего тестов: {0} | Успешно: {1} | Замечаний: {2} | Критических: {3}",
                r.TotalChecks, r.PassedCount, r.WarningCount, r.CriticalCount));
            sb.AppendLine();
            sb.AppendLine("--- РЕЗУЛЬТАТЫ ПРОВЕРОК БЕЗОПАСНОСТИ ---");
            foreach (var item in r.SecurityChecks)
            {
                sb.AppendLine(string.Format("[{0}] [{1}] {2}: {3}", item.StatusText, item.Category, item.Title, item.StatusValue));
                sb.AppendLine("   Описание: " + item.Description);
                if (!string.IsNullOrEmpty(item.Recommendation))
                    sb.AppendLine("   Совет: " + item.Recommendation);
                if (!string.IsNullOrEmpty(item.FixCommand))
                    sb.AppendLine("   PowerShell Fix: " + item.FixCommand);
                sb.AppendLine();
            }

            sb.AppendLine("--- ОТКРЫТЫЕ ПРОСЛУШИВАЕМЫЕ ПОРТЫ (TCP) ---");
            foreach (var p in r.OpenPorts)
            {
                sb.AppendLine(string.Format("Порт {0} ({1}) - {2} | Риск: {3} | {4}",
                    p.Port, p.ServiceName, p.LocalAddress, p.RiskLevel, p.ExposureText));
            }
            sb.AppendLine();

            sb.AppendLine("--- СЕТЕВЫЕ АДАПТЕРЫ ---");
            foreach (var a in r.Adapters)
            {
                sb.AppendLine(string.Format("Адаптер: {0} ({1}) - Статус: {2}", a.Name, a.InterfaceType, a.Status));
                sb.AppendLine(string.Format("   IPv4: {0} / {1} | Шлюз: {2} | DNS: {3}", a.IPv4Address, a.SubnetMask, a.Gateway, a.DnsServers));
                sb.AppendLine(string.Format("   MAC: {0} | Скорость: {1}", a.MacAddress, a.Speed));
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private string GenerateJsonReport(AuditReport r)
        {
            // Простая сериализация в JSON без внешних библиотек
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine(string.Format("  \"scanDate\": \"{0:o}\",", r.ScanDate));
            sb.AppendLine(string.Format("  \"securityScore\": {0},", r.SecurityScore));
            sb.AppendLine(string.Format("  \"securityRating\": \"{0}\",", EscapeJson(r.SecurityRating)));
            sb.AppendLine(string.Format("  \"publicIP\": \"{0}\",", EscapeJson(r.PublicIP)));
            sb.AppendLine(string.Format("  \"defaultGateway\": \"{0}\",", EscapeJson(r.DefaultGateway)));
            sb.AppendLine(string.Format("  \"gatewayPing\": \"{0}\",", EscapeJson(r.GatewayPing)));
            sb.AppendLine(string.Format("  \"dnsResponseTime\": \"{0}\",", EscapeJson(r.DnsResponseTime)));
            sb.AppendLine("  \"securityChecks\": [");
            for (int i = 0; i < r.SecurityChecks.Count; i++)
            {
                var c = r.SecurityChecks[i];
                sb.AppendLine("    {");
                sb.AppendLine(string.Format("      \"title\": \"{0}\",", EscapeJson(c.Title)));
                sb.AppendLine(string.Format("      \"category\": \"{0}\",", EscapeJson(c.Category)));
                sb.AppendLine(string.Format("      \"severity\": \"{0}\",", c.Severity));
                sb.AppendLine(string.Format("      \"statusValue\": \"{0}\",", EscapeJson(c.StatusValue)));
                sb.AppendLine(string.Format("      \"description\": \"{0}\",", EscapeJson(c.Description)));
                sb.AppendLine(string.Format("      \"recommendation\": \"{0}\",", EscapeJson(c.Recommendation ?? "")));
                sb.AppendLine(string.Format("      \"fixCommand\": \"{0}\"", EscapeJson(c.FixCommand ?? "")));
                sb.AppendLine(i < r.SecurityChecks.Count - 1 ? "    }," : "    }");
            }
            sb.AppendLine("  ],");
            sb.AppendLine("  \"openPorts\": [");
            for (int i = 0; i < r.OpenPorts.Count; i++)
            {
                var p = r.OpenPorts[i];
                sb.AppendLine("    {");
                sb.AppendLine(string.Format("      \"port\": {0},", p.Port));
                sb.AppendLine(string.Format("      \"localAddress\": \"{0}\",", EscapeJson(p.LocalAddress)));
                sb.AppendLine(string.Format("      \"serviceName\": \"{0}\",", EscapeJson(p.ServiceName)));
                sb.AppendLine(string.Format("      \"riskLevel\": \"{0}\",", EscapeJson(p.RiskLevel)));
                sb.AppendLine(string.Format("      \"isExposedToLAN\": {0}", p.IsExposedToLAN ? "true" : "false"));
                sb.AppendLine(i < r.OpenPorts.Count - 1 ? "    }," : "    }");
            }
            sb.AppendLine("  ]");
            sb.AppendLine("}");
            return sb.ToString();
        }

        private string EscapeJson(string str)
        {
            if (string.IsNullOrEmpty(str)) return "";
            return str.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "\\n");
        }
    }
}

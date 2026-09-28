using System;
using System.Windows;
using System.Windows.Media;

namespace NetGuard.Models
{
    public enum SecuritySeverity
    {
        Safe,
        Warning,
        Critical
    }

    public class SecurityItem
    {
        public string Title { get; set; }
        public string Category { get; set; }
        public SecuritySeverity Severity { get; set; }
        public string StatusValue { get; set; }
        public string Description { get; set; }
        public string Recommendation { get; set; }
        public string FixCommand { get; set; }

        public Visibility HasFixCommand
        {
            get
            {
                return string.IsNullOrEmpty(FixCommand) ? Visibility.Collapsed : Visibility.Visible;
            }
        }

        public string StatusText
        {
            get
            {
                switch (Severity)
                {
                    case SecuritySeverity.Safe: return "БЕЗОПАСНО";
                    case SecuritySeverity.Warning: return "ВНИМАНИЕ";
                    case SecuritySeverity.Critical: return "УГРОЗА";
                    default: return "ИНФО";
                }
            }
        }

        public SolidColorBrush BadgeBackground
        {
            get
            {
                switch (Severity)
                {
                    case SecuritySeverity.Safe:
                        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#133624"));
                    case SecuritySeverity.Warning:
                        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3E2D0E"));
                    case SecuritySeverity.Critical:
                        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#441A1A"));
                    default:
                        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#252830"));
                }
            }
        }

        public SolidColorBrush BadgeForeground
        {
            get
            {
                switch (Severity)
                {
                    case SecuritySeverity.Safe:
                        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#76D499"));
                    case SecuritySeverity.Warning:
                        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFD066"));
                    case SecuritySeverity.Critical:
                        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF8D80"));
                    default:
                        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A8C7FA"));
                }
            }
        }

        public string StatusIcon
        {
            get
            {
                switch (Severity)
                {
                    case SecuritySeverity.Safe: return "✓";
                    case SecuritySeverity.Warning: return "⚠";
                    case SecuritySeverity.Critical: return "✕";
                    default: return "ℹ";
                }
            }
        }
    }
}

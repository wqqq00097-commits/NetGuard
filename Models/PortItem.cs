using System;
using System.Windows.Media;

namespace NetGuard.Models
{
    public class PortItem
    {
        public int Port { get; set; }
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public string ServiceName { get; set; }
        public string RiskLevel { get; set; } // "Низкий", "Средний", "Высокий"
        public bool IsExposedToLAN { get; set; }
        public string Details { get; set; }

        public SolidColorBrush RiskBackground
        {
            get
            {
                if (RiskLevel == "Высокий")
                    return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#441A1A"));
                if (RiskLevel == "Средний")
                    return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3E2D0E"));
                return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#133624"));
            }
        }

        public SolidColorBrush RiskForeground
        {
            get
            {
                if (RiskLevel == "Высокий")
                    return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF8D80"));
                if (RiskLevel == "Средний")
                    return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFD066"));
                return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#76D499"));
            }
        }

        public string ExposureText
        {
            get
            {
                return IsExposedToLAN ? "Вся сеть (0.0.0.0)" : "Только локально (localhost)";
            }
        }
    }
}

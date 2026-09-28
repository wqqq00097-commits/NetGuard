using System;
using System.Collections.Generic;

namespace NetGuard.Models
{
    public class AuditReport
    {
        public DateTime ScanDate { get; set; }
        public int SecurityScore { get; set; }
        public string SecurityRating { get; set; }
        public string ScoreSummary { get; set; }

        public string PublicIP { get; set; }
        public string DefaultGateway { get; set; }
        public string GatewayPing { get; set; }
        public string DnsResponseTime { get; set; }
        public string ActiveAdapterName { get; set; }

        public int TotalChecks { get; set; }
        public int PassedCount { get; set; }
        public int WarningCount { get; set; }
        public int CriticalCount { get; set; }

        public List<SecurityItem> SecurityChecks { get; set; }
        public List<PortItem> OpenPorts { get; set; }
        public List<AdapterItem> Adapters { get; set; }

        public AuditReport()
        {
            SecurityChecks = new List<SecurityItem>();
            OpenPorts = new List<PortItem>();
            Adapters = new List<AdapterItem>();
        }
    }
}

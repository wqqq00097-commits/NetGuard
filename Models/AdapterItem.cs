using System;

namespace NetGuard.Models
{
    public class AdapterItem
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string InterfaceType { get; set; }
        public string Status { get; set; }
        public string IPv4Address { get; set; }
        public string SubnetMask { get; set; }
        public string Gateway { get; set; }
        public string DnsServers { get; set; }
        public string MacAddress { get; set; }
        public string Speed { get; set; }
        public bool IsActive { get; set; }
    }
}

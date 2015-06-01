#include "wiredolphin.h"
#include "ui_wiredolphin.h"

#include <iostream>

#include <winsock2.h>
#include <pcap.h>


using namespace std;

//-----------------
/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

char packet_filter[] = "ip and udp";
//-----------------

wiredolphin::wiredolphin(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::wiredolphin)
{
    ui->setupUi(this);

    ui->treewdgt_output->setColumnCount(6);
    ui->treewdgt_output->setHeaderLabels(QStringList() << "Time" << "Length" << "Source IP" << "Source Port" <<
                                         "Destination IP" << "Destination Port");



    timer = new QTimer(this);


    QObject::connect(timer, SIGNAL(timeout()), this, SLOT(eventinitiated()));

    //timer->start(1000);

    if(!timer->isActive())
        cout << "timer is not running" << endl;



    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list on the local machine */
    cout << "we are retrieving the device list on the local machine" << endl;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        cout << "error in pcap_findalldevs: " << errbuf << endl;
        QApplication::quit();
    }

    /* Print the list */
    cout << " we are not printing the list" << endl;
    char index = '1';
    for(d=alldevs; d; d=d->next)
    {
        //cout << ++i << d->name << endl;
        if (d->description) {
            QString interfacestring = QString(index);
            interfacestring.append(". ");
            interfacestring.append(d->name);
            interfacestring.append("\n\t");
            interfacestring.append(d->description);
            this->ui->te_interfacelist->appendPlainText(interfacestring);
            //this->ui->te_interfacelist->appendPlainText(d->description);
            //cout << " " << d->description << endl;
            index++;
        }
        else
            cout << " (no description available)" << endl;
    }



}

void wiredolphin::eventinitiated()
{
    //this->ui->te_infooutput->appendPlainText("timer expired; restarted");
    pcap_loop(adhandle, 1, packet_handler, (uchar *)this);
}

wiredolphin::~wiredolphin()
{
    delete ui;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;

    wiredolphin *current = (wiredolphin *) param;

    /*
     * unused variables
     */
    //(VOID)(param);
    //(VOID)(pkt_data);

/*    for (unsigned int i = 0; i < header->len; i++)
         cout << pkt_data[i] << " ";
    cout << endl;*/

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data +
         14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    QTreeWidgetItem *entry = new QTreeWidgetItem(current->ui->treewdgt_output);

    /*
    QString output = QString(timestr);
    output.append(" ");
    output.append(QString::number(header->ts.tv_usec));
    output.append(" ");
    output.append(QString::number(header->len));*/

    entry->setText(0, QString(timestr));
    entry->setText(1, QString::number(header->len));
/*
    output.append(" ");
    output.append(QString::number(ih->saddr.byte1));
    output.append(".");
    output.append(QString::number(ih->saddr.byte2));
    output.append(".");
    output.append(QString::number(ih->saddr.byte3));
    output.append(".");
    output.append(QString::number(ih->saddr.byte4));
    output.append(" ");
    output.append(QString::number(sport));*/

    QString sourceip;
    sourceip.append(QString::number(ih->saddr.byte1));
    sourceip.append(".");
    sourceip.append(QString::number(ih->saddr.byte2));
    sourceip.append(".");
    sourceip.append(QString::number(ih->saddr.byte3));
    sourceip.append(".");
    sourceip.append(QString::number(ih->saddr.byte4));
    entry->setText(2, sourceip);

    entry->setText(3, QString::number(sport));


/*
    output.append(" ");
    output.append(QString::number(ih->daddr.byte1));
    output.append(".");
    output.append(QString::number(ih->daddr.byte2));
    output.append(".");
    output.append(QString::number(ih->daddr.byte3));
    output.append(".");
    output.append(QString::number(ih->daddr.byte4));
    output.append(" ");
    output.append(QString::number(dport));
*/
    //current->ui->te_infooutput->appendPlainText(output);

    QString destip;
    destip.append(QString::number(ih->daddr.byte1));
    destip.append(".");
    destip.append(QString::number(ih->daddr.byte2));
    destip.append(".");
    destip.append(QString::number(ih->daddr.byte3));
    destip.append(".");
    destip.append(QString::number(ih->daddr.byte4));
    entry->setText(4, destip);

    entry->setText(5, QString::number(dport));


    current->ui->treewdgt_output->addTopLevelItem(entry);

    //cout << timestr << " " << header->ts.tv_usec << " " << header->len << endl;
}

void wiredolphin::on_btn_capture_clicked()
{
    cout << "remaining time " << this->timer->remainingTime() << endl;
    int inum;
    int i=0;

    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list on the local machine */
    cout << "we are retrieving the device list on the local machine" << endl;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        cout << "error in pcap_findalldevs: " << errbuf << endl;
        QApplication::quit();
    }

    /* Print the list */
    cout << " we are not printing the list" << endl;
    for(d=alldevs; d; d=d->next)
    {
        cout << ++i << d->name << endl;
        if (d->description)
            cout << " " << d->description << endl;
        else
            cout << " (no description available)" << endl;
    }

    if(i==0)
    {
        cout << endl << "No interfaces found! Make sure WinPcap is installed." << endl;
        QApplication::quit();
    }

    QString message = this->ui->le_interfacenumber->text();
    //unsigned int interfacenumber = message.toUInt();

    //cout << "the interface number is: " << interfacenumber << endl;

    //cout << "Enter the interface number (1-" << i << ")" << endl;
    //cin >> inum;

    inum = message.toUInt();
    cout << "the interface number is: " << inum << endl;

    if(inum < 1 || inum > i)
    {
        cout << "Interface number out of range." << endl;
        /* Free the device list */
        pcap_freealldevs(alldevs);
        QApplication::quit();
    }

    /* Jump to the selected adapter */
    cout << "jumping to the selected adapter" << endl;
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the device */
    cout << "opening the device" << endl;
    if ( (adhandle= pcap_open(d->name,          // name of the device
                              65536,            // portion of the packet to capture
                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                              PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                              1000,             // read timeout
                              NULL,             // authentication on the remote machine
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        cout << endl << "Unable to open the adapter. " << d->name << "is not supported by WinPcap" << endl;
        /* Free the device list */
        pcap_freealldevs(alldevs);
        QApplication::quit();
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        cout << endl << "This program works only on Ethernet networks." << endl;
        /* Free the device list */
        pcap_freealldevs(alldevs);
        QApplication::quit();
    }

    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;

    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        QApplication::quit();
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        QApplication::quit();
    }


    cout << endl << "listening" << " " << d->description << "..." << endl;

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */

    timer->start(1000);
    //pcap_loop(adhandle, 1, packet_handler, (uchar *)this);

}

void wiredolphin::on_btn_stop_clicked()
{
    timer->stop();
}

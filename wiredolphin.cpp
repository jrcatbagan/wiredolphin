#include "wiredolphin.h"
#include "ui_wiredolphin.h"

#include <iostream>

#include <pcap.h>


using namespace std;

wiredolphin::wiredolphin(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::wiredolphin)
{
    ui->setupUi(this);
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

    /*
     * unused variables
     */
    (VOID)(param);
    (VOID)(pkt_data);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    cout << timestr << " " << header->ts.tv_usec << " " << header->len << endl;
}

void wiredolphin::on_btn_capture_clicked()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
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

    cout << endl << "listening" << " " << d->description << "..." << endl;

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);
}

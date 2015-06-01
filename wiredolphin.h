#ifndef WIREDOLPHIN_H
#define WIREDOLPHIN_H

#include <QMainWindow>
#include <QTimer>
#include <pcap.h>



namespace Ui {
class wiredolphin;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

class wiredolphin : public QMainWindow
{
    Q_OBJECT

public:
    explicit wiredolphin(QWidget *parent = 0);
    ~wiredolphin();
    QTimer *timer;


private slots:
    void on_btn_capture_clicked();
    void eventinitiated();

    void on_btn_stop_clicked();

private:

    pcap_t *adhandle;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    u_int netmask;
    struct bpf_program fcode;
    Ui::wiredolphin *ui;
    friend void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
};


#endif // WIREDOLPHIN_H

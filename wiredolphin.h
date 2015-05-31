#ifndef WIREDOLPHIN_H
#define WIREDOLPHIN_H

#include <QMainWindow>
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


private slots:
    void on_btn_capture_clicked();

private:
    Ui::wiredolphin *ui;
};

#endif // WIREDOLPHIN_H

#include "wiredolphin.h"
#include <QApplication>

//#include <WinSock2.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    wiredolphin w;
    w.show();

    return a.exec();
}


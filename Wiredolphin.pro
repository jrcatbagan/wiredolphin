#-------------------------------------------------
#
# Project created by QtCreator 2015-05-31T13:44:15
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Wiredolphin
TEMPLATE = app

INCLUDEPATH += $$_PRO_FILE_PWD_/WpdPack/Include
LIBS += -L$$_PRO_FILE_PWD_/WpdPack/Lib -lwpcap -lpacket
DEFINES += WPCAP
DEFINES += HAVE_REMOTE

SOURCES += main.cpp\
        wiredolphin.cpp

HEADERS  += wiredolphin.h

FORMS    += wiredolphin.ui

// main.cpp - Creating windows with names
#include <QApplication>
#include "ServerWindow.h"
#include "ClientWindow.h"

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);

    ServerWindow server("Chat Server");
    server.show();

    ClientWindow client("Chat Client");
    client.show();

    return a.exec();
}

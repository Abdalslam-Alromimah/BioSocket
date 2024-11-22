// ChatController.h - Business logic layer
#ifndef CHATCONTROLLER_H
#define CHATCONTROLLER_H

#include "NetworkManager.h"
#include <QObject>

class ChatController : public QObject {
    Q_OBJECT
public:
    explicit ChatController(bool isServer, QObject *parent = nullptr);
    void initialize();
    void sendMessage(const QString& message);

signals:
    void messageReceived(const QString& message);
    void connectionStatusChanged(const QString& status);

private slots:
    void handleReceivedMessage(const QString& message);
    void handleConnectionEstablished();
    void handleConnectionError(const QString& error);

private:
    NetworkManager* networkManager;
    bool isServer;
};
#endif // SERVER_H

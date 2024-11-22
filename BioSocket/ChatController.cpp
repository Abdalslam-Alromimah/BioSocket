// ChatController.cpp
#include "ChatController.h"

ChatController::ChatController(bool isServer, QObject *parent)
    : QObject(parent), isServer(isServer) {
    networkManager = new NetworkManager(this);

    connect(networkManager, &NetworkManager::messageReceived,
            this, &ChatController::handleReceivedMessage);
    connect(networkManager, &NetworkManager::connectionEstablished,
            this, &ChatController::handleConnectionEstablished);
    connect(networkManager, &NetworkManager::connectionError,
            this, &ChatController::handleConnectionError);
}

void ChatController::initialize() {
    if (isServer) {
        networkManager->startServer(1234);
    } else {
        networkManager->connectToServer("127.0.0.1", 1234);
    }
}

void ChatController::sendMessage(const QString& message) {
    networkManager->sendMessage(message);
}

void ChatController::handleReceivedMessage(const QString& message) {
    emit messageReceived(message);
}

void ChatController::handleConnectionEstablished() {
    emit connectionStatusChanged("Connected");
}

void ChatController::handleConnectionError(const QString& error) {
    emit connectionStatusChanged("Error: " + error);
}

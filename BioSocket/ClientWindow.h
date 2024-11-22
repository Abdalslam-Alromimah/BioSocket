// ClientWindow.h - Add name property
#ifndef CLIENTWINDOW_H
#define CLIENTWINDOW_H

#include "ChatController.h"
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>


class ClientWindow : public QWidget {
    Q_OBJECT
public:
    explicit ClientWindow(const QString& name = "Client", QWidget *parent = nullptr);

private slots:
    void onSendClicked();
    void updateMessages(const QString& message);
    void updateStatus(const QString& status);
    void onFileTransferClicked();  // Declare the slot for handling the file transfer button click

private:
    void setupUI();
    void setupConnections();
    void positionWindow();
    NetworkManager* networkManager;
    ChatController* controller;
    QLineEdit* messageInput;
    QPushButton* sendButton;
    QLabel* messageLabel;
    QLabel* statusLabel;
    QLabel* nameLabel;       // New: Label to show name
    QLabel* encryptedMessageLabel;
    QString clientName;      // New: Store client name
    QFrame* messageFrame;
    QFrame* inputFrame;
    QVBoxLayout* mainLayout;
    QHBoxLayout* inputLayout;
    QPushButton* fileTransferButton;

};
#endif // CLIENTWINDOW_H

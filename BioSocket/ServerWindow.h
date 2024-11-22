
// ServerWindow.h - Add name property
#ifndef SERVERWINDOW_H
#define SERVERWINDOW_H

#include "ChatController.h"
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>

class ServerWindow : public QWidget {
    Q_OBJECT
public:
    explicit ServerWindow(const QString& name = "Server", QWidget *parent = nullptr);

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
    QLabel* encryptedMessageLabel;
    QLabel* nameLabel;       // New: Label to show name
    QString serverName;      // New: Store server name
    QVBoxLayout *mainLayout; // Declare the layout as a member variable
    QHBoxLayout *inputLayout;    // Add this declaration for the input layout
    QFrame *messageFrame;     // Declare the frame
    QFrame *inputFrame;       // Add this declaration
    QPushButton* fileTransferButton;


};
#endif // SERVER_H

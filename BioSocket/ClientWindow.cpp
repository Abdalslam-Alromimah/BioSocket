#include "ClientWindow.h"
#include <QVBoxLayout>
#include <QApplication>
#include <QScreen>
#include <QFont>
#include "ChatStyle.h"
#include <QFrame>
#include <QScrollArea>
#include <QFileDialog>

ClientWindow::ClientWindow(const QString& name, QWidget *parent)
    : QWidget(parent), clientName(name),networkManager(new NetworkManager(this)) {
    controller = new ChatController(false, this);
    setupUI();
    setupConnections();
    positionWindow();
    controller->initialize();
}

void ClientWindow::setupUI() {
    setWindowTitle(clientName);
    setMinimumSize(380, 600);

    // Main layout
    mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    // Title area
    nameLabel = new QLabel(clientName, this);
    nameLabel->setObjectName("titleLabel");
    nameLabel->setAlignment(Qt::AlignCenter);

    // Status label
    statusLabel = new QLabel("Connecting...", this);
    statusLabel->setObjectName("statusLabel");
    statusLabel->setAlignment(Qt::AlignCenter);
//encrypted label
    encryptedMessageLabel = new QLabel("encryptedMessageLabel...", this);
    encryptedMessageLabel->setObjectName("encryptedMessageLabel");
    encryptedMessageLabel->setAlignment(Qt::AlignCenter);

    // Message display area
    messageFrame = new QFrame(this);
    messageFrame->setObjectName("messageFrame");
    QVBoxLayout* messageLayout = new QVBoxLayout(messageFrame);
    messageLabel = new QLabel(this);
    messageLabel->setObjectName("messageLabel");
    messageLabel->setWordWrap(true);
    messageLayout->addWidget(messageLabel);
    messageLayout->addWidget(encryptedMessageLabel);


    // Input area
    inputFrame = new QFrame(this);
    inputFrame->setObjectName("inputFrame");
    inputLayout = new QHBoxLayout(inputFrame);
    inputLayout->setSpacing(10);
    inputLayout->setContentsMargins(10, 5, 10, 5);

    messageInput = new QLineEdit(this);
    messageInput->setPlaceholderText("Type a message...");

    sendButton = new QPushButton(this);
    sendButton->setIcon(QIcon(":/send.png")); // You'll need to add a send icon
    sendButton->setFixedSize(40, 40);

    inputLayout->addWidget(messageInput);
    inputLayout->addWidget(sendButton);

    //file TransferButton
    fileTransferButton = new QPushButton(this);
    fileTransferButton->setText("Send File");
    fileTransferButton->setIcon(QIcon(":/folder.png")); // Add an icon
    inputLayout->addWidget(fileTransferButton);


    // Add everything to main layout
    mainLayout->addWidget(nameLabel);
    mainLayout->addWidget(statusLabel);
    mainLayout->addWidget(messageFrame);
    mainLayout->addStretch();
    mainLayout->addWidget(inputFrame);

    // Apply Samsung style
    setStyleSheet(ChatStyle::SAMSUNG_STYLE);
}

void ClientWindow::onFileTransferClicked() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Transfer");
    if (!filePath.isEmpty()) {
        //ClientController->sendFile(filePath);
        networkManager->sendFile(filePath);  // Corrected to use 'networkManager' instead of 'NetworkManager'

    }
}
void ClientWindow::setupConnections() {
    connect(sendButton, &QPushButton::clicked, this, &ClientWindow::onSendClicked);
    connect(controller, &ChatController::messageReceived, this, &ClientWindow::updateMessages);
    connect(controller, &ChatController::connectionStatusChanged, this, &ClientWindow::updateStatus);
    connect(fileTransferButton, &QPushButton::clicked, this, &ClientWindow::onFileTransferClicked);

}

void ClientWindow::positionWindow() {
    QScreen *screen = QApplication::primaryScreen();
    if (screen) {
        QRect screenGeometry = screen->availableGeometry();
        move(screenGeometry.left(), screenGeometry.top());
    }
}

void ClientWindow::onSendClicked() {
    if (!messageInput->text().isEmpty()) {
        controller->sendMessage(messageInput->text());
        messageInput->clear();
    }
}

void ClientWindow::updateMessages(const QString& message) {
    messageLabel->setText("Server: " + message);
    // Display the encrypted message
        QByteArray encryptedData = message.toUtf8(); // Assuming the message is received as a QString
        encryptedMessageLabel->setText("Encrypted: " + encryptedData.toHex());
}

void ClientWindow::updateStatus(const QString& status) {
    statusLabel->setText(status);
}

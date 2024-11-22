#ifndef NETWORKMANAGER_H
#define NETWORKMANAGER_H

#include <QObject>
#include <QTcpSocket>
#include <QTcpServer>
#include "encryption.h"
#include <memory>

class NetworkManager : public QObject {
    Q_OBJECT
public:
    explicit NetworkManager(QObject *parent = nullptr);
    void connectToServer(const QString& host, quint16 port);
    void startServer(quint16 port);
    void sendMessage(const QString& message);
    QByteArray encryptFileData(const QByteArray& fileData);
    QByteArray decryptFileData(const QByteArray& encryptedData);
    void sendFile(const QString& filePath);
    void processReceivedFileData(const QByteArray& encryptedData);


signals:
    void messageReceived(const QString& message);
    void connectionEstablished();
    void connectionError(const QString& error);

private slots:
    void handleNewConnection();
    void handleReadyRead();
    void handleEncryptedConnection();

private:
    QTcpServer* tcpServer;
    QTcpSocket* socket;
    bool isServer;
    std::unique_ptr<Encryption> encryption;
    std::vector<unsigned char> aesKey;
    std::vector<unsigned char> iv;
    bool encryptionEstablished;
    void startFileTransfer(const QString& fileName, qint64 encryptedFileSize);
    QString saveDirectory;

    void setupEncryption();
    void handleEncryptedMessage(const QByteArray& data);
    QByteArray prepareEncryptedMessage(const QString& message);
    // Member variables for file transfer state
        QByteArray fileBuffer;       // Buffer to hold the received file data
        qint64 receivedFileSize = 0; // Tracks the size of the received data
        qint64 totalFileSize = 0;    // Total file size for transfer
        QString currentFileName;     // Name of the file being transferred
};

#endif // NETWORKMANAGER_H


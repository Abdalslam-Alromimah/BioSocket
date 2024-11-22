//  NetworkManager.cpp
#include "NetworkManager.h"
#include <QDataStream>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QDir>

NetworkManager::NetworkManager(QObject *parent)
    : QObject(parent), tcpServer(nullptr), socket(nullptr), isServer(false),
      encryption(std::make_unique<Encryption>()), encryptionEstablished(false) {
    // Set a default save directory for received files
        saveDirectory = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);

}

void NetworkManager::connectToServer(const QString& host, quint16 port) {
    socket = new QTcpSocket(this);

    connect(socket, &QTcpSocket::connected, this, &NetworkManager::handleEncryptedConnection);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::handleReadyRead);

    socket->connectToHost(host, port);
}

void NetworkManager::startServer(quint16 port) {
    isServer = true;
    tcpServer = new QTcpServer(this);

    if (!tcpServer->listen(QHostAddress::Any, port)) {
        emit connectionError("Server failed to start");
        return;
    }

    connect(tcpServer, &QTcpServer::newConnection, this, &NetworkManager::handleNewConnection);
}

void NetworkManager::handleNewConnection() {
    socket = tcpServer->nextPendingConnection();
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::handleReadyRead);
    setupEncryption();
}

void NetworkManager::setupEncryption() {
    if (isServer) {
        // Generate AES key and send it encrypted with RSA
        aesKey = encryption->generateAESKey();
        auto encryptedKey = encryption->encryptAESKeyWithRSA(aesKey);

        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);
        stream << static_cast<quint32>(encryptedKey.size());
        data.append(QByteArray(reinterpret_cast<const char*>(encryptedKey.data()),
                              encryptedKey.size()));

        socket->write(data);
        encryptionEstablished = true;
        emit connectionEstablished();
    }
}

void NetworkManager::handleEncryptedConnection() {
    // Client waits for the encrypted AES key
    if (!isServer) {
        encryptionEstablished = false;
        emit connectionEstablished();
    }
}

void NetworkManager::handleReadyRead() {
    if (!socket) return;

    QByteArray data = socket->readAll();

    if (!isServer && !encryptionEstablished) {
        // Client receives the encrypted AES key
        QDataStream stream(data);
        quint32 keySize;
        stream >> keySize;

        QByteArray encryptedKeyData = data.mid(sizeof(quint32), keySize);
        std::vector<unsigned char> encryptedKey(encryptedKeyData.begin(), encryptedKeyData.end());

        try {
            aesKey = encryption->decryptAESKeyWithRSA(encryptedKey);
            encryptionEstablished = true;
        } catch (const std::exception& e) {
            emit connectionError(QString("Encryption error: ") + e.what());
            return;
        }
    } else {
        handleEncryptedMessage(data);
    }
}
QByteArray NetworkManager::prepareEncryptedMessage(const QString& message) {
    std::vector<unsigned char> iv;
    std::vector<unsigned char> encryptedMessage = encryption->encryptMessageWithAES(
        message.toStdString(), aesKey, iv);

    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);

    // Write IV size and IV
    stream << static_cast<quint32>(iv.size());
    // Write encrypted message size
    stream << static_cast<quint32>(encryptedMessage.size());

    // Append IV and encrypted message
    data.append(QByteArray(reinterpret_cast<const char*>(iv.data()), iv.size()));
    data.append(QByteArray(reinterpret_cast<const char*>(encryptedMessage.data()),
                          encryptedMessage.size()));

    return data;
}

void NetworkManager::startFileTransfer(const QString& fileName, qint64 encryptedFileSize) {
    currentFileName = QDir(saveDirectory).filePath(fileName);
    totalFileSize = encryptedFileSize;
    receivedFileSize = 0;
    fileBuffer.clear();
}
void NetworkManager::handleEncryptedMessage(const QByteArray& data) {
    QDataStream stream(data);
    quint32 ivSize, messageSize;
    stream >> ivSize >> messageSize;

    QByteArray ivData = data.mid(sizeof(quint32) * 2, ivSize);
    QByteArray encryptedData = data.mid(sizeof(quint32) * 2 + ivSize, messageSize);

    std::vector<unsigned char> iv(ivData.begin(), ivData.end());
    std::vector<unsigned char> encryptedMessage(encryptedData.begin(), encryptedData.end());

    try {
        std::string decryptedMessage = encryption->decryptMessageWithAES(
            encryptedMessage, aesKey, iv);
        QString message = QString::fromStdString(decryptedMessage);

        // Add file transfer handling
        if (message.startsWith("ENCRYPTED_FILE_TRANSFER")) {
            QStringList parts = message.split('\n');
            if (parts.size() == 3) {
                QString fileName = parts[1];
                qint64 encryptedFileSize = parts[2].toLongLong();

                // Start file transfer
                startFileTransfer(fileName, encryptedFileSize);
                return;
            }
        }

        emit messageReceived(message);
        // Emit the encrypted message as well
        emit messageReceived(QString::fromUtf8(encryptedData.toHex()));

    } catch (const std::exception& e) {
        emit connectionError(QString("Decryption error: ") + e.what());
    }
}

void NetworkManager::sendFile(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit connectionError("Could not open file: " + filePath);
        return;
    }

    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    qint64 fileSize = file.size();

    // Read entire file
    QByteArray fileData = file.readAll();
    file.close();

    // Encrypt entire file
    QByteArray encryptedFileData = encryptFileData(fileData);

    // Prepare encrypted file transfer header
    QByteArray header;
    QDataStream headerStream(&header, QIODevice::WriteOnly);
    headerStream << QString("ENCRYPTED_FILE_TRANSFER");
    headerStream << fileName;
    headerStream << encryptedFileData.size(); // Encrypted file size

    // Encrypt the header
    QByteArray encryptedHeader = prepareEncryptedMessage(QString::fromUtf8(header));
    socket->write(encryptedHeader);

    // Send encrypted file chunks
    const qint64 CHUNK_SIZE = 1024 * 1024; // 1 MB chunks
    for (qint64 i = 0; i < encryptedFileData.size(); i += CHUNK_SIZE) {
        QByteArray chunk = encryptedFileData.mid(i, CHUNK_SIZE);
        socket->write(chunk);
        socket->waitForBytesWritten();
    }

    emit messageReceived("Encrypted file transfer complete: " + fileName);
}

void NetworkManager::processReceivedFileData(const QByteArray& encryptedData) {
    if (receivedFileSize + encryptedData.size() <= totalFileSize) {
        fileBuffer.append(encryptedData);
        receivedFileSize += encryptedData.size();

        // Update progress
        double progress = (static_cast<double>(receivedFileSize) / totalFileSize) * 100.0;
        emit messageReceived(QString("Encrypted file transfer progress: %1%").arg(progress, 0, 'f', 2));

        if (receivedFileSize == totalFileSize) {
            // Decrypt the entire file
            QByteArray decryptedFileData = decryptFileData(fileBuffer);

            // Save decrypted file
            QFile outputFile(currentFileName);
            if (outputFile.open(QIODevice::WriteOnly)) {
                outputFile.write(decryptedFileData);
                outputFile.close();

                emit messageReceived("Encrypted file transfer complete: " + currentFileName);
            } else {
                emit connectionError("Could not save decrypted file: " + currentFileName);
            }

            // Reset file transfer state
            fileBuffer.clear();
            receivedFileSize = 0;
            totalFileSize = 0;
        }
    }
}

QByteArray NetworkManager::encryptFileData(const QByteArray& fileData) {
    // Convert QByteArray to std::vector for encryption
    std::vector<unsigned char> inputData(fileData.begin(), fileData.end());

    // Generate a new IV for file encryption
    std::vector<unsigned char> iv = encryption->generateIV();

    // Encrypt the entire file
    std::string inputDataStr(inputData.begin(), inputData.end()); // Convert to std::string

    // Then call the encryptMessageWithAES function with std::string
    std::vector<unsigned char> encryptedData = encryption->encryptMessageWithAES(inputDataStr, aesKey, iv);


    // Combine IV and encrypted data
    QByteArray combinedData;
    QDataStream stream(&combinedData, QIODevice::WriteOnly);

    // Write IV size and data
    quint32 ivSize = iv.size();
    stream << ivSize;
    stream.writeRawData(reinterpret_cast<const char*>(iv.data()), ivSize);

    // Write encrypted data
    stream.writeRawData(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());

    return combinedData;
}

QByteArray NetworkManager::decryptFileData(const QByteArray& encryptedData) {
    QDataStream stream(encryptedData);

    // Read IV size
    quint32 ivSize;
    stream >> ivSize;

    // Read IV
    QByteArray ivData(ivSize, 0);
    stream.readRawData(ivData.data(), ivSize);
    std::vector<unsigned char> iv(ivData.begin(), ivData.end());

    // Read encrypted data
    QByteArray remainingData = encryptedData.mid(sizeof(quint32) + ivSize);
    std::vector<unsigned char> encryptedFileData(remainingData.begin(), remainingData.end());

    // Decrypt file
    std::vector<unsigned char> decryptedData = encryption->decryptMessageWithAES(
        encryptedFileData, aesKey, iv);

    return QByteArray(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
}

void NetworkManager::sendMessage(const QString& message) {
    if (!socket || !socket->isOpen() || !encryptionEstablished) return;

    try {
        QByteArray encryptedData = prepareEncryptedMessage(message);
        socket->write(encryptedData);
    } catch (const std::exception& e) {
        emit connectionError(QString("Encryption error: ") + e.what());
    }
}

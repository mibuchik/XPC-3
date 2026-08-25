#include "worker.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QProcess>

extern "C" {
#include "../XPC-3/xpc3.h"
}

CryptoWorker::CryptoWorker(bool isEncrypt, const QString &inFile, const QString &outFile, const QString &password, QObject *parent)
    : QThread(parent), m_isEncrypt(isEncrypt), m_inFile(inFile), m_outFile(outFile), m_password(password) {}

void CryptoWorker::run() {
    emit logMessage(QString("🚀 %1 process started...").arg(m_isEncrypt ? "Encryption" : "Decryption"));
    emit logMessage(QString("   Input: %1").arg(m_inFile));
    emit logMessage(QString("   Output: %1").arg(m_outFile));

    QFileInfo inInfo(m_inFile);
    bool isDirectoryInput = inInfo.isDir();
    QString actualInFile = m_inFile;
    QString tempTarFile = "";

    if (m_isEncrypt && isDirectoryInput) {
        emit logMessage("📦 Target is a directory. Archiving folder with tar...");
        tempTarFile = m_inFile + ".tmp.tar";
        QFile::remove(tempTarFile);

        QDir dir(m_inFile);
        QString folderName = dir.dirName();
        QString parentDir = QFileInfo(m_inFile).absolutePath();

        QProcess tarProc;
        tarProc.start("tar", QStringList() << "-cf" << tempTarFile << "-C" << parentDir << folderName);
        tarProc.waitForFinished(-1);

        if (tarProc.exitCode() != 0 || !QFile::exists(tempTarFile)) {
            emit logMessage("❌ Error archiving directory with tar.");
            emit workFinished(false, "Failed to archive directory prior to encryption.");
            return;
        }
        actualInFile = tempTarFile;
        emit logMessage("✅ Directory archived to temporary tar stream.");
    }

    emit logMessage("🧠 Computing Memory-Hard XKDF (64 MiB RAM, 3 passes)...");

    std::string inStr = actualInFile.toStdString();
    std::string outStr = m_outFile.toStdString();
    std::string passStr = m_password.toStdString();

    int res = 0;
    if (m_isEncrypt) {
        res = xpc3_encrypt_file(inStr.c_str(), outStr.c_str(), passStr.c_str());
    } else {
        res = xpc3_decrypt_file(inStr.c_str(), outStr.c_str(), passStr.c_str());
    }

    if (!tempTarFile.isEmpty()) {
        QFile::remove(tempTarFile);
    }

    if (res == XPC_OK) {
        emit logMessage("✨ Cryptographic operations completed successfully!");

        if (m_isEncrypt) {
            if (isDirectoryInput) {
                if (QDir(m_inFile).removeRecursively()) {
                    emit logMessage(QString("🗑️ Source directory deleted: %1").arg(m_inFile));
                } else {
                    emit logMessage(QString("⚠️ Could not delete source directory: %1").arg(m_inFile));
                }
            } else {
                if (m_inFile != m_outFile) {
                    if (QFile::remove(m_inFile)) {
                        emit logMessage(QString("🗑️ Source file deleted: %1").arg(m_inFile));
                    } else {
                        emit logMessage(QString("⚠️ Could not delete source file: %1").arg(m_inFile));
                    }
                }
            }
            emit workFinished(true, QString("Encryption succeeded!\nOutput saved to: %1\nSource deleted.").arg(m_outFile));
        } else {
            // Decryption succeeded
            if (m_inFile != m_outFile) {
                if (QFile::remove(m_inFile)) {
                    emit logMessage(QString("🗑️ Encrypted source file deleted: %1").arg(m_inFile));
                }
            }

            // Check if decrypted file is a tar archive
            QProcess testTar;
            testTar.start("tar", QStringList() << "-tf" << m_outFile);
            testTar.waitForFinished(-1);

            if (testTar.exitCode() == 0) {
                emit logMessage("📦 Decrypted payload is a directory archive. Extracting folder...");
                QFileInfo outInfo(m_outFile);
                QString destParentDir = outInfo.absolutePath();

                QProcess extractProc;
                extractProc.start("tar", QStringList() << "-xf" << m_outFile << "-C" << destParentDir);
                extractProc.waitForFinished(-1);

                if (extractProc.exitCode() == 0) {
                    QFile::remove(m_outFile);
                    emit logMessage(QString("📂 Directory extracted successfully to: %1").arg(destParentDir));
                    emit workFinished(true, QString("Decryption succeeded!\nDirectory extracted to: %1").arg(destParentDir));
                    return;
                } else {
                    emit logMessage("⚠️ Failed to auto-extract tar archive, keeping output file.");
                }
            }

            emit workFinished(true, QString("Decryption succeeded!\nFile saved to: %1").arg(m_outFile));
        }
    } else {
        QString errMsg;
        switch (res) {
            case XPC_ERR_MEMORY:
                errMsg = "Memory allocation failure (could not allocate 64 MiB buffer)";
                break;
            case XPC_ERR_AUTH_FAILED:
            case XPC_ERR_INVALID_PASS:
                errMsg = "Authentication failed! Incorrect password or tampered file.";
                break;
            case XPC_ERR_FILE_IO:
                errMsg = "File I/O error reading input or writing output file.";
                break;
            case XPC_ERR_INVALID_FORMAT:
                errMsg = "Invalid XPC-3 file structure or corrupt header.";
                break;
            case XPC_ERR_DECOMPRESSION:
                errMsg = "Decompression failed (corrupted payload).";
                break;
            default:
                errMsg = QString("Cryptographic failure (Error code %1)").arg(res);
                break;
        }
        emit logMessage(QString("❌ Error: %1").arg(errMsg));
        emit workFinished(false, errMsg);
    }
}

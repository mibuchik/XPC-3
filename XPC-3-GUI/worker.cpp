#include "worker.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QProcess>
#include <QElapsedTimer>

extern "C" {
#include "../XPC-3/xpc3.h"
}

CryptoWorker::CryptoWorker(bool isEncrypt, const QStringList &inFiles, const QString &password, bool shredSource, QObject *parent)
    : QThread(parent), m_isEncrypt(isEncrypt), m_inFiles(inFiles), m_password(password), m_shredSource(shredSource) {}

QString CryptoWorker::autoEncOutputPath(const QString &inPath) {
    QString p = inPath.trimmed();
    while (p.endsWith('/') || p.endsWith('\\')) p.chop(1);
    if (p.isEmpty()) return "";
    return p + ".xpc";
}

QString CryptoWorker::autoDecOutputPath(const QString &inPath) {
    QString p = inPath.trimmed();
    if (p.isEmpty()) return "";
    if (p.endsWith(".xpc", Qt::CaseInsensitive)) {
        return p.left(p.length() - 4);
    }
    if (p.endsWith(".xpc3", Qt::CaseInsensitive)) {
        return p.left(p.length() - 5);
    }
    return p + ".dec";
}

qint64 CryptoWorker::calculatePathSize(const QString &path) {
    QFileInfo info(path);
    if (!info.exists()) return 0;
    if (info.isFile()) return info.size();
    if (info.isDir()) {
        qint64 total = 0;
        QDirIterator it(path, QDir::Files, QDirIterator::Subdirectories);
        while (it.hasNext()) {
            it.next();
            total += it.fileInfo().size();
        }
        return total;
    }
    return 0;
}

void CryptoWorker::run() {
    int totalFiles = m_inFiles.size();
    if (totalFiles == 0) {
        emit workFinished(false, tr("No files to process."));
        return;
    }

    emit logMessage(tr("🚀 Starting batch %1 of %2 target(s)...")
                    .arg(m_isEncrypt ? "Encryption" : "Decryption")
                    .arg(totalFiles));

    qint64 totalBytes = 0;
    for (const QString &f : m_inFiles) {
        totalBytes += calculatePathSize(f);
    }

    QElapsedTimer timer;
    timer.start();

    qint64 bytesDone = 0;
    int successCount = 0;
    int failCount = 0;

    for (int i = 0; i < totalFiles; ++i) {
        QString currentInFile = m_inFiles[i];
        QFileInfo inInfo(currentInFile);
        qint64 itemSize = calculatePathSize(currentInFile);

        emit itemStarted(i, currentInFile);
        emit logMessage(tr("🔹 [%1/%2] Processing: %3 (%4 KB)")
                        .arg(i + 1)
                        .arg(totalFiles)
                        .arg(inInfo.fileName())
                        .arg(itemSize / 1024));

        if (!inInfo.exists()) {
            failCount++;
            emit itemFinished(i, false, tr("File not found"));
            emit logMessage(tr("❌ File not found: %1").arg(currentInFile));
            continue;
        }

        bool isDirectoryInput = inInfo.isDir();
        QString actualInFile = currentInFile;
        QString tempTarFile = "";

        if (m_isEncrypt && isDirectoryInput) {
            emit logMessage(tr("📦 Archiving folder '%1' with tar...").arg(inInfo.fileName()));
            tempTarFile = currentInFile + ".tmp.tar";
            QFile::remove(tempTarFile);

            QDir dir(currentInFile);
            QString folderName = dir.dirName();
            QString parentDir = QFileInfo(currentInFile).absolutePath();

            QProcess tarProc;
            tarProc.start("tar", QStringList() << "-cf" << tempTarFile << "-C" << parentDir << folderName);
            tarProc.waitForFinished(-1);

            if (tarProc.exitCode() != 0 || !QFile::exists(tempTarFile)) {
                failCount++;
                emit itemFinished(i, false, tr("Tar archiving failed"));
                emit logMessage(tr("❌ Error archiving directory with tar: %1").arg(currentInFile));
                continue;
            }
            actualInFile = tempTarFile;
        }

        QString currentOutFile = m_isEncrypt ? autoEncOutputPath(currentInFile) : autoDecOutputPath(currentInFile);
        std::string inStr = actualInFile.toStdString();
        std::string outStr = currentOutFile.toStdString();
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
            successCount++;

            if (m_isEncrypt) {
                if (m_shredSource) {
                    if (isDirectoryInput) {
                        QDir(currentInFile).removeRecursively();
                    } else if (currentInFile != currentOutFile) {
                        QFile::remove(currentInFile);
                    }
                    emit logMessage(tr("🗑️ Source shredded: %1").arg(inInfo.fileName()));
                }
            } else {
                if (m_shredSource && currentInFile != currentOutFile) {
                    QFile::remove(currentInFile);
                    emit logMessage(tr("🗑️ Container shredded: %1").arg(inInfo.fileName()));
                }

                // Check if decrypted file is a tar archive and unpack
                QProcess testTar;
                testTar.start("tar", QStringList() << "-tf" << currentOutFile);
                testTar.waitForFinished(-1);

                if (testTar.exitCode() == 0) {
                    QFileInfo outInfo(currentOutFile);
                    QString destParentDir = outInfo.absolutePath();

                    QProcess extractProc;
                    extractProc.start("tar", QStringList() << "-xf" << currentOutFile << "-C" << destParentDir);
                    extractProc.waitForFinished(-1);

                    if (extractProc.exitCode() == 0) {
                        QFile::remove(currentOutFile);
                        emit logMessage(tr("📂 Unpacked archive to: %1").arg(destParentDir));
                    }
                }
            }

            emit itemFinished(i, true, tr("OK"));
            emit logMessage(tr("✨ Success: %1 -> %2").arg(inInfo.fileName(), QFileInfo(currentOutFile).fileName()));
        } else {
            failCount++;
            QString errMsg;
            switch (res) {
                case XPC_ERR_MEMORY:
                    errMsg = "Memory failure (64 MiB)";
                    break;
                case XPC_ERR_AUTH_FAILED:
                case XPC_ERR_INVALID_PASS:
                    errMsg = "Auth failed / wrong pass";
                    break;
                case XPC_ERR_FILE_IO:
                    errMsg = "File I/O error";
                    break;
                case XPC_ERR_INVALID_FORMAT:
                    errMsg = "Corrupt / invalid format";
                    break;
                case XPC_ERR_DECOMPRESSION:
                    errMsg = "Decompression failed";
                    break;
                default:
                    errMsg = tr("Crypto error %1").arg(res);
                    break;
            }
            emit itemFinished(i, false, errMsg);
            emit logMessage(tr("❌ Error on %1: %2").arg(inInfo.fileName(), errMsg));
        }

        bytesDone += itemSize;
        int overallPercent = (int)(((double)(i + 1) / totalFiles) * 100.0);
        qint64 elapsedMs = timer.elapsed();
        double speedMBs = (elapsedMs > 50) ? ((double)bytesDone / (1024.0 * 1024.0)) / (elapsedMs / 1000.0) : 0.0;

        emit batchProgress(overallPercent, speedMBs, bytesDone, totalBytes, i + 1, totalFiles);
    }

    QString summary;
    if (totalFiles == 1) {
        if (successCount == 1) {
            summary = tr("Operation succeeded for %1!").arg(QFileInfo(m_inFiles.first()).fileName());
        } else {
            summary = tr("Operation failed for %1!").arg(QFileInfo(m_inFiles.first()).fileName());
        }
    } else {
        summary = tr("Batch completed!\nSuccessful: %1 / %2\nFailed: %3")
                  .arg(successCount)
                  .arg(totalFiles)
                  .arg(failCount);
    }

    emit logMessage(tr("🏁 Batch finished. %1 ok, %2 failed.").arg(successCount).arg(failCount));
    emit workFinished(failCount == 0, summary);
}

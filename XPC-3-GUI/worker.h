#ifndef WORKER_H
#define WORKER_H

#include <QThread>
#include <QString>
#include <QStringList>

class CryptoWorker : public QThread {
    Q_OBJECT
public:
    CryptoWorker(bool isEncrypt, const QStringList &inFiles, const QString &password, bool shredSource, QObject *parent = nullptr);

signals:
    void logMessage(const QString &msg);
    void itemStarted(int index, const QString &filePath);
    void itemFinished(int index, bool success, const QString &message);
    void batchProgress(int percent, double speedMBs, qint64 bytesDone, qint64 totalBytes, int itemsDone, int totalItems);
    void workFinished(bool allSuccess, const QString &summaryMessage);

protected:
    void run() override;

private:
    bool m_isEncrypt;
    QStringList m_inFiles;
    QString m_password;
    bool m_shredSource;

    QString autoEncOutputPath(const QString &inPath);
    QString autoDecOutputPath(const QString &inPath);
    qint64 calculatePathSize(const QString &path);
};

#endif // WORKER_H

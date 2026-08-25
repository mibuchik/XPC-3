#ifndef WORKER_H
#define WORKER_H

#include <QThread>
#include <QString>

class CryptoWorker : public QThread {
    Q_OBJECT
public:
    CryptoWorker(bool isEncrypt, const QString &inFile, const QString &outFile, const QString &password, QObject *parent = nullptr);

signals:
    void logMessage(const QString &msg);
    void workFinished(bool success, const QString &message);

protected:
    void run() override;

private:
    bool m_isEncrypt;
    QString m_inFile;
    QString m_outFile;
    QString m_password;
};

#endif // WORKER_H

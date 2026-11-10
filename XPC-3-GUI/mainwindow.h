#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QTextEdit>
#include <QTabWidget>
#include <QLabel>
#include <QCheckBox>
#include <QListWidget>
#include <QStringList>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QEvent>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>

class CryptoWorker;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void handleInputPath(const QString &filePath);
    void handleInputPaths(const QStringList &filePaths);

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;
    void changeEvent(QEvent *event) override;
    void closeEvent(QCloseEvent *event) override;

private slots:
    void browseEncInput();
    void browseEncFolder();
    void browseDecInput();
    void toggleEncPassword();
    void toggleDecPassword();
    void startEncryption();
    void startDecryption();
    void appendLog(const QString &msg);
    void handleFinished(bool success, const QString &message);
    void onBatchProgress(int percent, double speedMBs, qint64 bytesDone, qint64 totalBytes, int itemsDone, int totalItems);
    void onItemStarted(int index, const QString &filePath);
    void onItemFinished(int index, bool success, const QString &message);
    void clearEncQueue();
    void clearDecQueue();
    void updateEncOutputHint();
    void updateDecOutputHint();

    // Tray Icon Slots
    void toggleWindowVisibility();
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);

private:
    void applySystemTheme();
    bool isSystemDarkTheme() const;
    void setupTrayIcon();
    void setEncFiles(const QStringList &files);
    void setDecFiles(const QStringList &files);
    QString autoEncOutputPath(const QString &inPath);
    QString autoDecOutputPath(const QString &inPath);

    QTabWidget *m_tabWidget;

    // Encrypt Controls
    QLineEdit *m_encInPath;
    QPushButton *m_encClearBtn;
    QListWidget *m_encQueueList;
    QLabel *m_encOutHintLabel;
    QLineEdit *m_encPassword;
    QPushButton *m_encShowPassBtn;
    QCheckBox *m_encShredCheck;
    QPushButton *m_encBtn;
    QLabel *m_encDropZone;
    QStringList m_encFiles;

    // Decrypt Controls
    QLineEdit *m_decInPath;
    QPushButton *m_decClearBtn;
    QListWidget *m_decQueueList;
    QLabel *m_decOutHintLabel;
    QLineEdit *m_decPassword;
    QPushButton *m_decShowPassBtn;
    QCheckBox *m_decShredCheck;
    QPushButton *m_decBtn;
    QLabel *m_decDropZone;
    QStringList m_decFiles;

    // Progress & Log Console
    QLabel *m_speedLabel;
    QProgressBar *m_progressBar;
    QTextEdit *m_logConsole;

    // System Tray
    QSystemTrayIcon *m_trayIcon;
    QMenu *m_trayMenu;

    // Badges & Recursion guard
    QList<QLabel*> m_badges;
    bool m_isApplyingTheme;

    CryptoWorker *m_worker;
};

#endif // MAINWINDOW_H

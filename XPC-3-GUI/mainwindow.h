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
    void updateEncOutputHint(const QString &inPath);
    void updateDecOutputHint(const QString &inPath);

    // Tray Icon Slots
    void toggleWindowVisibility();
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);

private:
    void applySystemTheme();
    bool isSystemDarkTheme() const;
    void setupTrayIcon();
    QString autoEncOutputPath(const QString &inPath);
    QString autoDecOutputPath(const QString &inPath);

    QTabWidget *m_tabWidget;

    // Encrypt Controls
    QLineEdit *m_encInPath;
    QLabel *m_encOutHintLabel;
    QLineEdit *m_encPassword;
    QPushButton *m_encShowPassBtn;
    QCheckBox *m_encShredCheck;
    QPushButton *m_encBtn;
    QLabel *m_encDropZone;

    // Decrypt Controls
    QLineEdit *m_decInPath;
    QLabel *m_decOutHintLabel;
    QLineEdit *m_decPassword;
    QPushButton *m_decShowPassBtn;
    QCheckBox *m_decShredCheck;
    QPushButton *m_decBtn;
    QLabel *m_decDropZone;

    // Progress & Log Console
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

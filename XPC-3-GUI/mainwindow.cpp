#include "mainwindow.h"
#include "worker.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QMimeData>
#include <QFileInfo>
#include <QDateTime>
#include <QGuiApplication>
#include <QApplication>
#include <QPalette>
#include <QIcon>
#include <QSystemTrayIcon>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_isApplyingTheme(false), m_worker(nullptr) {
    setWindowTitle(tr("XPC-3"));
    setWindowIcon(QIcon(":/icon.png"));
    resize(760, 720);
    setAcceptDrops(true);

    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(14);

    // --- CARD HEADER ---
    QWidget *headerCard = new QWidget(this);
    headerCard->setObjectName("shadcnCard");
    QVBoxLayout *headerLayout = new QVBoxLayout(headerCard);
    headerLayout->setContentsMargins(20, 20, 20, 20);
    headerLayout->setSpacing(8);

    QHBoxLayout *titleRow = new QHBoxLayout();
    titleRow->setSpacing(12);

    QLabel *logoImgLabel = new QLabel(headerCard);
    QPixmap logoPix(":/icon.png");
    logoImgLabel->setPixmap(logoPix.scaled(28, 28, Qt::KeepAspectRatio, Qt::SmoothTransformation));

    QLabel *titleLabel = new QLabel(tr("XPC-3"), headerCard);
    titleLabel->setObjectName("titleLabel");

    titleRow->addWidget(logoImgLabel);
    titleRow->addWidget(titleLabel);
    titleRow->addStretch();

    QLabel *descLabel = new QLabel(tr("Production-grade triple cascade file encryption powered by 64 MiB Memory-Hard XKDF."), headerCard);
    descLabel->setObjectName("descLabel");

    // Badges Row
    QHBoxLayout *badgesLayout = new QHBoxLayout();
    badgesLayout->setSpacing(8);
    badgesLayout->setAlignment(Qt::AlignLeft);

    auto createBadge = [this](const QString &text) {
        QLabel *b = new QLabel(text);
        b->setObjectName("badgeLabel");
        m_badges.append(b);
        return b;
    };

    badgesLayout->addWidget(createBadge("🛡️ XPC-3 Feistel"));
    badgesLayout->addWidget(createBadge("🔒 AES-256-GCM"));
    badgesLayout->addWidget(createBadge("⚡ ChaCha20-Poly1305"));
    badgesLayout->addWidget(createBadge("🧠 64MB XKDF"));
    badgesLayout->addWidget(createBadge("📦 Batch Queue"));
    badgesLayout->addStretch();

    headerLayout->addLayout(titleRow);
    headerLayout->addWidget(descLabel);
    headerLayout->addLayout(badgesLayout);

    mainLayout->addWidget(headerCard);

    // --- TABS COMPONENT ---
    m_tabWidget = new QTabWidget(this);

    // --- ENCRYPT TAB ---
    QWidget *encTab = new QWidget();
    QVBoxLayout *encLayout = new QVBoxLayout(encTab);
    encLayout->setContentsMargins(18, 18, 18, 18);
    encLayout->setSpacing(12);

    m_encDropZone = new QLabel(tr("Drag & drop file(s) or folder here, or click to browse"), encTab);
    m_encDropZone->setObjectName("shadcnDropZone");
    m_encDropZone->setAlignment(Qt::AlignCenter);
    m_encDropZone->setFixedHeight(72);
    encLayout->addWidget(m_encDropZone);

    QHBoxLayout *encInLayout = new QHBoxLayout();
    m_encInPath = new QLineEdit(encTab);
    m_encInPath->setPlaceholderText(tr("Select target file(s) or folder to encrypt..."));
    QPushButton *btnEncBrowse = new QPushButton(tr("Files..."), encTab);
    btnEncBrowse->setObjectName("secondaryButton");
    btnEncBrowse->setCursor(Qt::PointingHandCursor);

    QPushButton *btnEncFolderBrowse = new QPushButton(tr("Folder..."), encTab);
    btnEncFolderBrowse->setObjectName("secondaryButton");
    btnEncFolderBrowse->setCursor(Qt::PointingHandCursor);

    m_encClearBtn = new QPushButton(tr("Clear"), encTab);
    m_encClearBtn->setObjectName("ghostButton");
    m_encClearBtn->setCursor(Qt::PointingHandCursor);
    m_encClearBtn->setVisible(false);

    encInLayout->addWidget(m_encInPath);
    encInLayout->addWidget(btnEncBrowse);
    encInLayout->addWidget(btnEncFolderBrowse);
    encInLayout->addWidget(m_encClearBtn);
    encLayout->addLayout(encInLayout);

    // Adaptive Queue List (hidden until > 1 file selected)
    m_encQueueList = new QListWidget(encTab);
    m_encQueueList->setFixedHeight(100);
    m_encQueueList->setVisible(false);
    encLayout->addWidget(m_encQueueList);

    m_encOutHintLabel = new QLabel(tr("Destination: (select file or folder first)"), encTab);
    m_encOutHintLabel->setObjectName("hintLabel");
    encLayout->addWidget(m_encOutHintLabel);

    QHBoxLayout *encPassLayout = new QHBoxLayout();
    m_encPassword = new QLineEdit(encTab);
    m_encPassword->setEchoMode(QLineEdit::Password);
    m_encPassword->setPlaceholderText(tr("Enter secret passphrase..."));
    m_encShowPassBtn = new QPushButton(tr("👁"), encTab);
    m_encShowPassBtn->setObjectName("ghostButton");
    m_encShowPassBtn->setFixedWidth(40);
    m_encShowPassBtn->setCursor(Qt::PointingHandCursor);
    encPassLayout->addWidget(m_encPassword);
    encPassLayout->addWidget(m_encShowPassBtn);
    encLayout->addLayout(encPassLayout);

    m_encShredCheck = new QCheckBox(tr("Delete (shred) source file after encryption"), encTab);
    m_encShredCheck->setObjectName("optionCheckBox");
    m_encShredCheck->setChecked(false);
    encLayout->addWidget(m_encShredCheck);

    m_encBtn = new QPushButton(tr("Encrypt Targets"), encTab);
    m_encBtn->setObjectName("primaryButton");
    m_encBtn->setFixedHeight(42);
    m_encBtn->setCursor(Qt::PointingHandCursor);
    encLayout->addWidget(m_encBtn);

    m_tabWidget->addTab(encTab, tr("Encrypt"));

    // --- DECRYPT TAB ---
    QWidget *decTab = new QWidget();
    QVBoxLayout *decLayout = new QVBoxLayout(decTab);
    decLayout->setContentsMargins(18, 18, 18, 18);
    decLayout->setSpacing(12);

    m_decDropZone = new QLabel(tr("Drag and drop .xpc file(s) here, or click to browse"), decTab);
    m_decDropZone->setObjectName("shadcnDropZone");
    m_decDropZone->setAlignment(Qt::AlignCenter);
    m_decDropZone->setFixedHeight(72);
    decLayout->addWidget(m_decDropZone);

    QHBoxLayout *decInLayout = new QHBoxLayout();
    m_decInPath = new QLineEdit(decTab);
    m_decInPath->setPlaceholderText(tr("Select .xpc file(s) to decrypt..."));
    QPushButton *btnDecBrowse = new QPushButton(tr("Files..."), decTab);
    btnDecBrowse->setObjectName("secondaryButton");
    btnDecBrowse->setCursor(Qt::PointingHandCursor);

    m_decClearBtn = new QPushButton(tr("Clear"), decTab);
    m_decClearBtn->setObjectName("ghostButton");
    m_decClearBtn->setCursor(Qt::PointingHandCursor);
    m_decClearBtn->setVisible(false);

    decInLayout->addWidget(m_decInPath);
    decInLayout->addWidget(btnDecBrowse);
    decInLayout->addWidget(m_decClearBtn);
    decLayout->addLayout(decInLayout);

    // Adaptive Queue List (hidden until > 1 file selected)
    m_decQueueList = new QListWidget(decTab);
    m_decQueueList->setFixedHeight(100);
    m_decQueueList->setVisible(false);
    decLayout->addWidget(m_decQueueList);

    m_decOutHintLabel = new QLabel(tr("Destination: (select .xpc file first)"), decTab);
    m_decOutHintLabel->setObjectName("hintLabel");
    decLayout->addWidget(m_decOutHintLabel);

    QHBoxLayout *decPassLayout = new QHBoxLayout();
    m_decPassword = new QLineEdit(decTab);
    m_decPassword->setEchoMode(QLineEdit::Password);
    m_decPassword->setPlaceholderText(tr("Enter secret passphrase..."));
    m_decShowPassBtn = new QPushButton(tr("👁"), decTab);
    m_decShowPassBtn->setObjectName("ghostButton");
    m_decShowPassBtn->setFixedWidth(40);
    m_decShowPassBtn->setCursor(Qt::PointingHandCursor);
    decPassLayout->addWidget(m_decPassword);
    decPassLayout->addWidget(m_decShowPassBtn);
    decLayout->addLayout(decPassLayout);

    m_decShredCheck = new QCheckBox(tr("Delete .xpc container after successful decryption"), decTab);
    m_decShredCheck->setObjectName("optionCheckBox");
    m_decShredCheck->setChecked(false);
    decLayout->addWidget(m_decShredCheck);

    m_decBtn = new QPushButton(tr("Decrypt Targets"), decTab);
    m_decBtn->setObjectName("primaryButton");
    m_decBtn->setFixedHeight(42);
    m_decBtn->setCursor(Qt::PointingHandCursor);
    decLayout->addWidget(m_decBtn);

    m_tabWidget->addTab(decTab, tr("Decrypt"));

    mainLayout->addWidget(m_tabWidget);

    // Speed & Progress status
    m_speedLabel = new QLabel(this);
    m_speedLabel->setObjectName("speedLabel");
    m_speedLabel->setAlignment(Qt::AlignCenter);
    m_speedLabel->setVisible(false);
    mainLayout->addWidget(m_speedLabel);

    // Progress Bar
    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setFixedHeight(16);
    m_progressBar->setTextVisible(true);
    m_progressBar->setVisible(false);
    mainLayout->addWidget(m_progressBar);

    // Log Console Box
    QLabel *logLabel = new QLabel(tr("Console Output"), this);
    logLabel->setObjectName("consoleLabel");
    mainLayout->addWidget(logLabel);

    m_logConsole = new QTextEdit(this);
    m_logConsole->setReadOnly(true);
    m_logConsole->setFixedHeight(120);
    m_logConsole->setFont(QFont("Monospace", 9));
    mainLayout->addWidget(m_logConsole);

    setCentralWidget(centralWidget);

    // Connections
    connect(btnEncBrowse, &QPushButton::clicked, this, &MainWindow::browseEncInput);
    connect(btnEncFolderBrowse, &QPushButton::clicked, this, &MainWindow::browseEncFolder);
    connect(m_encClearBtn, &QPushButton::clicked, this, &MainWindow::clearEncQueue);

    connect(btnDecBrowse, &QPushButton::clicked, this, &MainWindow::browseDecInput);
    connect(m_decClearBtn, &QPushButton::clicked, this, &MainWindow::clearDecQueue);

    connect(m_encShowPassBtn, &QPushButton::clicked, this, &MainWindow::toggleEncPassword);
    connect(m_decShowPassBtn, &QPushButton::clicked, this, &MainWindow::toggleDecPassword);

    connect(m_encInPath, &QLineEdit::textChanged, this, &MainWindow::updateEncOutputHint);
    connect(m_decInPath, &QLineEdit::textChanged, this, &MainWindow::updateDecOutputHint);

    connect(m_encBtn, &QPushButton::clicked, this, &MainWindow::startEncryption);
    connect(m_decBtn, &QPushButton::clicked, this, &MainWindow::startDecryption);

    setupTrayIcon();
    applySystemTheme();
    appendLog("System tray icon active. System ready.");
}

MainWindow::~MainWindow() {
    if (m_worker && m_worker->isRunning()) {
        m_worker->terminate();
        m_worker->wait();
    }
}

void MainWindow::setupTrayIcon() {
    QIcon icon(":/icon.png");

    m_trayMenu = new QMenu(this);
    QAction *toggleAction = new QAction(tr("Show / Hide Window"), this);
    QAction *exitAction = new QAction(tr("Exit XPC-3"), this);

    connect(toggleAction, &QAction::triggered, this, &MainWindow::toggleWindowVisibility);
    connect(exitAction, &QAction::triggered, qApp, &QApplication::quit);

    m_trayMenu->addAction(toggleAction);
    m_trayMenu->addSeparator();
    m_trayMenu->addAction(exitAction);

    m_trayIcon = new QSystemTrayIcon(icon, this);
    m_trayIcon->setContextMenu(m_trayMenu);
    m_trayIcon->setToolTip(tr("XPC-3"));

    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::onTrayIconActivated);
    m_trayIcon->show();
}

void MainWindow::toggleWindowVisibility() {
    if (isVisible()) {
        hide();
    } else {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
        toggleWindowVisibility();
    }
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (m_trayIcon->isVisible()) {
        hide();
        m_trayIcon->showMessage(tr("XPC-3"), tr("Application is minimized to system tray."),
                                 QSystemTrayIcon::Information, 2000);
        event->ignore();
    } else {
        event->accept();
    }
}

bool MainWindow::isSystemDarkTheme() const {
    QColor windowColor = QGuiApplication::palette().color(QPalette::Window);
    double lightness = 0.299 * windowColor.red() + 0.587 * windowColor.green() + 0.114 * windowColor.blue();
    return lightness < 128.0;
}

void MainWindow::changeEvent(QEvent *event) {
    if ((event->type() == QEvent::PaletteChange || event->type() == QEvent::StyleChange) && !m_isApplyingTheme) {
        applySystemTheme();
    }
    QMainWindow::changeEvent(event);
}

void MainWindow::applySystemTheme() {
    if (m_isApplyingTheme) return;
    m_isApplyingTheme = true;

    bool dark = isSystemDarkTheme();

    QString badgeCss = dark ?
        "background-color: rgba(0, 245, 184, 0.08); color: #00f5b8; border: 1px solid rgba(0, 245, 184, 0.3); border-radius: 9999px; padding: 4px 12px; font-size: 11px; font-weight: 600;" :
        "background-color: #f1f5f9; color: #0f766e; border: 1px solid #cbd5e1; border-radius: 9999px; padding: 4px 12px; font-size: 11px; font-weight: 600;";

    for (QLabel *b : m_badges) {
        b->setStyleSheet(badgeCss);
    }

    QString qss = dark ? R"(
        QMainWindow { background-color: #0b0c10; }
        QWidget { color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        #shadcnCard { background-color: #12141d; border: 1px solid #1e2235; border-radius: 10px; }
        #titleLabel { color: #f8fafc; font-weight: 700; font-size: 20px; }
        #descLabel { color: #94a3b8; }
        #hintLabel { color: #38bdf8; font-weight: 500; font-family: monospace; font-size: 12px; }
        #speedLabel { color: #00f5b8; font-weight: 600; font-family: monospace; font-size: 12px; }
        #consoleLabel { color: #94a3b8; font-size: 12px; font-weight: 600; }
        #optionCheckBox { color: #94a3b8; font-size: 12px; font-weight: 500; spacing: 8px; }
        #optionCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #334155; background-color: #0f172a; }
        #optionCheckBox::indicator:checked { background-color: #00f5b8; border: 1px solid #00f5b8; }
        #shadcnDropZone { background-color: #0f1118; border: 2px dashed #24293e; border-radius: 8px; color: #64748b; font-size: 13px; font-weight: 500; }
        #shadcnDropZone:hover { background-color: #161a26; border-color: #00f5b8; color: #f8fafc; }
        QTabWidget::pane { border: 1px solid #1e2235; background-color: #12141d; border-radius: 8px; }
        QTabBar::tab { background-color: #0b0c10; color: #64748b; padding: 8px 20px; border-radius: 6px; margin: 4px 2px; font-weight: 600; font-size: 13px; }
        QTabBar::tab:selected { background-color: #1e2235; color: #00f5b8; }
        QLineEdit { background-color: #0b0c10; border: 1px solid #1e2235; border-radius: 6px; padding: 9px 12px; color: #f8fafc; font-size: 13px; }
        QLineEdit:focus { border: 1px solid #00f5b8; background-color: #0f1118; }
        QListWidget { background-color: #08090d; border: 1px solid #1e2235; border-radius: 6px; color: #cbd5e1; font-size: 12px; padding: 4px; }
        QListWidget::item { padding: 4px 8px; border-radius: 4px; }
        QListWidget::item:selected { background-color: #1e2235; color: #00f5b8; }
        #primaryButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00f5b8, stop:1 #02c39a); color: #050608; border: none; border-radius: 6px; font-weight: 700; font-size: 13px; }
        #primaryButton:hover { background: #34d399; }
        #primaryButton:disabled { background-color: #1e2235; color: #475569; }
        #secondaryButton { background-color: #1a1e2b; color: #f8fafc; border: 1px solid #282f44; border-radius: 6px; font-weight: 600; padding: 0 14px; }
        #secondaryButton:hover { background-color: #242c3f; border-color: #38bdf8; }
        #ghostButton { background-color: transparent; color: #94a3b8; border: 1px solid #1e2235; border-radius: 6px; padding: 0 12px; }
        #ghostButton:hover { background-color: #1e2235; color: #00f5b8; }
        QTextEdit { background-color: #08090d; border: 1px solid #1a1e2b; border-radius: 6px; color: #cbd5e1; padding: 10px; font-family: monospace; font-size: 12px; }
        QProgressBar { background-color: #12141d; border: 1px solid #1e2235; border-radius: 4px; text-align: center; color: #f8fafc; font-size: 11px; font-weight: 600; }
        QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00f5b8, stop:1 #38bdf8); border-radius: 3px; }
        QMenu { background-color: #12141d; color: #f8fafc; border: 1px solid #1e2235; padding: 4px; border-radius: 6px; }
        QMenu::item { padding: 6px 20px; border-radius: 4px; }
        QMenu::item:selected { background-color: #1e2235; color: #00f5b8; }
    )" : R"(
        QMainWindow { background-color: #f8fafc; }
        QWidget { color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        #shadcnCard { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; }
        #titleLabel { color: #0f172a; font-weight: 700; font-size: 20px; }
        #descLabel { color: #64748b; }
        #hintLabel { color: #0284c7; font-weight: 500; font-family: monospace; font-size: 12px; }
        #speedLabel { color: #0f766e; font-weight: 600; font-family: monospace; font-size: 12px; }
        #consoleLabel { color: #64748b; font-size: 12px; font-weight: 600; }
        #optionCheckBox { color: #475569; font-size: 12px; font-weight: 500; spacing: 8px; }
        #optionCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #cbd5e1; background-color: #ffffff; }
        #optionCheckBox::indicator:checked { background-color: #0f766e; border: 1px solid #0f766e; }
        #shadcnDropZone { background-color: #f1f5f9; border: 2px dashed #cbd5e1; border-radius: 8px; color: #64748b; font-size: 13px; font-weight: 500; }
        #shadcnDropZone:hover { background-color: #e2e8f0; border-color: #0f766e; color: #0f172a; }
        QTabWidget::pane { border: 1px solid #e2e8f0; background-color: #ffffff; border-radius: 8px; }
        QTabBar::tab { background-color: #f1f5f9; color: #64748b; padding: 8px 20px; border-radius: 6px; margin: 4px 2px; font-weight: 600; font-size: 13px; }
        QTabBar::tab:selected { background-color: #ffffff; color: #0f766e; }
        QLineEdit { background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 9px 12px; color: #0f172a; font-size: 13px; }
        QLineEdit:focus { border: 1px solid #0f766e; }
        QListWidget { background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; color: #0f172a; font-size: 12px; padding: 4px; }
        QListWidget::item { padding: 4px 8px; border-radius: 4px; }
        QListWidget::item:selected { background-color: #f1f5f9; color: #0f766e; }
        #primaryButton { background-color: #0f766e; color: #ffffff; border: none; border-radius: 6px; font-weight: 700; font-size: 13px; }
        #primaryButton:hover { background-color: #115e59; }
        #primaryButton:disabled { background-color: #e2e8f0; color: #94a3b8; }
        #secondaryButton { background-color: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; border-radius: 6px; font-weight: 600; padding: 0 14px; }
        #secondaryButton:hover { background-color: #e2e8f0; }
        #ghostButton { background-color: transparent; color: #64748b; border: 1px solid #cbd5e1; border-radius: 6px; padding: 0 12px; }
        #ghostButton:hover { background-color: #e2e8f0; color: #0f172a; }
        QTextEdit { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; color: #1e293b; padding: 10px; font-family: monospace; font-size: 12px; }
        QProgressBar { background-color: #e2e8f0; border: 1px solid #cbd5e1; border-radius: 4px; text-align: center; color: #0f172a; font-size: 11px; font-weight: 600; }
        QProgressBar::chunk { background-color: #0f766e; border-radius: 3px; }
        QMenu { background-color: #ffffff; color: #0f172a; border: 1px solid #e2e8f0; padding: 4px; border-radius: 6px; }
        QMenu::item { padding: 6px 20px; border-radius: 4px; }
        QMenu::item:selected { background-color: #f1f5f9; color: #0f766e; }
    )";

    setStyleSheet(qss);
    m_isApplyingTheme = false;
}

QString MainWindow::autoEncOutputPath(const QString &inPath) {
    QString p = inPath.trimmed();
    while (p.endsWith('/') || p.endsWith('\\')) p.chop(1);
    if (p.isEmpty()) return "";
    return p + ".xpc";
}

QString MainWindow::autoDecOutputPath(const QString &inPath) {
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

void MainWindow::setEncFiles(const QStringList &files) {
    m_encFiles = files;
    m_encQueueList->clear();

    if (files.isEmpty()) {
        m_encInPath->clear();
        m_encQueueList->setVisible(false);
        m_encClearBtn->setVisible(false);
        updateEncOutputHint();
    } else if (files.size() == 1) {
        m_encInPath->setText(files.first());
        m_encQueueList->setVisible(false);
        m_encClearBtn->setVisible(true);
        updateEncOutputHint();
    } else {
        m_encInPath->setText(tr("Queue: %1 items selected").arg(files.size()));
        for (const QString &f : files) {
            QFileInfo fi(f);
            qint64 sz = fi.isDir() ? 0 : fi.size();
            QString label = fi.isDir() ? tr("📁 [Folder] %1").arg(fi.fileName())
                                       : tr("📄 %1 (%2 KB)").arg(fi.fileName()).arg(sz / 1024);
            new QListWidgetItem(label, m_encQueueList);
        }
        m_encQueueList->setVisible(true);
        m_encClearBtn->setVisible(true);
        m_encOutHintLabel->setText(tr("Destination: %1 encrypted containers (*.xpc)").arg(files.size()));
    }
}

void MainWindow::setDecFiles(const QStringList &files) {
    m_decFiles = files;
    m_decQueueList->clear();

    if (files.isEmpty()) {
        m_decInPath->clear();
        m_decQueueList->setVisible(false);
        m_decClearBtn->setVisible(false);
        updateDecOutputHint();
    } else if (files.size() == 1) {
        m_decInPath->setText(files.first());
        m_decQueueList->setVisible(false);
        m_decClearBtn->setVisible(true);
        updateDecOutputHint();
    } else {
        m_decInPath->setText(tr("Queue: %1 containers selected").arg(files.size()));
        for (const QString &f : files) {
            QFileInfo fi(f);
            QString label = tr("🔒 %1 (%2 KB)").arg(fi.fileName()).arg(fi.size() / 1024);
            new QListWidgetItem(label, m_decQueueList);
        }
        m_decQueueList->setVisible(true);
        m_decClearBtn->setVisible(true);
        m_decOutHintLabel->setText(tr("Destination: %1 decrypted outputs").arg(files.size()));
    }
}

void MainWindow::clearEncQueue() {
    setEncFiles(QStringList());
}

void MainWindow::clearDecQueue() {
    setDecFiles(QStringList());
}

void MainWindow::updateEncOutputHint() {
    if (m_encFiles.size() > 1) {
        m_encOutHintLabel->setText(tr("Destination: %1 encrypted containers (*.xpc)").arg(m_encFiles.size()));
        return;
    }
    QString inPath = m_encInPath->text().trimmed();
    if (inPath.isEmpty()) {
        m_encOutHintLabel->setText(tr("Destination: (select file or folder first)"));
    } else {
        m_encOutHintLabel->setText(tr("Destination: %1").arg(autoEncOutputPath(inPath)));
    }
}

void MainWindow::updateDecOutputHint() {
    if (m_decFiles.size() > 1) {
        m_decOutHintLabel->setText(tr("Destination: %1 decrypted outputs").arg(m_decFiles.size()));
        return;
    }
    QString inPath = m_decInPath->text().trimmed();
    if (inPath.isEmpty()) {
        m_decOutHintLabel->setText(tr("Destination: (select .xpc file first)"));
    } else {
        m_decOutHintLabel->setText(tr("Destination: %1").arg(autoDecOutputPath(inPath)));
    }
}

void MainWindow::handleInputPath(const QString &filePath) {
    handleInputPaths(QStringList() << filePath);
}

void MainWindow::handleInputPaths(const QStringList &filePaths) {
    if (filePaths.isEmpty()) return;

    QStringList encList;
    QStringList decList;

    for (const QString &p : filePaths) {
        if (p.endsWith(".xpc", Qt::CaseInsensitive) || p.endsWith(".xpc3", Qt::CaseInsensitive)) {
            decList.append(p);
        } else {
            encList.append(p);
        }
    }

    if (!decList.isEmpty() && encList.isEmpty()) {
        m_tabWidget->setCurrentIndex(1);
        setDecFiles(decList);
        appendLog(tr("Loaded %1 container(s) for decryption.").arg(decList.size()));
    } else {
        m_tabWidget->setCurrentIndex(0);
        setEncFiles(encList.isEmpty() ? filePaths : encList);
        appendLog(tr("Loaded %1 target(s) for encryption.").arg(encList.isEmpty() ? filePaths.size() : encList.size()));
    }
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event) {
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event) {
    const QList<QUrl> urls = event->mimeData()->urls();
    if (urls.isEmpty()) return;

    QStringList paths;
    for (const QUrl &u : urls) {
        QString local = u.toLocalFile();
        if (!local.isEmpty()) paths.append(local);
    }

    handleInputPaths(paths);
}

void MainWindow::browseEncInput() {
    QStringList paths = QFileDialog::getOpenFileNames(this, tr("Select Files to Encrypt"));
    if (!paths.isEmpty()) {
        setEncFiles(paths);
    }
}

void MainWindow::browseEncFolder() {
    QString path = QFileDialog::getExistingDirectory(this, tr("Select Directory to Encrypt"));
    if (!path.isEmpty()) {
        setEncFiles(QStringList() << path);
    }
}

void MainWindow::browseDecInput() {
    QStringList paths = QFileDialog::getOpenFileNames(this, tr("Select .xpc Files to Decrypt"), "", "XPC Files (*.xpc *.xpc3);;All Files (*)");
    if (!paths.isEmpty()) {
        setDecFiles(paths);
    }
}

void MainWindow::toggleEncPassword() {
    bool isPassword = (m_encPassword->echoMode() == QLineEdit::Password);
    m_encPassword->setEchoMode(isPassword ? QLineEdit::Normal : QLineEdit::Password);
    m_encShowPassBtn->setText(isPassword ? "🙈" : "👁");
}

void MainWindow::toggleDecPassword() {
    bool isPassword = (m_decPassword->echoMode() == QLineEdit::Password);
    m_decPassword->setEchoMode(isPassword ? QLineEdit::Normal : QLineEdit::Password);
    m_decShowPassBtn->setText(isPassword ? "🙈" : "👁");
}

void MainWindow::appendLog(const QString &msg) {
    QString timeStr = QDateTime::currentDateTime().toString("hh:mm:ss");
    QString formattedMsg = msg;
    if (msg.startsWith("✨") || msg.contains("completed successfully", Qt::CaseInsensitive) || msg.contains("success", Qt::CaseInsensitive) || msg.contains("ok", Qt::CaseInsensitive)) {
        formattedMsg = QString("<span style='color:#00f5b8; font-weight:600;'>%1</span>").arg(msg);
    } else if (msg.startsWith("❌") || msg.contains("error", Qt::CaseInsensitive) || msg.contains("failed", Qt::CaseInsensitive)) {
        formattedMsg = QString("<span style='color:#f87171; font-weight:600;'>%1</span>").arg(msg);
    } else if (msg.startsWith("⚠️") || msg.contains("warning", Qt::CaseInsensitive)) {
        formattedMsg = QString("<span style='color:#fbbf24;'>%1</span>").arg(msg);
    } else if (msg.startsWith("🧠") || msg.startsWith("🚀") || msg.startsWith("📦") || msg.startsWith("🔹")) {
        formattedMsg = QString("<span style='color:#38bdf8;'>%1</span>").arg(msg);
    } else if (msg.startsWith("🗑️") || msg.startsWith("💾")) {
        formattedMsg = QString("<span style='color:#c084fc;'>%1</span>").arg(msg);
    }
    m_logConsole->append(tr("<span style='color:#64748b;'>[%1]</span> %2").arg(timeStr, formattedMsg));
}

void MainWindow::startEncryption() {
    QStringList targets = m_encFiles;
    if (targets.isEmpty()) {
        QString single = m_encInPath->text().trimmed();
        if (!single.isEmpty()) targets.append(single);
    }

    QString pass = m_encPassword->text();

    if (targets.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, tr("Input Required"), tr("Please select at least one target file and enter a passphrase."));
        return;
    }

    m_encBtn->setEnabled(false);
    m_decBtn->setEnabled(false);
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0);
    m_speedLabel->setVisible(true);
    m_speedLabel->setText(tr("⚡ Preparing XKDF memory pass (64 MiB RAM)..."));

    bool shred = m_encShredCheck->isChecked();
    m_worker = new CryptoWorker(true, targets, pass, shred, this);
    connect(m_worker, &CryptoWorker::batchProgress, this, &MainWindow::onBatchProgress);
    connect(m_worker, &CryptoWorker::itemStarted, this, &MainWindow::onItemStarted);
    connect(m_worker, &CryptoWorker::itemFinished, this, &MainWindow::onItemFinished);
    connect(m_worker, &CryptoWorker::logMessage, this, &MainWindow::appendLog);
    connect(m_worker, &CryptoWorker::workFinished, this, &MainWindow::handleFinished);
    m_worker->start();
}

void MainWindow::startDecryption() {
    QStringList targets = m_decFiles;
    if (targets.isEmpty()) {
        QString single = m_decInPath->text().trimmed();
        if (!single.isEmpty()) targets.append(single);
    }

    QString pass = m_decPassword->text();

    if (targets.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, tr("Input Required"), tr("Please select at least one .xpc file and enter a passphrase."));
        return;
    }

    m_encBtn->setEnabled(false);
    m_decBtn->setEnabled(false);
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0);
    m_speedLabel->setVisible(true);
    m_speedLabel->setText(tr("⚡ Preparing XKDF memory pass (64 MiB RAM)..."));

    bool shred = m_decShredCheck->isChecked();
    m_worker = new CryptoWorker(false, targets, pass, shred, this);
    connect(m_worker, &CryptoWorker::batchProgress, this, &MainWindow::onBatchProgress);
    connect(m_worker, &CryptoWorker::itemStarted, this, &MainWindow::onItemStarted);
    connect(m_worker, &CryptoWorker::itemFinished, this, &MainWindow::onItemFinished);
    connect(m_worker, &CryptoWorker::logMessage, this, &MainWindow::appendLog);
    connect(m_worker, &CryptoWorker::workFinished, this, &MainWindow::handleFinished);
    m_worker->start();
}

void MainWindow::onBatchProgress(int percent, double speedMBs, qint64 bytesDone, qint64 totalBytes, int itemsDone, int totalItems) {
    m_progressBar->setValue(percent);
    QString speedStr = QString::number(speedMBs, 'f', 1);
    QString doneMB = QString::number(bytesDone / (1024.0 * 1024.0), 'f', 1);
    QString totalMB = QString::number(totalBytes / (1024.0 * 1024.0), 'f', 1);

    m_speedLabel->setText(tr("⚡ %1 MB/s | %2/%3 items (%4 / %5 MB) | %6%")
                          .arg(speedStr)
                          .arg(itemsDone)
                          .arg(totalItems)
                          .arg(doneMB)
                          .arg(totalMB)
                          .arg(percent));
}

void MainWindow::onItemStarted(int index, const QString &filePath) {
    QListWidget *list = (m_tabWidget->currentIndex() == 0) ? m_encQueueList : m_decQueueList;
    if (index >= 0 && index < list->count()) {
        QListWidgetItem *item = list->item(index);
        item->setText(tr("⏳ [Processing...] %1").arg(QFileInfo(filePath).fileName()));
        item->setForeground(QColor("#38bdf8"));
        list->scrollToItem(item);
    }
}

void MainWindow::onItemFinished(int index, bool success, const QString &message) {
    QListWidget *list = (m_tabWidget->currentIndex() == 0) ? m_encQueueList : m_decQueueList;
    if (index >= 0 && index < list->count()) {
        QListWidgetItem *item = list->item(index);
        if (success) {
            item->setText(tr("✅ [Done] %1").arg(item->text().section(" ", 2)));
            item->setForeground(QColor("#00f5b8"));
        } else {
            item->setText(tr("❌ [%1] %2").arg(message, item->text().section(" ", 2)));
            item->setForeground(QColor("#f87171"));
        }
    }
}

void MainWindow::handleFinished(bool success, const QString &message) {
    m_encBtn->setEnabled(true);
    m_decBtn->setEnabled(true);
    m_speedLabel->setVisible(false);
    m_progressBar->setVisible(false);

    if (success) {
        QMessageBox::information(this, tr("Success"), message);
    } else {
        QMessageBox::warning(this, tr("Completed with Alerts"), message);
    }

    if (m_worker) {
        m_worker->deleteLater();
        m_worker = nullptr;
    }
}

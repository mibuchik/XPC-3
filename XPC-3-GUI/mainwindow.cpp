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
    setWindowTitle("XPC-3");
    setWindowIcon(QIcon(":/icon.png"));
    resize(740, 690);
    setAcceptDrops(true);

    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(16);

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

    QLabel *titleLabel = new QLabel("XPC-3", headerCard);
    titleLabel->setObjectName("titleLabel");
    titleLabel->setStyleSheet("font-size: 20px; font-weight: 700; letter-spacing: -0.5px;");

    titleRow->addWidget(logoImgLabel);
    titleRow->addWidget(titleLabel);
    titleRow->addStretch();

    QLabel *descLabel = new QLabel("Production-grade triple cascade file encryption powered by 64 MiB Memory-Hard XKDF.", headerCard);
    descLabel->setObjectName("descLabel");
    descLabel->setStyleSheet("font-size: 13px; font-weight: 400;");

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
    encLayout->setContentsMargins(20, 20, 20, 20);
    encLayout->setSpacing(14);

    m_encDropZone = new QLabel("Drag & drop file or folder here, or click to browse", encTab);
    m_encDropZone->setObjectName("shadcnDropZone");
    m_encDropZone->setAlignment(Qt::AlignCenter);
    m_encDropZone->setFixedHeight(80);
    encLayout->addWidget(m_encDropZone);

    QHBoxLayout *encInLayout = new QHBoxLayout();
    m_encInPath = new QLineEdit(encTab);
    m_encInPath->setPlaceholderText("Select file or folder to encrypt...");
    QPushButton *btnEncBrowse = new QPushButton("File", encTab);
    btnEncBrowse->setObjectName("secondaryButton");
    btnEncBrowse->setCursor(Qt::PointingHandCursor);

    QPushButton *btnEncFolderBrowse = new QPushButton("Folder", encTab);
    btnEncFolderBrowse->setObjectName("secondaryButton");
    btnEncFolderBrowse->setCursor(Qt::PointingHandCursor);

    encInLayout->addWidget(m_encInPath);
    encInLayout->addWidget(btnEncBrowse);
    encInLayout->addWidget(btnEncFolderBrowse);
    encLayout->addLayout(encInLayout);

    m_encOutHintLabel = new QLabel("Destination: (select file or folder first)", encTab);
    m_encOutHintLabel->setObjectName("hintLabel");
    m_encOutHintLabel->setStyleSheet("font-size: 12px; font-weight: 500; font-family: monospace;");
    encLayout->addWidget(m_encOutHintLabel);

    QHBoxLayout *encPassLayout = new QHBoxLayout();
    m_encPassword = new QLineEdit(encTab);
    m_encPassword->setEchoMode(QLineEdit::Password);
    m_encPassword->setPlaceholderText("Enter secret passphrase...");
    m_encShowPassBtn = new QPushButton("👁", encTab);
    m_encShowPassBtn->setObjectName("ghostButton");
    m_encShowPassBtn->setFixedWidth(40);
    m_encShowPassBtn->setCursor(Qt::PointingHandCursor);
    encPassLayout->addWidget(m_encPassword);
    encPassLayout->addWidget(m_encShowPassBtn);
    encLayout->addLayout(encPassLayout);

    m_encBtn = new QPushButton("Encrypt Target", encTab);
    m_encBtn->setObjectName("primaryButton");
    m_encBtn->setFixedHeight(42);
    m_encBtn->setCursor(Qt::PointingHandCursor);
    encLayout->addWidget(m_encBtn);

    m_tabWidget->addTab(encTab, "Encrypt");

    // --- DECRYPT TAB ---
    QWidget *decTab = new QWidget();
    QVBoxLayout *decLayout = new QVBoxLayout(decTab);
    decLayout->setContentsMargins(20, 20, 20, 20);
    decLayout->setSpacing(14);

    m_decDropZone = new QLabel("Drag and drop .xpc file here, or click to browse", decTab);
    m_decDropZone->setObjectName("shadcnDropZone");
    m_decDropZone->setAlignment(Qt::AlignCenter);
    m_decDropZone->setFixedHeight(80);
    decLayout->addWidget(m_decDropZone);

    QHBoxLayout *decInLayout = new QHBoxLayout();
    m_decInPath = new QLineEdit(decTab);
    m_decInPath->setPlaceholderText("Select .xpc file to decrypt...");
    QPushButton *btnDecBrowse = new QPushButton("Browse", decTab);
    btnDecBrowse->setObjectName("secondaryButton");
    btnDecBrowse->setCursor(Qt::PointingHandCursor);
    decInLayout->addWidget(m_decInPath);
    decInLayout->addWidget(btnDecBrowse);
    decLayout->addLayout(decInLayout);

    m_decOutHintLabel = new QLabel("Destination: (select .xpc file first)", decTab);
    m_decOutHintLabel->setObjectName("hintLabel");
    m_decOutHintLabel->setStyleSheet("font-size: 12px; font-weight: 500; font-family: monospace;");
    decLayout->addWidget(m_decOutHintLabel);

    QHBoxLayout *decPassLayout = new QHBoxLayout();
    m_decPassword = new QLineEdit(decTab);
    m_decPassword->setEchoMode(QLineEdit::Password);
    m_decPassword->setPlaceholderText("Enter secret passphrase...");
    m_decShowPassBtn = new QPushButton("👁", decTab);
    m_decShowPassBtn->setObjectName("ghostButton");
    m_decShowPassBtn->setFixedWidth(40);
    m_decShowPassBtn->setCursor(Qt::PointingHandCursor);
    decPassLayout->addWidget(m_decPassword);
    decPassLayout->addWidget(m_decShowPassBtn);
    decLayout->addLayout(decPassLayout);

    m_decBtn = new QPushButton("Decrypt File", decTab);
    m_decBtn->setObjectName("primaryButton");
    m_decBtn->setFixedHeight(42);
    m_decBtn->setCursor(Qt::PointingHandCursor);
    decLayout->addWidget(m_decBtn);

    m_tabWidget->addTab(decTab, "Decrypt");

    mainLayout->addWidget(m_tabWidget);

    // Progress Bar
    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 0);
    m_progressBar->setFixedHeight(4);
    m_progressBar->setTextVisible(false);
    m_progressBar->setVisible(false);
    mainLayout->addWidget(m_progressBar);

    // Log Console Box
    QLabel *logLabel = new QLabel("Console Output", this);
    logLabel->setObjectName("consoleLabel");
    logLabel->setStyleSheet("font-size: 12px; font-weight: 600;");
    mainLayout->addWidget(logLabel);

    m_logConsole = new QTextEdit(this);
    m_logConsole->setReadOnly(true);
    m_logConsole->setFixedHeight(130);
    m_logConsole->setFont(QFont("Monospace", 9));
    mainLayout->addWidget(m_logConsole);

    setCentralWidget(centralWidget);

    // Connections
    connect(btnEncBrowse, &QPushButton::clicked, this, &MainWindow::browseEncInput);
    connect(btnEncFolderBrowse, &QPushButton::clicked, this, &MainWindow::browseEncFolder);
    connect(btnDecBrowse, &QPushButton::clicked, this, &MainWindow::browseDecInput);

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
    QAction *toggleAction = new QAction("Show / Hide Window", this);
    QAction *exitAction = new QAction("Exit XPC-3", this);

    connect(toggleAction, &QAction::triggered, this, &MainWindow::toggleWindowVisibility);
    connect(exitAction, &QAction::triggered, qApp, &QApplication::quit);

    m_trayMenu->addAction(toggleAction);
    m_trayMenu->addSeparator();
    m_trayMenu->addAction(exitAction);

    m_trayIcon = new QSystemTrayIcon(icon, this);
    m_trayIcon->setContextMenu(m_trayMenu);
    m_trayIcon->setToolTip("XPC-3");

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
        m_trayIcon->showMessage("XPC-3", "Application is minimized to system tray.",
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

    // Style badges dynamically
    QString badgeCss = dark ?
        "background-color: #27272a; color: #a1a1aa; border: 1px solid #3f3f46; border-radius: 9999px; padding: 3px 10px; font-size: 11px; font-weight: 500;" :
        "background-color: #f4f4f5; color: #71717a; border: 1px solid #e4e4e7; border-radius: 9999px; padding: 3px 10px; font-size: 11px; font-weight: 500;";

    for (QLabel *b : m_badges) {
        b->setStyleSheet(badgeCss);
    }

    // Dynamic shadcn/ui Theme Stylesheet (Dark vs Light)
    QString qss = dark ? R"(
        QMainWindow { background-color: #09090b; }
        QWidget { color: #fafafa; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        #shadcnCard { background-color: #18181b; border: 1px solid #27272a; border-radius: 8px; }
        #titleLabel { color: #fafafa; }
        #descLabel { color: #a1a1aa; }
        #hintLabel { color: #a1a1aa; }
        #consoleLabel { color: #a1a1aa; }
        #shadcnDropZone { background-color: #09090b; border: 1px dashed #3f3f46; border-radius: 8px; color: #71717a; font-size: 13px; font-weight: 500; }
        #shadcnDropZone:hover { background-color: #18181b; border-color: #a1a1aa; color: #fafafa; }
        QTabWidget::pane { border: 1px solid #27272a; background-color: #18181b; border-radius: 8px; }
        QTabBar::tab { background-color: #09090b; color: #71717a; padding: 8px 18px; border-radius: 6px; margin: 4px 2px; font-weight: 500; font-size: 13px; }
        QTabBar::tab:selected { background-color: #27272a; color: #fafafa; }
        QLineEdit { background-color: #09090b; border: 1px solid #27272a; border-radius: 6px; padding: 8px 12px; color: #fafafa; font-size: 13px; }
        QLineEdit:focus { border: 1px solid #a1a1aa; }
        #primaryButton { background-color: #fafafa; color: #09090b; border: none; border-radius: 6px; font-weight: 600; font-size: 13px; }
        #primaryButton:hover { background-color: #e4e4e7; }
        #secondaryButton { background-color: #27272a; color: #fafafa; border: 1px solid #3f3f46; border-radius: 6px; font-weight: 500; }
        #secondaryButton:hover { background-color: #3f3f46; }
        #ghostButton { background-color: transparent; color: #a1a1aa; border: 1px solid #27272a; border-radius: 6px; }
        #ghostButton:hover { background-color: #27272a; color: #fafafa; }
        QTextEdit { background-color: #09090b; border: 1px solid #27272a; border-radius: 6px; color: #a1a1aa; padding: 8px; }
        QProgressBar { background-color: #18181b; border-radius: 2px; }
        QProgressBar::chunk { background-color: #fafafa; border-radius: 2px; }
        QMenu { background-color: #18181b; color: #fafafa; border: 1px solid #27272a; padding: 4px; border-radius: 6px; }
        QMenu::item { padding: 6px 20px; border-radius: 4px; }
        QMenu::item:selected { background-color: #27272a; color: #fafafa; }
    )" : R"(
        QMainWindow { background-color: #ffffff; }
        QWidget { color: #09090b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        #shadcnCard { background-color: #f4f4f5; border: 1px solid #e4e4e7; border-radius: 8px; }
        #titleLabel { color: #09090b; }
        #descLabel { color: #71717a; }
        #hintLabel { color: #71717a; }
        #consoleLabel { color: #71717a; }
        #shadcnDropZone { background-color: #ffffff; border: 1px dashed #e4e4e7; border-radius: 8px; color: #71717a; font-size: 13px; font-weight: 500; }
        #shadcnDropZone:hover { background-color: #f4f4f5; border-color: #71717a; color: #09090b; }
        QTabWidget::pane { border: 1px solid #e4e4e7; background-color: #f4f4f5; border-radius: 8px; }
        QTabBar::tab { background-color: #ffffff; color: #71717a; padding: 8px 18px; border-radius: 6px; margin: 4px 2px; font-weight: 500; font-size: 13px; }
        QTabBar::tab:selected { background-color: #e4e4e7; color: #09090b; }
        QLineEdit { background-color: #ffffff; border: 1px solid #e4e4e7; border-radius: 6px; padding: 8px 12px; color: #09090b; font-size: 13px; }
        QLineEdit:focus { border: 1px solid #71717a; }
        #primaryButton { background-color: #09090b; color: #ffffff; border: none; border-radius: 6px; font-weight: 600; font-size: 13px; }
        #primaryButton:hover { background-color: #27272a; }
        #secondaryButton { background-color: #e4e4e7; color: #09090b; border: 1px solid #d4d4d8; border-radius: 6px; font-weight: 500; }
        #secondaryButton:hover { background-color: #d4d4d8; }
        #ghostButton { background-color: transparent; color: #71717a; border: 1px solid #e4e4e7; border-radius: 6px; }
        #ghostButton:hover { background-color: #e4e4e7; color: #09090b; }
        QTextEdit { background-color: #ffffff; border: 1px solid #e4e4e7; border-radius: 6px; color: #18181b; padding: 8px; }
        QProgressBar { background-color: #e4e4e7; border-radius: 2px; }
        QProgressBar::chunk { background-color: #09090b; border-radius: 2px; }
        QMenu { background-color: #ffffff; color: #09090b; border: 1px solid #e4e4e7; padding: 4px; border-radius: 6px; }
        QMenu::item { padding: 6px 20px; border-radius: 4px; }
        QMenu::item:selected { background-color: #f4f4f5; color: #09090b; }
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
    return p + ".dec";
}

void MainWindow::updateEncOutputHint(const QString &inPath) {
    if (inPath.trimmed().isEmpty()) {
        m_encOutHintLabel->setText("Destination: (select file or folder first)");
    } else {
        m_encOutHintLabel->setText(QString("Destination: %1").arg(autoEncOutputPath(inPath)));
    }
}

void MainWindow::updateDecOutputHint(const QString &inPath) {
    if (inPath.trimmed().isEmpty()) {
        m_decOutHintLabel->setText("Destination: (select .xpc file first)");
    } else {
        m_decOutHintLabel->setText(QString("Destination: %1").arg(autoDecOutputPath(inPath)));
    }
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event) {
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event) {
    const QList<QUrl> urls = event->mimeData()->urls();
    if (!urls.isEmpty()) {
        QString filePath = urls.first().toLocalFile();
        if (filePath.endsWith(".xpc", Qt::CaseInsensitive)) {
            m_tabWidget->setCurrentIndex(1);
            m_decInPath->setText(filePath);
        } else {
            m_tabWidget->setCurrentIndex(0);
            m_encInPath->setText(filePath);
        }
        appendLog(QString("Target dropped: %1").arg(filePath));
    }
}

void MainWindow::browseEncInput() {
    QString path = QFileDialog::getOpenFileName(this, "Select File to Encrypt");
    if (!path.isEmpty()) m_encInPath->setText(path);
}

void MainWindow::browseEncFolder() {
    QString path = QFileDialog::getExistingDirectory(this, "Select Directory to Encrypt");
    if (!path.isEmpty()) m_encInPath->setText(path);
}

void MainWindow::browseDecInput() {
    QString path = QFileDialog::getOpenFileName(this, "Select .xpc File to Decrypt", "", "XPC Files (*.xpc);;All Files (*)");
    if (!path.isEmpty()) m_decInPath->setText(path);
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
    m_logConsole->append(QString("[%1] %2").arg(timeStr, msg));
}

void MainWindow::startEncryption() {
    QString inFile = m_encInPath->text().trimmed();
    QString outFile = autoEncOutputPath(inFile);
    QString pass = m_encPassword->text();

    if (inFile.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, "Input Required", "Please select a target file and enter a passphrase.");
        return;
    }

    if (!QFileInfo::exists(inFile)) {
        QMessageBox::critical(this, "File Not Found", QString("Target file does not exist:\n%1").arg(inFile));
        return;
    }

    m_encBtn->setEnabled(false);
    m_decBtn->setEnabled(false);
    m_progressBar->setVisible(true);

    m_worker = new CryptoWorker(true, inFile, outFile, pass, this);
    connect(m_worker, &CryptoWorker::logMessage, this, &MainWindow::appendLog);
    connect(m_worker, &CryptoWorker::workFinished, this, &MainWindow::handleFinished);
    m_worker->start();
}

void MainWindow::startDecryption() {
    QString inFile = m_decInPath->text().trimmed();
    QString outFile = autoDecOutputPath(inFile);
    QString pass = m_decPassword->text();

    if (inFile.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, "Input Required", "Please select an encrypted .xpc file and enter a passphrase.");
        return;
    }

    if (!QFileInfo::exists(inFile)) {
        QMessageBox::critical(this, "File Not Found", QString("Selected .xpc file does not exist:\n%1").arg(inFile));
        return;
    }

    m_encBtn->setEnabled(false);
    m_decBtn->setEnabled(false);
    m_progressBar->setVisible(true);

    m_worker = new CryptoWorker(false, inFile, outFile, pass, this);
    connect(m_worker, &CryptoWorker::logMessage, this, &MainWindow::appendLog);
    connect(m_worker, &CryptoWorker::workFinished, this, &MainWindow::handleFinished);
    m_worker->start();
}

void MainWindow::handleFinished(bool success, const QString &message) {
    m_encBtn->setEnabled(true);
    m_decBtn->setEnabled(true);
    m_progressBar->setVisible(false);

    if (success) {
        QMessageBox::information(this, "Success", message);
    } else {
        QMessageBox::critical(this, "Error", message);
    }

    m_worker->deleteLater();
    m_worker = nullptr;
}

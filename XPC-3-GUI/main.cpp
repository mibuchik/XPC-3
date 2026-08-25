#include "mainwindow.h"
#include <QApplication>
#include <QIcon>
#include <QTranslator>
#include <QLocale>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>

class JsonTranslator : public QTranslator {
public:
    QJsonObject dict;
    bool loadLanguage(const QString &langCode) {
        QFile file(":/lang/" + langCode + ".json");
        if (file.open(QIODevice::ReadOnly)) {
            QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
            dict = doc.object();
            return !dict.isEmpty();
        }
        return false;
    }
    virtual QString translate(const char *context, const char *sourceText, const char *disambiguation = 0, int n = -1) const override {
        Q_UNUSED(context); Q_UNUSED(disambiguation); Q_UNUSED(n);
        QString key = QString::fromUtf8(sourceText);
        if (dict.contains(key)) {
            return dict.value(key).toString();
        }
        return key;
    }
    virtual bool isEmpty() const override {
        return dict.isEmpty();
    }
};

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setApplicationName("XPC-3");

    JsonTranslator *translator = new JsonTranslator();
    QString lang = QLocale::system().name().split("_").first();
    // Default to ru for russian, es for spanish, etc.
    if (translator->loadLanguage(lang)) {
        a.installTranslator(translator);
    } else {
        // Fallback or just ignore if English / unsupported
    }

    a.setWindowIcon(QIcon(":/icon.png"));

    MainWindow w;
    w.show();
    return a.exec();
}

#include <QApplication>
#include <QIcon>
#include "mainwindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("XPC-3");
    app.setOrganizationName("Xalether Labs inc.");
    app.setDesktopFileName("xpc3-gui");

    app.setWindowIcon(QIcon(":/icon.png"));

    MainWindow window;
    window.show();

    return app.exec();
}

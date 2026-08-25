QT += core gui widgets

TARGET = xpc3-gui
TEMPLATE = app

CONFIG += c++11

XPC_SRC_DIR = $$quote($$PWD/../XPC-3)

INCLUDEPATH += $$XPC_SRC_DIR
DEPENDPATH += $$XPC_SRC_DIR

DEFINES += OPENSSL_SUPPRESS_DEPRECATED

LIBS += -lcrypto -lz

HEADERS += \
    mainwindow.h \
    worker.h \
    $$XPC_SRC_DIR/xpc_types.h \
    $$XPC_SRC_DIR/xkdf.h \
    $$XPC_SRC_DIR/xbe.h \
    $$XPC_SRC_DIR/xcm.h \
    $$XPC_SRC_DIR/xpc3.h

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    worker.cpp \
    $$XPC_SRC_DIR/xkdf.c \
    $$XPC_SRC_DIR/xbe.c \
    $$XPC_SRC_DIR/xcm.c \
    $$XPC_SRC_DIR/xpc3.c

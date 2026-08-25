CXX ?= g++
CC ?= gcc
MOC ?= moc
RCC ?= rcc

CXXFLAGS ?= -O3 -Wall -Wextra -std=c++11 -fPIC $(shell pkg-config --cflags Qt5Widgets) -I../XPC-3 -DOPENSSL_SUPPRESS_DEPRECATED
CFLAGS ?= -O3 -Wall -Wextra -std=c11 -fPIC -DOPENSSL_SUPPRESS_DEPRECATED -I../XPC-3
LIBS ?= $(shell pkg-config --libs Qt5Widgets) -lcrypto -lz

TARGET = xpc3-gui

CPP_SRCS = main.cpp mainwindow.cpp worker.cpp
C_SRCS = ../XPC-3/xkdf.c ../XPC-3/xbe.c ../XPC-3/xcm.c ../XPC-3/xpc3.c
MOC_HDRS = mainwindow.h worker.h

MOC_SRCS = mainwindow.moc.cpp worker.moc.cpp
OBJS = main.o mainwindow.o worker.o xkdf.o xbe.o xcm.o xpc3.o mainwindow.moc.o worker.moc.o qrc_resources.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LIBS)

qrc_resources.cpp: resources.qrc
	$(RCC) $< -o $@

qrc_resources.o: qrc_resources.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.moc.cpp: %.h
	$(MOC) $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

mainwindow.moc.o: mainwindow.moc.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

worker.moc.o: worker.moc.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

xkdf.o: ../XPC-3/xkdf.c
	$(CC) $(CFLAGS) -c $< -o $@

xbe.o: ../XPC-3/xbe.c
	$(CC) $(CFLAGS) -c $< -o $@

xcm.o: ../XPC-3/xcm.c
	$(CC) $(CFLAGS) -c $< -o $@

xpc3.o: ../XPC-3/xpc3.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) *.o *.moc.cpp qrc_resources.cpp

.PHONY: all clean

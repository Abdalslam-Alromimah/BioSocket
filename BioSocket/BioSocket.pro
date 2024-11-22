QT       += core gui network
#QT += core network widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

SOURCES += \
    encryption.cpp \
    main.cpp \
    NetworkManager.cpp \
    ChatController.cpp \
    ClientWindow.cpp \
    ServerWindow.cpp

HEADERS += \
    ChatStyle.h \
    NetworkManager.h \
    ChatController.h \
    ClientWindow.h \
    ServerWindow.h \
    encryption.h
# OpenSSL configuration
win32 {
    #OPENSSL_INCLUDE_PATH = E:\code\vcpkg\installed\x64-windows\include
    #OPENSSL_LIB_PATH = E:\code\vcpkg\installed\x64-windows\lib

    OPENSSL_PATH =E:\vcpkg\installed\x64-windows
    INCLUDEPATH += $$OPENSSL_PATH/include
    LIBS += -L$$OPENSSL_PATH/lib \
            -llibssl \
            -llibcrypto

    CONFIG(debug, debug|release) {
        DESTDIR = bin/debug
    } else {
        DESTDIR = bin/release
    }

   # openssl_dlls.path = $$DESTDIR
    #openssl_dlls.files = \
   #     $$OPENSSL_PATH/bin/libssl-3-x64.dll \
   #     $$OPENSSL_PATH/bin/libcrypto-3-x64.dll
   # COPIES += openssl_dlls
}

unix {
    LIBS += -lssl -lcrypto
}

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

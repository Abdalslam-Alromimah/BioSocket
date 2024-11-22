// ChatStyle.h
#ifndef CHATSTYLE_H
#define CHATSTYLE_H

#include <QString>

namespace ChatStyle {
    const QString SAMSUNG_STYLE = R"(
        QWidget {
            background-color: #f2f2f2;
            font-family: 'Segoe UI', Arial;
        }

        QLabel#titleLabel {
            color: #000000;
            font-size: 20px;
            font-weight: bold;
            padding: 10px;
            background-color: #ffffff;
            border-radius: 15px;
            margin: 5px;
        }

        QLabel#statusLabel {
            color: #636363;
            font-size: 13px;
            padding: 5px;
        }

        QLabel#messageLabel {
            background-color: #ffffff;
            padding: 15px;
            border-radius: 12px;
            margin: 5px;
            font-size: 14px;
        }

        QLineEdit {
            background-color: #ffffff;
            border: none;
            border-radius: 20px;
            padding: 12px 20px;
            margin: 5px;
            font-size: 14px;
            min-height: 40px;
        }

        QLineEdit:focus {
            border: 2px solid #1a73e8;
        }

        QPushButton {
            background-color: #1a73e8;
            color: white;
            border: none;
            border-radius: 20px;
            padding: 12px 25px;
            font-size: 14px;
            font-weight: bold;
            min-height: 40px;
        }

        QPushButton:hover {
            background-color: #1557b0;
        }

        QPushButton:pressed {
            background-color: #0d47a1;
        }

        QFrame#messageFrame {
            background-color: #ffffff;
            border-radius: 15px;
            margin: 10px;
        }

        QFrame#inputFrame {
            background-color: #ffffff;
            border-radius: 25px;
            margin: 10px;
            padding: 5px;
        }
    )";
}

#endif // CHATSTYLE_H

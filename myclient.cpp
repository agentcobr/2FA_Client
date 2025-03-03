#include "MyClient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QDataStream>
#include <QTime> // Добавлен заголовок для QTime

MyClient::MyClient(const QString& host, int port, QWidget* pwgt)
    : QWidget(pwgt), m_nNextBlockSize(0)
{
    m_pTcpSocket = new QTcpSocket(this);
    m_pTcpSocket->connectToHost(host, port);

    connect(m_pTcpSocket, &QTcpSocket::readyRead, this, &MyClient::slotReadyRead);
    connect(m_pTcpSocket, &QTcpSocket::errorOccurred, this, &MyClient::slotError);

    photoLabel = new QLabel(this);
    QPixmap pixmap("D:/4 курс/KB_SH_ZH/cyrsach/program/NDIL.png");
    photoLabel->setPixmap(pixmap.scaled(200, 200, Qt::KeepAspectRatio));
    photoLabel->setFrameStyle(QFrame::Box | QFrame::Raised);
    photoLabel->setAlignment(Qt::AlignCenter);

    m_tabWidget = new QTabWidget(this);
    m_tabWidget->addTab(createAccountTab(), "Create Account");
    m_tabWidget->addTab(authTab(), "Authentication");
    m_tabWidget->addTab(showLogTab(), "Log");

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(m_tabWidget);
    setLayout(mainLayout);

    setWindowTitle("Ndil");
    resize(500, 400);
}

QWidget* MyClient::createAccountTab() {
    QWidget* tab = new QWidget;

    m_ptxtNickname = new QLineEdit(tab);
    m_ptxtFirstname = new QLineEdit(tab);
    m_ptxtLastname = new QLineEdit(tab);
    m_ptxtEmail = new QLineEdit(tab);
    m_ptxtPassword = new QLineEdit(tab);
    m_ptxtPasswordRepeat = new QLineEdit(tab);

    m_ptxtPassword->setEchoMode(QLineEdit::Password);
    m_ptxtPasswordRepeat->setEchoMode(QLineEdit::Password);

    m_ptxtNickname->setPlaceholderText("Login");
    m_ptxtFirstname->setPlaceholderText("Firstname");
    m_ptxtLastname->setPlaceholderText("Lastname");
    m_ptxtEmail->setPlaceholderText("Email");
    m_ptxtPassword->setPlaceholderText("Password");
    m_ptxtPasswordRepeat->setPlaceholderText("Repeat Password");

    QPushButton* btnCreateAccount = new QPushButton("Create Account", tab);

    connect(btnCreateAccount, &QPushButton::clicked, this, [this]() {
        QString login = m_ptxtNickname->text();
        QString firstname = m_ptxtFirstname->text();
        QString lastname = m_ptxtLastname->text();
        QString email = m_ptxtEmail->text();
        QString password = m_ptxtPassword->text();
        QString passwordRepeat = m_ptxtPasswordRepeat->text();

        if (login.isEmpty() || firstname.isEmpty() || lastname.isEmpty() ||
            email.isEmpty() || password.isEmpty() || passwordRepeat.isEmpty()) {
            QMessageBox::warning(this, "Error", "All fields are required!");
            return;
        }

        qDebug() << "Form data:"
                 << "Nickname:" << login 
                 << "Firstname:" << firstname
                 << "Lastname:" << lastname
                 << "Email:" << email
                 << "Password:" << password;

        if (!validatePassword(password, passwordRepeat)) {
            QMessageBox::warning(this, "Error", "Passwords do not match or are too short!");
            return;
        }

        sendRequest("REGISTER", {login, firstname, lastname, email, password});
    });

    QVBoxLayout* layout = new QVBoxLayout(tab);
    layout->addWidget(photoLabel);
    layout->addWidget(m_ptxtNickname);
    layout->addWidget(m_ptxtFirstname);
    layout->addWidget(m_ptxtLastname);
    layout->addWidget(m_ptxtEmail);
    layout->addWidget(m_ptxtPassword);
    layout->addWidget(m_ptxtPasswordRepeat);
    layout->addWidget(btnCreateAccount);

    return tab;
}

QWidget* MyClient::authTab() {
    QWidget* tab = new QWidget;

    m_ptxtAuthNickname = new QLineEdit(tab);
    m_ptxtAuthPassword = new QLineEdit(tab);
    m_ptxtAuthOTP = new QLineEdit(tab);

    m_ptxtAuthPassword->setEchoMode(QLineEdit::Password); 
    m_ptxtAuthNickname->setPlaceholderText("Login");
    m_ptxtAuthPassword->setPlaceholderText("Password");
    m_ptxtAuthOTP->setPlaceholderText("OTP");
    m_ptxtAuthOTP->setEnabled(false);

    QPushButton* btnSendLogin = new QPushButton("Send Login and Password", tab);
    QPushButton* btnSendOTP = new QPushButton("Send OTP", tab);
    btnSendOTP->setEnabled(false);

    connect(btnSendLogin, &QPushButton::clicked, this, [this, btnSendOTP]() {
        QString login = m_ptxtAuthNickname->text();
        QString password = m_ptxtAuthPassword->text();

        if (login.isEmpty() || password.isEmpty()) {
            QMessageBox::warning(this, "Error", "Login and password fields are required!");
            return;
        }

        sendRequest("AUTH", {login, password});
        m_ptxtAuthOTP->setEnabled(true);
        btnSendOTP->setEnabled(true);
    });

    connect(btnSendOTP, &QPushButton::clicked, this, [this]() {
        QString nickname = m_ptxtAuthNickname->text();
        QString otp = m_ptxtAuthOTP->text();

        if (otp.isEmpty()) {
            QMessageBox::warning(this, "Error", "OTP field is required!");
            return;
        }

        sendRequest("VERIFY_OTP", {nickname, otp}); 
    });

    QVBoxLayout* layout = new QVBoxLayout(tab);
    layout->addWidget(photoLabel);
    layout->addWidget(m_ptxtAuthNickname);
    layout->addWidget(m_ptxtAuthPassword);
    layout->addWidget(btnSendLogin);
    layout->addWidget(m_ptxtAuthOTP);
    layout->addWidget(btnSendOTP);

    return tab;
}

QWidget* MyClient::showLogTab() {
    QWidget* tab = new QWidget;

    m_ptxtLog = new QTextEdit(tab);
    m_ptxtLog->setReadOnly(true);

    m_btnClearLog = new QPushButton("Clear Log", tab);
    connect(m_btnClearLog, &QPushButton::clicked, this, &MyClient::clearLog);

    QVBoxLayout* layout = new QVBoxLayout(tab);
    layout->addWidget(m_ptxtLog);
    layout->addWidget(m_btnClearLog);

    return tab;
}

bool MyClient::validatePassword(const QString& password, const QString& passwordRepeat) {
    return (password.length() >= 6) && (password == passwordRepeat);
}

void MyClient::sendRequest(const QString& action, const QStringList& params) {
    QByteArray arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_5);
    out << quint16(0) << action;

    for (const QString& param : params) {
        out << param;
    }

    out.device()->seek(0);
    out << quint16(arrBlock.size() - sizeof(quint16));
    m_pTcpSocket->write(arrBlock);

    m_ptxtLog->append(QString("[INFO] Sent request: %1").arg(action));
}

void MyClient::slotReadyRead() {
    QDataStream in(m_pTcpSocket);
    in.setVersion(QDataStream::Qt_6_5);

    for (;;) {
        if (m_nNextBlockSize == 0) {
            if (m_pTcpSocket->bytesAvailable() < static_cast<qint64>(sizeof(quint16)))
                break;
            in >> m_nNextBlockSize;
        }

        if (m_pTcpSocket->bytesAvailable() < m_nNextBlockSize)
            break;

        QTime time;
        QString response;
        in >> time >> response;

        m_ptxtLog->append("[" + time.toString() + "] " + response);

        if (response == "OTP_SENT") {
            QMessageBox::information(this, "OTP", "Check your email for OTP code");
        }
        else if (response == "AUTH_SUCCESS") {
            QMessageBox::information(this, "Success", "Authentication successful!");
            m_ptxtAuthOTP->clear();
            m_ptxtAuthPassword->clear();
        }
        else if (response == "OTP_INVALID") {
            QMessageBox::warning(this, "Error", "Invalid OTP code");
        }
        else if (response == "REGISTER_SUCCESS") {
            QMessageBox::information(this, "Success", "Registration successful!");
        }
        else if (response == "REGISTER_FAILED") {
            QMessageBox::warning(this, "Error", "Registration failed");
        }

        m_nNextBlockSize = 0;
    }
}

void MyClient::clearLog() {
    m_ptxtLog->clear();
}

void MyClient::slotError(QAbstractSocket::SocketError) {
    QMessageBox::critical(this, "Error", m_pTcpSocket->errorString());
}

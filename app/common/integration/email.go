package integration

import (
	"fmt"
	"net/smtp"

	"github.com/rs/zerolog/log"

	"github.com/GonnaFlyMethod/gofundament/app/common/config"
)

type EmailManager struct {
	smtpConfig config.SMTPConfig
	appConfig  config.AppConfig
}

func NewEmailManager(globalConfig config.Config) *EmailManager {
	return &EmailManager{
		smtpConfig: globalConfig.SMTP,
		appConfig:  globalConfig.AppConfig,
	}
}

func (em *EmailManager) SendVerifCodeForSignUp(emailOfReceiver, nickname, code string) {
	from := fmt.Sprintf("From: <%s>\r\n", em.smtpConfig.Email)
	to := fmt.Sprintf("To: <%s>\r\n", emailOfReceiver)
	subject := "Subject: Sign up verification code\r\n"
	body := fmt.Sprintf("Hey, %s!\nYour verification code is %s", nickname, code)

	fullMsg := from + to + subject + "\r\n" + body

	fullMsgBytes := []byte(fullMsg)

	em.sendEmail(emailOfReceiver, fullMsgBytes)
}

func (em *EmailManager) SendVerifCodeForPasswordUpdate(emailOfReceiver, code string) {
	from := fmt.Sprintf("From: <%s>\r\n", em.smtpConfig.Email)
	to := fmt.Sprintf("To: <%s>\r\n", emailOfReceiver)
	subject := "Subject: Password update verification code\r\n"
	body := fmt.Sprintf("Your verification code is %s", code)

	fullMsg := from + to + subject + "\r\n" + body

	fullMsgBytes := []byte(fullMsg)

	em.sendEmail(emailOfReceiver, fullMsgBytes)
}

func (em *EmailManager) SendPasswordUpdateNotification(emailOfReceiver string, feelLikeGetHacked bool) {
	from := fmt.Sprintf("From: <%s>\r\n", em.smtpConfig.Email)
	to := fmt.Sprintf("To: <%s>\r\n", emailOfReceiver)
	subject := "Subject: Password was updated\r\n"

	body := "Hey, your password was updated."

	if feelLikeGetHacked {
		body += " You have picked option 'feel like get hacked'. It means:\n1) We've deleted your sessions" +
			"on other devices/browsers;\n2) If malicious user got access to your account they would be logged out;" +
			"3) We assume that you have changed your password on another one, so if malicious user had your " +
			"credentials they are not valid anymore"
	}

	fullMsg := from + to + subject + "\r\n" + body

	fullMsgBytes := []byte(fullMsg)

	em.sendEmail(emailOfReceiver, fullMsgBytes)
}

func (em *EmailManager) SendVerifCodeForPasswordReset(emailOfReceiver, code string) {
	from := fmt.Sprintf("From: <%s>\r\n", em.smtpConfig.Email)
	to := fmt.Sprintf("To: <%s>\r\n", emailOfReceiver)
	subject := "Subject: Password reset verification code\r\n"

	body := fmt.Sprintf("Your verification code is %s", code)

	fullMsg := from + to + subject + "\r\n" + body

	fullMsgBytes := []byte(fullMsg)

	em.sendEmail(emailOfReceiver, fullMsgBytes)
}

func (em *EmailManager) SendPasswordResetNotification(emailOfReceiver string) {
	from := fmt.Sprintf("From: <%s>\r\n", em.smtpConfig.Email)
	to := fmt.Sprintf("To: <%s>\r\n", emailOfReceiver)
	subject := "Subject: Password reset\r\n"

	urlForPasswordReset := fmt.Sprintf("%s/password-reset", em.appConfig.Domain)

	body := fmt.Sprintf(`Hey, your password for gofundament account was changed,
if you haven't performed this action it's possible to recover access by entering %s into the form at %s'`,
		emailOfReceiver, urlForPasswordReset)

	fullMsg := from + to + subject + "\r\n" + body

	fullMsgBytes := []byte(fullMsg)

	em.sendEmail(emailOfReceiver, fullMsgBytes)
}

func (em *EmailManager) SendVerifCodeToCleanSessions(emailOfReceiver, code string) {
	from := fmt.Sprintf("From: <%s>\r\n", em.smtpConfig.Email)
	to := fmt.Sprintf("To: <%s>\r\n", emailOfReceiver)
	subject := "Subject: Password reset\r\n"

	body := fmt.Sprintf(
		`Hey. We've detected large amount of sessions that were created for your account.'
To continue work with your gofundament account thouse sessions should be cleaned (you will be logged out from
other devices/browsers). Use this verification code to continue %s
`, code)

	fullMsg := from + to + subject + "\r\n" + body

	fullMsgBytes := []byte(fullMsg)

	em.sendEmail(emailOfReceiver, fullMsgBytes)
}

func (em *EmailManager) sendEmail(emailOfReceiver string, body []byte) {
	sender := em.smtpConfig.Email
	password := em.smtpConfig.Password

	recipient := []string{
		emailOfReceiver,
	}

	smtpHost := em.smtpConfig.Host
	smtpPort := em.smtpConfig.Port

	auth := smtp.PlainAuth("", sender, password, smtpHost)

	if err := smtp.SendMail(smtpHost+":"+smtpPort, auth, sender, recipient, body); err != nil {
		log.Error().Err(err).Msg("error while trying to send email")
	}
}

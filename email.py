import smtplib
from common import *
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders

smtp_auth = config.get('Email','smtp_auth',"val")
smtp_server = config.get("Email","smtp_server","val")
smtp_server_port=int(config.get("Email","smtp_server_port","val"))
smtp_sender=config.get("Email","smtp_sender","val")
smtp_password=config.get("Email","smtp_password","val")
smtp_list = (config.get("Email","smtp_list","val"))

def attach_files(msg, compressed_output):
    # Open the file to be attached
    attachment = open(compressed_output, "rb")

    # Extract just the file name from the path
    file_name = os.path.basename(compressed_output)

    # Create a MIME object for the attachment
    mime_attachment = MIMEBase('application', 'octet-stream')
    mime_attachment.set_payload(attachment.read())

    # Encode the payload in Base64
    encoders.encode_base64(mime_attachment)

    # Add a header to specify the file name in the email
    mime_attachment.add_header(
        'Content-Disposition', 
        f"attachment; filename={file_name}"
    )

    # Attach the MIME object to the email message
    msg.attach(mime_attachment)

    # Close the file
    attachment.close()


def email_body():
	email_body = f'\r\n\r\nAttack Story'                     
	return email_body

def send_email(compressed_output):
	
	########## Extract date and time from file name to use in Subject line #########
	file_name = os.path.basename(compressed_output)  # "2024-11-18_16.24.54.tgz"
	# Extract the date and time part from the file path
	datetime_part = file_name.rsplit('.', 1)[0] # "2024-11-18_16.24.54"
	# Parse the date and time into a datetime object
	parsed_datetime = datetime.datetime.strptime(datetime_part, "%Y-%m-%d_%H.%M.%S")
	# Format the datetime object into the desired format
	formatted_datetime = parsed_datetime.strftime("%B %d, %Y %H:%M")
	##########################################################

	msg = MIMEMultipart()
	msg["From"] = smtp_sender
	msg["To"] = smtp_list
	msg["Subject"] = f"Attack Story - {formatted_datetime}"
	attach_files(msg,compressed_output)
	msg_body=email_body()
	msg.attach(MIMEText(msg_body, 'html'))
	mailserver = smtplib.SMTP(host=smtp_server,port=smtp_server_port)
	
	if smtp_auth.upper() == "TRUE":
		mailserver.starttls()
		mailserver.ehlo()
		mailserver.login(smtp_sender, smtp_password)
	else:
		mailserver.ehlo()
	mailserver.sendmail(from_addr=smtp_sender,to_addrs=smtp_list.split(","), msg=msg.as_string())
	mailserver.quit()
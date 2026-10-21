# Cheap signature-framework layer for the PHP session.upload_progress advisory
# (2026-10-21). Matches the form-part name the handler keys on, inside the request
# body. Plaintext HTTP only. The behavioral script detect-php-upload-progress.zeek
# is the durable layer (adds session-id and part-count context).

signature php-upload-progress-field {
	ip-proto == tcp
	http-request-body /.*name=\"PHP_SESSION_UPLOAD_PROGRESS\"/
	event "PHP session.upload_progress field in multipart POST (2026-10-21 advisory)"
}

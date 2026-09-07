// The spoof_auth cookie is HttpOnly, so it can neither be read nor deleted from JavaScript.
// The server echoes the cookie details in the lesson output whenever it issues one, and the
// /SpoofCookie/cleanup endpoint expires it, so both are driven from the server side here.
var cookieIssued = false;

function hasCookie() {
	var lessonText = $('#spoof_attack_output').text() + $('#spoof_attack_feedback').text();
	if (lessonText.indexOf('spoof_auth=') !== -1)
		cookieIssued = true;
	return cookieIssued;
}

function cleanup() {
	$.get('SpoofCookie/cleanup').always(function() {
		cookieIssued = false;
		$('#spoof_username').removeAttr('disabled');
		$('#spoof_password').removeAttr('disabled');
		$('#spoof_submit').removeAttr('disabled');
		$('#spoof_attack_feedback').html('');
		$('#spoof_attack_output').html('');
	});
}

var feedback = document.getElementById('spoof_attack_feedback');
var output = document.getElementById('spoof_attack_output');

var obs = new MutationObserver(function(mutations) {
	mutations.forEach(function() {
		if (hasCookie()) {
			$('#spoof_username').prop('disabled', true);
			$('#spoof_password').prop('disabled', true);
			$('#spoof_submit').prop('disabled', true);
		}
	});
});

var obsConfig = { characterData: false, attributes: false, childList: true, subtree: false };
obs.observe(feedback, obsConfig);
obs.observe(output, obsConfig);

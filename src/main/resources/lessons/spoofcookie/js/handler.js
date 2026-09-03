// The spoof_auth cookie is HttpOnly, so the browser hides it from scripts on purpose.
// The login state is derived from the assignment output rendered by the server instead,
// and the cookie is erased by the server endpoint below.
function hasSpoofCookie() {
	return $('#spoof_attack_output').text().indexOf('spoof_auth=') !== -1;
}

function cleanup() {
	$.get('SpoofCookie/cleanup').always(function() {
		$('#spoof_username').removeAttr('disabled');
		$('#spoof_password').removeAttr('disabled');
		$('#spoof_submit').removeAttr('disabled');
		$('#spoof_attack_feedback').html('');
		$('#spoof_attack_output').html('');
	});
}

var obs = new MutationObserver(function(mutations) {
	mutations.forEach(function() {
		if (hasSpoofCookie()) {
			$('#spoof_username').prop('disabled', true);
			$('#spoof_password').prop('disabled', true);
			$('#spoof_submit').prop('disabled', true);
		}
	});
});

var observerOptions = { characterData: false, attributes: false, childList: true, subtree: false };
obs.observe(document.getElementById('spoof_attack_feedback'), observerOptions);
obs.observe(document.getElementById('spoof_attack_output'), observerOptions);

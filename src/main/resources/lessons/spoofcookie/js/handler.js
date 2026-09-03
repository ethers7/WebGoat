// The cookie is HttpOnly, so it is not readable/writable from JS: ask the server to expire it
// and derive the logged-in state from the cookie details the server prints in the output div.
function hasSpoofCookie() {
	return $('#spoof_attack_output').text().indexOf('spoof_auth=') !== -1;
}

function cleanup() {
	$.get('SpoofCookie/cleanup').always(function () {
		$('#spoof_username').removeAttr('disabled');
		$('#spoof_password').removeAttr('disabled');
		$('#spoof_submit').removeAttr('disabled');
		$('#spoof_attack_feedback').html('');
		$('#spoof_attack_output').html('');
	});
}

var target = document.getElementById('spoof_attack_feedback');

var obs = new MutationObserver(function(mutations) {
	mutations.forEach(function() {
		if (hasSpoofCookie()) {
			$('#spoof_username').prop('disabled', true);
			$('#spoof_password').prop('disabled', true);
			$('#spoof_submit').prop('disabled', true);
		}
	});
});

obs.observe(target, { characterData: false, attributes: false, childList: true, subtree: false });

function imgrequest( url, el )
{
	var httpRequest;
	try { httpRequest = new XMLHttpRequest(); }
	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }
	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }
	if ( typeof(el)!='undefined' ) {
		el.onclick = null;
		el.style.opacity = '0.7';
		httpRequest.onreadystatechange = function()
		{
			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';
		}
	}
	httpRequest.open('GET', url, true);
	httpRequest.send(null);
}
var autorefresh=3000;
var tautorefresh;
function setautorefresh(t)
{
	clearTimeout(tautorefresh);
	autorefresh = t;
	if (t>0) tautorefresh = setTimeout('updateDiv()',autorefresh);
}
function updateDiv()
{
	var httpRequest;
	try {
		httpRequest = new XMLHttpRequest();
	}
	catch(trymicrosoft) {
		try {
			httpRequest = new ActiveXObject('Msxml2.XMLHTTP');
		}
		catch(oldermicrosoft) {
			try {
				httpRequest = new ActiveXObject('Microsoft.XMLHTTP');
			}
			catch(failed) {
				httpRequest = false;
			}
		}
	}
	if (!httpRequest) {
		alert('Your browser does not support Ajax.');
		return false;
	}
	httpRequest.onreadystatechange = function()
	{
		if (httpRequest.readyState == 4) {
			if(httpRequest.status == 200) {
				requestError=0;
				document.getElementById('wrapper').innerHTML = httpRequest.responseText;
			}
			tautorefresh = setTimeout('updateDiv()',autorefresh);
		}
	}
	httpRequest.open('GET', '/?action=div', true);
	httpRequest.send(null);
}
function start()
{
	 setautorefresh(autorefresh);
}

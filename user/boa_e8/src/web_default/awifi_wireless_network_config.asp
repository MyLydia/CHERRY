<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>中国电信</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=UTF-8">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<SCRIPT language="javascript" type="text/javascript">

/********************************************************************
**          on document load
********************************************************************/
var cgi = new Object();
<%initAwifiNetworkConfig();%>

function awifiSecClick() 
{	
	if(document.AwifiStation.awifiEnabled.checked){
		enableTextField(document.AwifiStation.awifi_name);
	}
	else{
		disableTextField(document.AwifiStation.awifi_name);
	}			
}

function on_submit(){
	var str;
	if (document.AwifiStation.awifiEnabled.checked) {
		str = document.AwifiStation.awifi_name.value;

		if (str.length == 0) {
			alert("SSID不能为空.");
			return;
		}

		if (str.length > 26) {
			alert('无线名称 "aWiFi-' + str + '" 不能大于32个字符。');
			return;
		}

		/*
		if (isIncludeInvalidChar(str)) {
			alert("SSID 含有非法字符，请重新输入!");
			return;
		}
		*/
	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.AwifiStation.submit();
}

function on_init()
{
	sji_docinit(document, cgi);
	awifiSecClick();
}

</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
<form action="/boaform/admin/formAwifiNetworkConfig" method="post" name="AwifiStation">
	<div class="text_location">
		aWiFi 无线网络启用 <input name="awifiEnabled" id="awifiEnabled" onclick="awifiSecClick();" type="checkbox">
	</div>
	<div id="awifisetting" class="text_location">
		<p>		
			<span>WiFi 名称</span>	<span style="margin:10px;">aWiFi-<input id="commentText" name="awifi_name" maxlength="26" size="26" value="" type="text"></span>
		</p>	
		<input onclick="on_submit();" name="awifiSave" value="保存/应用" type="button">
		<input type="hidden" name="submit-url" value="/awifi_wireless_network_config.asp">
		<input type="hidden" name="postSecurityFlag" value="">
	<div>
</form>
</blockquote>
<script>
</script>
</body>
<%addHttpNoCache();%>
</html>

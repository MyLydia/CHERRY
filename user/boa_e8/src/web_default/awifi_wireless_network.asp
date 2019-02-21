<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>中国电信</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<SCRIPT language="javascript" type="text/javascript">

/********************************************************************
**          on document load
********************************************************************/
var cgi = new Object();
<%initAwifiNetwork();%>

function awifiSecClick() 
{	
	if(document.AwifiStation.awifiEnabled.checked){
		document.AwifiStation.awifi_name.disabled = false;
	}
	else{
		document.AwifiStation.awifi_name.disabled = true;
	}			
}

function checkSSIDStr(str)
{
	var re =  /^[0-9a-zA-Z-]*$/g;
	 if (!re.test(str)) 
	 	return false;
	 return true;
}

function on_submit(){
	var str;
	if (document.AwifiStation.awifiEnabled.checked) {
		str = document.AwifiStation.awifi_name.value;

		if(!(str.substr(0,5) == "aWiFi" && str.length ==5) && !((str.length >6 && str.substr(0,6) == "aWiFi-" && checkSSIDStr(str)))){
			alert('无线名称必须为 "aWiFi" 或者"aWiFi-xxxx" x只能是字母、数字、"-"');
			return;
		}
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
<form action="/boaform/admin/formAwifiNetwork" method="post" name="AwifiStation">
	<div class="text_location">
		aWiFi 无线网络启用 <input name="awifiEnabled" id="awifiEnabled" onclick="awifiSecClick();" type="checkbox">
	</div>
	<div id="awifisetting" class="text_location">
		<p>		
			<span>WiFi 名称</span>	<span style="margin:10px;"><input id="commentText" name="awifi_name" maxlength="16" size="16" value="" type="text"></span>
		</p>	
		<input onclick="on_submit();" name="awifiSave" value="保存/应用" type="button">
		<input type="hidden" name="submit-url" value="/awifi_wireless_network.asp">
		<input type="hidden" name="postSecurityFlag" value="">
	<div>
</form>
</blockquote>
<script>
</script>
</body>
<%addHttpNoCache();%>
</html>

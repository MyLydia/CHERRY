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
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
<blockquote>
<form action="/boaform/admin/formAwifiStation" method="post" name="AwifiStation">
	<div class="text_location">
		<p>
			将跳转至爱wifi管理平台，绑定上架portal页。
		</p>
		<br>
			<input name="awifi_station" type="button" value="启用个性化站点" onClick=<% getInfo("awifi-portal-url"); %>> 
			<input type="hidden" value="/awifi_unique_station.asp" name="submit-url">
		<br>
	</div>
</form>
</blockquote>
</body>
<%addHttpNoCache();%>
</html>

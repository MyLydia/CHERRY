<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>中国移动</title>
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
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>设备基本信息</b></div>
			<table class="flat" border="1">
				<tr>
					<td width="168"  class="hdb">设备型号</td>
					<td width="360" class="hdt"><% getInfo("devModel"); %></td>
				</tr>
				<tr>
					<td class="hdb">设备标识号</td>
					<td class="hdt"><% getInfo("devId"); %></td>
				</tr>
				<tr>
					<td class="hdb">GPON SN</td>
					<td class="hdt"><% getInfo("gpon_sn"); %></td>
				</tr>
				<tr>
					<td class="hdb">硬件版本</td>
					<td class="hdt"><% getInfo("hdVer"); %></td>
				</tr>
				<tr>
					<td class="hdb">软件版本</td>
					<td class="hdt"><% getInfo("stVer"); %></td>
				</tr>
			</table>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

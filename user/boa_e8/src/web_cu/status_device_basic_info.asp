<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>�й��ƶ�</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">

function on_init()
{
	var ponmode = '<% getInfo("ponmode"); %>';
	if (ponmode != '1')
	{
		document.getElementById("gponsn").style.display = "none";
	}
}
</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<div align="left" style="padding-left:20px;">
			<div align="left"><b>�豸������Ϣ</b></div>
			<table class="flat" border="1">
				<tr>
					<td width="168"  class="hdb">�豸�ͺ�</td>
					<td width="360" class="hdt"><% getInfo("devModel"); %></td>
				</tr>
				<tr>
					<td class="hdb">�豸��ʶ��</td>
					<td class="hdt"><% getInfo("devId"); %></td>
				</tr>
				<tr id='gponsn'>
					<td class="hdb">GPON SN</td>
					<td class="hdt"><% getInfo("gpon_sn"); %></td>
				</tr>
				<tr>
					<td class="hdb">Ӳ���汾</td>
					<td class="hdt"><% getInfo("hdVer"); %></td>
				</tr>
				<tr>
					<td class="hdb">����汾</td>
					<td class="hdt"><% getInfo("province_sw_ver"); %></td>
				</tr>
			</table>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

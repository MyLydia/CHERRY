<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>�й�����</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">
var Procfg = "<% checkWrite("procfg"); %>";
function on_init()
{
	Table = document.getElementById("tab");
	if(Procfg == "1"){
		NewRow = Table.insertRow();
		cell = NewRow.insertCell(0);
		cell.className = "hdb";
		cell.innerHTML ="����ʱ��";
		cell = NewRow.insertCell(1);
		cell.innerHTML ="<% getInfo("buildtime"); %>";
	}
}
</script>

</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad='on_init()'>
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>�豸������Ϣ</b></div>
			<table id="tab" class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td width="20%"  class="hdb">�豸�ͺ�</td>
					<td><% getInfo("devModel"); %></td>
				</tr>
				<tr>
					<td class="hdb">�豸��ʶ��</td>
					<td><% getInfo("devId"); %></td>
				</tr>
				<tr>
					<td class="hdb">Ӳ���汾</td>
					<td><% getInfo("hdVer"); %></td>
				</tr>
				<tr>
					<td class="hdb">����汾</td>
					<td><% getInfo("stVer"); %></td>
				</tr>
			</table>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

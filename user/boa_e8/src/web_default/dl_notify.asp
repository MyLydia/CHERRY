<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<html>
<head>
<title>�й�����-�汾����</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<style>
body { 
	font-family: "��������";
    background-repeat: no-repeat;
    background-attachment: fixed;
    background-position: center top; 
}
tr {height: 16px;}
select {width: 150px;}
</style>
<!--ϵͳ�����ű�-->
<script language="javascript" src="/common.js"></script>
<script language="javascript" type="text/javascript">
var phase;

<% initFirmwareUpgradeWarnPage(); %>

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	if (phase == 1)//upgrading
	{
		document.getElementById("upgrading").style.display = "block";
		document.getElementById("rebooting").style.display = "none";
		document.getElementById("upgradeok").style.display = "none";
	}
	else if (phase == 2)//rebooting
	{
		document.getElementById("upgrading").style.display = "none";
		document.getElementById("rebooting").style.display = "block";
		document.getElementById("upgradeok").style.display = "none";
	}
	else//upgrade ok
	{
		document.getElementById("upgrading").style.display = "none";
		document.getElementById("rebooting").style.display = "none";
		document.getElementById("upgradeok").style.display = "block";
	}
}

function count()
{
	if (phase == 1)
	{
		setTimeout("top.location.href=\"/dl_notify.asp\"", 2000);
	}
	else if (phase == 2)
	{
		setTimeout("top.location.href=\"/dl_notify.asp\"", 90000);
	}
}

</script>

</head>
<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" bgcolor="E0E0E0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init()">
	<div align="center" style="padding-left:5px; padding-top:5px">
		<form action="/boaform/formFirmwareUpgradeWarn" method="post">
			<br><br><br>
			<div align="center">
				<font color='red' font size="26"><b>��ʾ</b></font>
				<br>
			</div>
			<div id="upgrading" align="center">
				<p style="font-size:26px"><b>�ն����ڽ��а汾�����������µ硣</b><br></p>
				<p style="font-size:18px">
				ITMS ƽ̨���ڶ��豸����Զ����������ϵͳ������<br>�Զ�����ҵ��10 �����ڣ�����ע�����¼��㣺&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>
				1�������������У���Ҫ�µ硣&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>
				2�������������У���Ҫ�β���ˡ�&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>
				3�������������в�Ҫ�رո�ҳ�档&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				</p>
			</div>
			<div id="rebooting" align="center">
				<p style="font-size:26px"><b>�ն�������������ȴ���</b></p>
			</div>
			<div id="upgradeok" align="center">
				<p style="font-size:26px"><b>�ն������ɹ���������ʹ��ҵ��<br>лл�������ĵȴ���</b></p>
			</div>
			<br>
			<input type="hidden" name="submit-url" value="/dl_notify.asp">

			<script>
			count();
			</script>
		</form>
	</DIV>

</body>
</html>




<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<html>
<head>
<title>中国电信-版本升级</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<style>
body { 
	font-family: "华文宋体";
    background-repeat: no-repeat;
    background-attachment: fixed;
    background-position: center top; 
}
tr {height: 16px;}
select {width: 150px;}
</style>
<!--系统公共脚本-->
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
<!--主页代码-->
<body topmargin="0" bgcolor="E0E0E0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init()">
	<div align="center" style="padding-left:5px; padding-top:5px">
		<form action="/boaform/formFirmwareUpgradeWarn" method="post">
			<br><br><br>
			<div align="center">
				<font color='red' font size="26"><b>提示</b></font>
				<br>
			</div>
			<div id="upgrading" align="center">
				<p style="font-size:26px"><b>终端正在进行版本升级，请勿下电。</b><br></p>
				<p style="font-size:18px">
				ITMS 平台正在对设备进行远程升级，且系统启动后<br>自动配置业务（10 分钟内），请注意以下几点：&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>
				1、在升级过程中，不要下电。&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>
				2、在升级过程中，不要拔插光纤。&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<br>
				3、在升级过程中不要关闭该页面。&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				</p>
			</div>
			<div id="rebooting" align="center">
				<p style="font-size:26px"><b>终端正在重启，请等待。</b></p>
			</div>
			<div id="upgradeok" align="center">
				<p style="font-size:26px"><b>终端升级成功，可正常使用业务，<br>谢谢您的耐心等待。</b></p>
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




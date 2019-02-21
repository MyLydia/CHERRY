<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>Version Information Setup</TITLE>
<META http-equiv=pragma content=no-cache>
<meta http-equiv=refresh content="5">
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(../style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" type="text/javascript">
</SCRIPT>

<STYLE type=text/css>
@import url(/style/default.css);
div.backlogin {
	font-size: 7px;
	position: relative;
	<% regresultLoginStyle(); %>
	top: 40px;
	margin: auto;
	width: 200px;
	text-align: right;
	color:black;
	text-decoration:underline;
}
</STYLE>
</head>

<script type='text/javascript'> 
var resFile;

<% initTermInsp(); %>
	
function on_init()
{
	if(resFile==1)
	{
		document.getElementById("testing").style.display = "none";
		document.getElementById("content").style.display = "block";
	}
	else
	{		
		document.getElementById("testing").style.display = "block";
		document.getElementById("content").style.display = "none";
	}
}
</script>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init()">
<blockquote>
<div align="left" id="testing">
	<b> <font color='red'><h1>终端正在自检，请稍后...</h1></font></b>
</div>
<DIV align="left" id="content" style="padding-left:20px; padding-top:5px"><br>
	<div id="login_" class=backlogin>
		<a id="login_font" href="/admin/login.asp" <% regresultLoginFontStyle(); %>>返回登录页面</a>
	</div>

	<div align="left"><b>终端硬件信息</b></div>
			<table class="flat" border="1" cellpadding="1" cellspacing="1" width="65%">
				<tr>
					<td width="20%"  class="hdb">终端厂家</td>
					<td><% getInfo("rtk_manufacturer"); %></td>
				</tr>
				<tr>
					<td class="hdb">终端硬件信息</td>
					<td><% getInfo("devModel"); %>, <% getInfo("hdVer"); %></td>
				</tr>
				<tr>
					<td class="hdb">终端CPU</td>
					<% terminalInspectionShow("SCCPURate"); %>
				</tr>
				<tr>
					<td class="hdb">终端内存</td>
					<% terminalInspectionShow("SCMemRate"); %>
				</tr>
				<tr>
					<td class="hdb">终端无线</td>
					<td><% getInfo("SCwlanState"); %></td>
				</tr>
				<tr>
					<td class="hdb">终端网口</td>
					<% terminalInspectionShow("LANPorts"); %>
					<td></td>
				</tr>
				<tr>
					<td class="hdb">终端语音端口</td>
					<% voip_e8c_get("SCportstatus"); %>
				</tr>
				<tr>
					<td class="hdb">收光状态</td>
					<td><% ponGetStatus("rx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">发光状态</td>
					<td><% ponGetStatus("tx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">光模块温度</td>
					<td><% ponGetStatus("temperature"); %></td>
				</tr>
				<tr>
					<td class="hdb">二层丢帧率</td>
					<td><% terminalInspectionShow("stbRate"); %></td>
				</tr>
				<tr>
					<td class="hdb">二层时延</td>
					<td><% terminalInspectionShow("stbDelay"); %></td>
				</tr>
				<tr>
					<td class="hdb">二层抖动</td>
					<td><% terminalInspectionShow("stbTerm"); %></td>
				</tr>
			</table>	
			<br><br>
		<b>终端软件信息</b>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1" width="65%">
				<tr>
					<td width="20%"  class="hdb">OLT注册状态</td>
					<td><% showOLT_status(); %></td>
				</tr>
				<tr>
					<td class="hdb">ITMS注册状态</td>
					<td><% getInfo("SCtr069Register"); %></td>
				</tr>
				<tr>
					<td class="hdb">ITMS下发状态</td>
					<td><% getInfo("SCtr069Download"); %></td>
				</tr>
				<tr>
					<td class="hdb">管理地址</td>
					<% terminalInspectionShow("tr069IPAdd"); %>
				</tr>
				<tr>
					<td class="hdb">宽带拨号状态</td>
					<% terminalInspectionShow("SCWANState"); %>
				</tr>
				<tr>
					<td class="hdb">宽带IP地址</td>
					<% terminalInspectionShow("InterIPAdd"); %>
				</tr>
				<tr>
					<td class="hdb">语音注册状态</td>
					<% voip_e8c_get("registerStatus"); %>
				</tr>
				<tr>
					<td class="hdb">语音IP地址</td>
					<% terminalInspectionShow("VoiceIPAdd"); %>
				</tr>
			</table>
</DIV>
</blockquote>
</html>


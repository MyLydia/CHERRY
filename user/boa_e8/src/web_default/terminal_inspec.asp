<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>Version Information Setup</TITLE>
<META http-equiv=pragma content=no-cache>
<meta http-equiv=refresh content="5">
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<STYLE type=text/css>
@import url(../style/default.css);
</STYLE>
<!--ϵͳ�����ű�-->
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
	<b> <font color='red'><h1>�ն������Լ죬���Ժ�...</h1></font></b>
</div>
<DIV align="left" id="content" style="padding-left:20px; padding-top:5px"><br>
	<div id="login_" class=backlogin>
		<a id="login_font" href="/admin/login.asp" <% regresultLoginFontStyle(); %>>���ص�¼ҳ��</a>
	</div>

	<div align="left"><b>�ն�Ӳ����Ϣ</b></div>
			<table class="flat" border="1" cellpadding="1" cellspacing="1" width="65%">
				<tr>
					<td width="20%"  class="hdb">�ն˳���</td>
					<td><% getInfo("rtk_manufacturer"); %></td>
				</tr>
				<tr>
					<td class="hdb">�ն�Ӳ����Ϣ</td>
					<td><% getInfo("devModel"); %>, <% getInfo("hdVer"); %></td>
				</tr>
				<tr>
					<td class="hdb">�ն�CPU</td>
					<% terminalInspectionShow("SCCPURate"); %>
				</tr>
				<tr>
					<td class="hdb">�ն��ڴ�</td>
					<% terminalInspectionShow("SCMemRate"); %>
				</tr>
				<tr>
					<td class="hdb">�ն�����</td>
					<td><% getInfo("SCwlanState"); %></td>
				</tr>
				<tr>
					<td class="hdb">�ն�����</td>
					<% terminalInspectionShow("LANPorts"); %>
					<td></td>
				</tr>
				<tr>
					<td class="hdb">�ն������˿�</td>
					<% voip_e8c_get("SCportstatus"); %>
				</tr>
				<tr>
					<td class="hdb">�չ�״̬</td>
					<td><% ponGetStatus("rx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">����״̬</td>
					<td><% ponGetStatus("tx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">��ģ���¶�</td>
					<td><% ponGetStatus("temperature"); %></td>
				</tr>
				<tr>
					<td class="hdb">���㶪֡��</td>
					<td><% terminalInspectionShow("stbRate"); %></td>
				</tr>
				<tr>
					<td class="hdb">����ʱ��</td>
					<td><% terminalInspectionShow("stbDelay"); %></td>
				</tr>
				<tr>
					<td class="hdb">���㶶��</td>
					<td><% terminalInspectionShow("stbTerm"); %></td>
				</tr>
			</table>	
			<br><br>
		<b>�ն������Ϣ</b>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1" width="65%">
				<tr>
					<td width="20%"  class="hdb">OLTע��״̬</td>
					<td><% showOLT_status(); %></td>
				</tr>
				<tr>
					<td class="hdb">ITMSע��״̬</td>
					<td><% getInfo("SCtr069Register"); %></td>
				</tr>
				<tr>
					<td class="hdb">ITMS�·�״̬</td>
					<td><% getInfo("SCtr069Download"); %></td>
				</tr>
				<tr>
					<td class="hdb">�����ַ</td>
					<% terminalInspectionShow("tr069IPAdd"); %>
				</tr>
				<tr>
					<td class="hdb">�������״̬</td>
					<% terminalInspectionShow("SCWANState"); %>
				</tr>
				<tr>
					<td class="hdb">���IP��ַ</td>
					<% terminalInspectionShow("InterIPAdd"); %>
				</tr>
				<tr>
					<td class="hdb">����ע��״̬</td>
					<% voip_e8c_get("registerStatus"); %>
				</tr>
				<tr>
					<td class="hdb">����IP��ַ</td>
					<% terminalInspectionShow("VoiceIPAdd"); %>
				</tr>
			</table>
</DIV>
</blockquote>
</html>


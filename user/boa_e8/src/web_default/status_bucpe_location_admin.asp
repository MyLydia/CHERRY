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
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>�豸��Ϣ</b></div>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td width=150px  class="hdb">�豸���к�</td>
					<td><% getInfo("rtk_serialno"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">WAN MAC</td>
					<td><% getInfo("BUCPEWANMAC"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">LAN MAC</td>
					<td><% getInfo("elan-Mac"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">����������</td>
					<td><% getInfo("BUCPEUplink"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">����汾��</td>
					<td><% getInfo("stVer"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">B1�ӿ�Э��汾</td>
					<td><% getInfo("BUCPEB1InterfaceVersion"); %></td>
				</tr>
<!-- 
				<tr>
					<td width=150px  class="hdb">�豸��ǰʱ��</td>
					<td><% getInfo("uptime"); %></td>
				</tr>
-->
				<tr>
					<td width=150px  class="hdb">�豸��ǰʱ��</td>
					<td><% getInfo("date"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">�ϱ�·�������ã�</td>
					<td><% getInfo("BUCPEInformURL"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">�ϱ�·�������ã�</td>
					<td><% getInfo("BUCPEInformURLbak"); %></td>
				</tr>
								<tr>
					<td width=150px  class="hdb">�豸ע��ID</td>
					<td><% getInfo("locationRegID"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">UUID</td>
					<td><% getInfo("locationUUID"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">�����ϱ�������֣�</td>
					<td><% getInfo("BUCPEInformCycle"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">����ִ�����ڣ�Сʱ��</td>
					<td><% getInfo("BUCPETaskCycle"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">���ò���·��ǰ׺</td>
					<td><% getInfo("BUCPEspeedURL"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">���ò���·��ǰ׺</td>
					<td><% getInfo("BUCPEspeedbakURL"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">Traceroute��������</td>
					<td><% getInfo("BUCPETraceURL"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">�豸�ϱ�״̬</td>
					<td><% getInfo("locationLocationInform0"); %></td>
				</tr>
<!-- 
				<tr>
					<td width=150px  class="hdb">����ƽ̨ʱ�������</td>
					<td><% getInfo("BUCPEtimeURL"); %></td>
				</tr> 
-->
			</table>
		</div>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>����λ����Ϣ״̬A</b></div>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td width=150px  class="hdb">���꾭��ֵ���ȣ�</td>
					<td><% getInfo("locationALongitude"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">����γ��ֵ���ȣ�</td>
					<td><% getInfo("locationALatitude"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">���꺣�θ߶ȣ��ף�</td>
					<td><% getInfo("locationAElevation"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">ˮƽ���ȣ�</td>
					<td><% getInfo("locationAHorizontalerror"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">��ֱ���ȣ�</td>
					<td><% getInfo("locationAAltitudeerror"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">λ���������</td>
					<td><% getInfo("locationAAreacode"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">�������ʱ��</td>
					<td><% getInfo("locationATimeStamp"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">����ǩ��</td>
					<td><% getInfo("locationAGISDigest"); %></td>
				</tr>
			</table>
		</div>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>����λ����Ϣ״̬B</b></div>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td width=150px  class="hdb">���꾭��ֵ���ȣ�</td>
					<td><% getInfo("locationBLongitude"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">����γ��ֵ���ȣ�</td>
					<td><% getInfo("locationBLatitude"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">���꺣�θ߶ȣ��ף�</td>
					<td><% getInfo("locationBElevation"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">ˮƽ���ȣ�</td>
					<td><% getInfo("locationBHorizontalerror"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">��ֱ���ȣ�</td>
					<td><% getInfo("locationBAltitudeerror"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">λ���������</td>
					<td><% getInfo("locationBAreacode"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">�������ʱ��</td>
					<td><% getInfo("locationBTimeStamp"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">����ǩ��</td>
					<td><% getInfo("locationBGISDigest"); %></td>
				</tr>
			</table>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

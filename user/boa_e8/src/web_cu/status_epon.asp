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
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>������Ϣ</b></div>
			<table class="flat" border="1">
				<tr>
					<td class="hdb">����״̬</td>
					<td width="360" class="hdt"><% showepon_status(); %></td>
				</tr>
				<tr <% checkWrite("priv"); %>>
					<td class="hdb">MAC ��ַ</td>
					<td class="hdt"><% ponGetStatus("epon-mac-address"); %></td>
				</tr>
				<tr <% checkWrite("priv"); %>>
					<td class="hdb">FEC ����</td>
					<td class="hdt">֧��</td>
				</tr>
				<tr <% checkWrite("priv"); %>>
					<td class="hdb">FEC ����״̬</td>
					<td class="hdt"><% ponGetStatus("epon-fec-us-state"); %></td>
				</tr>
				<tr <% checkWrite("priv"); %>>
					<td class="hdb">FEC ����״̬</td>
					<td class="hdt"><% ponGetStatus("epon-fec-ds-state"); %></td>
				</tr>
				<tr <% checkWrite("priv"); %>>
					<td class="hdb">����ģʽ�����ؽ�����</td>
					<td class="hdt"><% ponGetStatus("epon-triple-churning"); %></td>
				</tr>
			</table>
			<br>
			<div align="left"><b>��ģ����Ϣ</b></div>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td class="hdb">����⹦��</td>
					<td class="hdt" width="360"><% ponGetStatus("tx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">���չ⹦��</td>
					<td class="hdt"><% ponGetStatus("rx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">�����¶�</td>
					<td class="hdt"><% ponGetStatus("temperature"); %></td>
				</tr>
				<tr>
					<td class="hdb">�����ѹ</td>
					<td class="hdt"><% ponGetStatus("voltage"); %></td>
				</tr>
				<tr>
					<td class="hdb">ƫ�õ���</td>
					<td class="hdt"><% ponGetStatus("bias-current"); %></td>
				</tr>
			</table>
			
			<span <% checkWrite("priv"); %>>
			<div align="left"><b>��·����ͳ����Ϣ</b></div>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td class="hdb">�����ֽ�</td>
					<td class="hdt" width="360"><% ponGetStatus("bytes-sent"); %></td>
				</tr>
				<tr>
					<td class="hdb">�����ֽ�</td>
					<td class="hdt"><% ponGetStatus("bytes-received"); %></td>
				</tr>
				<tr>
					<td class="hdb">����֡</td>
					<td class="hdt"><% ponGetStatus("packets-sent"); %></td>
				</tr>
				<tr>
					<td class="hdb">����֡</td>
					<td class="hdt"><% ponGetStatus("packets-received"); %></td>
				</tr>
				<tr>
					<td class="hdb">���͵���֡</td>
					<td class="hdt"><% ponGetStatus("unicast-packets-sent"); %></td>
				</tr>
				<tr>
					<td class="hdb">���յ���֡</td>
					<td class="hdt"><% ponGetStatus("unicast-packets-received"); %></td>
				</tr>
				<tr>
					<td class="hdb">�����鲥֡</td>
					<td class="hdt"><% ponGetStatus("multicast-packets-sent"); %></td>
				</tr>
				<tr>
					<td class="hdb">�����鲥֡</td>
					<td class="hdt"><% ponGetStatus("multicast-packets-received"); %></td>
				</tr>
				<tr>
					<td class="hdb">���͹㲥֡</td>
					<td class="hdt"><% ponGetStatus("broadcast-packets-sent"); %></td>
				</tr>
				<tr>
					<td class="hdb">���չ㲥֡</td>
					<td class="hdt"><% ponGetStatus("broadcast-packets-received"); %></td>
				</tr>
				<tr>
					<td class="hdb">���� FEC ����֡</td>
					<td class="hdt"><% ponGetStatus("fec-errors"); %></td>
				</tr>
				<tr>
					<td class="hdb">���� HEC ����֡</td>
					<td class="hdt"><% ponGetStatus("hec-errors"); %></td>
				</tr>
				<tr>
					<td class="hdb">���Ͷ�ʧ֡</td>
					<td class="hdt"><% ponGetStatus("packets-dropped"); %></td>
				</tr>
				<tr>
					<td class="hdb">���� PAUSE ������֡</td>
					<td class="hdt"><% ponGetStatus("pause-packets-sent"); %></td>
				</tr>
				<tr>
					<td class="hdb">���� PAUSE ������֡</td>
					<td class="hdt"><% ponGetStatus("pause-packets-received"); %></td>
				</tr>
			</table>
			<br>

			<div align="left"><b>�澯��Ϣ</b></div>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td class="hdb">EPON �澯��Ϣ</td>
					<td class="hdt" width="360"><% ponGetStatus("epon-los"); %></td>
				</tr>
			</table>
			<br>
			</span>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

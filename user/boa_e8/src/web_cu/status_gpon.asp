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
    <table cellSpacing=0 cellPadding=0 width="100%" border=0>
         <tr>
         <td width=10>&nbsp;</td>
         <br>
		 <td>	<table class="flat" border="1">
			    <tr>
			    	<td class='dhb' colspan='2' align="center">��·������Ϣ</td>
			    </tr>
				<tr>
					<td class="hdb" width="20%" >PON��·����״̬</td>
					<td width="360" class="hdt" id="PON_state"><% showgpon_status(); %></td>
				</tr>
				<tr>
					<td class="hdb">FECʹ��</td>
					<td class="hdt" id="FEC">
					<script language=JavaScript type=text/javascript>
					if(document.getElementById("PON_state").innerText == "����")
							document.getElementById("FEC").innerHTML="-";
						else
						    document.getElementById("FEC").innerHTML="enable";
					</script> 
					</td>
				</tr>
				<tr>
					<td class="hdb">����ģʽ</td>
					<td class="hdt" id="encryption">
					<script language=JavaScript type=text/javascript>
					if(document.getElementById("PON_state").innerText == "����")
							document.getElementById("encryption").innerHTML="-";
						else
						    document.getElementById("encryption").innerHTML="<% ponGetStatus("gpon-encryption"); %>";
					</script> 					
					</td>
				</tr>
				<tr>
					<td class="hdb">�澯��Ϣ</td>
					<td class="hdt" id ="alarm">
					<script language=JavaScript type=text/javascript>
						if(document.getElementById("PON_state").innerText == "����")
							document.getElementById("alarm").innerHTML="�����ж�";
						else
						    document.getElementById("alarm").innerHTML="�޸澯";

					</script> 
					</td> 
				</tr>

				</table>
			<br>
	
			<table class="flat" border="1" >
				<tr>
					<td class='hdb' colspan='2' align="center">��·����ͳ��</TD>
				</tr>
				<tr>
					<td class="hdb">PON�ڷ�����</td>
					<td class="hdt" width="360"><% ponGetStatus("packets-sent"); %></td>
				</tr>
				<tr>
					<td class="hdb">PON���հ���</td>
					<td class="hdt"><% ponGetStatus("packets-received"); %></td>
				</tr>
			</table>
			<br>
	
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td class='hdb' colspan='2' align="center">��ģ����Ϣ</TD>
				</tr>
				<tr>
					<td class="hdb" width="20%">����⹦��</td>
					<td class="hdt" width="360"><% ponGetStatus("tx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">���չ⹦��</td>
					<td class="hdt"><% ponGetStatus("rx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">������ѹ</td>
					<td class="hdt"><% ponGetStatus("voltage")%> </td>
				</tr>
				<tr>
					<td class="hdb">��������</td>
					<td class="hdt"><% ponGetStatus("bias-current"); %></td>
				</tr>
				<tr>
					<td class="hdb">�����¶�</td>
					<td class="hdt"><% ponGetStatus("temperature"); %></td>
				</tr>
			</table>
			</td>
		<tr>
          <td width=10>&nbsp;</td>
          <td>&nbsp;</td>
          <td width=10>&nbsp;</td>
        </tr>
        </table>

	
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

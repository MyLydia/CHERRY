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
    <table cellSpacing=0 cellPadding=0 width="100%" border=0>
         <tr>
         <td width=10>&nbsp;</td>
         <br>
		 <td>	<table class="flat" border="1">
			    <tr>
			    	<td class='dhb' colspan='2' align="center">链路连接信息</td>
			    </tr>
				<tr>
					<td class="hdb" width="20%" >PON链路连接状态</td>
					<td width="360" class="hdt" id="PON_state"><% showgpon_status(); %></td>
				</tr>
				<tr>
					<td class="hdb">FEC使能</td>
					<td class="hdt" id="FEC">
					<script language=JavaScript type=text/javascript>
					if(document.getElementById("PON_state").innerText == "离线")
							document.getElementById("FEC").innerHTML="-";
						else
						    document.getElementById("FEC").innerHTML="enable";
					</script> 
					</td>
				</tr>
				<tr>
					<td class="hdb">加密模式</td>
					<td class="hdt" id="encryption">
					<script language=JavaScript type=text/javascript>
					if(document.getElementById("PON_state").innerText == "离线")
							document.getElementById("encryption").innerHTML="-";
						else
						    document.getElementById("encryption").innerHTML="<% ponGetStatus("gpon-encryption"); %>";
					</script> 					
					</td>
				</tr>
				<tr>
					<td class="hdb">告警信息</td>
					<td class="hdt" id ="alarm">
					<script language=JavaScript type=text/javascript>
						if(document.getElementById("PON_state").innerText == "离线")
							document.getElementById("alarm").innerHTML="连接中断";
						else
						    document.getElementById("alarm").innerHTML="无告警";

					</script> 
					</td> 
				</tr>

				</table>
			<br>
	
			<table class="flat" border="1" >
				<tr>
					<td class='hdb' colspan='2' align="center">链路性能统计</TD>
				</tr>
				<tr>
					<td class="hdb">PON口发包数</td>
					<td class="hdt" width="360"><% ponGetStatus("packets-sent"); %></td>
				</tr>
				<tr>
					<td class="hdb">PON口收包数</td>
					<td class="hdt"><% ponGetStatus("packets-received"); %></td>
				</tr>
			</table>
			<br>
	
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td class='hdb' colspan='2' align="center">光模块信息</TD>
				</tr>
				<tr>
					<td class="hdb" width="20%">发射光功率</td>
					<td class="hdt" width="360"><% ponGetStatus("tx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">接收光功率</td>
					<td class="hdt"><% ponGetStatus("rx-power"); %></td>
				</tr>
				<tr>
					<td class="hdb">工作电压</td>
					<td class="hdt"><% ponGetStatus("voltage")%> </td>
				</tr>
				<tr>
					<td class="hdb">工作电流</td>
					<td class="hdt"><% ponGetStatus("bias-current"); %></td>
				</tr>
				<tr>
					<td class="hdb">工作温度</td>
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

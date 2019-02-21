<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>中国电信</title>
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
			<div align="left"><b>设备信息</b></div>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td width=150px  class="hdb">设备序列号</td>
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
					<td width=150px  class="hdb">上联口类型</td>
					<td><% getInfo("BUCPEUplink"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">软件版本号</td>
					<td><% getInfo("stVer"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">B1接口协议版本</td>
					<td><% getInfo("BUCPEB1InterfaceVersion"); %></td>
				</tr>
<!-- 
				<tr>
					<td width=150px  class="hdb">设备当前时间</td>
					<td><% getInfo("uptime"); %></td>
				</tr>
-->
				<tr>
					<td width=150px  class="hdb">设备当前时间</td>
					<td><% getInfo("date"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">上报路径（主用）</td>
					<td><% getInfo("BUCPEInformURL"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">上报路径（备用）</td>
					<td><% getInfo("BUCPEInformURLbak"); %></td>
				</tr>
								<tr>
					<td width=150px  class="hdb">设备注册ID</td>
					<td><% getInfo("locationRegID"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">UUID</td>
					<td><% getInfo("locationUUID"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">周期上报间隔（分）</td>
					<td><% getInfo("BUCPEInformCycle"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">任务执行周期（小时）</td>
					<td><% getInfo("BUCPETaskCycle"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">主用测速路径前缀</td>
					<td><% getInfo("BUCPEspeedURL"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">备用测速路径前缀</td>
					<td><% getInfo("BUCPEspeedbakURL"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">Traceroute测试域名</td>
					<td><% getInfo("BUCPETraceURL"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">设备上报状态</td>
					<td><% getInfo("locationLocationInform0"); %></td>
				</tr>
<!-- 
				<tr>
					<td width=150px  class="hdb">管理平台时间服务器</td>
					<td><% getInfo("BUCPEtimeURL"); %></td>
				</tr> 
-->
			</table>
		</div>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>地理位置信息状态A</b></div>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td width=150px  class="hdb">坐标经度值（度）</td>
					<td><% getInfo("locationALongitude"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">坐标纬度值（度）</td>
					<td><% getInfo("locationALatitude"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">坐标海拔高度（米）</td>
					<td><% getInfo("locationAElevation"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">水平误差（度）</td>
					<td><% getInfo("locationAHorizontalerror"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">垂直误差（度）</td>
					<td><% getInfo("locationAAltitudeerror"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">位置区域代码</td>
					<td><% getInfo("locationAAreacode"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">坐标测量时间</td>
					<td><% getInfo("locationATimeStamp"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">测量签名</td>
					<td><% getInfo("locationAGISDigest"); %></td>
				</tr>
			</table>
		</div>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>地理位置信息状态B</b></div>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td width=150px  class="hdb">坐标经度值（度）</td>
					<td><% getInfo("locationBLongitude"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">坐标纬度值（度）</td>
					<td><% getInfo("locationBLatitude"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">坐标海拔高度（米）</td>
					<td><% getInfo("locationBElevation"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">水平误差（度）</td>
					<td><% getInfo("locationBHorizontalerror"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">垂直误差（度）</td>
					<td><% getInfo("locationBAltitudeerror"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">位置区域代码</td>
					<td><% getInfo("locationBAreacode"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">坐标测量时间</td>
					<td><% getInfo("locationBTimeStamp"); %></td>
				</tr>
				<tr>
					<td width=150px  class="hdb">测量签名</td>
					<td><% getInfo("locationBGISDigest"); %></td>
				</tr>
			</table>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

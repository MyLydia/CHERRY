<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>中国移动</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv="refresh" content="5">
<meta http-equiv=content-script-type content=text/javascript>
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<SCRIPT language="javascript" type="text/javascript">
var links = new Array();
<% listWanConfig(); %>
/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	if(links.length > 0)
	{
		lstrc1.deleteRow(1);
		lstrc2.deleteRow(1);
		lstrc3.deleteRow(1);
		lstrc4.deleteRow(1);
	}
	
	if(lstrc1.rows){while(lstrc1.rows.length > 2) lstrc1.deleteRow(2);}
	for(var i = 0; i < links.length; i++)
	{
		var row = lstrc1.insertRow(i + 1);
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";
		row.className = "hdt";

		var cell = row.insertCell(0);
		cell.innerHTML = (links[i].servName==""?"-":links[i].servName);
		cell = row.insertCell(1);
		cell.innerHTML = (links[i].strStatus==""?"-":links[i].strStatus);
		cell = row.insertCell(2);
		cell.innerHTML = (links[i].ipAddr==""?"-":links[i].ipAddr);
		cell = row.insertCell(3);
		cell.innerHTML = (links[i].netmask==""?"-":links[i].netmask);
	}
	if(lstrc2.rows){while(lstrc2.rows.length > 2) lstrc2.deleteRow(2);}
	for(var i = 0; i < links.length; i++)
	{
		var row = lstrc2.insertRow(i + 1);
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";
		row.className = "hdt";

		var cell = row.insertCell(0);
		cell.innerHTML = (links[i].servName==""?"-":links[i].servName);
		cell = row.insertCell(1);
		cell.innerHTML = (links[i].cmode==""?"-":links[i].cmode);
		cell = row.insertCell(2);
		if(links[i].protocol=="br1483")
			cell.innerHTML="-";
		else
			cell.innerHTML = (links[i].protocol==""?"-":links[i].protocol);
	}
if(lstrc3.rows){while(lstrc3.rows.length > 2) lstrc3.deleteRow(2);}
	for(var i = 0; i < links.length; i++)
	{
		var row = lstrc3.insertRow(i + 1);
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";
		row.className = "hdt";

		var cell = row.insertCell(0);
		cell.innerHTML = (links[i].servName==""?"-":links[i].servName);
		cell = row.insertCell(1);
		cell.innerHTML = ((links[i].vlanId + "/" + links[i].vprio)=="/"?"-":(links[i].vlanId + "/" + links[i].vprio));
		cell = row.insertCell(2);
		cell.innerHTML = (links[i].MacAddr==""?"-":links[i].MacAddr);
	}

	if(lstrc4.rows){while(lstrc4.rows.length > 2) lstrc4.deleteRow(2);}
	//if(net_info.rows){while(net_info.rows.length > 2) net_info.deleteRow(2);}
	for(var i = 0; i < links.length; i++)
	{
		var row = lstrc4.insertRow(i + 1);
		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";
		row.className = "dbt";
		row.className = "hdt";

		var cell = row.insertCell(0);
		cell.innerHTML = (links[i].servName==""?"-":links[i].servName);
		cell = row.insertCell(1);
		cell.innerHTML = (links[i].gateway==""?"-":links[i].gateway);
		cell = row.insertCell(2);
		cell.innerHTML = (links[i].dns1==""?"-":links[i].dns1);
		cell = row.insertCell(3);
		cell.innerHTML = (links[i].dns2==""?"-":links[i].dns2);
	}

	
/*
	if(net_info.rows){while(net_info.rows.length > 1) net_info.deleteRow(1);}
	for(var i = 0; i < links.length; i++)
	{
		var row = net_info.insertRow(i + 1);

		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = links[i].servName;
		cell = row.insertCell(1);
		cell.innerHTML = links[i].gateway;
		cell = row.insertCell(2);
		cell.innerHTML = links[i].dns1;
		cell = row.insertCell(3);
		cell.innerHTML = links[i].dns2;
	}*/
}

</SCRIPT>

</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
            <br>
	      	<table class="flat" id="lstrc1" border="1" cellpadding="1" cellspacing="1" width="100%">
	          <tbody>
	            <tr align=middle class="hdb">
	              <td width="20%">连接名称</td>
	              <td>连接状态</td>
					<td>IP地址</td>
					<td>子网掩码</td>
				</tr>
	            <tr align=middle class="hdt">
	              <td width="20%">-</td>
	              <td>-</td>
	              <td>-</td>
	              <td>-</td>
	            </tr> 
	          </tbody>
			</table>
			<br>
	        <table class="flat" id="lstrc2" border="1" cellpadding="1" cellspacing="1" width="100%"> 
	          <tbody>
	            <tr align=middle class="hdb">
	              <td width="20%">连接名称</td>
	              <td>连接状态</td>
	              <td>IP获取方式</td>
	            </tr> 
	            <tr align=middle class="hdt">
	              <td width="20%">-</td>
	              <td>-</td>
	              <td>-</td>
	            </tr>
	          </tbody>
	        </table>
	        <br>
	        <table class="flat" id="lstrc3" border="1" cellpadding="1" cellspacing="1" width="100%">
	          <tbody>
	            <tr align=middle class="hdb">
	              <td width="20%">连接名称</td>
	              <td>VLAN/优先级</td>
	              <td>MAC地址</td>
	            </tr>
	            <tr align=middle class="hdt">
	              <td width="20%">-</td>
	              <td>-</td>
	              <td>-</td>
	            </tr>
	          </tbody>
	        </table>
	        <br>
	        <table class="flat" id="lstrc4" border="1" cellpadding="1" cellspacing="1" width="100%">
	          <tbody>
	            <tr align=middle class="hdb">
	              <td width="20%">连接名称</td>
	              <td>默认网关</td>
	              <td>首选DNS</td>
	              <td>备用DNS</td>
				</tr>
	            <tr align=middle class="hdt">
	              <td width="20%">-</td>
	              <td>-</td>
	              <td>-</td>
	              <td>-</td>
	            </tr>
	          </tbody>
			</table>
	                     
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

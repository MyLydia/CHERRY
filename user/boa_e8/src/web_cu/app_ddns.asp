<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>动态DNS</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<script language="javascript" src="jquery-3.2.1.min.js"></script>
<SCRIPT language="javascript" type="text/javascript">

/********************************************************************
**          on document load
********************************************************************/

function btnApply()
{
	if(!sji_checkhostname(form.hostname.value, 1, 32))
	{
		alert("请输入合法的主机名！");
		return false;
	}

	if(!sji_checkusername(form.orayusername.value, 0, 32))
	{
		alert("请输入合法的用户名！");
		return false;
	}
	if(!sji_checkpswnor(form.oraypassword.value, 0, 32))
	{
		alert("请输入合法的密码！");
		return false;
	}

	form.submit();
}

function checkChange(cb)
{
	if(cb.checked==true){
		cb.value = 1;
	}
	else{
		cb.value = 0;
	}
}

function refreshStatus(){
	$.ajax({
		type: 'POST',
		url: '/app_ddns.asp',
		success: function(data) {
			$("#div_ddns_status").html($(data).find("#div_ddns_status").html()); 
		}
	});

}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formDDNS method=POST name="ddns">
				<b></b><br><br><br>
				<table border="0" cellpadding="0" cellspacing="0">
				<tr>
					<td width="180">服务商:</td>
					<td>花生壳</td>
				</tr>
				<tr>
					<td width="180">网路侧接口:</td>
					<td> <select name="ext_if"> <% if_wan_list("rtInternet"); %> </select> </td>
				</tr>
				<tr>
					<td width="180">域名:</td>
					<td><input type="text" name="hostname" style="width:200px " value=<% checkWrite("ddns_hostname"); %>></td>
				</tr>
				<tr>
					<td width="180">用户名:</td>
					<td><input type="text" name="orayusername" size="20" maxlen="64" style="width:200px " value=<% checkWrite("ddns_orayusername"); %>></td>
				</tr>
				<tr>
					<td>密码:</td>
					<td><input type="password" name="oraypassword" style="width:200px " value=<% checkWrite("ddns_oraypassword"); %>></td>
				</tr>
				<tr>
					<td>使能：</td>
					<td><input type="checkbox" name="ddnsEnable" onChange="checkChange(this)" <% checkWrite("ddns_enable"); %>></td>
				</tr>
				</table>
				<br>
				<br>
				<input type="button" class="btnsaveup" value="保存" onClick="btnApply()">
				<input type="hidden" id="action" name="action" value="ad">
				<input type="hidden" value="/app_ddns.asp" name="submit-url">
			</form>
		</div>
	</blockquote>
<script>
	ifIdx = <% checkWrite("ddns_ext_if"); %>;
	if (ifIdx != 65535)
		document.ddns.ext_if.value = ifIdx;
	else
		document.ddns.ext_if.selectedIndex = 0;
	setInterval("refreshStatus()",3000);
</script>
</body>
<%addHttpNoCache();%>
</html>

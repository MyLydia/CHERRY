<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>VLAN 配置</TITLE>
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
<SCRIPT language="javascript" type="text/javascript">

//need get from mib
var vlan_enbale;
var _vlanid4v4;
var _vlanid4v6;

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	//sji_docinit(document, cgi);
	with ( document.forms[0] )
	{
		vlan[0].checked = true;
		if(vlan_enbale)
		{
			vlan[1].checked = true;
			typelst.style.display="block";
		}
		vlanid4v4.value = _vlanid4v4;
		vlanid4v6.value = _vlanid4v6;
	}
}

function on_action(act)
{
	with ( document.forms[0] )
	{
		if(act == "close")
		{
			vlan[0].checked = true;
			typelst.style.display="none";
		}
		else
		{
			vlan[1].checked = true;
			typelst.style.display="block";
		}
	}
	
}

function on_submit()
{
	//vlan id 0~4095
	with ( document.forms[0] )
	{
		if(vlanid4v4.value == "" || vlanid4v6.value == "")
		{
			alert("vlan id不能为空！");
			return;
		}
		if(parseInt(vlanid4v4.value, 10) >4095 ||parseInt(vlanid4v4.value, 10)<0 || parseInt(vlanid4v6.value, 10)>4095 || parseInt(vlanid4v6.value, 10).value<0)
		{
			alert("vlan id的范围是0~4095！");
			return;
		}
	}
	document.vlan_cfg.submit();	
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/formVlanCfg method=POST name="vlan_cfg">
				<b>VLAN 配置</b><br><br>
				这个页面允许你启用或者禁用VLAN功能<br><br>
			
				<hr align="left" class="sep" size="1" width="90%">				
				<table border=0  cellspacing=0 cellpadding=0>
					<tr>
						<td width=120>VLAN:</td>
						<td width=350>
						<input type="radio" name=vlan value=0 onclick="on_action('close')">禁用&nbsp;&nbsp;
						<input type="radio" name=vlan value=1 onclick="on_action('open')">启用</td>
					</tr>
				</table>
				<br>

				<table id="typelst" class="table1_bg_nowidth" border="1" width = "200px" cellpadding="0" cellspacing="0" style="display:none;">
					<tr class="hd" align="center">
						<td width="100px">协议类型</td>
						<td width="100px">VLAN ID</td> 
					</tr>
					<tr class="hd" align="center">
						<td width="100px">0x0800</td>
						<td width="100px">
							<input type="text" id ="vlanid4v4" name="vlanid4v4" maxlength="4" size="4" value="0">
						</td> 
					</tr>
					<tr class="hd" align="center">
						<td width="100px">0x86DD</td>
						<td width="100px">
							<input type="text" id ="vlanid4v6" name="vlanid4v6" maxlength="4" size="4" value="0">
						</td> 
					</tr>
				</table>
				<br>
				
				<input type="button" class="btnsaveup" name="apply" onClick='on_submit()' value="保存/应用"> 
				<input type="hidden" name="submit-url" value="/net_vlan_cfg.asp">	

				<script> 
					<% initPage("vlan4ipv6"); %>
					on_init();
				</script>
			</form>
		</DIV>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

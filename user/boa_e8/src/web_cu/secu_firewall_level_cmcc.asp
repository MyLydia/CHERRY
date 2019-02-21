<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>广域网访问设置</TITLE>
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

/********************************************************************
**          on document load
********************************************************************/
var cgi = new Object();
<%initPageFirewall();%>

function on_init()
{
	sji_docinit(document, cgi);
	ChangeLevel();
}

function refresh()
{
	window.location.reload(true);
}

function ChangeLevel()
{
	var index=document.getElementById("SecLevel").selectedIndex;
	var rioIndex=parseInt(index)+1;
	document.getElementById("fwProtectType"+rioIndex).click();
}

function typeClick(o)
{
	if(o.checked)
	{
		var rioId=o.getAttribute("id").toString();
		var index = rioId.substr(rioId.length-1,1);
		document.getElementById("SecLevel").selectedIndex=parseInt(index)-1;
	}
}

</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form action=/boaform/admin/formFirewall method=POST name="form">
				<!--<b>选择<font color="red">防火墙等级</font>，进行相应的设置.</b><br><br>-->
				<hr align="left" class="sep" size="1" width="90%">
				<table width="538px" border="0" cellspacing="1" cellpadding="3">
					<tr>
						<td height="27">防火墙等级配置:
							<select id="SecLevel" name="filterLevel" onchange="ChangeLevel()">
								<option value="0">低级</option>
								<option value="1">中级</option>
								<option value="2">高级</option>
							</select>
						</td>
					</tr>
					<tr>
						<td><INPUT id=fwProtectType1 type="radio" onclick="typeClick(this)"  name="fwProtectType"  checked>
						Tear Drop、LAND、Flooding without IP、Ping of Death、Source IP Cheating </td>
					</tr>
					<tr>
						<td><INPUT id=fwProtectType2 type="radio" onclick="typeClick(this)"  name="fwProtectType" >
						Port Scan、SYN Flooding、Smurf </td>
					</tr>
					<tr>
						<td><INPUT id=fwProtectType3 type="radio" onclick="typeClick(this)"  name="fwProtectType" >
						Ping attack from WAN、Invalid packets from WAN </td>
					</tr>
				</table>
				<hr align="left" class="sep" size="1" width="90%">
				<input type="submit" class="btnsaveup" value="确 定" name="apply">
				<input type="reset" onclick="refresh()" class="BtnCnl" value="取消">
				<input type="hidden" name="submit-url" value="">
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>中国移动-SAMBA共享</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=utf-8">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">

var nbn = "<% getInfo("samba-netbios-name"); %>";
var ss = "<% getInfo("samba-server-string"); %>";

function changeBlockState(idname, status) {
	var i;
	var tempelems = document.getElementById(idname).getElementsByTagName("*");
	for (i = 0; i < tempelems.length; i++) {
		if (tempelems[i].disabled != undefined)
			tempelems[i].disabled = status;
	}

	// disable the element itself
	var tempelems = document.getElementById(idname);
	if (tempelems.disabled != undefined)
		tempelems.disabled = status;
}

function changeSambaCap()
{
	with (document.formSamba) {
		if (sambaCap[0].checked) {
			/* Disable */
			netBIOSName.value = "";
			serverString.value = "";
			changeBlockState("conf", true);
		} else {
			/* Enable */
			netBIOSName.value = nbn;
			serverString.value = ss;
			changeBlockState("conf", false);
		}
	}
}
</script>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000"  onLoad="changeSambaCap();">
	<blockquote>
	<div align="left" style="padding-left:20px; padding-top:10px">
         <form name="formSamba" action=/boaform/admin/formSamba method="post">
           <b>SAMBA共享<br>
            </b>
            <br>
           SAMBA共享等配置。
           <br>
            <br>
<table border="0" cellpadding="0" cellspacing="0">
				<tr>
					<td width="80">启用SAMBA:</td>
						<td><input type="radio" value="0" name="sambaCap" onClick="changeSambaCap();" <% checkWrite("samba-cap0"); %>>
						禁用
						&nbsp;
						<input type="radio" value="1" name="sambaCap" onClick="changeSambaCap();" <% checkWrite("samba-cap1"); %>>
						启用
					</td>
				</tr>	
<tbody id="conf">
				<tr <% checkWrite("nmbd-cap"); %>>
					<td><b>NetBIOS Name 名称&nbsp;:</b></td>
					<td><input type="text" name="netBIOSName" maxlength="31"></td>
				</tr>
				<tr>
					<td><b>服务器字符串&nbsp;:</b></td>
					<td><input type="text" name="serverString" maxlength="31"></td>
				</tr>
</tbody>
</table>
<br>
<input class="btnsaveup" type='submit' value='保存' name="apply">
<input type="hidden" value="/samba_cmcc.asp" name="submit-url"> 

</form>
</div>
</blockquote>
</body>
</html>

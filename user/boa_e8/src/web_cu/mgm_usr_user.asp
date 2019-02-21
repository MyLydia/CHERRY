<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<html>
<head>
<title>用户管理</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<!--系统公共脚本-->
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">

var cgi = new Object();
<% initPageMgmUser(); %>

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);
	if (cgi.issu)
		lstin.deleteRow(1);
	if(cgi.modify_success)
		document.getElementById("success_prompt").style = "";	
}

/********************************************************************
**          on document submit
********************************************************************/
function checkpasswd(passwd)
{                                                                                                                                                      
	var regNumber = /\d+/;
	var regString = /[a-zA-Z]+/;
	var regSpecialString = /[(\ )(\~)(\!)(\@)(\#) (\$)(\%)(\^)(\&)(\*)(\()(\))(\-)(\_)(\+)(\=) (\[)(\])(\{)(\})(\|)(\\)(\;)(\:)(\')(\")(\,)(\.)(\/)(\`) (\<)(\>)(\?)(\)]+/
		if(regNumber.test(passwd)&&regString.test(passwd)&&regSpecialString.test(passwd))
			return true;
		else
			return false;
}

function on_submit()
{
	with (document.forms[0]) {
		if (!cgi.issu) {
			if (oldPasswd.value.length <= 0) {
				oldPasswd.focus();
				alert("旧密码不能为空，请输入密码!");
				return;
			}
		/*	if (oldPasswd.value.length <= 7) {
				oldPasswd.focus();
				alert("旧密码长度不能小于8，请输入密码!");
				return;
			}
			if (oldPasswd.value.length >= 64) {
				oldPasswd.focus();
				alert("旧密码长度不能大于63，请输入密码!");
				return;
			}
			if (checkpasswd(oldPasswd.value) == false) {
				oldPasswd.focus();
				alert("旧密码错误，请重新输入密码!");
				return;
			}
		*/
		}

		if (newPasswd.value.length <= 0) {
			newPasswd.focus();
			alert("新密码不能为空，请输入新密码!");
			return;
		}
		if (newPasswd.value.length <= 7) {
			newPasswd.focus();
			alert("新密码长度不能小于8，请输入新密码!");
			return;
		}
		if (newPasswd.value.length >= 64) {
			newPasswd.focus();
			alert("新密码长度不能大于63，请输入新密码!");
			return;
		}
		if(checkpasswd(newPasswd.value) == false)
		{
			newPasswd.focus();
			alert("新密码错误，请重新输入新密码，必须同时包括数字，字母以及特殊字符。");
			return;
		}
		if (affirmPasswd.value.length <= 0) {
			affirmPasswd.focus();
			alert("确认密码不能为空，请输入确认密码!");
			return;
		}
		if (newPasswd.value != affirmPasswd.value) {
			affirmPasswd.focus();
			alert("新密码和确认密码不匹配，请重新输入确认密码!");
			return;
		}
		
		submit();

	}
}
</script>
</head>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<div align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action="/boaform/admin/formPasswordSetup" method="post">
					<br>
					<table id="lstin" border="0" cellpadding="0" cellspacing="0" width = "100%">
						<tr>
							<TD width = "30%" height="26">用户名：</TD>
                              <TD ><SELECT >
                              <option id=oldUsername style="WIDTH: 115px"  size=1 name=oldUsername value = "r"><% getInfo("normal-user"); %></option>
                                  
                              </SELECT></TD>
						<tr>
							<td>旧密码:</td>
							<td><input name="oldPasswd" type="password" size="20" maxlength="64" style="width:200px"></td>
						</tr>
						<tr>
							<TD>新密码：</TD>
							<td><input name="newPasswd" type="password" size="15" maxlength="64" style="width:200px"></td>
						</tr>
						<tr>
							<TD>确认新密码：</TD>
							<td><input name="affirmPasswd" type="password" size="15" maxlength="64" style="width:200px"></td>
						</tr>
						<tr id="success_prompt" style="display:none">
							<td style="color:#0000ff;font-weight:bold">密码修改成功</td>
						</tr>
					</table>
				</div>
				<!-- <hr align="left" class="sep" size="1" width="90%"> -->
				
				<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
				<td colspan="2"><P align=center>
				<input type="button" class="btnsaveup1" value="确定" onclick="on_submit();">&nbsp;&nbsp;
				<input type="button" class="btnsaveup2" value="取消" onclick="window.location.reload()">
				<input type="hidden" name="submit-url" value="">

				</P></td>
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

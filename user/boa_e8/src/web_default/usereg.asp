<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<html>
<head>
<title>�й�����-�߼�IDע��</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<style>
body { 
	font-family: "��������";
    background-image: url('/image/loid_register.gif');
    background-repeat: no-repeat;
    background-attachment: fixed;
    background-position: center top; 
}
tr {height: 16px;}
select {width: 150px;}
</style>
<!--ϵͳ�����ű�-->
<script language="javascript" src="/urlEncodeGBK.js"></script>
<script language="javascript" src="/common.js"></script>
<script type="text/javascript" src="/base64_code.js"></script>
<script language="javascript" type="text/javascript">

var over;
var loid;
var password;
var registered;
var provinceType;
var showreset=0;
var showterminal=0;
<% initE8clientUserRegPage(); %>

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	document.getElementById("normaldisplay").style.display = "none";
	document.getElementById("normaldisplay_ah").style.display = "none";
	if(provinceType == 2)
	{
		var normaldisplay = document.getElementById("normaldisplay_ah");
		document.getElementById("toptop").style.paddingTop = "0px";
		document.getElementById("toptop").style.paddingLeft = "0px";
	}
	else
	{
		var normaldisplay = document.getElementById("normaldisplay");
	}
	
	if(registered == 1) {
		normaldisplay.style.display = "none";
		document.getElementById("errordisplay").style.display = "block";
		document.getElementById("over_msg").style.display = "none";
		document.getElementById("registered_msg").style.display = "block";
		document.getElementById("loid_ah").disabled = true;
		document.getElementById("loid1").disabled = true;
		document.getElementById("pValue1").disabled = true;
		document.getElementById("encode1").disabled = true;
	}
	else if (over == 1) {
		normaldisplay.style.display = "none";
		document.getElementById("errordisplay").style.display = "block";
		document.getElementById("over_msg").style.display = "block";
		document.getElementById("registered_msg").style.display = "none";
	} else {
		normaldisplay.style.display = "block";
		document.getElementById("errordisplay").style.display = "none";
		document.getElementById("registered_msg").style.display = "none";
		document.getElementById("loid").value = loid;
		if(provinceType == 2)
		{
			document.getElementById("loid_ah").value = loid;
			document.getElementById("pValue1").value = password;
		}
		else
		{
			document.getElementById("loid1").value = loid;
			document.getElementById("encode1").value = password;
		}
	}

	if (window.top != window.self) {
		// in a frame
		document.getElementById("back").style.display = "none";
		document.getElementById("back_error").style.display = "none";
	} else {
		// the topmost frame
		document.getElementById("back").style.display = "block";
		document.getElementById("back_error").style.display = "block";
	}
	if(showreset)
	{
		//SICHUNAG: control the reset button on the webpage of register(showreset=1:display)
		document.getElementById("resetfactory").style.display = ""; 
	}
	if(showterminal)
	{
		document.getElementById("terminalinspection").style.display = ""; 
	}
}

function reset_loid()
{
	document.getElementById("loid").value = "";
	document.getElementById("loid1").value = "";
	document.getElementById("encode1").value = "";
	document.getElementById("loid_ah").value = "";
	document.getElementById("pValue1").value = "";
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit() 
{
	var loid,password,regbutton;	

	if(document.forms[0].stbTestStart.value == "1")
		return true;
	if(provinceType == 2)
	{
		loid = document.getElementById("loid_ah");
		password = document.getElementById("pValue1");
		regbutton = document.getElementById("regbutton_ah");
	}
	
	else
	{
		loid = document.getElementById("loid1");
		password = document.getElementById("encode1");
		regbutton = document.getElementById("regbutton1");
	}

	if (sji_checkpppacc(loid.value, 1, 24) == false) {
		loid.focus();
		alert("�߼� ID\"" + loid.value + "\"������Ч�ַ��򳤶Ȳ���1-24�ֽ�֮�䣬���������룡");
		return false;
	}

	document.getElementById("loid").value = loid.value;
	document.getElementById("usereg_encode").value = encode64(password.value);
	document.getElementById("loid_ah").disabled = true;
	document.getElementById("loid1").disabled = true;
	document.getElementById("pValue1").disabled = true;
	document.getElementById("encode1").disabled = true;
	regbutton.disabled = true;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	//alert(document.getElementById("usereg_encode").value);
	return true;
}

function on_click_button()
{
	var resetpassword = prompt("����������", "");
	document.forms[0].reset_encode.value =encode64(resetpassword);
	if (document.forms[0].reset_encode.value == "")	
	{		
		alert("��������Ϊ��!");		
		return false;	
	}	
	else	
	{
		document.forms[0].factoryreset.vaule = "factoryreset";
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		return true;	
	}
}
function on_term_insp_button()
{
	document.forms[0].stbTestStart.value = "1";
	document.forms[0].terminalinspection.value = "terminalinspection";
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>

</head>
<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" bgcolor="E0E0E0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init()">
	<div id="toptop" align="center" style="padding-left:5px; padding-top:5px">
		<form id="form" action="/boaform/formUserReg" method="post" onsubmit="return on_submit()">
			<!--<p align="center"><font size="+2"><b>�߼�IDע��</b></font></p><br><br> -->
				<div align="center" id="errordisplay">
				  <table height="200" cellspacing="0" cellpadding="0" align="center" border="0">
						<tr>
							<td>
							<span id="over_msg" style="display: none">����������Դ���������ϵ 10000 ��</span>
							</td>
						</tr>
						<tr>
							<td>
							<span id="registered_msg" style="display: none">��ע��ɹ���������ע��</span>
							</td>
						</tr>
				   </table>
				   <table border="0" cellpadding="1" cellspacing="0">
					<tr>
					<td align="center" id="back_error"><input type="button" value="���ص�¼ҳ��" onClick="location.href='/admin/login.asp';" style="border-style:groove; font-weight:bold "></td>&nbsp;&nbsp;
					</tr>
				   </table>
				</div>
				<div id="normaldisplay_ah" width="100%" height="100%" align="center" valign="middle";>
					<div style="background-image:url(/image/loidreg_ah_01.gif); width:100%; height:544px; float:center">
						<div style="background-image:url(/image/loidreg_ah.gif); width:830px; height:544px; float:center">
							<div style="width:830px; height:155px; float:center">
							</div>
							<div style="width:685px; height:85px; float:center; text-align:right">
							<a href="/admin/login.asp"><font size="2" color="black" style="font-family:SimSun">���ص�¼ҳ��</font></a>
							</div>
							<div style="width:830px; float:center">
							<table style="width:830px;" align="center">
								<tr>
									<td colspan="2" align="center" height="35px"><font size="2" color="black" style="font-family:SimSun">ע���������������߼�ID������</font></td>
								</tr>
								<tr>
									<td align="right" width="45%" height="35px"><font size="2" color="black" style="font-family:SimSun">�߼�ID��</font></td>
									<td ><input type="text" name="loid_ah" id="loid_ah" style="width:150; height:25" /><font size="2" color="#E36032">&nbsp;*</font></td>
								</tr>
								<tr>
									<td  align="right" width="45%" height="35px"><font size="2" color="black" style="font-family:SimSun">���룺</font></td>
									<td ><input type="password" name="pValue1" id="pValue1" autocomplete="off" style="width:150; height:25" /></td>
								</tr>
								<tr>
									<td colspan="2" align="center" height="35px">
									<input type="submit" style="width:70px;" id="regbutton_ah" value="ȷ��"/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
									<input type="button" style="width:70px;" value="����" onClick="reset_loid();">
									</td>
								</tr>
							</table>
							</div>
							<!---
							<div style="width:830px; height:200px; float:center">
							</div>
							--->
						</div>
					</div>
				</div>
				<br><br><br>
				<div align="center" id="normaldisplay">
					<b> <% UserRegMsg(); %>
				  <table cellspacing="0" cellpadding="0" align="center" border="0">
							<tr nowrap><td>�߼� ID��</td><td align="right"><input type="text" id="loid1" name="loid1" maxlength="24" size="24" style="width:150px "></td></tr>
							<tr nowrap><td>���룺</td><td align="right"><input type="text" id="encode1" name="encode1" autocomplete="off" maxlength="24" size="24" style="width:150px "></td></tr>
				  </table>
					<% UserRegMsgPassword(); %>
				  <table border="0" cellpadding="1" cellspacing="0">
					<tr>
					<td align="right"><input type="submit" id="regbutton1" value="ȷ��" style="width:80px; border-style:groove; font-weight:bold "></td>&nbsp;&nbsp;
					<td align="right" id="reset"><input type="button" value="����" onClick="reset_loid();" style="width:80px; border-style:groove; font-weight:bold "></td>&nbsp;&nbsp;
					<td align="right" id="back"><input type="button" value="���ص�¼ҳ��" onClick="location.href='/admin/login.asp';" style="border-style:groove; font-weight:bold "></td>
					<!--SICHUANG -->					
					<td align="right" id="resetfactory" style="display: none"><input type="submit" value="�ָ�����" onClick="return on_click_button();" style="border-style:groove; font-weight:bold "></td>
					<td align="right" id="terminalinspection" style="display: none"><input type="submit" value="�ն��Լ�" onClick="return on_term_insp_button();" style="border-style:groove; font-weight:bold "></td>
					</tr>

				  </table>
				  </b>
				</div>
			<br>
			<input type="hidden" name="loid" id="loid" value=''>
			<!--SICHUANG -->
			<input type="hidden" name="resetpassword"  value="">
			<input type="hidden" name="stbTestStart" value="0">
			<input type="hidden" name="submit-url" value="/useregresult.asp">
			<input type="hidden" name="usereg_encode" id="usereg_encode" value="">
			<input type="hidden" name="reset_encode" id="reset_encode" value="">
			<input type="hidden" name="factoryreset" value="">
			<input type="hidden" name="terminalinspection" value="">
			<input type="hidden" name="postSecurityFlag" value="">
		</form>
	</DIV>

</body>
</html>




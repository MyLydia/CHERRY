<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<html>
<head>
<title>中国移动-逻辑ID注册</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<style type=text/css>
/* Style the tab */
div.tab {
	width:100%;
    display:inline-block;
}

/* Style the buttons inside the tab */
div.tab li {
    padding:9px 15px;
    display:inline-block;
    border-radius:3px 3px 0px 0px;
    background:#2CBCD4; 
	border:none; 
	color:#FFFFFF;
    font-size:11px;
    font-weight:600;
    transition:all linear 0.15s;
}

/* Create an back tablink class */
div.tab li.back {
    background:#FFFFFF;
    color:#2CBCD4;
}

/* Style the tab content */
.tabcontent {
    display: none;
    padding: 6px 12px;
    border: 1px solid #ccc;
    border-top: none;
	color:#FFFFFF;
	background:#2CBCD4;
	position: relative;
	-moz-border-radius-bottomright: 10px;
	-moz-border-radius-bottomleft: 10px;
	-webkit-border-bottom-right-radius: 10px;
	-webkit-border-bottom-left-radius: 10px;
	border-bottom-right-radius: 10px;
	border-bottom-left-radius: 10px;
}

input[type="button"].BtnApply {
	background:#2CBCD4; border:none; color:#FFFFFF;
	height:30px; min-width:90px;
	font-size:11px;
	line-height:11px;
	-webkit-border-radius: 4px;
	-moz-border-radius: 4px;
	border-radius: 4px;
	cursor:pointer;
}

input[type="submit"].BtnApply {
	background:#2CBCD4; border:none; color:#FFFFFF;
	height:30px; min-width:90px;
	font-size:11px;
	line-height:11px;
	-webkit-border-radius: 4px;
	-moz-border-radius: 4px;
	border-radius: 4px;
	cursor:pointer;
}

.tex_inpt input{
	height: 30px;
	width: 350px;
	border-radius: 5px;
	border: solid 1px #e9e9e9;
	outline: none;
	font-size: 15px;
	padding-left: 10px;
}

</style>
<!--系统公共脚本-->
<script language="javascript" type="text/javascript">
var over;
var loid;
var password;
var registered;
var provinceType;
var pageIndex=0;
var loid_allow_empty = <% checkWrite("loid_allow_empty"); %>;
<% initE8clientUserRegPage(); %>

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	document.getElementById("normaldisplay").style.display = "none";
	document.getElementById("normaldisplay1").style.display = "none";
	document.getElementById("passwordTab").style.display = "block";

	var normaldisplay = document.getElementById("normaldisplay");
	var normaldisplay1 = document.getElementById("normaldisplay1");
	var regbutton = document.getElementById("regbutton1");
	
	reset_loid();
	
	if(registered == 1) {
		normaldisplay.style.display = "none";
		normaldisplay1.style.display = "none";
		document.getElementById("errordisplay").style.display = "block";
		document.getElementById("over_msg").style.display = "none";
		document.getElementById("registered_msg").style.display = "block";
		document.getElementById("errordisplay1").style.display = "block";
		document.getElementById("over_msg1").style.display = "none";
		document.getElementById("registered_msg1").style.display = "block";
		regbutton.disabled = true;
	}
	else if (over == 1) {
		normaldisplay.style.display = "none";
		normaldisplay1.style.display = "none";
		document.getElementById("errordisplay").style.display = "block";
		document.getElementById("over_msg").style.display = "block";
		document.getElementById("registered_msg").style.display = "none";
		document.getElementById("errordisplay1").style.display = "block";
		document.getElementById("over_msg1").style.display = "block";
		document.getElementById("registered_msg1").style.display = "none";
	} else {
		normaldisplay.style.display = "block";
		normaldisplay1.style.display = "block";
		document.getElementById("errordisplay").style.display = "none";
		document.getElementById("registered_msg").style.display = "none";
		document.getElementById("errordisplay1").style.display = "none";
		document.getElementById("registered_msg1").style.display = "none";
		
		document.getElementById("loid").value = loid;
		document.getElementById("password").value = password;

		document.getElementById("loid1").value = loid;
		document.getElementById("password1").value = password;
		
		document.getElementById("password2").value = password;
	}
}

function reset_loid()
{
	document.getElementById("loid").value = "";
	document.getElementById("password").value = "";
	document.getElementById("loid1").value = "";
	document.getElementById("password1").value = "";
	document.getElementById("password2").value = "";
}

function sji_checkpppacc(username, smin, smax)
{
	var str = username;
	if(typeof username == "undefined")return false;
	if(typeof smin != "undefined" && username.length < smin)return false;
	if(typeof smax != "undefined" && username.length > smax)return false;

	//var pattern = /^([a-zA-Z0-9%@.,~+=_*&])+$/;
	for (var i=0; i<str.length; i++) {
		if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') || (str.charAt(i) >= 'A' && str.charAt(i) <= 'Z') || (str.charAt(i) >= 'a' && str.charAt(i) <= 'z') ||
		   (str.charAt(i) == '.') || (str.charAt(i) == ':') || (str.charAt(i) == '-') || (str.charAt(i) == '_') || (str.charAt(i) == ' ') || (str.charAt(i) == '/') || (str.charAt(i) == '@') ||
		   (str.charAt(i) == '!') ||(str.charAt(i) == '~') ||(str.charAt(i) == '#') ||(str.charAt(i) == '$') ||(str.charAt(i) == '%') ||(str.charAt(i) == '^') ||(str.charAt(i) == '&') ||
		   (str.charAt(i) == '*') ||(str.charAt(i) == '(') ||(str.charAt(i) == ')') ||(str.charAt(i) == '+') ||(str.charAt(i) == '=') ||(str.charAt(i) == '?') ||(str.charAt(i) == '>') ||
		   (str.charAt(i) == '<') )
			continue;
		return false;
	}
	return true;
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit() 
{
	var loid = document.getElementById("loid1");
	var password = document.getElementById("password1");
	var password2 = document.getElementById("password2");
	var regbutton = document.getElementById("regbutton1");

	if(loid_allow_empty == 1 && loid.value==''){
	}
	else if (sji_checkpppacc(loid.value, 1, 24) == false) {
		loid.focus();
		alert("逻辑 ID\"" + loid.value + "\"存在无效字符或长度不在1-24字节之间，请重新输入！");
		return false;
	}

	if(pageIndex==0){
		document.getElementById("loid").value = "";
		document.getElementById("password").value = password2.value;
	}
	else if(pageIndex==1){
		document.getElementById("loid").value = loid.value;
		document.getElementById("password").value = password.value;
	}
		
	regbutton.disabled = true;

	document.getElementById("form").submit();
	return true;
}

function openTab(evt, tabName) {
    // Declare all variables
    var i, tabcontent, tablinks;

    // Get all elements with class="tabcontent" and hide them
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }

    // Get all elements with class="tablinks" and remove the class "active"
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }

    // Show the current tab, and add an "active" class to the button that opened the tab
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
	if(tabName=="passwordTab"){
		pageIndex = 0;
	}
	else if(tabName=="loidTab"){
		pageIndex = 1;
	}
}
</script>
</head>
<body leftmargin="0" topmargin="0" onLoad="on_init();">
<br><br><br><br>
<form id="form" action=/boaform/formUserReg method=POST>
<table cellspacing="0" width="530" height="550" align="center">
	<tr>
	<td>
		<div class="tab">
		  <% checkWrite("web_loid_page_enable"); %>
		</div>
		<div id="passwordTab" class="tabcontent" align="left">
		  <div id="toptop">
				<!--<p align="center"><font size="+2"><b>逻辑ID注册</b></font></p><br><br> -->
				<div align="center" id="errordisplay1">
					<p id="over_msg1" class="msg_tex" style="display: none;">	
						<br><br><br><br><br>
						<font color="white" size="5" align="left">超过最大重试次数，请联系 10086 号</font>
					</p>
					<p id="registered_msg1" class="msg_tex" style="display: none;">
						<br><br><br><br><br>
						<font color="white" size="5" align="left">已注册成功，无需再注册</font>
					</p>	
				</div>
				<div align="left" id="normaldisplay1">
				<font color="white" size="5" align="left">GPON终端注册</font>
				<br><br>
				<table cellspacing="0" cellpadding="0" align="center" border="0">
					<tr><td align="left"><font color="white" size="2">GPON 上行智能家庭网关业务注册提示：</font></td></tr>
					<tr><td align="left"><font color="white" size="2">1.请插紧“光纤E/G”接口的光纤，检查并确认光信号灯已处于熄灭状态</font></td></tr>
					<tr><td align="left"><font color="white" size="2">2.准确输入“Password”，点击“确定”进行注册</font></td></tr>
					<tr><td align="left"><font color="white" size="2">3.在注册及业务下发过程中（10 分钟内）不要断电、不要拔光纤</font></td></tr>
					<tr><td align="left"><font color="white" size="2">4.本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册</font></td></tr>
				</table>
				<table cellspacing="0" cellpadding="0" align="center" border="0" width="220" height="100">
					<tr><td align="right"><font color="white" size="2">Password：</font></td><td align="right" class="tex_inpt" ><input type="text" id="password2" name="password2" maxlength="24" size="24" style="width:150px; height:30px;" value=""></td></tr>
				</table>
					</b>
				</div>
			<br>
		   </DIV>
		</div>
		<div id="loidTab" class="tabcontent" align="left">
		  <div id="toptop">
					<!--<p align="center"><font size="+2"><b>逻辑ID注册</b></font></p><br><br> -->
				<div align="center" id="errordisplay">
					<p id="over_msg" class="msg_tex" style="display: none;">
						<br><br><br><br><br>
						<font color="white" size="5" align="left">超过最大重试次数，请联系 10086 号</font>
					</p>
					<p id="registered_msg" class="msg_tex" style="display: none;">
						<br><br><br><br><br>
						<font color="white" size="5" align="left">已注册成功，无需再注册</font>
					</p>	
				</div>
				<div align="left" id="normaldisplay">
				<font color="white" size="5">GPON终端注册</font>
				<br><br>
				<table cellspacing="0" cellpadding="0" align="center" border="0">
					<tr><td align="left"><font color="white" size="2">GPON 上行智能家庭网关业务注册提示：</font></td></tr>
					<tr><td align="left"><font color="white" size="2">1.请插紧“光纤E/G”接口的光纤，检查并确认光信号灯已处于熄灭状态</font></td></tr>
					<tr><td align="left"><font color="white" size="2">2.准确输入“逻辑ID”和“密码”，点击“确定”进行注册</font></td></tr>
					<tr><td align="left"><font color="white" size="2">3.在注册及业务下发过程中（10 分钟内）不要断电、不要拔光纤</font></td></tr>
					<tr><td align="left"><font color="white" size="2">4.本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册</font></td></tr>
				</table>
				<table cellspacing="0" cellpadding="0" align="center" border="0" width="220" height="100">
					<tr><td align="right"><font color="white" size="2">逻辑 ID：</font></td><td align="right" class="tex_inpt" ><input type="text" id="loid1" name="loid1" maxlength="24" size="24" style="width:150px; height:30px; " value=""></td></tr>
					<tr><td></td></tr>
					<tr><td align="right"><font color="white" size="2">密码：</font></td><td align="right" class="tex_inpt" ><input type="text" id="password1" name="password1" maxlength="24" size="24" style="width:150px; height:30px;" value=""></td></tr>
				</table>
					</b>
				</div>
			<br>
			</DIV>
		</div>
	</td>
	</tr>
	<tr>
	<td>
		<table cellspacing="0" cellpadding="0" align="center" border="0">
			<tr>
				<td align="right"><input class="BtnApply" type="submit" id="regbutton1" name="regbutton1" value="确定" onClick="on_submit()"></td>
				<td align="left" id="reset">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input class="BtnApply" type="button" value="重置" onClick="reset_loid();"></td>
			</tr>
		</table>
	</td>
	</tr>
	<tr>
	<td>
		<input type="hidden" name="loid" id="loid" value=''>
		<input type="hidden" name="password" id="password" value=''>
		<input type="hidden" name="submit-url" value="/useregresult.asp">
	</td>
	</tr>
</table>
</form>
<script>
// Get the element with id="loidbtn" and click on it
//document.getElementById("loidbtn").click();
</script>
</body>
<%addHttpNoCache();%>
</html>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<html>
<head>
<title>�й���ͨ-�߼�IDע��</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<style>
.loid{
    background: url(../image/loid.png) no-repeat;
    border: 0 none !important;
    width: 324px;
    color: #898989;
    height: 50px !important;
    padding-left: 50px;
	margin-bottom: 10px;
	-webkit-box-shadow:0 0 0 50px transparent inset;
}
.loid_reg{
	width: 330px;
    margin: 0 auto;
    display: inline-block;
}
.btns{
    background: #4b4a4a;
    border-radio: 5px;
    border-radius: 10px;
    padding: 4px 20px;
    border: 0 none;
    color: #898989;
    margin-top: 15px;
	cursor:pointer;
}
.loidpas{
	height: 53px !important;
    background: url(../image/pass_input.png) no-repeat;
    border: 0 none !important;
    padding-left: 50px;
	color:#898989;
	font-size:14px;
	width:250px;
	-webkit-box-shadow:0 0 0 50px transparent inset;
}
.loid_remind{
    text-align: left;
    padding-top: 500px;
    padding-left: 20px;
    width: 1300px;
}
.loid_remind p{
    color: #c0c0c0;
	font-size: 14px;
}
#errordisplay{
    margin: 0 auto;
    width: 500px;
    text-align: center;
    padding-top: 230px;
}
#back_error{
	position: absolute;
    top: 0;
    right: 20px;
}
#back_error input{
	background: 0 none;
    border: 0;
    font-size: 20px;
	color:#c0c0c0;
}
.login_admin{
	position: absolute;
    top: 0;
    left: 475px;
}
.msg_tex{
    background: url(../image/error_icon.png) no-repeat;
    width: 510px;
    height: 101px;
    padding-left: 130px;
    padding-top: 33px;
    font-size: 19px;
    margin: 0 auto;
    position: absolute;
    left: 400px;
    top: 280px;
    text-align: left;
}
#back_error input {
    background: 0 none;
    border: 0;
    font-size: 20px;
    color: #c0c0c0;
}
</style>

<!--ϵͳ�����ű�-->
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
/*	document.getElementById("normaldisplay").style.display = "none";
	document.getElementById("normaldisplay1").style.display = "none";
	document.getElementById("loidTab").style.display = "block";

	var normaldisplay = document.getElementById("normaldisplay");
	var normaldisplay1 = document.getElementById("normaldisplay1");
	var regbutton = document.getElementById("regbutton1");
*/	

	
	if(registered == 1) {
		normaldisplay.style.display = "none";
		//normaldisplay1.style.display = "none";
		document.getElementById("errordisplay").style.display = "block";
		document.getElementById("over_msg").style.display = "none";
		document.getElementById("registered_msg").style.display = "block";
		//document.getElementById("errordisplay1").style.display = "block";
		//document.getElementById("over_msg1").style.display = "none";
		//document.getElementById("registered_msg1").style.display = "block";
		regbutton.disabled = true;
	}
	else if (over == 1) {
		normaldisplay.style.display = "none";
		//normaldisplay1.style.display = "none";
		document.getElementById("errordisplay").style.display = "block";
		document.getElementById("over_msg").style.display = "block";
		document.getElementById("registered_msg").style.display = "none";
		//document.getElementById("errordisplay1").style.display = "block";
		//document.getElementById("over_msg1").style.display = "block";
		//document.getElementById("registered_msg1").style.display = "none";
	} else {
		normaldisplay.style.display = "block";
		//normaldisplay1.style.display = "block";
		document.getElementById("errordisplay").style.display = "none";
		document.getElementById("registered_msg").style.display = "none";
		//document.getElementById("errordisplay1").style.display = "none";
		//document.getElementById("registered_msg1").style.display = "none";
		
		document.getElementById("loid").value = loid;
		document.getElementById("password").value = password;

		document.getElementById("loid1").value = loid;
		document.getElementById("password1").value = password;
		
		//document.getElementById("password2").value = password;
	}
}
/*
function reset_loid()
{
	document.getElementById("loid").value = "";
	document.getElementById("password").value = "";
	document.getElementById("loid1").value = "";
	document.getElementById("password1").value = "";
	document.getElementById("password2").value = "";
}
*/
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
	//var password2 = document.getElementById("password2");
	var regbutton = document.getElementById("regbutton1");

	if(loid_allow_empty == 1 && loid.value==''){
	}
	else if (sji_checkpppacc(loid.value, 1, 24) == false) {
		loid.focus();
		alert("�߼� ID\"" + loid.value + "\"������Ч�ַ��򳤶Ȳ���1-24�ֽ�֮�䣬���������룡");
		return false;
	}

	if(pageIndex==0){
		document.getElementById("loid").value = loid.value;
		document.getElementById("password").value = password.value;
	}
	/*
	else if(pageIndex==1){
		document.getElementById("loid").value = "";
		document.getElementById("password").value = password2.value;
	}*/
		
	regbutton.disabled = true;

	document.getElementById("form").submit();
	return true;
}
/*
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
	if(tabName=="loidTab"){
		pageIndex = 0;
	}
	else if(tabName=="passwordTab"){
		pageIndex = 1;
	}
}*/
</script>
</head>
<body leftmargin="0" topmargin="0" onLoad="on_init();">
<form id="form" action=/boaform/formUserReg method=POST>
	<div class="Unicom_bg">
		<p class="site">����Ӫҵ�� www.10010.com  &nbsp;&nbsp; �ͷ�����10010  &nbsp;&nbsp; ��ֵר��10011</p>
		<div class="backlogin"><a id="login_font" href="admin/login.asp">���ص�¼ҳ��</a></div>	
		
		
				<div align="center" id="errordisplay">
					<p id="over_msg" class="msg_tex" style="display: none;">
					
						����������Դ���������ϵ 10086 ��
					</p>
					<p id="registered_msg" class="msg_tex" style="display: none;">
						
						��ע��ɹ���������ע��
					</p>
						
				</div>
<!--
				<div align="left" id="normaldisplay">
				<font color="white" size="5">GPON�ն�ע��</font>
				<br><br>
				<table cellspacing="0" cellpadding="0" align="center" border="0">
					<tr><td align="left"><font color="white" size="2">GPON �������ܼ�ͥ����ҵ��ע����ʾ��</font></td></tr>
					<tr><td align="left"><font color="white" size="2">1.����������E/G���ӿڵĹ��ˣ���鲢ȷ�Ϲ��źŵ��Ѵ���Ϩ��״̬</font></td></tr>
					<tr><td align="left"><font color="white" size="2">2.׼ȷ���롰�߼�ID���͡����롱�������ȷ��������ע��</font></td></tr>
					<tr><td align="left"><font color="white" size="2">3.��ע�ἰҵ���·������У�10 �����ڣ���Ҫ�ϵ硢��Ҫ�ι���</font></td></tr>
					<tr><td align="left"><font color="white" size="2">4.��ע�Ṧ�ܽ��������豸����֤��ҵ���·��������������豸��������ע��</font></td></tr>
				</table>
				<table cellspacing="0" cellpadding="0" align="center" border="0" width="220" height="100">
					<tr><td align="right"><font color="white" size="2">�߼� ID��</font></td><td align="right" class="tex_inpt" ><input type="text" id="loid1" name="loid1" maxlength="24" size="24" style="width:150px; height:30px; " value=""></td></tr>
					<tr><td></td></tr>
					<tr><td align="right"><font color="white" size="2">���룺</font></td><td align="right" class="tex_inpt" ><input type="text" id="password1" name="password1" maxlength="24" size="24" style="width:150px; height:30px;" value=""></td></tr>
				</table>
					</b>
</div>
-->	
<div id="normaldisplay">				
	<div class="login_admin">
		<a style="padding-right:0;" class="others" href="#"></a>
		<p>�߼�IDע��</p>
		<div class="loid_reg">
			<input class="loid" value="�߼�ID" onfocus="this.value=''" onblur="if(this.value==''){this.value='�߼�ID'}"  size="10" type="text" name="loid1" id="loid1" maxlength="27">
			<input class="loidpas" value="��֤��" type="text" name="password1" id="password1" maxlength="27" onfocus="this.value=''" onblur="if(this.value==''){this.value='��֤��'}">
			<input class="paswd_go" type="submit" id="regbutton" name="regbutton" onClick="on_submit()" value=" "/>	
			<input class="btns" type="reset" value="����" name="reset" >							
		</div>												
	</div>
	<div class="loid_remind">
		<p>��ͥ�����ն��߼�IDע����ʾ��</p>
		<p>1.�������ˣ���鲢ȷ�Ϲ��źŵ��Ѵ���Ϩ��״̬<p>
		<p>2.׼ȷ���롰�߼�ID��H�͡����롱�����ȷ������ע��<p>
		<p>3.��ע��ҵ���·������У�10�����ڣ���Ҫ�ϵ磬��Ҫ�ε������ߡ�<p>
		<p>4.��ע�Ṧ�ܽ��������豸����֤��ҵ���·��������������豸��������ע�ᡣ<p>
	</div>
</div>		

		
		
		
<!--
		
		<div id="passwordTab" align="left">
		 
				<p align="center"><font size="+2"><b>�߼�IDע��</b></font></p><br><br> 
				<div align="center" id="errordisplay1">
					<p id="over_msg1" class="msg_tex" style="display: none;">	
						
						<font>����������Դ���������ϵ 10086 ��</font>
					</p>
					<p id="registered_msg1" class="msg_tex" style="display: none;">
					
						<font>��ע��ɹ���������ע��</font>
					</p>	
				</div>
				
				<div align="left" id="normaldisplay1">

				<table cellspacing="0" cellpadding="0" align="center" border="0" width="220" height="100">
					<tr><td align="right"><font color="white" size="2">Password��</font></td><td align="right" class="tex_inpt" ><input type="text" id="password2" name="password2" maxlength="24" size="24" style="width:150px; height:30px;" value=""></td></tr>
				</table>
					</b>
				</div>
		-->
		 
		</div>
		
		



	<div>
		<input type="hidden" name="loid" id="loid" value=''>
		<input type="hidden" name="password" id="password" value=''>
		<input type="hidden" name="submit-url" value="/useregresult.asp">
	</div>

</div>
</form>
<script>
// Get the element with id="loidbtn" and click on it
//document.getElementById("loidbtn").click();
</script>
</body>
<%addHttpNoCache();%>
</html>
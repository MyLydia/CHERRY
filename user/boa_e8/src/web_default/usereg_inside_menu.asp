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
tr {height: 16px;}
</style>
<!--ϵͳ�����ű�-->
<script language="javascript" src="/common.js"></script>
<script type="text/javascript" src="/base64_code.js"></script>
<script language="javascript" type="text/javascript">

var over;
var loid;
var password;
var registered = 0;
var btn_disabled = 0;
<% initE8clientUserRegPage(); %>

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	if (over == 1) {
		document.getElementById("normaldisplay").style.display = "none";
		document.getElementById("errordisplay").style.display = "block";
		document.getElementById("over_msg").style.display = "block";
	} else {
		document.getElementById("normaldisplay").style.display = "block";
		document.getElementById("errordisplay").style.display = "none";
		document.getElementById("loid").value = loid;
		document.getElementById("password").value = password;
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

	if(btn_disabled)
	{
		document.getElementById("loid").disabled = true;
		document.getElementById("password").disabled = true;
		document.getElementById("regbutton").disabled = true;
		document.getElementById("reset_btn").disabled = true;
}
}

function reset_loid()
{
	document.getElementById("loid").value = loid;
	document.getElementById("password").value = password;
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit() 
{
	var loid = document.getElementById("loid");
	var pwd = document.getElementById("password");
	var encode = document.getElementById("usereg_encode");
	var reg_button = document.getElementById("regbutton");

	if (sji_checkpppacc(loid.value, 1, 24) == false) {
		loid.focus();
		alert("�߼� ID\"" + loid.value + "\"������Ч�ַ��򳤶Ȳ���1-24�ֽ�֮�䣬���������룡");
		return false;
	}

	reg_button.disabled = true;
	encode.value = encode64(pwd.value);
	pwd.disabled = true;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>

</head>
<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->

   

<body topmargin="0" bgcolor="E0E0E0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init()">
				  
	  <div align="left" style="padding-left:20px; padding-top:10px">
		<form id="form" action="/boaform/formUserReg_inside_menu" method="post" onsubmit="return on_submit()">
			<!--<p align="center"><font size="+2"><b>�߼�IDע��</b></font></p><br><br> -->
				<div id="errordisplay">
				  <table height="200" cellspacing="0" cellpadding="0" border="0">
						<tr>
							<td>
							<span id="over_msg" style="display: none">����������Դ���������ϵ 10000 ��</span>
							</td>
						</tr>
				   </table>
				   <table border="0" cellpadding="1" cellspacing="0">
					<tr>
					<td  id="back_error"><input type="button" value="���ص�¼ҳ��" onClick="location.href='/admin/login.asp';" style="width:80px; border-style:groove; font-weight:bold "></td>&nbsp;&nbsp;
					</tr>
				   </table>
				</div>
			
				<div  id="normaldisplay">
				<label align="left">�߼�ID���� <br>	
				  <b> �߼�ID�����������豸��ע�ἰ�·����벻Ҫ���ģ�����޸��߼�ID����ҵ�����������������ء�<br>
				  </label>	

					<% UserInsideRegPage(); %>
				  </b>
				</div>
			<br>
			
			<input type="hidden" name="submit-url" value="/useregresult.asp">
			<input type="hidden" name="usereg_encode" id="usereg_encode" value="">
			<input type="hidden" name="postSecurityFlag" value="">		
		</form>
	</DIV>

</body>
</html>




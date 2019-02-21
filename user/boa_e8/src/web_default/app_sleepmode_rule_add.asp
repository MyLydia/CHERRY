<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>定时网关休眠</TITLE>
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
var cgi = new Object();

function setValue(id,value)
{
	document.getElementById(id).value=value;
}
function btnApply()
{
	var week = 0;

	if(document.getElementById("right").checked)
	{
		week = 1;
	}
	else
	{
		if(document.getElementById("mon").checked)
			week += 0x2;
		if(document.getElementById("tue").checked)
			week += 0x4;
		if(document.getElementById("wen").checked)
			week += 0x8;
		if(document.getElementById("thr").checked)
			week += 0x10;
		if(document.getElementById("fri").checked)
			week += 0x20;
		if(document.getElementById("sat").checked)
			week += 0x40;
		if(document.getElementById("sun").checked)
			week += 0x80;
	}
	setValue("day", week);
	document.form.action.value="add";
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	form.submit();
}

function on_init()
{
	var i=0;
	for(i=0; i<24; i++)
		document.form.hour.options.add(new Option(i, i));

	for(i=0; i<60; i++)
		document.form.minute.options.add(new Option(i, i));
}

/*
function timeDisplay()
{
	var selc = document.getElementById("day");
	var index = selc.selectedIndex;

	if( selc.options[index].value==0 )
	{
		document.getElementById("hour").disabled=true;
		document.getElementById("minute").disabled=true;
	}
	else
	{
		document.getElementById("hour").disabled=false;
		document.getElementById("minute").disabled=false;
	}
}
*/
function checkboxOnclick(checkbox)
{
	if ( checkbox.checked == true)
	{
		document.getElementById("mon").checked=false;
		document.getElementById("mon").disabled=true;
		document.getElementById("tue").checked=false;
		document.getElementById("tue").disabled=true;
		document.getElementById("wen").checked=false;
		document.getElementById("wen").disabled=true;
		document.getElementById("thr").checked=false;
		document.getElementById("thr").disabled=true;
		document.getElementById("fri").checked=false;
		document.getElementById("fri").disabled=true;
		document.getElementById("sat").checked=false;
		document.getElementById("sat").disabled=true;
		document.getElementById("sun").checked=false;
		document.getElementById("sun").disabled=true;
		document.getElementById("hour").disabled=true;
		document.getElementById("minute").disabled=true;
	}
	else
	{
		document.getElementById("mon").disabled=false;
		document.getElementById("tue").disabled=false;
		document.getElementById("wen").disabled=false;
		document.getElementById("thr").disabled=false;
		document.getElementById("fri").disabled=false;
		document.getElementById("sat").disabled=false;
		document.getElementById("sun").disabled=false;
		document.getElementById("hour").disabled=false;
		document.getElementById("minute").disabled=false;
	}
}


</SCRIPT>
</HEAD>


<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init()">
  <blockquote>
	<DIV align="left" style="padding-left:20px; padding-top:5px">
		<form id="form" action=/boaform/admin/formSleepMode method=POST name="form">
			<b>添加家庭网关定时休眠规则-- 最多允许您添加 100条规则.</b><br><br><br>
			<hr align="left" class="sep" size="1" width="90%">
				<tr>
					<td width="120">设置休眠周期:&nbsp;</td>
					<td>
						<input type="checkbox" id="right" name="right" value="0" onclick="checkboxOnclick(this)"/>立即休眠/唤醒
						<input type="checkbox" id="mon" name="mon" value="1" />星期一
						<input type="checkbox" id="tue" name="tue" value="2" />星期二
						<input type="checkbox" id="wen" name="wen" value="3" />星期三
						<input type="checkbox" id="thr" name="thr" value="4" />星期四
						<input type="checkbox" id="fri" name="fri" value="5" />星期五
						<input type="checkbox" id="sat" name="sat" value="6" />星期六
						<input type="checkbox" id="sun" name="sun" value="7" />星期日
					</td>
					<td>&nbsp;</td>
				</tr>
				<br><br>
				<tr>
					<td width="120">设置休眠时间:&nbsp;</td>
					<td>
						<select id="hour" name="hour">
						</select>
					</td>

					<td>时&nbsp;</td>

					<td>
						<select id="minute" name="minute">
						</select>
					</td>

					<td>分&nbsp;</td>
				</tr>
				<br><br>
				<tr>
					<td width="120">使能/禁止:&nbsp;</td>
					<td><input type="radio" name="timerEnable" value="off" checked>&nbsp;&nbsp;禁止</td>
					<td><input type="radio" name="timerEnable" value="on" >&nbsp;&nbsp;使能</td>
				</tr>
				<br><br>
				<tr>
					<td width="120">动作:&nbsp;</td>
					<td><input type="radio" name="onoffEnable" value="off" checked>&nbsp;&nbsp;唤醒</td>
					<td><input type="radio" name="onoffEnable" value="on" >&nbsp;&nbsp;休眠</td>
				</tr>
			<br><br>
			<hr align="left" class="sep" size="1" width="90%">
			<input type="button" class="button" value="保存/应用" onClick="btnApply()">
			<input type="hidden" name="action" value="add">
			<input type="hidden" name="submit-url" value="/app_sleepmode_rule.asp">
			<input type="hidden" name="day" id="day" value="">
			<input type="hidden" name="postSecurityFlag" value="">
			<script>
				//timeDisplay();
			</script>
		</form>
	</div>
  </blockquote>
</body>
<%addHttpNoCache();%></html>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>��ʱ��������</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--ϵͳ�����ű�-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">

var cgi = new Object();
var rules = new Array();
var act_idx = -1;
with(rules){<% initPageSleepModeRule(); %>}

var day_display = new Array("��������/����","����һ","���ڶ�","������","������","������","������","������");

function on_chkclick(index)
{
	if(index < 0 || index >= rules.length)
		return;
	act_idx=index;
	//alert(act_idx);
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);

	if(cgi.bandcontrolEnable == false)
	{
		document.getElementById("table_list").style.display="none";
		document.getElementById("act_btn").style.display="none";
	}
	
	document.getElementById("input_div").style.display="none";

	if(rulelst.rows)
	{
		while(rulelst.rows.length > 1)
			rulelst.deleteRow(1);
	}

	for(var i = 0; i < rules.length; i++)
	{
		var row = rulelst.insertRow(i + 1);
		var str = "";

		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";

		var cell = row.insertCell(0);

		if((rules[i].day&0x1)!=0)
		{
			str += day_display[0];
		}
		else
		{
			for(var j = 0; j <= 7; j++)
			{
				if((rules[i].day&(0x1<<j))!=0)
					str += day_display[j];
			}
		}
		cell.innerHTML = str;

		cell = row.insertCell(1);
		
		if((rules[i].day&0x1)!=0)
			cell.innerHTML = "--";
		else
			cell.innerHTML = rules[i].hour + ":" + rules[i].minute;
		
		cell = row.insertCell(2);
		if(rules[i].enable==1)
			cell.innerHTML = "ʹ��";
		else
			cell.innerHTML = "��ֹ";

		cell = row.insertCell(3);
		if(rules[i].onoff==1)
			cell.innerHTML = "����";
		else
			cell.innerHTML = "����";
		
		cell = row.insertCell(4);
		cell.innerHTML = "<input type=\"radio\" name=\"act_select\" onClick=\"on_chkclick(" + i + ");\">";
	}
}

function addClick()
{
   var loc = "app_sleepmode_rule_add.asp";
   var code = "window.location.href=\"" + loc + "\"";
   eval(code);
}

function setValue(id,value)
{
	document.getElementById(id).value=value;
}

function modifyClick()
{
	if(act_idx == -1)
	{
		alert("����ѡ��Ҫ�޸ĵĹ���!");
		return false;
	}
	document.getElementById("input_div").style.display="";

	var i=0;
	for(i=0; i<24; i++)
		document.form.hour.options.add(new Option(i, i));

	for(i=0; i<60; i++)
		document.form.minute.options.add(new Option(i, i));
	
	//document.getElementById("day").value=rules[act_idx].day;
	if((rules[act_idx].day&0x1)!=0)
	{
		document.getElementById("right").checked=true;
		
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
		if((rules[act_idx].day&0x2)!=0)
			document.getElementById("mon").checked=true;
		if((rules[act_idx].day&0x4)!=0)
			document.getElementById("tue").checked=true;
		if((rules[act_idx].day&0x8)!=0)
			document.getElementById("wen").checked=true;
		if((rules[act_idx].day&0x10)!=0)
			document.getElementById("thr").checked=true;
		if((rules[act_idx].day&0x20)!=0)
			document.getElementById("fri").checked=true;
		if((rules[act_idx].day&0x40)!=0)
			document.getElementById("sat").checked=true;
		if((rules[act_idx].day&0x80)!=0)
			document.getElementById("sun").checked=true;
	}
	document.getElementById("hour").value=rules[act_idx].hour;
	document.getElementById("minute").value=rules[act_idx].minute;

	if(rules[act_idx].enable==1){
		document.form.timerEnable[1].checked = true;
	}else{
		document.form.timerEnable[0].checked = true;
	}

	if(rules[act_idx].onoff==1){
		document.form.onoffEnable[1].checked = true;
	}else{
		document.form.onoffEnable[0].checked = true;
	}

	//timeDisplay()
	return true;
}

function ModifyApply()
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
	setValue("idx", act_idx);
	setValue("action", "modify");
	return true;
}

function back2add()
{
	/*mean user cancel modify, refresh web page again!*/
	document.getElementById("input_div").style.display="none";
	
	setValue("idx",-1);
	getObj("form").submit();
}

function on_action(act)
{
	form.action.value = act;

	if(act == "rm")
	{
		//alert(act_idx);
		if(act_idx == -1)
		{
			alert("����ѡ��Ҫɾ���Ĺ���!");
			return false;
		}
		setValue("idx",act_idx);
		setValue("action", "del");
	}

	with(form)
	{
		submit();
	}
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
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formSleepMode method=POST name="form">
				<b>���ü�ͥ���ض�ʱ���߹���-- �������֧�� 100������.</b><br><br>
				<div id="table_list">
				<hr align="left" class="sep" size="1" width="90%">
				<div align="left" style="padding-left:20px;"><br>
					<table id="rulelst" class="flat" border="1" cellpadding="2" cellspacing="0">
						<tr align="center" class="hd">
							<td width="120px">�ظ�����</td>
							<td width="120px">ʱ��</td>
							<td width="120px">����/��ֹ</td>
							<td width="120px">����</td>
							<td>ѡ��</td>
						</tr>
					</table>
				</div>
				</div>
				<br>
				<div id="input_div">
					<hr align="left" class="sep" size="1" width="90%">
					<tr>
						<td width="120">������������:&nbsp;</td>
						<td>
						<!--
							<select id="day" name="day" onchange="timeDisplay()">
  								<option value=0>��������/����</option>
 								<option value=1>����һ</option>
								<option value=2>���ڶ�</option>
								<option value=3>������</option>
								<option value=4>������</option>
								<option value=5>������</option>
								<option value=6>������</option>
								<option value=7>������</option>
							</select>
							-->
							<input type="checkbox" id="right" name="right" value="0" onclick="checkboxOnclick(this)"/>��������/����
							<input type="checkbox" id="mon" name="mon" value="1" />����һ
							<input type="checkbox" id="tue" name="tue" value="2" />���ڶ�
							<input type="checkbox" id="wen" name="wen" value="3" />������
							<input type="checkbox" id="thr" name="thr" value="4" />������
							<input type="checkbox" id="fri" name="fri" value="5" />������
							<input type="checkbox" id="sat" name="sat" value="6" />������
							<input type="checkbox" id="sun" name="sun" value="7" />������
						</td>
						<td>&nbsp;</td>
					</tr>
					<br><br>
					<tr>
						<td width="120">��������ʱ��:&nbsp;</td>
						<td>
							<select id="hour" name="hour">
							</select>
						</td>

						<td>ʱ&nbsp;</td>

						<td>
							<select id="minute" name="minute">
							</select>
						</td>

						<td>��&nbsp;</td>
					</tr>
					<br><br>
					<tr>
						<td width="120">ʹ��/��ֹ:&nbsp;</td>
						<td><input type="radio" name="timerEnable" value="off" >&nbsp;&nbsp;��ֹ</td>
						<td><input type="radio" name="timerEnable" value="on" >&nbsp;&nbsp;����</td>
					</tr>
					<br><br>
					<tr>
						<td width="120">����:&nbsp;</td>
						<td><input type="radio" name="onoffEnable" value="off" >&nbsp;&nbsp;����</td>
						<td><input type="radio" name="onoffEnable" value="on" >&nbsp;&nbsp;����</td>
					</tr>
					
					<br><br>
					<tr>
						<td  class="td2">
							<input type="submit" class="btnsaveup" value="����" id="modify" onclick="return ModifyApply();" />
							<input name="back" type="button" id="back" value="ȡ ��"  class="btndeleup" onclick="back2add()"/>
						</td>
					</tr>
				</div>
				<br>
				<div id="act_btn">
				<hr align="left" class="sep" size="1" width="90%">
				<input type="button" class="btnaddup" name="add" onClick="addClick()" value="���">
				<input type="button" class="btnsaveup" name="modify" onClick="return modifyClick();" value="�޸�">
				<input type="button" class="btndeleup" name="remove" onClick="on_action('rm')" value="ɾ��">
				</div>
				<input type="hidden" id="action" name="action" value="none">
				<input type="hidden" name="idx" id="idx" value="">
				<input type="hidden" name="day" id="day" value="">
				<input type="hidden" name="submit-url" value="/app_sleepmode_rule.asp" >
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

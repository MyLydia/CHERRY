<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>��������������</TITLE>
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
with(rules){<% rteMacFilterList(); %>}

function on_chkclick(index)
{
	if(index < 0 || index >= rules.length)
		return;
	rules[index].select = !rules[index].select;
}
/********************************************************************
**          on document load
********************************************************************/
function refresh_rulelst()
{
	if(rulelst.rows)
	{
		while(rulelst.rows.length > 1)
			rulelst.deleteRow(1);
	}

	var list_i = 0;
	for(var i = 0; i < rules.length; i++)
	{
		//alert("i=\""+i);alert("mode=\""+rules[i].mode);
		//if (cur_filtermode == rules[i].mode)
		{
			
			var row = rulelst.insertRow(list_i + 1);

			row.nowrap = true;
			row.vAlign = "top";
			row.align = "center";

			var cell; // = row.insertCell(0);
			//cell.innerHTML = rules[i].devname;
			cell = row.insertCell(0);
			cell.innerHTML = rules[i].name;
			cell = row.insertCell(1);
			cell.innerHTML = rules[i].mac;
			cell = row.insertCell(2);
			cell.innerHTML = "����";
			cell = row.insertCell(3);
			cell.innerHTML = "<input type=\"checkbox\" onClick=\"on_chkclick(" + i + ");\">";
			list_i++;
		}
	}
}

function on_init()
{
	sji_docinit(document, cgi);
	
	if(cgi.macFilterEnble == false)
	{
		form.add.disabled = true;
		form.remove.disabled = true;
		document.getElementById("FilterInfo").style.display="none";
		form.macFilterMode[0].disabled = true;
		form.macFilterMode[1].disabled = true;
	}

	refresh_rulelst();
		
	if(rules.length == 0)
	{
		form.remove.disabled = true;
	}
}

function addClick()
{
   var loc = "secu_macfilter_src_add.asp";
   var code = "window.location.href=\"" + loc + "\"";
   eval(code);
}

function removeClick()
{
	with ( document.forms[0] )
	{
		form.bcdata.value = sji_encode(rules, "select");
		submit();
	}
}

function btnApply()
{
	form.action.value = 'sw';
	//alert(form.action.value);
	form.submit();
}

function on_action(act)
{
	form.action.value = act;
	var cur_filterEnble = 0;
	var cur_filtermode = 0;
    cur_filterEnble =  (form.macFilterEnble.checked == true) ? 1:0;
	cur_filtermode = (form.macFilterMode.value == "on") ? 1:0;//form.macFilterMode.value ;
	//alert(cur_filterEnble);
	if(cur_filterEnble == 0)
	{
		if(!confirm("�Ƿ����MAC���ˣ�"))
		{
			form.macFilterEnble.checked = true;
			return;
		}
		/*form.add.disabled = true;
		form.remove.disabled = true;
		document.getElementById("macfilter_list").style.display="none";
		form.macFilterMode[0].disabled = true;
		form.macFilterMode[1].disabled = true;*/
	}else{
		if(!confirm("�Ƿ�����MAC���ˣ�"))
		{
			form.macFilterEnble.checked = false;
			return;
		}

		/*form.add.disabled = false;
		form.remove.disabled = false;
		document.getElementById("macfilter_list").style.display="block";
		form.macFilterMode[0].disabled = false;
		form.macFilterMode[1].disabled = false;*/
		
		//refresh_rulelst();
	}
	with(form)
	{
		submit();
	}
}

function change_mode(act)
{
	form.action.value = act;
	var cur_filtermode = 0;
	cur_filtermode = (form.macFilterMode.value == "on") ? 1:0;//form.macFilterMode.value ;
	//alert(cur_filterEnble);
	if(cur_filtermode == 0)
	{
		if(!confirm("�ı����ģʽ���л����й��˹������Ƿ����Ҫ�ı����ģʽΪ��������"))
		{
			form.macFilterMode[0].checked = false;
			form.macFilterMode[1].checked = true;
			return;
		}
	}else{
		if(!confirm("�ı����ģʽ���л����й��˹������Ƿ����Ҫ�ı����ģʽΪ��������"))
		{
			form.macFilterMode[0].checked = true;
			form.macFilterMode[1].checked = false;
			return;
		}

		/*form.add.disabled = false;
		form.remove.disabled = false;
		document.getElementById("macfilter_list").style.display="block";
		form.macFilterMode[0].disabled = false;
		form.macFilterMode[1].disabled = false;*/
		
		//refresh_rulelst();
	}
	with(form)
	{
		submit();
	}
}



function RefreshPage()
{
	location.href = document.location.href;
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
	<form id="form" action=/boaform/admin/formRteMacFilter method=POST name="form">
	<table>
      <tbody>
        <tr>
          <td>MAC���˿���:
            <input id="macFilterEnble" onclick="on_action('sw')" type="checkbox" value="on" name="macFilterEnble"></td>
        </tr>
      </tbody>
    </table>
    <div id="FilterInfo" style="visibility: visible;"> 
		<table border="0" cellpadding="0" cellspacing="0" width="100%">
 		<tbody>
 			<tr>
	  			<td>�ڰ�����ģʽ��
	  			<input id="FilterMode" onclick="change_mode('sw')" type="radio" value="off" name="macFilterMode">
	  			������
	  			<input id="FilterMode" onclick="change_mode('sw')" type="radio" value="on" name="macFilterMode">
	  			������ 
	  			<br>
	  			<br>
	  			</td>
			</tr>
		</tbody>
		</table>
		<div id="macfilter_list" align="left">
		<table id="rulelst" width="100%" border="1" class="tblList">
			<tbody>
				<tr>
					<td class="table_title" align="middle" width="35%"><strong><font>���˹�������</font></strong></td>
					<td width="30%" align="center" class="table_title"><strong><font>MAC��ַ</font></strong></td>
					<td class="table_title" align="middle" width="20%"><strong><font>ʹ��</font></strong></td>
					<td width="15%" align="center" class="table_title"><strong><font>ɾ��</font></strong></td>
				</tr>
			</tbody>
		</table>
		<br>
		<left>
			<input name="add" onclick="addClick()" type="button" value="���" class="BtnAdd">
			<input name="remove" onclick="removeClick(this.form.rml)" type="button" value="ɾ��" class="BtnDel">
			<br>
			<br>
		</left>
		</div>
	</div>
		<p align="center">
			<input type="hidden" name="action" value="rm">
			<input type="hidden" name="bcdata" value="le">
			<input type="hidden" name="submit-url" value="">
		</p>
	</form>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

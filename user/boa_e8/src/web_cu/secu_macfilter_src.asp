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
			cell.innerHTML = "启用";
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
		if(!confirm("是否禁用MAC过滤？"))
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
		if(!confirm("是否启用MAC过滤？"))
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
		if(!confirm("改变过滤模式将切换所有过滤规则，您是否真的要改变过滤模式为黑名单？"))
		{
			form.macFilterMode[0].checked = false;
			form.macFilterMode[1].checked = true;
			return;
		}
	}else{
		if(!confirm("改变过滤模式将切换所有过滤规则，您是否真的要改变过滤模式为白名单？"))
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
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
	<form id="form" action=/boaform/admin/formRteMacFilter method=POST name="form">
	<table>
      <tbody>
        <tr>
          <td>MAC过滤开关:
            <input id="macFilterEnble" onclick="on_action('sw')" type="checkbox" value="on" name="macFilterEnble"></td>
        </tr>
      </tbody>
    </table>
    <div id="FilterInfo" style="visibility: visible;"> 
		<table border="0" cellpadding="0" cellspacing="0" width="100%">
 		<tbody>
 			<tr>
	  			<td>黑白名单模式：
	  			<input id="FilterMode" onclick="change_mode('sw')" type="radio" value="off" name="macFilterMode">
	  			黑名单
	  			<input id="FilterMode" onclick="change_mode('sw')" type="radio" value="on" name="macFilterMode">
	  			白名单 
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
					<td class="table_title" align="middle" width="35%"><strong><font>过滤规则名称</font></strong></td>
					<td width="30%" align="center" class="table_title"><strong><font>MAC地址</font></strong></td>
					<td class="table_title" align="middle" width="20%"><strong><font>使能</font></strong></td>
					<td width="15%" align="center" class="table_title"><strong><font>删除</font></strong></td>
				</tr>
			</tbody>
		</table>
		<br>
		<left>
			<input name="add" onclick="addClick()" type="button" value="添加" class="BtnAdd">
			<input name="remove" onclick="removeClick(this.form.rml)" type="button" value="删除" class="BtnDel">
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

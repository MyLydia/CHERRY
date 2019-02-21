<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
<TITLE>中国移动</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<link rel="stylesheet" type="text/css" href="/style/default.css">
<link rel="stylesheet" type="text/css" href="/style/backgroup_style.css">
<!--系统公共脚本-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">
var timeout = 300000;	/* 5 min */
var timeoutTimer;

timeoutTimer = setTimeout(timeoutFunc, timeout);

function timeoutFunc()
{
	document.forms[0].submit();
}

function resetTimeoutFunc()
{
	clearTimeout(timeoutTimer);
	timeoutTimer = setTimeout(timeoutFunc, timeout);
}
/********************************************************************
**          menu class
********************************************************************/
function menu(name)
{
	this.name = name;
	this.names = new Array();
	this.objs = new Array();
	
	this.destroy = function(){delete map;map = null;}
	this.add = function(obj, name){var i = this.names.length; if(name){this.names[i] = name;}else{this.names[i] = obj.name;} this.objs[i] = obj;}
	
	return this;
}

var mnroot = new menu("root");
<% createMenuEx(); %>


/********************************************************************
**          on document load
********************************************************************/
var NavImage = new Array();
NavImage[0]=new Array("nav_condition_n.png");
NavImage[1]=new Array("nav_network_n.png");
NavImage[2]=new Array("nav_security_n.png");
NavImage[3]=new Array("nav_yingyong_n.png");
NavImage[4]=new Array("nav_administration_n.png");
NavImage[5]=new Array("nav_diagnosis_n.png");
NavImage[6]=new Array("nav_help_n.png");
var NavImageClick = new Array();
NavImageClick[0]=new Array("nav_condition_h.png");
NavImageClick[1]=new Array("nav_network_h.png");
NavImageClick[2]=new Array("nav_security_h.png");
NavImageClick[3]=new Array("nav_yingyong_h.png");
NavImageClick[4]=new Array("nav_administration_h.png");
NavImageClick[5]=new Array("nav_diagnosis_h.png");
NavImageClick[6]=new Array("nav_help_h.png");

function on_init()
{
	var fst = null;
	
	if(!topmenu) topmenu = document.getElementById("topmenu");
	if(!submenu) submenu = document.getElementById("submenu");
	
	if(topmenu.cells){while(topmenu.cells.length > 0) topmenu.deleteCell(0);}
	
	for(var i = 0; i < mnroot.names.length; i++)
	{
		var cell = topmenu.insertCell(i);
        var txt = "<a href=\"#\" onClick=\"on_catalog(" + i + ");\"><div class=\"menusize\"><img  id=\"catalogimg"+i+"\"src=\"image/"+NavImage[i]+"\"><br>"; 
		//txt += "<a href=\"#\" onClick=\"on_catolog(" + i + ");\">";
		txt += "<font style=\"font-size:14px;font-weight:bold;\" id=\"catalogfont"+i+"\">" + mnroot.names[i] + "</font></div></a>";
		//cell.bgColor = "#EF8218";
		cell.width = "95";
		cell.align = "center";
		//cell.style = "line-height: 25px;";
		cell.innerHTML = txt;
		cell.mnobj = mnroot.objs[i];
		if(fst == null)fst = i;
	}
	topmenu.sel = 0;
	//topmenu.cells[0].bgColor = "#427594";
	document.getElementById("catalogimg0").src="image/"+NavImageClick[0];
	//document.getElementById("catalogfont0").style="color:#fff45c;font-size:14px;font-weight:bold;";
		document.getElementById("catalogfont0").style.color="fff45c"
		document.getElementById("catalogfont0").style.fontSize="14px"
		document.getElementById("catalogfont0").style.fontWeight="bold"
	
	
	//menuname.innerHTML = mnroot.names[0];
	on_catalog(fst);
}

/********************************************************************
**          on_catalog changed
********************************************************************/
function on_catalog(index)
{
	var fst = null;
	
	if(!topmenu.cells || index >= topmenu.cells.length)return;
	
	if(topmenu.sel != index)
	{
		//topmenu.cells[topmenu.sel].bgColor = "#EF8218";
		document.getElementById("catalogimg"+topmenu.sel).src="image/"+NavImage[topmenu.sel];
		//document.getElementById("catalogfont"+topmenu.sel).style="font-size:14px;font-weight:bold;";
		document.getElementById("catalogfont"+topmenu.sel).style.fontSize="14px";  
		document.getElementById("catalogfont"+topmenu.sel).style.fontWeight="bold";  
		document.getElementById("catalogfont"+topmenu.sel).style.color="#ffffff";
		//topmenu.cells[index].bgColor = "#427594";
		document.getElementById("catalogimg"+index).src="image/"+NavImageClick[index];
	//	document.getElementById("catalogfont"+index).style="color:#fff45c;font-size:14px;font-weight:bold;";
		document.getElementById("catalogfont"+index).style.color="#fff45c";
		document.getElementById("catalogfont"+index).style.fontSize="14px";
		document.getElementById("catalogfont"+index).style.fontWeight="bold";
		//document.getElementById("menu"+index).color="#fff45c";
		topmenu.sel = index;
		//menuname.innerHTML = mnroot.names[index];
	}
	
	var mnobj = topmenu.cells[index].mnobj;
	
	if(submenu.cells){while(submenu.cells.length > 1) submenu.deleteCell(1);}

	for(var i = 0; i < mnobj.names.length; i++)
	{
		var cell = submenu.insertCell(i * 2 + 1);
		var index = i * 2 + 2;
		cell = submenu.insertCell(index);
		var txt ="<a href=\"#\" onClick=\"on_menu(" + index + ");\">";
        txt += "<span class=\"menu_space\" id=\"menufont"+index+"\">" + mnobj.names[i] + "</span></a>";
		//cell.width = "75px";
		cell.innerHTML = txt;
		cell.nowrap = true;
		cell.name = mnobj.names[i];
		cell.mnobj = mnobj.objs[i];
		if(fst == null)fst = index;
	}
	submenu.sel=fst;
	document.getElementById("menufont"+fst).style.color="#fff45c";
	document.getElementById("menufont"+fst).style.fontSize="12px";
	on_menu(fst);
}

/********************************************************************
**          on menu fire
********************************************************************/
function on_menu(index)
{
	if(!submenu.cells || index >= submenu.cells.length)return;
	
	if(submenu.sel != index)
	{
		//document.getElementById("menufont"+submenu.sel).style="color:#fff45c;font-size:12px;";
		//document.getElementById("menufont"+index).style="color:#fff45c;font-size:12px;";
		document.getElementById("menufont"+submenu.sel).style.color="#ffffff";
		document.getElementById("menufont"+submenu.sel).fontSize="12px";
		document.getElementById("menufont"+index).style.color="#fff45c";
		document.getElementById("menufont"+index).style.fontSize="12px";
		submenu.sel = index;
	}
	
	tbobj = submenu.cells[index];
	var mnobj = tbobj.mnobj;
	//var lstmenu = leftFrame.lstmenu;
	if(!lstmenu) lstmenu = leftFrame.document.getElementById("lstmenu");
	if(!lstmenu)return;
	if(lstmenu.rows){while(lstmenu.rows.length > 0) lstmenu.deleteRow(0);}
	
	for(var i = 0; i < mnobj.names.length; i++)
	{
		var row = lstmenu.insertRow(i);
		
		row.nowrap = true;
		row.vAlign = "top";
		
		var cell = row.insertCell(0);
		
		cell.width = "100%";
		cell.align = "center";

		if(i == 0){			
			if(mnobj.names[i].length>12)
				cell.innerHTML = "<br><table border=\"0\" width=\"100%\"><td width=\"10%\"> </td><td width=\"80%\" style=\"padding:0px 0px 10px 0px\"><a id=\"thirdmenufont"+i+"\" onClick=\"on_thirdmenu(" + i + ")\"; style=\"color:#fff45c\" href=\"" + mnobj.objs[i] + "\", target=\"contentIframe\">" + mnobj.names[i] + "</a></td><td width=\"10%\"> </td></table>";
			else
				cell.innerHTML = "<br><table border=\"0\" width=\"100%\"><td width=\"10%\"> </td><td width=\"80%\"><a id=\"thirdmenufont"+i+"\" onClick=\"on_thirdmenu(" + i + ")\"; style=\"color:#fff45c\" href=\"" + mnobj.objs[i] + "\", target=\"contentIframe\">" + mnobj.names[i] + "</a></td><td width=\"10%\"> </td></table>";
		}
		else{
			cell.innerHTML = "<td><table border=\"0\" width=\"100%\"><td width=\"10%\"> </td><td width=\"80%\"><a id=\"thirdmenufont"+i+"\" onClick=\"on_thirdmenu(" + i + ")\"; href=\"" + mnobj.objs[i] + "\", target=\"contentIframe\">" + mnobj.names[i] + "</a></td><td width=\"10%\"> </td></table>";
		}
		
		cell.nowrap = true;
		cell.name = mnobj.names[i];
		cell.mnobj = mnobj.objs[i];
	}
	contentIframe.location.href=mnobj.objs[0];
}

function on_thirdmenu(index){
	tbobj = submenu.cells[submenu.sel ];
	var mnobj = tbobj.mnobj;
	for(var i = 0; i < mnobj.names.length; i++){
		document.getElementById("thirdmenufont"+i).style.color="#ffffff";
	}
	//document.getElementById("thirdmenufont"+index).style="color:#fff45c";
	document.getElementById("thirdmenufont"+index).style.color="#fff45c";

}
function contenFramesize()
{
	getElById('contentIframe').style.height=600; 
	var mainbody = contentIframe.document.body.scrollHeight;
	var trmainbody = getElById('trmain').clientHeight;
	var mainbodyoffset = getElById('contentIframe').offsetHeight;
	var end = mainbody;
	if (end < (trmainbody-31))
		end = trmainbody-31;
	getElById('contentIframe').style.height=end;	//must be id
}

function getElById(idVal) {
	if (document.getElementById != null)
	return document.getElementById(idVal)
	if (document.all != null)
	return document.all[idVal]	
	alert("Problem getting element by id")
	return null
}		
</SCRIPT>
<style>
.welcomeLink input{
	background:0 none;
	border: 0 none;
	color: #fff;
	font-weight: bold;
}
#topmenu span{
	color:#fff;
}
#topmenu  a{
	color:#fff;
	TEXT-DECORATION: none;
	font-family: "微软雅黑";
}
#lstmenu a{
	color: #fff;
	TEXT-DECORATION: none;
	font-weight: bold;
	font-family: "微软雅黑";
}
#submenu a{
	color:#fff;
	TEXT-DECORATION: none;
	font-family: "微软雅黑";
	cursor:pointer;
}
.menu_space {
    display: inline-block;
    padding: 0 8px;
}
#contentIframe {
    background: #f8f8f8;
}
.menusize {
    color: #ffffff;
    font-size: 14px;
    font-weight: bold;
    height: 70px;
    line-height: 25px;
    text-align: center;
    text-decoration: none;
    width: 70px;
	cursor:pointer;
}
p{
	text-align: center;
}
</style>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();" align=center;>
<form action=/boaform/admin/formLogout method=POST name="top" target="_top">
	<table border="0" width="1100" cellspacing="0" cellpadding="0" align="center" height="50">
		<tr class="type_backgroup">
			<td class="toplogo"> 
				<img class="logoimg" src="image/mobile2.png">
			</td>
			<td class="type_cmcc">
			  型号：  <% getInfo("devModel"); %>
			</td>
			<td class="welcomeLink" align="right" valign="center">
			欢迎您！&nbsp;<input type="submit" value="退出">
			</td>
		</tr>
	</table>
	
	<table border="0" cellpadding="0" cellspacing="0" width="1100" align="center"> 
		<tr nowrap class ="type_backgroup"> 
			<td class = "type_backgroup" width="150" rowspan="3" id="menuname">&nbsp;
			<td height="32"  width="1000" style="font-size:9pt" align="right"></td>
		</tr>
		<tr> 
			<td class="type_backgroup" height="70"> 
				<table class ="type_backgroup" border="0" cellpadding="0" cellspacing="0" width="665" height="70"> 	
					<tr id="topmenu" nowrap style="color:#fff;">
					  <td align="center" width="70">　</td>
					</tr>
				</table>
			</td>
		</tr>
	  <tr> 
		<td height="34" bgcolor="#303841"> 
		<table border="0" cellpadding="0" cellspacing="0" height="30">
			<tr id="submenu" style="font-size:9pt; color:#C0C0C0" nowrap> 
			  <td>　</td>
			</tr>
		</table>
		</td>
	  </tr>
	</table>


<div name="leftFrame" class="leftframe" style="margin:0px auto; width:1100px; text-align: center;">


<table border="0" cellpadding="0" cellspacing="0">
  <tr valign="top" id='trmain'>
    <td bgcolor="#363e47" valign="top">
		<table border="0" cellpadding="0" cellspacing="0" width="135" id="lstmenu">
		<tr><td></td></tr> 
		</table>
	</td>
	<td width="1100">
	<iframe id="contentIframe" name="contentIframe" align="middle" src="status_device_basic_info.asp" frameborder="0" width="965"  onload="contenFramesize();"></iframe>
	</td>
  </tr>
</table>
</div>

		
	<table cellSpacing=0 cellPadding=0 width=1100 border=0 align="center">
		<tr>
			<td	bgcolor="#f8f8f8" width="150" height="50" align="right"></td>
			<td	bgcolor="#f8f8f8" width="680" height="50" align="center"><label size="12px" color="#333333">京ICP备05002571号&copy中国移动通信版权所有</label></td>
			<td	bgcolor="#f8f8f8" width="150" height="50" align="right"></td>
		</tr>
	</table>

	

</form>
</body>
<%addHttpNoCache();%>
</html>

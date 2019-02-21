<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
<TITLE>中国联通</TITLE>
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
NavImage[0]=new Array("");
NavImage[1]=new Array("");
NavImage[2]=new Array("");
NavImage[3]=new Array("");
NavImage[4]=new Array("");
NavImage[5]=new Array("");
NavImage[6]=new Array("");
var NavImageClick = new Array();
NavImageClick[0]=new Array("");
NavImageClick[1]=new Array("");
NavImageClick[2]=new Array("");
NavImageClick[3]=new Array("");
NavImageClick[4]=new Array("");
NavImageClick[5]=new Array("");
NavImageClick[6]=new Array("");

function on_init()
{
	var fst = null;
	
	if(!topmenu) topmenu = document.getElementById("topmenu");
	if(!submenu) submenu = document.getElementById("submenu");
	
	if(topmenu.cells){while(topmenu.cells.length > 0) topmenu.deleteCell(0);}
	
	for(var i = 0; i < mnroot.names.length; i++)
	{
		var cell = topmenu.insertCell(i);
        var txt = "<a href=\"#\" onClick=\"on_catalog(" + i + ");\"><div class=\"menusize\"><p  id=\"catalogimg"+i+"\"src=\"image/"+NavImage[i]+"\"></p>"; 
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
		document.getElementById("catalogfont0").style.color="ff9a5d"
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
		document.getElementById("catalogfont"+index).style.color="#ff9a5d";
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
	document.getElementById("menufont"+fst).style.color="#ff9a5d";
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
		document.getElementById("menufont"+index).style.color="#ff9a5d";
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
				cell.innerHTML = "<table class=\"cu_cell\" border=\"0\" width=\"100%\"><td width=\"100%\" style=\"padding:0px 0px 10px 0px\"><a id=\"thirdmenufont"+i+"\" onClick=\"on_thirdmenu(" + i + ")\"; class=\"menu_select\" style=\"color:#ff9a5d\"  href=\"" + mnobj.objs[i] + "\", target=\"contentIframe\">" + mnobj.names[i] + "</a></td></table>";
			else
				cell.innerHTML = "<table class=\"cu_cell\" border=\"0\" width=\"100%\"><td  width=\"100%\"><a id=\"thirdmenufont"+i+"\" onClick=\"on_thirdmenu(" + i + ")\"; class=\"menu_select\" style=\"color:#ff9a5d\"  href=\"" + mnobj.objs[i] + "\", target=\"contentIframe\">" + mnobj.names[i] + "</a></td></table>";
		}
		else{
			cell.innerHTML = "<td><table class=\"cu_cell\"  border=\"0\" width=\"100%\"> </td><td width=\"100%\"><a id=\"thirdmenufont"+i+"\" onClick=\"on_thirdmenu(" + i + ")\"; class=\"menu_select\" href=\"" + mnobj.objs[i] + "\", target=\"contentIframe\">" + mnobj.names[i] + "</a></td></table>";
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
	document.getElementById("thirdmenufont"+index).style.color="#ff9a5d";

}
function contenFramesize()
{
	getElById('contentIframe').style.height=450; 
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
.toplogo{
	background:#2bbdd4;
	width:180px;
	height:50px;
	padding-left: 80px;
}
.type_cmcc{
	background:#2bbdd4;
	width:605px;
	color:#fff;
	font-size: 15px;
}
.welcomeLink{
	color: #fff;
    font-size: 14px;
    font-weight: bold;
    text-align: right;
    position: absolute;
    top: 30px;
    right: 170px;
}
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
    padding: 0 3px;
}

.menusize {
    color: #ffffff;
    font-size: 14px;
    font-weight: bold;
    height: 30px;
    line-height: 30px;
    text-align: center;
    text-decoration: none;
    width: 70px;
	cursor:pointer;
}
p{
	text-align: center;
	display: block;
	-webkit-margin-before: 0em;
	-webkit-margin-after: 0em;
	-webkit-margin-start: 0px;
	-webkit-margin-end: 0px;

}
.cu_main{
    border: 1px solid #7c7c7e;
    border-radius: 20px;
    width: 1050px;
    margin: 0 auto;
    height: 570px;
    margin-top: 85px;
    display: inline-block;
}
table tr td{
	height:10px;
}
.cu_cell{
    background: #3d3d40;
    line-height: 38px;
    border-bottom: 1px solid #888888;
    border-left: 1px solid #888888;
    border-top: 1px solid #888888;
    height: 38px;
    font-size: 12px;
	display: inline-block;
    margin-top: 8px;
}
.menu_select{
	padding-left:10px;
}

iframe{
	border:0 none;
}
</style>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();" align=center;>
<form action=/boaform/admin/formLogout method=POST name="top" target="_top">
<div class="Unicom_bg">
	<p class="site">网上营业厅 www.10010.com  &nbsp;&nbsp; 客服热线10010  &nbsp;&nbsp; 充值专线10011</p>
	<div class="welcomeLink">
		欢迎您！&nbsp;<input type="submit" value="退出">
	</div>
	<div class="cu_main">


	
	<table border="0" cellpadding="0" cellspacing="0" width="1015" align="center"> 
		<tr nowrap > 
			<td height="20" width="165" rowspan="3" id="menuname">&nbsp;
			<td height="20"  width="830" style="font-size:9pt" align="right"></td>
		</tr>
		<tr> 
			<td height="70"> 
				<table border="0" cellpadding="0" cellspacing="0" width="665" height="70"> 	
					<tr id="topmenu" nowrap style="color:#fff;">
					  <td align="center" width="70">　</td>
					</tr>
				</table>
			</td>
		</tr>
	  <tr> 
		<td height="34" bgcolor="#464647" style="border:1px solid #929292;"> 
		<table border="0" cellpadding="0" cellspacing="0" height="30">
			<tr id="submenu" style="font-size:9pt; color:#C0C0C0" nowrap> 
			  <td>　</td>
			</tr>
		</table>
		</td>
	  </tr>
	</table>


<div name="leftFrame" class="leftframe" style="margin:0px auto; width:1020px; text-align: center;">


<table border="0" cellpadding="0" cellspacing="0">
  <tr valign="top" id='trmain'>
    <td bgcolor="" valign="top">
		<table border="0" cellpadding="0" cellspacing="0" width="170" id="lstmenu">
		<tr><td></td></tr> 
		</table>
	</td>
	<td width="850">
	<iframe frameborder="no" border="0" marginwidth="0" marginheight="0" class="contentIframe" id="contentIframe" name="contentIframe" align="middle" src="status_device_basic_info.asp" width="846"  onload="contenFramesize();"></iframe>
	</td>
  </tr>
</table>
</div>
<script>
	function getQueryString(name) {
		var reg = new RegExp('(^|&)' + name + '=([^&]*)(&|$)', 'i');
		var r = window.location.search.substr(1).match(reg);
		if (r != null) {
			return unescape(r[2]);
		}
		return null;
	}

	setTimeout(function () {
		var index = getQueryString('index') || 0;
		on_catalog(index);
	}, 200);

</script>
	
</form>
</body>
<%addHttpNoCache();%>
</html>

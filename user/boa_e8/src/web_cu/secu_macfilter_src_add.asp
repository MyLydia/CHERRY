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
var rules = new Array();
with(rules){<% rteMacFilterList(); %>}

/********************************************************************
**          on document apply
********************************************************************/
function btnApply()
{
	/*
	if(form.devname.value == "")
	{
		alert("局域网设备名不能为空！");
		return false;
	}
	*/
	//var cur_filtermode = 0;
	//cur_filtermode = (form.mode.value == "on") ? 1:0;//form.macFilterMode.value ;
	if(form.mac.value == "")
	{
		alert("mac 地址不能为空！");
		return false;
	}
	if(!sji_checkmac(form.mac.value))
	{
		alert("mac 地址错误！");
		return false;
	}
	for(var i = 0; i < rules.length; i++)
	{
		if(/*rules[i].name == form.devname.value ||*/ rules[i].mac == form.mac.value)
		{
			alert( "该规则已存在");//alert("That rule already exists");
			return false;
		}
	}
	form.submit();
}

function RefreshPage()
{
	location.href = document.location.href;
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
  <blockquote>
	<DIV align="left" style="padding-left:20px; padding-top:5px">
		<form id="form" action=/boaform/admin/formRteMacFilter method=POST name="form">
			<b>MAC地址接入控制</b><br><br><br>
			<!--本页将添加需过滤的已连接路由器的指定局域网设备的MAC地址。<br>
			在"局域网设备名"一栏中输入需限制的局域网设备名，在"MAC地址"一栏输入该设备的MAC地址。<br>
			进入命令窗口输入命令"ipconfig /all"来查看基于PC的MAC地址。<br> -->
			<table border="0" cellpadding="0" cellspacing="0" width="100%">
                  <tbody><tr>
                    <td>过滤规则名称：</td>
                    <td><input type="text" name="name"maxlength="31"></td>
                    <td>&nbsp;</td>
                  </tr>
                  <tr>
                    <td>MAC地址：</td>
                    <td><input type="text" name="mac" maxlength="17"></td>
                    <td>（格式：AA:BB:CC:DD:EE:FF）</td>
                  </tr>
                  <tr>
				  	<td>
				  	</td>
				  </tr>
                  <tr>
				  	<td>
				  	</td>
				  </tr>
                </tbody>
            </table>
    		<p align="center">
				<input type="button" class="btnsaveup"  id="btnOK" value="确定" onclick="btnApply()" >
				<input type="button" class="btnsaveup" id="btnCancel" value="取消" onclick="RefreshPage()">
				<input type="hidden" name="action" value="ad">
				<input type="hidden" name="submit-url" value="/secu_macfilter_src.asp">
			</p>
		</form>
	</div>
  </blockquote>
</body>
<%addHttpNoCache();%></html>

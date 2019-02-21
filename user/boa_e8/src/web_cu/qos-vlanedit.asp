<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<html>
<head>
<title>设置VLAN值</title>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<!--系统公共脚本-->
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">
var vArrayStr = [
		<% getWANItfArray(); %>
	];

function on_init(){
	with(document.forms[0]){
	
	}
}
function is_integer(val)
{
	if (/^(\+|-)?\d+$/.test( val ))
	{
		return true;
	}
	else
	{
		return false;
	}
}
function on_save() {
	with(document.forms[0]) {		
		vlan   = getValue('vlanValue');
		if (is_integer(vlan) == false ||  vlan < 1 || vlan > 4094)
		{
			alert("vlan的有效值为1-4094区间的整数，请重新输入");
			return false;
		}
		submit();
	}	
}

function clickPage(filename)
{
			location.replace(filename);
}
function WriteWanNameSelected()
{	
	for (i = 0; i < vArrayStr.length; i++)
	{
		document.write('<option value=' + vArrayStr[i][0] + '>' + vArrayStr[i][1] +  '</option>');
	}		
}
</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
	<DIV align="left" style="padding-left:20px; padding-top:5px;">
		<form id="form" action="/boaform/admin/formQosVlan" method="post">

		   <table class="tblList" border="1" id="lstrc">
                    <tbody>
                      <tr>
                        <td class="table_title" width="100" align="center">接口</td>
                        <td class="table_title" align="center">VLAN</td>
                      </tr>
                      <tr>
                        <td align="center">
							<select id="sel_Interface" name="sel_Interface" onchange="ChangeInterface(this)">
								<script language="JavaScript" type="text/javascript">
									WriteWanNameSelected();
								</script>
							</select>
                          
						</td>
                        <td align="center"><input id="vlanValue" name="vlanValue" value="" type="text"></td>
                      </tr>                    
                    </tbody>
		  </table>

		  <div id="AddBtn">
                <table width="100%" border="0">
                  <tbody>
                    <tr>
                      <td><input id="AddCls" onclick="clickPage('net_qos_imq_policy.asp')" value="返回队列编辑页面" name="AddCls" type="button"></td>
					</tr>
                  </tbody>
		  </table>
		  </div>
		  </div>		  
		  </div>
		  <br><br>
		   <table width="828px">
					<tbody>
						<td colspan="2">
							<p align="center">
								<input id="btnOK" onclick="on_save();" src="/image/ok_cmcc.gif" type="image" border="0">&nbsp;&nbsp;
								<img id="btnCancel" onclick="on_save" src="/image/cancel_cmcc.gif" border="0">
							</p>
						</td>
					</tbody>
		  </table>
		  <input type="hidden" id="lst" name="lst" value="">
		  <input type="hidden" name="submit-url" value="/qos-vlanedit.asp">
		</form>
	</DIV>
</blockquote>
</body>
<%addHttpNoCache();%>
</html>

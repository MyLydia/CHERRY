<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
<TITLE>WLAN共享配置</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">
var _ssid_idx;
var _userid_enable;
var _userid="";
var _text_hint="请输入手机号码";

function getObj(id)
{
	return(document.getElementById(id));
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{	
	var obj=getObj("wlan_shareid");
	obj.value = _userid;
	
	var wlshare_id = obj.value; 
	if(wlshare_id == 'N/A' || wlshare_id == ''){
		obj.style.color='#999999';
		obj.value = _text_hint;		
	}else{
		obj.style.color='#000000';		
	}

}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit() 
{
	var user_id;
	{
		user_id = getObj("wlan_shareid").value;
		if(user_id == ""){
			getObj("ShareIndex").value = 2;
			getObj("EnableUserId").value = 0;
		}
		else
			getObj("UserId").value = user_id;

		getObj("wlanshare").submit();
	}

}

function tips(Id)
{
	var Tips = getObj(Id).value;
	if(Tips == _text_hint)
	{
		getObj(Id).value = "";
		getObj(Id).style.color='#000000';
	}
}

function pageCheckValue()
{
	return true;
}

function refresh()
{
	window.location.reload(true);
}

</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:10px">
			<form id="wlanshare" action=/boaform/admin/formWlanShare method=POST name=wlanshare>
				<table border="0" cellpadding="3" cellspacing="0">
				<tr>
					<td>WLAN共享功能绑定信息配置:</td>
					<td ><input name="wlan_shareid" id="wlan_shareid" type="text" size="15" value="" onfocus="tips(this.id);"/>
					</td>
				</tr>
				</table>
				<input type="hidden" name="UserId" id="UserId">
                <input type="hidden" name="ShareIndex" id="ShareIndex" value="2">
                <input type="hidden" name="EnableUserId" id="EnableUserId" value="1">	
				<input type="hidden" name="submit-url" value="/net_wlan_share.asp">
			</form>
			<script>
			<% initPage("wlshare"); %>
			</script>
		</DIV>
		<br><br>
		<DIV class=\"child\"><tr><center>
					<td class="td1"></td>
					<td class="td2">
					<input class="btnsaveup" name="Btn_Add" type="button" id="Btn_Add" value="确定" onclick="on_submit()"/>
					&nbsp;&nbsp;
					<button onclick="refresh()" name=btnCancel value="Cancel" class="btnsaveup2">取消</button>
					</td>
	<blockquote>
</body>
<%addHttpNoCache();%>
</html>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>PING����</TITLE>
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
var links = new Array();
with(links){<% listWanif("rt"); %>}

/********************************************************************
**          on document load
********************************************************************/
function isValidUrlName(url)
			{
				var i=0;
				var invalidArray = new Array();
				invalidArray[i++] = "www";
				invalidArray[i++] = "com";
				invalidArray[i++] = "org";
				invalidArray[i++] = "net";
				invalidArray[i++] = "edu";
				invalidArray[i++] = "www.";
				invalidArray[i++] = ".com";
				invalidArray[i++] = ".org";
				invalidArray[i++] = ".net";
				invalidArray[i++] = ".edu";
				for (i = 0; i < url.length; i++)
				{
					if (url.charAt(i) == '\\')
					{
						return false;
					}
				}
				if (url == "")
				{
					return false;
				}
				if (url.length < 3)
				{
					return false;
				}
				for(j=0; j< invalidArray.length; j++)
				{
					if (url == invalidArray[j])
					{
						return false;
					}
				}
				return true;
			} 

function on_Apply(){
	var url = document.forms[0].target_addr.value;
	if(!sji_checkvip(document.forms[0].target_addr.value) && !sji_checkhostname(document.forms[0].target_addr.value)
		&& !isIPv6(document.forms[0].target_addr.value) || !isValidUrlName(url)){
		alert("Ŀ���ַ�Ƿ������������룡");
		document.forms[0].target_addr.value="";
		return false;
	}
	if(document.forms[0].target_num.value > 0 && document.forms[0].target_num.value <= 10)
	{
		document.forms[0].submit();
	}
	else
	{
		alert("�ظ������Ƿ������������룡");
		document.forms[0].target_num.focus();
		return false;
	}
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
	<form id="form" action=/boaform/admin/formPing method="HEAD" target="pingresult" >
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>PING����</b></div>
			<br>
			<table width="50%" align="left" valign="middle">
			<tr><td>�ظ�������<input type="text" name="target_num" maxlength="60" />(1-10��)</td></tr>
			<tr><td>�ӿ�ѡ��<select name="waninf"><% checkWrite("wan-interface-name"); %></select></td></tr>
			<tr>
			<td>Ŀ���ַ��<input type="text" name="target_addr" maxlength="60" />
			<button class="btnsaveup" type="submit" width="100px" onClick="on_Apply()">��ʼ</button></td>
			</tr>
			</table>
		</div>
		<div align="left"><br>
		<iframe align="left" id="pingresult" name="pingresult" src='' frameborder='0' width='500' ></iframe>
		</div>
	</form>
	</blockquote>
</body>
</html>

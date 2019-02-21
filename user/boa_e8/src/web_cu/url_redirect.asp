<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>强制门户设置</TITLE>
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
	
function checkTextStr(str)
{
	for (var i=0; i<str.length; i++) 
	{
		if ( str.charAt(i) == '%' || str.charAt(i) =='&' ||str.charAt(i) =='\\' || str.charAt(i) =='?' || str.charAt(i)=='"') 
			return false;			
	}
	return true;
}

function applyClick()
{	
	if(!checkTextStr(document.formURLRedirect.redirect_url.value))
	{
		if(document.formURLRedirect.urlredirect_enable.checked == true)
		{
			alert("设置的URL错误!");
			return true;
		}
		document.formURLRedirect.redirect_url.focus();
		return false;	
	}
	return true;
}

function updateState()
{
	if (document.formURLRedirect.urlredirect_enable.checked) {
		enableTextField(document.formURLRedirect.redirect_url);
  	}
  	else {
 		disableTextField(document.formURLRedirect.redirect_url);
  	}
}

function checkChange(cb)
{
	if(cb.checked==true){
		cb.value = 1;
	}
	else{
		cb.value = 0;
	}

	updateState();
}
</SCRIPT>
</HEAD>
<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body>
<blockquote>

<DIV align="left" style="padding-left:20px; padding-top:5px">
<form action=/boaform/formURLRedirect method=POST name="formURLRedirect">
<table border="0" cellpadding="0" cellspacing="0">
<tr><td> 强制门户开关:</td>
      <td>
		<input type="checkbox" name="urlredirect_enable" onChange="checkChange(this)" <% checkWrite("urlredirect_enable"); %>>
      </td>
</tr>
<tr>
	<td>URL: </td>
	<td><input type="text" name="redirect_url" size="32" maxlength="64" value=<% getInfo("redirect_url"); %> ></td>
</tr>
<tr>
	<td><input class="btnsaveup" type="submit" value="保存/应用" name="save" onClick="return applyClick()">&nbsp;&nbsp;</td>
</tr>
<tr><td>
   <br>
        <input type="hidden" value="/url_redirect.asp" name="submit-url">
</td></tr>
</table>
<script> 
	 updateState(); 
</script>
</form>
</DIV>
</blockquote>
</body>
</html>

<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<HEAD>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_MLD_SNOOPING); %><% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</HEAD>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<h2 class="page_title"><% multilang(LANG_MLD_SNOOPING); %><% multilang(LANG_CONFIGURATION); %></h2>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/formMLDSnooping method=POST name="mldsnoop">				
				<table>
				<tr><th><% multilang(LANG_THIS_PAGE_BE_USED_TO_CONFIGURE_MLD_SNOOPING); %></th></tr>
				<tr><td><hr size=1 noshade align=top></td></tr>
				</table>

				<table>
					<tr><th><% multilang(LANG_MLD_SNOOPING); %>:</th>
						<td><font size=2>
						<input type="radio" name=snoop value=0><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
						<input type="radio" name=snoop value=1><% multilang(LANG_ENABLE); %></td>
				</tr></table>
				<br>
				<input type="submit" class="button" name="apply" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return on_submit(this)"> 
				<input type="hidden" name="submit-url" value="/app_mld_snooping.asp">
				<input type="hidden" name="postSecurityFlag" value="">
			<script>
				<% initPage("mldsnooping"); %>	
			</script>			
			</form>
		</DIV>
	</blockquote>
</body>
</html>

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

/********************************************************************
**          on document load
********************************************************************/
var cgi = new Object();
//<%initPageDos();%>

function on_init()
{
	sji_docinit(document, cgi);
}

</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formDos method=POST name="form">
				<hr align="left" class="sep" size="1" width="90%">
				<table width="341" border="0" cellspacing="1" cellpadding="3">
					<tr>
						<td> ������������: ����
						<INPUT id="is_dosEnble" type="checkbox" name="dosEnble" <% checkWrite("is_dosEnble"); %> ></td>
					</tr>
				</table>
				<hr align="left" class="sep" size="1" width="90%">
				<input type="submit" class="btnsaveup" value="ȷ��" name="apply">
		        &nbsp;&nbsp;
		        <input type="reset" class="BtnCnl" value="ȡ��">
				<input type="hidden" name="submit-url" value="">
			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>DMS Settings</TITLE>
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
<script type="text/javascript" src="share.js" charset="gbk"></script>
<SCRIPT language="javascript" type="text/javascript">
function dmsSelection()
{	
	return true;
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
<form action=/boaform/formDMSConf method=POST name="formDMSconf">
<table border=0 width="500" cellspacing=4 cellpadding=0>
  <b>DMS ����</b><br><br>
  <tr>
    ���ҳ�����������û��߽���DMS����
  </tr>
  <tr><hr size=1 noshade align=top></tr>
  <tr>
      <td width="30%">Digital Media Server:</td>
      <td width="70%">
	      <input type="radio" name="enableDMS" value=0 <% fmDMS_checkWrite("fmDMS-enable-dis"); %> onClick="dmsSelection()" >����&nbsp;&nbsp;
	      <input type="radio" name="enableDMS" value=1 <% fmDMS_checkWrite("fmDMS-enable-en"); %>  onClick="dmsSelection()" >����
      </td>
  </tr>  
</table>
<br>
      <input type="submit" value="����/Ӧ��" onClick="return on_submit()">&nbsp;&nbsp;
      <!--<input type="reset" value="Undo" name="reset" onClick="window.location.reload()">-->
      <input type="hidden" value="/dms.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</form>
</DIV>
</blockquote>
</body>
</html>

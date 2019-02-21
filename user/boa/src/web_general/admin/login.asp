<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<script type="text/javascript" src="rollups/md5.js"></script>
<script type="text/javascript" src="php-crypt-md5.js"></script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function setpass(obj)
{
	<% passwd2xmit(); %>
	obj.isclick = 1;
	postTableEncrypt(document.cmlogin.postSecurityFlag, document.cmlogin);	
}
function mlhandle()
{
	postTableEncrypt(document.formML.postSecurityFlag, document.formML);
	document.formML.submit();
	parent.location.reload();
}
</SCRIPT>
</head>

<body>
<blockquote>

<form action=/boaform/admin/formLogin method=POST name="cmlogin">
<input type="hidden" name="challenge">

<TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
  <TBODY>
  <TR vAlign=top>
    <TD width="50%"><A><IMG height=60 src="LoginFiles/realtek.jpg" width=170 useMap=#n1E6.$Body.0.1E8 border=0></A></TD>
  </TR>
  </TBODY>
</TABLE>

<CENTER>
  <TABLE cellSpacing=0 cellPadding=0 border=0>
    <TBODY>
      <TR vAlign=top>
        <TD width=350><BR> 
          <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
            <TBODY>
              <TR vAlign=top>
                <TD vAlign=center width="29%"><DIV align=right><IMG height=32 src="LoginFiles/locker.gif" width=32><BR><BR></DIV></TD>
                <TD vAlign=center width="5%"></TD> 
                <TD vAlign=center width="71%"><FONT color=#0000FF size=2><% multilang(LANG_INPUT_USERNAME_AND_PASSWORD); %></FONT><BR><BR></TD>
	      </TR>
              <TR vAlign=top>
                <TD vAlign=center width="29%"><DIV align=right><FONT color=#0000FF size=2><% multilang(LANG_USER); %><% multilang(LANG_NAME); %>:</FONT></DIV></TD>
                <TD vAlign=center width="5%"></TD>
                <TD vAlign=center width="71%"><FONT><INPUT maxLength=30 size=20 name=username></FONT></TD>
              </TR>
              <TR vAlign=top>
                <TD vAlign=center width="29%"><DIV align=right><FONT color=#0000FF size=2><% multilang(LANG_PASSWORD); %>:</FONT></DIV></TD>
                <TD vAlign=center width="5%"></TD>
                <TD vAlign=center width="71%"><FONT><INPUT type=password maxLength=30 size=20 name=password></FONT></TD>
	      </TR>

              <TR vAlign=top>
                <TD vAlign=center width="29%"></TD>
                <TD vAlign=center width="5%"></TD>
                <TD vAlign=center width="71%"><FONT size=2></FONT><BR><INPUT type=submit value="<% multilang(LANG_LOGIN); %>" name=save onClick=setpass(this)></TD>
	      </TR>
            </TBODY>
	  </TABLE>
        </TD>
      </TR>
    </TBODY>
  </TABLE>
</CENTER>
<DIV align=center></DIV>
<input type="hidden" value="/admin/login.asp" name="submit-url">
<input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>

<blockquote>
<form action=/boaform/admin/formLoginMultilang method=POST name="formML">
<CENTER><TABLE cellSpacing=0 cellPadding=0 border=0>
<tr><td>
	<% checkWrite("loginSelinit"); %>
	<input type="hidden" name="postSecurityFlag" value="">
</td></tr>
</TABLE></CENTER>
</form>
</blockquote>

</BODY>
</HTML>

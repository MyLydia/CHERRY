<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>�й��ƶ�-ʡ�����ּ�ͥ����ƽ̨</TITLE>
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

var tr069Configurable = <% getInfo("cwmp_conf"); %>;
var _certStatus = <% getInfo("ca-status") %>;

var msg = new Array(6);
msg[0] = "�ϴ�֤���ļ��ɹ���";   
msg[1] = "֤���ļ��Ƿ�,�ϴ�֤���ļ�ʧ�ܣ�";   
msg[2] = "֤�鹦�ܱ���ֹ��"; 
msg[3] = "֤�鹦�������ã�"; 
msg[4] = "֤���ļ�������,�����ϴ���";  
msg[5] = "֤���ļ��ļ�̫���ϴ�ʧ�ܣ�";

var msg_2 = "(����û�м���֤���ļ�!)";


/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	var i = 3;

	if(tr069Configurable == 1)
		return;

	itms = document.forms[0].length;
	itms-=6;

	for(i; i<itms;i++)
		document.forms[0].elements[i].disabled = true;
}

function isValidPort(port) 
{
	var fromport = 0;
	var toport = 100;
	
	portrange = port.split(':');
	if (portrange.length < 1 || portrange.length > 2) {
		return false;
	}
	if (isNaN(portrange[0]))
		return false;
	fromport = parseInt(portrange[0]);
	
	if (portrange.length > 1) {
		if (isNaN(portrange[1]))
			return false;
			
		toport = parseInt(portrange[1]);
		
		if (toport <= fromport)
			return false;      
	}
	
	if (fromport < 1 || fromport > 65535 || toport < 1 || toport > 65535) {
		return false;
	}
	
	return true;
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit(act) 
{
	with ( document.forms[0] ) 
	{
		action.value = act;
		if(act=="sv")
		{
			if (acsURL.value.length > 256) 
			{
				alert('The length of ACS URL (' + acsURL.value.length + ') is too long [1-256].');
				return false;
			}
			if(!sji_checkhttpurl(acsURL.value))
			{
				if(!acsURL.value=="")
				{
					alert("ACS URL �ǲ��Ϸ��� URL!");
					return false;
				}
			}
			if(!sji_checknum(informInterval.value))
			{
				alert("�����ϱ����ʱ�����Ϊ������!");
				return false;
			}
			if (acsUser.value.length > 256) 
			{
				alert('The length of ACS user name (' + acsUser.value.length + ') is too long [0-256].');
				return false;
			}
			if(isInvalidInput(acsUser.value))
			{
				alert("ACS �û������зǷ��ַ�������������!");
				return false;
			}      
			if (acsPwd.value.length > 256) 
			{
				alert('The length of sysName (' + acsPwd.value.length + ') is too long [0-256].');
				return false;
			}
			if(isInvalidInput(acsPwd.value))
			{
				alert("ACS ���뺬�зǷ��ַ�������������!");
				return false;
			}      
			if (connReqUser.value.length > 256) 
			{
				alert('The length of connection request user name (' + connReqUser.value.length + ') is too long [0-256].');
				return false;
			}
			if(isInvalidInput(connReqUser.value))
			{
				alert("���������û������зǷ��ַ�������������!");
				return false;
			}
			if (connReqPwd.value.length > 256) 
			{
				alert('The length of connection request password (' + connReqPwd.value.length + ') is too long [0-256].');
				return false;
			}
			if(isInvalidInput(connReqPwd.value))
			{
				alert("�����������뺬�зǷ��ַ�������������!");
				return false;
			}
			applyTr069Config.value = "applyTr069Config";
			document.forms["form_69config"].submit();
			return true;
		}
	}

	return false;
}

function submit_CAcert()
{
	with ( document.forms[1] ) 
	{
		if (binary.value == "") 
		{
			alert("��ѡ��֤���ļ��ϴ���");
			return false;
		}
		else
			document.forms["ca_cert"].submit();
		
		return true;
	}
}

/*
 * isCharUnsafe - test a character whether is unsafe
 * @c: character to test
 */
function isInvalidChar(c)
{
	var unsafeString = "\"\\`\,='\t";

	return unsafeString.indexOf(c) != -1 
		|| c.charCodeAt(0) <= 32 
		|| c.charCodeAt(0) >= 123;
}

/*
 * isIncludeInvalidChar - test a string whether includes invalid characters
 * @s: string to test
 */
function isInvalidInput(s) 
{
	var i;	

	for (i = 0; i < s.length; i++) {
		if (isInvalidChar(s.charAt(i)) == true)
			return true;
	}

	return false;
} 

function intervaldisable()
{
	document.forms[0].informInterval.disabled = true;
}

function intervalenable()
{
	document.forms[0].informInterval.disabled = false;
}

function refresh()
{
	window.location.reload(true);
}

function update_cert_info()
{		
	var obj = getElById('binary');
	
	obj = getElById('CertStatus_id');
	if((_certStatus == 0) || (_certStatus == 2) || (_certStatus == 3))
		obj.width = 380;
	else
		obj.width = 400;
	
	for (var i=0; i<2; i++)
	{
		if (form_69config.certauth[i].checked)
		{
			var vcert = form_69config.certauth[i].value;
			break;
		}
	}		
	//This time sample board show msg anyway
	//if (vcert!=0)
	{		
		obj = getElById('CertStatus_text');
		if ((_certStatus >= 0) && (_certStatus <= 5))
		{		
			obj.innerHTML = '<font color="#FF0000">' + msg[_certStatus] + '</font>';
		}
		obj2 = getElById('CertStatus_text2');
		if (_certStatus == 4)
		{		
			obj2.innerHTML = msg_2;
		}
	}
}

</script>
   </head>
   <body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad='on_init()'>
    <blockquote>
     <div align="left" style="padding-left:20px; padding-top:10px">
         <form name="form_69config" action=/boaform/admin/formTR069Config method="post">
           <b>ʡ�����ּ�ͥ����ƽ̨������<br>
            </b>
            <br>
           ʡ�����ּ�ͥ����ƽ̨���ء�ʡ�����ּ�ͥ����ƽ̨��������ַ�� ʡ�����ּ�ͥ����ƽ̨�������û��������롢����������֤�û������롢 ֪ͨ���ڵ����á�
           <br>
            <br>
            <table border="0" cellpadding="0" cellspacing="0">
			   <tr>
                  <td width="80">����֪ͨ:</td>
                  <td><input name='inform' value='0' type='radio' onClick="intervaldisable()" <% checkWrite("tr069-inform-0"); %> >
          ����
				&nbsp;
                  <input name='inform' value='1' type='radio' onClick="intervalenable()" <% checkWrite("tr069-inform-1"); %> >
          ����</td>		  
               </tr>
			   <tr>
                  <td width="200">����֪ͨʱ����[0 - 2147483647]:</td>
                  <td><input type='text' name='informInterval' size="20" maxlength="10" value="<% getInfo("inform-interval"); %>" <% checkWrite("tr069-interval"); %>>��</td>
               </tr>
			   <tr>
                  <td>����������/IP��ַ���˿�:</td>
                  <td><input type='text' name='acsURL' size="20" maxlength="256" value="<% getInfo("acs-url"); %>"></td>
               </tr>
               <tr>
                  <td>ƽ̨�û���:</td>
                  <td><input type='text' name='acsUser' size="20" maxlength="256" value="<% getInfo("acs-username"); %>"></td>
               </tr>
               <tr>
                  <td>ƽ̨����:</td>
                  <td><input type='password' name='acsPwd' size="20" maxlength="256" value="<% getInfo("acs-password"); %>"></td>
               </tr>
			   <tr>
                  <td width="200">�ն˵��û���:</td>
                  <td><input type='text' name='connReqUser' size="20" maxlength="256" value="<% getInfo("conreq-name"); %>"></td>
               </tr>
               <tr>
               <td>�ն˵�����:</td>
                  <td><input type='password' name='connReqPwd' size="20" maxlength="256" value="<% getInfo("conreq-pw"); %>"></td>
               </tr>
			   <!-- This time sample board has no this item
			   <tr>
                  <td width="80">Password��֤ģʽ:</td>
                  <td><input name='passauth' value='0' type='radio' <% checkWrite("tr069-passauth-0"); %> >
          ����
			&nbsp;
		          <input name='passauth' value='1' type='radio' <% checkWrite("tr069-passauth-1"); %> >
          ����</td>
               </tr>   
			   -->
			   <tr>
                  <td width="80">����֤�鹦��:</td>
                  <td><input id='certauthid' name='certauth' value='0' type='radio' <% checkWrite("tr069-certauth-0"); %> >
          ����
			&nbsp;
				  <input id='certauthid' name='certauth' value='1' type='radio' <% checkWrite("tr069-certauth-1"); %> >
          ����</td>
               </tr>
            </table>
			    <p > 
					<input type="hidden" name="applyTr069Config" value="">
					<input type="hidden" id="action" name="action" value="none">
					<input type="hidden" name="submit-url" value="/net_tr069_cmcc.asp">
				</P>
		  </form> 
</div>
<DIV align="left" style="padding-left:20px; padding-top:10px">
<form action=/boaform/admin/formTR069CACert method="post" enctype="multipart/form-data"  name="ca_cert">
			<table border="0" cellpadding="0" cellspacing="0">
				<tr>
					<td id=CertStatus_id2 width="0" align="left"><DIV id=CertStatus_text2 name="CertStatus_text2"></DIV></td>
				</tr>
 				<tr>
					<TD width=200>
                          �ļ�·��[���128���ַ�]:
                    </TD>
					<td>
		           		<input type="file" id="binary" name="binary" size="20">&nbsp;&nbsp;
		           		<input class="btnsaveup" type="button" onclick="submit_CAcert()" value="�ϴ�" >
					</td>
				</tr>
				<tr>
					<td>&nbsp;</td>
					<td id=CertStatus_id width="420" align="left"><DIV id=CertStatus_text name="CertStatus_text"></DIV></td>
					<td></td>
                </tr>
				<script>update_cert_info();</script> 
		   </table><br>
		<input type="hidden" id="action" name="action" value="none">
		<input type="hidden" name="submit-url" value="/net_tr069_cmcc.asp">
   </form>
</div>
		 <input class="btnsaveup" type='submit' onClick="return on_submit('sv')" value='����'>
         &nbsp;&nbsp;
         <BUTTON onclick="refresh()" name=btnCancel value="Cancel" class="btnsaveup2">ȡ��</BUTTON></TD>

      </blockquote>
   </body>
<%addHttpNoCache();%>
</html>

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

var cgi = new Object();
var rules = new Array();
with(rules){<% initPageURL(); %>}

function on_chkclick(index)
{
	if(index < 0 || index >= rules.length)
		return;
	rules[index].select = !rules[index].select;
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);

	if(cgi.urlfilterEnble == false)
	{
		UrlFilterForm.urlFilterMode[0].disabled = true;
		UrlFilterForm.urlFilterMode[1].disabled = true;

		document.getElementById("Filter").style.display="none";
	}

	if(rulelst.rows)
	{
		while(rulelst.rows.length > 1)
			rulelst.deleteRow(1);
	}

	for(var i = 0; i < rules.length; i++)
	{
		var row = rulelst.insertRow(i + 1);

		row.nowrap = true;
		row.vAlign = "top";
		row.align = "center";

		var cell = row.insertCell(0);
		cell.innerHTML = i+1;
		cell = row.insertCell(1);
		cell.innerHTML = rules[i].url;
		cell.align = "left";
		cell = row.insertCell(2);
		//cell.innerHTML = rules[i].port;
		//cell = row.insertCell(2);
		cell.innerHTML = "<input type=\"checkbox\" onClick=\"on_chkclick(" + i + ");\">";
	}
}

function addClick()
{
   var loc = "secu_urlfilter_add.asp";
   var code = "window.location.href=\"" + loc + "\"";
   eval(code);
}

function on_action(act)
{
	UrlFilterForm.action.value = act;

	if(act == "rm" && rules.length > 0)
	{
		UrlFilterForm.bcdata.value = sji_idxencode(rules, "select", "idx");
	}

	with(UrlFilterForm)
	{
		submit();
	}
}

//new
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

function btnAdd()
{
//var SubmitForm = new webSubmitForm();
	with ( document.forms[0] )
	{
		if(rules.length >= 100)
		{
			alert("���������100����¼!")
			return;
		}
		if (url.value.length > 31)
		{
			alert("URL���Ȳ��ܳ���31���ַ�!")
			return;
		}
		if(isValidUrlName(url.value) == false)
		{
			alert("�Ƿ���URL��ʽ������������.")
			return;
		}
		var str = url.value;
		var i;
		if (-1 != (i = str.indexOf("http")))
		{
			if(-1 != str.indexOf("https"))
				str = str.substring(i+8);
			else str = str.substring(i+7);
		}
		url.value = str;
		for(var j = 0; j < rules.length; j++)
		{
			if(rules[j].url.toLowerCase() == str.toLowerCase())
			{
				alert("��ͬ��URL���˹����Ѵ��ڣ�");
				return;
			}
		}
	}

	on_action("ad");

	return;
}

function cliEnableBox(checkBox)
{
	if (checkBox.checked == true)
	{
		document.getElementById("Filter").style.display = ''; 
	}
	else
	{
		document.getElementById("Filter").style.display = 'none'; 
	}
}

function ChangePolicy()
{
	with ( document.forms[0] )
	{
		if (urlFilterMode[0].checked == true)
		{
			if (confirm("�ı����ģʽ���л����й��˹������Ƿ����Ҫ�ı����ģʽΪ��������"))
			{
				on_action("md");
			}
			else
			{
				urlFilterMode[0].checked = false;
				urlFilterMode[1].checked = true;
				return;
			}
		}
		else if (urlFilterMode[1].checked == true )
		{
			if (confirm("�ı����ģʽ���л����й��˹������Ƿ����Ҫ�ı����ģʽΪ��������"))
			{
				on_action("md");
			}
			else
			{
				urlFilterMode[0].checked = true;
				urlFilterMode[1].checked = false;
				return;
			}
		}
	}
}

function RefreshPage()
{
	location.href = document.location.href;
}
</SCRIPT>
</HEAD>
<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<form name="UrlFilterForm" action=/boaform/admin/formURL method="post">
		<div>
		<table width="100%" cellspacing="0" cellpadding="0" border="0">
			<tbody>
	          <tr>
	            <td valign="top">
	                <table cellspacing="0" cellpadding="0" width="100%" border="0">
	                  <tbody>
	                    <tr>
	                      <td>
							  <table border="0" cellpadding="0" cellspacing="0">
		                      	<tbody>
		                      		<tr>
		                              <td>
		                              URL���˿���:
									  <input id="urlfilterEnble" onclick="cliEnableBox(this)" type="checkbox" name="urlfilterEnble">
		                              </td>
		                            </tr>
		                        </tbody>
		                       </table>
		                       <div id="Filter">
		                       <table border="0" cellpadding="0" cellspacing="0">
		                       	<tbody>
		                       		<tr>
		                              <td>
		                        		����URL����ģʽ�Լ�������������������100����<br>
		                          		����������ģʽ����ť�ı�URL����ģʽ��<br>
		                          		��������ӡ���ť����һ��URL����Ӧ��URL�б�������ɾ������ťɾ��һ��URL��<br>
		                         		URL��Ҫ��http://��URL���Ȳ��ܳ���31���ַ��� <br>
		                          		<script language="JavaScript" type="text/javascript">
											if(cgi.urlFilterMode==false)
											{
												document.write('��ǰ�Ĺ����б�Ϊ��<B>������</B>\n');
											}
											else
											{
												document.write('��ǰ�Ĺ����б�Ϊ��<B>������</B><BR>\n');
												document.write('<font color="#FF0000">��ʾ�������URL���������ʵ�URL����ȫƥ��</font>');
											}
								 		</script>
				                       </td>
				                      </tr>
		                          </tbody>
	                              </table>
	                              <table border="0" cellpadding="0" cellspacing="0">
	                              	<tbody>
	                              		<tr>
		                                <td width="120">	
                          				�ڰ�����ģʽ��
		                          		</td>
		                          		<td>
				                        	<input id="urlFilterMode" onclick="ChangePolicy()" type="radio" value="off" name="urlFilterMode">
				                          	������
				                          	<input id="urlFilterMode" onclick="ChangePolicy()" type="radio" value="on" name="urlFilterMode">
				                          	������
				                        </td>
		                          		</tr>
		                          	</tbody>
		                          </table>
		                          <div id="dnsdomain">
		                            <table cellspacing="0" cellpadding="0" border="0">
		                              <tbody>
		                                <tr>
		                                  <td width="120">URL:</td>
		                                  <td width="170"><input onkeydown="if(event.keyCode==13)return false" maxlength="31" size="30" name="url"></td>
		                                  <td width="5"></td>
		                                  <td><input onclick="btnAdd()" type="button" class="BtnApply" value="���"></td>
		                                </tr>
		                              </tbody>
		                            </table>
		                          </div>
		                          <br>
		                          <br>
		                          
								  <table class="tblList" id="rulelst" border="1">
									<tbody>
										<tr>
											<td class="table_title" align="middle" width="60"><strong>�� ��</strong></td>
											<td width="180" align="center" class="table_title"><strong><font color="#000000">URL</font></strong></td>
											<td class="table_title" align="middle" width="60"><strong><font color="#000000">ɾ ��</font></strong></td>
										</tr>
									</tbody>
								  </table>
		                          
		                          <br>
		                          <input onclick="on_action('rm')" type="button" class="BtnApply" value="ɾ��">
		                        </div>
		                       </td>
		                    </tr>
		                  </tbody>
		                </table>
		                <br>
		                <input type="hidden" id="action" name="action" value="none">
						<input type="hidden" name="bcdata" value="le">
						<input type="hidden" name="submit-url" value="">
	              </td>
		          </tr>
			  </tbody>
			</table>	
			</div>
          	<div>
    		<p align="center">
				<img id="btnOK" onclick="on_action('sw')" src="/image/ok_cmcc.gif" border="0">
				<img id="btnCancel" onclick="RefreshPage()" src="/image/cancel_cmcc.gif" border="0">
			</p>
         	</div>
		</form>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

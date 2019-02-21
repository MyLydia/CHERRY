<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>广域网访问设置</TITLE>
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
			alert("最多能设置100条记录!")
			return;
		}
		if (url.value.length > 31)
		{
			alert("URL长度不能超过31个字符!")
			return;
		}
		if(isValidUrlName(url.value) == false)
		{
			alert("非法的URL格式，请重新输入.")
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
				alert("相同的URL过滤规则已存在！");
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
			if (confirm("改变过滤模式将切换所有过滤规则，您是否真的要改变过滤模式为黑名单？"))
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
			if (confirm("改变过滤模式将切换所有过滤规则，您是否真的要改变过滤模式为白名单？"))
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
<!--主页代码-->
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
		                              URL过滤开关:
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
		                        		设置URL过滤模式以及过滤名单。（可设置100条）<br>
		                          		单击“更改模式”按钮改变URL过滤模式；<br>
		                          		单击“添加”按钮增加一条URL到对应的URL列表；单击“删除”按钮删除一条URL，<br>
		                         		URL不要带http://，URL长度不能超过31个字符。 <br>
		                          		<script language="JavaScript" type="text/javascript">
											if(cgi.urlFilterMode==false)
											{
												document.write('当前的过滤列表为：<B>黑名单</B>\n');
											}
											else
											{
												document.write('当前的过滤列表为：<B>白名单</B><BR>\n');
												document.write('<font color="#FF0000">提示：填入的URL将与您访问的URL做完全匹配</font>');
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
                          				黑白名单模式：
		                          		</td>
		                          		<td>
				                        	<input id="urlFilterMode" onclick="ChangePolicy()" type="radio" value="off" name="urlFilterMode">
				                          	黑名单
				                          	<input id="urlFilterMode" onclick="ChangePolicy()" type="radio" value="on" name="urlFilterMode">
				                          	白名单
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
		                                  <td><input onclick="btnAdd()" type="button" class="BtnApply" value="添加"></td>
		                                </tr>
		                              </tbody>
		                            </table>
		                          </div>
		                          <br>
		                          <br>
		                          
								  <table class="tblList" id="rulelst" border="1">
									<tbody>
										<tr>
											<td class="table_title" align="middle" width="60"><strong>序 号</strong></td>
											<td width="180" align="center" class="table_title"><strong><font color="#000000">URL</font></strong></td>
											<td class="table_title" align="middle" width="60"><strong><font color="#000000">删 除</font></strong></td>
										</tr>
									</tbody>
								  </table>
		                          
		                          <br>
		                          <input onclick="on_action('rm')" type="button" class="BtnApply" value="删除">
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

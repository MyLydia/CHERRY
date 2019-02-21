<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_PACKET_DUMP); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_PACKET_DUMP); %></h2>

<form action=/boaform/formCapture method=POST name="ping">
<table>
  <tr><td><font size=2>
	<% multilang(LANG_THIS_PAGE_IS_USED_TO_START_OR_STOP_A_WIRESHARK_PACKET_CAPTURE); %><br>
    <% multilang(LANG_YOU_NEED_TO_RETURN_TO_THIS_PAGE_TO_STOP_IT); %><br>
	<a href ="http://www.tcpdump.org/tcpdump_man.html" target=_blank"><% multilang(LANG_CLICK_HERE_FOR_THE_DOCUMENTATION_OF_THE_ADDITIONAL_ARGUMENTS); %></a>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>

<table>
  <tr>
      <th><% multilang(LANG_ADDITIONAL_ARGUMENTS); %>:</th>
      <td><input type="text" name="tcpdumpArgs" value="-s 1500" size="50" maxlength="50"></td>
      <input type="hidden" value="yes" name="dostart">
  </tr>

</table>

  <br>
      <input type="submit" value="<% multilang(LANG_START); %>" name="start">
      <input type="hidden" value="/pdump.asp" name="submit-url">
 </form>
<p>

<form action=/boaform/formCapture method=POST name="ping">
      <input type="submit" value="<% multilang(LANG_STOP); %>" name="stop">
      <input type="hidden" value="/pdump.asp" name="submit-url">
      <input type="hidden" value="no" name="dostart">
 </form>


</blockquote>
</body>

</html>

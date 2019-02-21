<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_GPON_SETTINGS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT>
function BundleAction(name,act, bid)
{
	document.osgimgt.bundle_name.value=name;	
	document.osgimgt.bundle_action.value=act;	
	document.osgimgt.bundle_id.value=bid;	
}
</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_BUNDLE_MANAGEMENT); %></h2>
<form action=/boaform/admin/formOsgiMgt method=POST name="osgimgt">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_MANAGE_OSGI_BUNDLES); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<input type="hidden" value="" name="bundle_name">
<input type="hidden" value="" name="bundle_action">
<input type="hidden" value="" name="bundle_id">
  <% getOSGIBundleList("1"); %>
</form>
</blockquote>
</body>
</html>

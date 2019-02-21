<html><! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta charset="utf-8">
<title>Html Wizard</title>
<link rel="stylesheet" href="reset.css">
<link rel="stylesheet" href="base.css">
<link rel="stylesheet" href="style.css">
<style>
.wizard_page{
   margin: 0 auto;
   width: 960px;
   height: 100%;
}
</style>
</head>
<body onload="init()">
<div id="header">
  	<div align="left">
   		<img width="231" height="103" src="./graphics/wizard.jpg">
  	</div>
</div>
<div class="wizard_page">
  	<iframe src=<% getTroubleInitUrl(); %> scrolling="no" frameborder="0" height="100%" id="mainFrame" width="100%%"></iframe>
</div>
</body>
</html>

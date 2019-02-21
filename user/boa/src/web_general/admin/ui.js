
function interlace(table) {
    var $table = $(table);
    var $tr = $table.find('tr');
    $tr.filter(':odd').addClass('odd');
    $tr.filter(':even').addClass('even');
}
function preloadImage(imgArray, path) {
 imgArray = imgArray || [];
 path = path || '';
 for (var i = 0; i < imgArray.length; i++) {
  var image = new Image();
  image.src = path + imgArray[i];
 }
}







function enableOrDisable(scope, filter, isChecked) {
    $(scope).find(':input').not(filter).prop('disabled', isChecked);
}

function showOrHide(scope, filter, isChecked) {
    var status = isChecked ? 'hide' : 'show';
    $(scope).not(filter)[status]();
}

var itemMap = {
    '1': 'enableOrDisable',
    '2': 'showOrHide'
};

function handleItems(ele, options) {
    var defaults = {
        scope: document,
        type: 1,
        filter: ele,
        reverse: false
    };
    var checked = false;
    options = $.extend(defaults, options);

    $(ele).bind('change', function() {
        checked = options.reverse ? !this.checked : this.checked;
        window[itemMap[options.type]](options.scope, options.filter, checked);
    });
}

var iframeHeight = 0, currentHeight = 0, timer;
function computeIframe(ele) {
 ele = ele || '#contentIframe';
 var $iframe = $(ele, top.document);
 var iframeDocument = $iframe[0].contentWindow.document;

 var currentHeight = iframeDocument.body && iframeDocument.body.clientHeight || 0;

 if (iframeHeight !== currentHeight) {
  $iframe.height(currentHeight);
  iframeHeight = currentHeight;
 }
 if (timer) {
  clearTimeout(timer);
  timer = null;
 }
  timer = setTimeout(function() {
  computeIframe(ele);
 }, 500);

}

function isIE() {
 return navigator.userAgent.indexOf("MSIE") > 0 ? true : false;
}
function isIE6() {
 return navigator.userAgent.indexOf("MSIE 6.0") > 0 ? true : false;
}
function getinput(){
 if (!isIE() || !isIE6()) return [];
 var list = document.getElementsByTagName("input");
 var inputText = [];
 for (var i = 0; i < list.length; i++){
  if (list[i].type == "text" || list[i].type == "password"){
   inputText.push(list[i]);
   list[i].className = "input_iesix";
  }
 }
 return inputText;
}



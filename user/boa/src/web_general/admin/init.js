






function preventDefault(e) {
    e = e || window.event;

    if (e.preventDefault) {
        e.preventDefault();
    } else {
        e.returnValue = false;
    }
}

function stopPropagation(e) {
    e = e || window.event;

    if (e.stopPropagation) {
        e.stopPropagation();
    } else {
        e.cancelBubble = true;
    }
}

function serialize(obj) {
    var str = '';
    var item = [];
    for (var key in obj) {
        if (obj.hasOwnProperty(key)) {
            item.push(encodeURIComponent(key) + '=' + encodeURIComponent(obj[key]));
        }
    }
    str = item.join('&');
    return str;
}
function formObj(form) {
    var obj = {};
    var elements = form.elements;

    for (var i = 0; i < elements.length; i++) {

        if (elements[i].nodeName.toLowerCase() === 'button') {
            continue;
        }
        if (/button|image|submit/i.test(elements[i].type)) {
            continue;
        }

        obj[elements[i].name] = elements[i].value;

    }
    return obj;
}
function formSerialize(formObj) {
    return serialize(formObj);
}

$(function() {


    renderNav();

    $('#nav a').bind('click', function(e) {
        preventDefault(e);

        var rel = this.rel;
        var items = $('#nav').find('a');

        renderSide(rel);

        setActive(items, this);


        $('#side li ul li a').unbind().bind('click', function (e) {
            preventDefault(e);

            var items = $('#side li ul li a');

            setActive(items, this);

            var src = $(this).attr('href') + '?v=' + Date.parse(new Date());

            $('#contentIframe').attr('src', src);

        });

        $('#side li ul li a:first').trigger('click');


        $('#side > li h3 a').unbind().bind('click', function(e) {
            preventDefault(e);
            setAccordion(this);

            var $first = $(this).parents('li').find('> ul > li:first > a');
            $first.trigger('click');
            return false;
        });

        return false;
    });
var index=0;


  $('#nav a').eq(index).trigger('click');


    $('#contentIframe').bind('load', function() {

   var $attention = $('#attention');
  $('form', $attention).unbind('submit').bind('submit', function(e) {

   preventDefault(e);

   var self = this;

            var data = formObj(self);

   $.ajax(self.action, {
    cache: false,
    type: 'post',
    data: data,
    success: function() {
     $attention.hide();
    },
    error: function() {
     $attention.hide();
    }
   });
            return false;
  });
        computeIframe();
    });
});



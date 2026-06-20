/*-----------------------------------------------------------------------------------
/*
/* Init JS
/*
-----------------------------------------------------------------------------------*/

 jQuery(document).ready(function($) {

/*----------------------------------------------------*/
/* FitText Settings
------------------------------------------------------ */

    setTimeout(function() {
	   $('h1.responsive-headline').fitText(1, { minFontSize: '38px', maxFontSize: '84px' });
	 }, 100);


/*----------------------------------------------------*/
/* Smooth Scrolling
------------------------------------------------------ */

   $('.smoothscroll').on('click',function (e) {
	    e.preventDefault();

	    var target = this.hash,
	    $target = $(target);

	    $('html, body').stop().animate({
	        'scrollTop': $target.offset().top
	    }, 800, 'swing', function () {
	        window.location.hash = target;
	    });
	});


/*----------------------------------------------------*/
/* Highlight the current section in the navigation bar
------------------------------------------------------*/

	var sections = $("section");
	var navigation_links = $("#nav-wrap a");

	sections.waypoint({

      handler: function(event, direction) {

		   var active_section;

			active_section = $(this);
			if (direction === "up") active_section = active_section.prev();

			var active_link = $('#nav-wrap a[href="#' + active_section.attr("id") + '"]');

         navigation_links.parent().removeClass("current");
			active_link.parent().addClass("current");

		},
		offset: '35%'

	});


/*----------------------------------------------------*/
/*	Make sure that #header-background-image height is
/* equal to the browser height.
------------------------------------------------------ */

   $('header').css({ 'height': $(window).height() });
   $(window).on('resize', function() {

        $('header').css({ 'height': $(window).height() });
        $('body').css({ 'width': $(window).width() })
   });


/*----------------------------------------------------*/
/*	Fade In/Out Primary Navigation
------------------------------------------------------*/

   $(window).on('scroll', function() {

		var h = $('header').height();
		var y = $(window).scrollTop();
      var nav = $('#nav-wrap');

	   if ( (y > h*.20) && (y < h) && ($(window).outerWidth() > 768 ) ) {
	      nav.fadeOut('fast');
	   }
      else {
         if (y < h*.20) {
            nav.removeClass('opaque').fadeIn('fast');
         }
         else {
            nav.addClass('opaque').fadeIn('fast');
         }
      }

	});


/*----------------------------------------------------*/
/*	Modal Popup
------------------------------------------------------*/

    $('.item-wrap a').magnificPopup({

       type:'inline',
       fixedContentPos: false,
       removalDelay: 200,
       showCloseBtn: false,
       mainClass: 'mfp-fade'

    });

    $(document).on('click', '.popup-modal-dismiss', function (e) {
    		e.preventDefault();
    		$.magnificPopup.close();
    });


/*----------------------------------------------------*/
/*	Flexslider
/*----------------------------------------------------*/
   $('.flexslider').flexslider({
      namespace: "flex-",
      controlsContainer: ".flex-container",
      animation: 'slide',
      controlNav: true,
      directionNav: false,
      smoothHeight: true,
      slideshowSpeed: 7000,
      animationSpeed: 600,
      randomize: false,
   });

/*----------------------------------------------------*/
/*	iOS fixed background fallback
/*----------------------------------------------------*/

   (function() {
      var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) ||
         (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
      var style = document.documentElement.style;
      var canClip = ('clipPath' in style) || ('webkitClipPath' in style);

      if (!isIOS || !canClip) return;

      var backgrounds = [
         {
            section: document.querySelector('header'),
            className: 'ios-fixed-bg--home'
         },
         {
            section: document.querySelector('#testimonials'),
            className: 'ios-fixed-bg--testimonials'
         }
      ].filter(function(item) {
         return item.section;
      }).map(function(item) {
         var layer = document.createElement('div');
         layer.className = 'ios-fixed-bg ' + item.className;
         layer.setAttribute('aria-hidden', 'true');
         document.body.insertBefore(layer, document.body.firstChild);
         item.layer = layer;
         return item;
      });

      if (!backgrounds.length) return;

      document.documentElement.classList.add('ios-fixed-bg-enabled');

      var ticking = false;

      function viewportHeight() {
         return window.visualViewport ? window.visualViewport.height : window.innerHeight;
      }

      function updateFixedBackgrounds() {
         ticking = false;

         var height = viewportHeight();
         document.documentElement.style.setProperty('--ios-fixed-bg-height', height + 'px');

         backgrounds.forEach(function(item) {
            var rect = item.section.getBoundingClientRect();
            var top = Math.max(0, rect.top);
            var bottom = Math.min(height, rect.bottom);

            if (bottom <= 0 || top >= height) {
               item.layer.style.opacity = '0';
               item.layer.style.clipPath = 'inset(0 0 100% 0)';
               item.layer.style.webkitClipPath = 'inset(0 0 100% 0)';
               return;
            }

            var clip = 'inset(' + top + 'px 0 ' + (height - bottom) + 'px 0)';
            item.layer.style.opacity = '1';
            item.layer.style.clipPath = clip;
            item.layer.style.webkitClipPath = clip;
         });
      }

      function requestUpdate() {
         if (ticking) return;
         ticking = true;
         window.requestAnimationFrame(updateFixedBackgrounds);
      }

      updateFixedBackgrounds();
      $(window).on('scroll resize orientationchange', requestUpdate);

      if (window.visualViewport) {
         window.visualViewport.addEventListener('resize', requestUpdate);
         window.visualViewport.addEventListener('scroll', requestUpdate);
      }
   })();

/*----------------------------------------------------*/
/*	contact form
------------------------------------------------------*/

   $('form#contactForm button.submit').click(function() {

      $('#image-loader').fadeIn();

      var contactName = $('#contactForm #contactName').val();
      var contactEmail = $('#contactForm #contactEmail').val();
      var contactSubject = $('#contactForm #contactSubject').val();
      var contactMessage = $('#contactForm #contactMessage').val();

      var data = 'contactName=' + contactName + '&contactEmail=' + contactEmail +
               '&contactSubject=' + contactSubject + '&contactMessage=' + contactMessage;

      $.ajax({

	      type: "POST",
	      url: "inc/sendEmail.php",
	      data: data,
	      success: function(msg) {

            // Message was sent
            if (msg == 'OK') {
               $('#image-loader').fadeOut();
               $('#message-warning').hide();
               $('#contactForm').fadeOut();
               $('#message-success').fadeIn();   
            }
            // There was an error
            else {
               $('#image-loader').fadeOut();
               $('#message-warning').html(msg);
	            $('#message-warning').fadeIn();
            }

	      }

      });
      return false;
   });


});









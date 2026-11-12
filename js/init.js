document.documentElement.classList.add("js");

/*-----------------------------------------------------------------------------------
/*
/* Init JS
/*
-----------------------------------------------------------------------------------*/

 jQuery(document).ready(function($) {

   const nav = $('#nav-wrap');
   const menuButton = document.querySelector('.mobile-btn');
   const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
   const syncMotion = () => { $.fx.off = reducedMotion.matches; };
   syncMotion();
   reducedMotion.addEventListener('change', syncMotion);

   function setMenu(open) {
      nav.toggleClass('menu-open', open);
      menuButton.setAttribute('aria-expanded', String(open));
      menuButton.setAttribute('aria-label', open ? 'Hide navigation' : 'Show navigation');
   }
   menuButton.addEventListener('click', () => setMenu(menuButton.getAttribute('aria-expanded') !== 'true'));
   $('#nav a').on('click', () => setMenu(false));
   nav.on('keydown', event => {
      if (event.key === 'Escape' && menuButton.getAttribute('aria-expanded') === 'true') {
         setMenu(false);
         menuButton.focus();
      }
   });
   matchMedia('(min-width: 768px)').addEventListener('change', () => setMenu(false));

/*----------------------------------------------------*/
/* Highlight the current section in the navigation bar
------------------------------------------------------*/

	var sections = $("header#home, main > section");
	var navigation_links = $("#nav a");

	sections.waypoint({

      handler: function(event, direction) {

		   var active_section;

			active_section = $(this);
			if (direction === "up") active_section = sections.eq(Math.max(0, sections.index(this) - 1));

			var active_link = $('#nav-wrap a[href="#' + active_section.attr("id") + '"]');

         navigation_links.parent().removeClass("current");
         navigation_links.removeAttr("aria-current");
			active_link.parent().addClass("current");
         active_link.attr("aria-current", "location");

		},
		offset: '35%'

	});


/*----------------------------------------------------*/
/*	Fade In/Out Primary Navigation
------------------------------------------------------*/

   $(window).on('scroll', function() {

		var h = $('header').height();
		var y = $(window).scrollTop();
      var nav = $('#nav-wrap');

	   if ( (y > h*.20) && (y < h) && ($(window).outerWidth() > 768 ) && !nav.find(':focus').length ) {
	      nav.stop(true, true).fadeOut('fast');
	   }
      else {
         if (y < h*.20) {
            nav.removeClass('opaque').stop(true, true).fadeIn('fast');
         }
         else {
            nav.addClass('opaque').stop(true, true).fadeIn('fast');
         }
      }

	});


   document.querySelectorAll('.item-wrap a[data-dialog]').forEach(link => {
      const dialog = document.getElementById(link.dataset.dialog);
      link.addEventListener('click', event => {
         if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || !dialog.showModal) return;
         event.preventDefault();
         dialog.showModal();
      });
   });

   // Safari keeps click-outside dismissal until closedby is supported.
   if (!('closedBy' in HTMLDialogElement.prototype)) {
      const outside = (event, dialog) => {
         const rect = dialog.getBoundingClientRect();
         return event.clientX < rect.left || event.clientX > rect.right ||
            event.clientY < rect.top || event.clientY > rect.bottom;
      };
      document.querySelectorAll('dialog[closedby="any"]').forEach(dialog => {
         let pressedOutside = false;
         dialog.addEventListener('pointerdown', event => { pressedOutside = outside(event, dialog); });
         dialog.addEventListener('pointerup', event => {
            if (pressedOutside && outside(event, dialog)) dialog.close();
            pressedOutside = false;
         });
      });
   }
});

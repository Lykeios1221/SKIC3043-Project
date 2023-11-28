$(document).ready(function () {
    // hide initially to appear with fade effect later
    $('.tooltiptext').hide();

// Make tooltips appear on hover
    $('.hover-fade-in-out').hover(function () {
        $(this).children('.tooltiptext').fadeIn('fast');
    }, function () {
        $(this).children('.tooltiptext').fadeOut('fast');
    });
})
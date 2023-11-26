$(document).ready(function () {
    // hide initially to appear with fade effect later
    $('.tooltiptext').hide();

    // Intercept the sign-up form submission for verification
    $("#signup_form").on('submit', function (e) {
        e.preventDefault();
        $.ajax({
            url: '/verify_email_duplicate',
            type: 'GET',
            data: {email: $(this).serializeArray()[2].value},
            dataType: 'text',
            contentType: 'text/plain',
            success: function (result) {
                let emailTooltip = $("#email_tooltip");
                let emailBorder = emailTooltip.siblings('input[type="email"]');

                if (result === 'True') { // Duplicated Email
                    emailTooltip.css('width', '180px')
                    emailTooltip.text('Email has been registered.');
                    emailTooltip.fadeIn('fast')
                    emailBorder.animate({borderColor: 'red'}, 'fast');
                    setTimeout(function () {
                        emailTooltip.fadeOut('slow')
                        emailBorder.animate({borderColor: 'transparent'}, 'slow');
                    }, 2000);
                } else if (result === 'False') { //Email available
                    $(this).off('submit').submit();
                } else if (result === 'Verifying') {
                    emailTooltip.css('width', '210px')
                    emailTooltip.text('Email is waiting for verification.');
                    emailTooltip.fadeIn('fast')
                    emailBorder.animate({borderColor: 'red'}, 'fast');
                    setTimeout(function () {
                        emailTooltip.fadeOut('slow')
                        emailBorder.animate({borderColor: 'transparent'}, 'slow');
                    }, 2000);
                } else if (result === 'Error') {
                    let errorMessage = "Unexpected error! Please try again later.";
                    $("#errorMessage").text(errorMessage);
                    $("#errorDialog").dialog("open");
                }
            }.bind(this),
            error: function (error) {
                console.log(error);
            }
        });
    });

    // Make tooltips appear on hover
    $('.hover-fade-in-out').hover(function () {
        $(this).children('.tooltiptext').fadeIn('fast');
    }, function () {
        $(this).children('.tooltiptext').fadeOut('fast');
    });

    // Config error dialog
    $("#errorDialog").dialog({
        autoOpen: false,
        modal: true,
        draggable: false,
        classes: {
            "ui-dialog": "ui-corner-all",
            "ui-dialog-titlebar": "ui-state-error",
        },
        show: {
            effect: "fade",
            duration: 500
        },
        hide: {
            effect: "fade",
            duration: 500
        },
    });
    $('#errorDialog').siblings(".ui-dialog-titlebar").prepend("<span class='ui-icon ui-icon-alert' style='float:left;margin: 4px 4px 0px -2px;'></span>");
});
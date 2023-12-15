function addActive(element) {
    scrollEnabled = false;
    $('#sidebar-func .sidebar-link').each(function (index, item) {
        $(item).removeClass('active')
    });

    setTimeout(function () {
        scrollEnabled = true;
    }, 300); // Enable scrolling after 3 second
    $(element).addClass('active')
}

const responsiveConfig = {
    details: {
        display: DataTable.Responsive.display.modal({
            header: function (row) {
                const data = row.data();
                return 'Details for item';
            }
        }), renderer: function (api, rowIdx, columns) {
            const clonedColumns = columns.slice(1);

            // Render the details in the modal with the modified columns array
            const data = $.map(clonedColumns, function (col, i) {
                return `<tr data-dt-row="${col.rowIndex}" data-dt-column="${col.columnIndex}">
                <td>${col.title}</td>
                <td>${col.data}</td>
            </tr>`;
            }).join('');


            return $('<table class="table"/>').append(data);
        }
    }
};

$(document).ready(function () {
    $('a[href^="#section-revenues"]').trigger('click')

    $('.jDataTable').each(function (i, item) {
        $(item).DataTable({
            responsive: responsiveConfig,
            columnDefs: [{
                targets: 0, searchable: false, orderable: false, className: 'dt-body-left'
            },],
            "order": [[1, 'asc']],
        })
    });

    // Add an event listener for scroll events
    $(window).scroll(function () {
        if (!scrollEnabled) {
            return; // Do nothing if scrolling is disabled
        }
        // Get the current scroll position
        var scrollPosition = $(window).scrollTop();

        // Iterate through each section to check its position
        $('section').each(function () {
            var sectionTop = $(this).offset().top - 200;
            var sectionBottom = sectionTop + $(this).outerHeight();

            // Check if the scroll position is within the section
            if (scrollPosition >= sectionTop && scrollPosition <= sectionBottom) {
                // Remove the active class from all links
                $('#sidebar-func .sidebar-link').not('a[href="#' + $(this).attr('id') + '"]').removeClass('active');
                // Add the active class to the link corresponding to the current section
                var targetLink = $('a[href="#' + $(this).attr('id') + '"]');
                targetLink.addClass('active');
            }
        });
    });

});

const getPdf = (type, id, email) => $.ajax({
    url: '/send_pdf',
    data: {'filename': `${type}_${id}`, 'email': email},
    xhrFields: {
        responseType: 'blob'
    }
})

function viewPdf(type, id, email) {
    getPdf(type, id, email)
        .then(function (pdfURL) {
            window.open(URL.createObjectURL(pdfURL), '_blank')
        })
}

let isButtonClicked = false;
let isModalBlocked = true;
let manualShow = false;

$('.jDataTable').on('click', 'td', function (e) {
    isButtonClicked = !!$(e.target).is('.btn');
    isModalBlocked = false;
});

$(document).on('show.bs.modal', '.dtr-bs-modal', function (e) {
    isModalBlocked = true;
    if (!manualShow) {
        e.preventDefault();
    }

    function checkModalBlocked() {
        if (isModalBlocked) {
            setTimeout(checkModalBlocked, 10);
        } else {
            if (!isButtonClicked) {
                manualShow = true;
                $('.dtr-bs-modal').modal('show')
            } else {
                isButtonClicked = false;
                $('.dtr-bs-modal').modal('hide')
            }
        }
    }

    if (!manualShow) {
        checkModalBlocked();
    }
    manualShow = false;
});

$('.dtr-bs-modal').on('hidden.bs.modal', function () {
    isButtonClicked = false;
});

var confirmDeleteDialog = (type, id) => `
<input type="hidden" name="type" value="${type}">
<input type="hidden" name="id" value="${id}">
<div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
        <div class="modal-header border-bottom border-dark border-opacity-50">
            <h5 class="modal-title">Delete ${type} of id ${id}</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body container-fluid">
            <label class="form-label w-100 my-2">To confirm, type "${type}_${id}" in the box below</label>
            <input type="text" class="form-control form-delete border-2" oninput="checkInputMatch('${type}_${id}')" id="confirm-box">
            <div class="form-text text-danger">Please note that your action will be logged and cannot be undone.</div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            <button type="submit" class="btn btn-danger" id="submit-delete" disabled>Confirm</button>
        </div>
    </div>
</div>
`

const confirmApproveDialog = (type, id, link) => `
<input type="hidden" name="type" value="${type}">
<input type="hidden" name="id" value="${id}">
<div class="modal-dialog modal-dialog-centered modal-fullscreen p-5">
    <div class="modal-content rounded-3">
        <div class="modal-header border-bottom border-dark border-opacity-50">
            <h5 class="modal-title">Approve ${type} of id ${id}</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body container-fluid">
            <div class="embed-responsive h-100 overflow-hidden mb-2" style="height: 90%!important;">
                <iframe class="embed-responsive-item w-100 h-100" src="${link}"></iframe>
            </div>
            <input class="form-check-input border-dark mx-2" type="checkbox" value="" id="flexCheckDefault" required>
            <label class="form-check-label" for="flexCheckDefault">
                I have read all information carefully and confirm that the details are correct.
            </label>
            <div class="form-text ms-2 text-danger">Please note that your action will be logged and cannot be undone.</div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            <button type="submit" class="btn btn-danger" id="submit-delete">Confirm</button>
        </div>
    </div>
</div>
`

function setDeleteModal(type, id) {
    const modal = $('#confirmation-modal')
    modal.attr('action', '/delete_item')
    modal.removeClass('modal-fullscreen m-5')
    modal.html(confirmDeleteDialog(type, id))
    modal.modal('show')
}

function checkInputMatch(text) {
    var inputText = $('#confirm-box').val();
    var submitButton = $('#submit-delete');

    var expectedText = text;
    if (inputText === expectedText) {
        submitButton.prop('disabled', false);
    } else {
        submitButton.prop('disabled', true);
    }
}

function setApproveModal(type, id, email) {
    const modal = $('#confirmation-modal')
    modal.attr('action', '/approve_asset')
    getPdf(type, id, email).then(function (pdfData) {
        modal.html(confirmApproveDialog(type, id, URL.createObjectURL(pdfData)))
        modal.modal('show')
    })
}

function setModalInfo(modal, data) {
    Object.keys(data).forEach(function (key) {
        const field = $(modal).find(`[name="${key}"]`);
        field.val(data[key] === 'None' ? '' : data[key]).change()
    });
}

function setProfileModal(userDict) {
    const modal = $('#edit-user-modal')
    console.log(userDict)
    setModalInfo(modal, userDict)
    modal.modal('show')
}
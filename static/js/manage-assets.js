$(document).ready(function () {
    // Initialize storage
    const userAssets = JSON.parse($('#userAssets').attr('data-assets').replace(/'/g, '"'));
    const revenues = JSON.parse(JSON.stringify(userAssets.revenues));
    const inventories = JSON.parse(JSON.stringify(userAssets.inventories));
    const expenses = JSON.parse(JSON.stringify(userAssets.expenses));
    let storageIndex = {'revenue': 0, 'expense': 0, 'inventory': 0};
    initializeTables();

    // Manage modify/delete requests from revenues table
    $(document).on('submit', '.revenue-row-form', function (evt) {
        processRowFormSubmit(evt, 'revenue', $(this), revenues);
    });

    // Manage modify/delete requests from expenses table
    $(document).on('submit', '.expense-row-form', function (evt) {
        processRowFormSubmit(evt, 'expense', $(this), expenses);
    });

    // Manage modify/delete requests from inventories table
    $(document).on('submit', '.inventory-row-form', function (evt) {
        processRowFormSubmit(evt, 'inventory', $(this), inventories);
    });

    function processRowFormSubmit(evt, type, form, storage) {
        evt.preventDefault();
        const formArgs = form.serializeArray()[0];
        const action = document.querySelector('button[name="action"]:focus').value;
        const data = JSON.parse(formArgs.value.replace(/'/g, '"'));
        const table = $(`#${type}-table`).DataTable();
        if (action === 'delete') {
            removeRowFromTable(table, form);
            removeFromStorage(storage, data.id);
        } else if (action === 'modify') {
            const modal = $(`#${type}-modal`);
            setModalInfo(modal, data);
        }
    }


    $('#revenue-form').on('submit', function (evt) {
        processAssetsSubmitForm(evt, 'revenue', $(this), revenues);
    })

    $('#expense-form').on('submit', function (evt) {
        processAssetsSubmitForm(evt, 'expense', $(this), expenses);
    })

    $('#inventory-form').on('submit', function (evt) {
        processAssetsSubmitForm(evt, 'inventory', $(this), inventories);
    })

    async function processAssetsSubmitForm(evt, type, form, storage) {
        evt.preventDefault();
        const dataDict = formMapToDict(form);
        const inputElement = $(`#${type}File`)[0];
        const id = dataDict.id === ''? 'temp_' + storageIndex[type]: dataDict.id;
        const valid = await validatePDF(`${type}_${id}`, inputElement);
        if (valid) {
            const table = $(`#${type}-table`).DataTable();
            let rowIndex = undefined;
            if (dataDict.id === '') {
                dataDict['id'] = id;
                storageIndex[type]++;
            } else {
                removeFromStorage(storage, dataDict['id'])
                rowIndex = table.column(1).data().indexOf(String(dataDict['id']));
            }
            storage.push(dataDict);
            const rowForm = generateRowForm(type, dataDict);
            drawTableRow(table, rowForm, excludeEntryByKey(dataDict, 'email').map(e => e[1]), rowIndex);
            $(`#${type}-modal`).modal('hide');
        } else {
            $(inputElement).parent().find('.invalid-feedback').hide().fadeIn('fast').delay(3000).fadeOut('fast');
        }
    }

    function validatePDF(key, inputElement) {
        return new Promise(function (resolve, reject) {
            const formData = new FormData();
            formData.append(key, inputElement.files[0]);
            $.ajax({
                type: 'post',
                url: 'validate_pdf',
                contentType: false,
                processData: false,
                data: formData
            }).done(function (response) {
                const valid = response['result'];
                resolve(valid);
            }).fail(function () {
                reject("Validation failed due to AJAX error.");
            });
        });
    }

    function generateRowForm(dataType, dataDict) {
        return `
        <form method="GET" class="${dataType}-row-form">
            <input type="hidden" name="data" value='${JSON.stringify(dataDict)}'>
            <button type="submit" name="action" value="delete" class="btn btn-danger">Delete</button>
            <button type="submit" name="action" value="modify" class="btn btn-secondary m-1"
                    data-bs-target="#${dataType}-modal" data-bs-toggle="modal">Modify</button>
        </form>
    `;
    }

    function excludeEntryByKey(dict, key) {
        return Object.entries(dict)
            .filter(entry => !entry[0]
                .includes(key));
    }

    function formMapToDict(form) {
        const resultDict = {};
        form.serializeArray().forEach((dict) => {
            resultDict[dict['name']] = dict['value'];
        });
        return resultDict;
    }

    function drawTableRow(table, form, data, index) {
        if (index === undefined) {
            table.row.add([form, ...data]).draw();
        } else {
            table.row(index).data([form, ...data]).draw();
        }
    }

    function findDictById(arrayOfDicts, idToFind) {
        return arrayOfDicts.find(function (dict) {
            return String(dict['id']) === String(idToFind);
        });
    }

    function removeRowFromTable(table, form) {
        table.row($(form).parents('tr'))
            .remove()
            .draw();
    }

    function removeFromStorage(storage, id) {
        const matchDict = findDictById(storage, id)
        for (let i = 0; i < storage.length; i++) {
            if (storage[i] === matchDict) {
                storage.splice(i, 1);
                i--;
                break;
            }
        }
    }

    function setModalInfo(modal, data) {
        Object.keys(data).forEach(function (key) {
            const field = $(modal).find(`[name="${key}"]`);
            field.val(data[key]).change()
        });
    }

    function initializeTables() {
        const responsiveConfig = {
            details: {
                display: DataTable.Responsive.display.modal({
                    header: function (row) {
                        const data = row.data();
                        return 'Details for item';
                    }
                }), renderer: function (api, rowIdx, columns) {
                    // Clone the columns and remove the last column (button column) from the cloned array
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
        $('.jDataTable').each(function () {
            $(this).DataTable({
                responsive: responsiveConfig, dom: '<"row"<"col-md-12"B>>' +  // New DOM structure
                    '<"row"<"col-md-6"l><"col-md-6"f>>' +// New DOM structure
                    '<"row"<"col-md-12"tr>>' + // New DOM structure
                    '<"row"<"col-md-5"i><"col-md-7"p>>', // New DOM structure
                buttons: [{
                    extend: 'copy', exportOptions: {
                        columns: ':not(:eq(0))' // Exclude column 1
                    }
                }, {
                    extend: 'csv', exportOptions: {
                        columns: ':not(:eq(0))' // Exclude column 1
                    }
                }, {
                    extend: 'excel', exportOptions: {
                        columns: ':not(:eq(0))' // Exclude column 1
                    }
                }, {
                    extend: 'pdf', exportOptions: {
                        columns: ':not(:eq(0))' // Exclude column 1
                    }
                }, {
                    extend: 'print', exportOptions: {
                        columns: ':not(:eq(0))' // Exclude column 1
                    }
                }], columnDefs: [{
                    targets: 0, searchable: false, orderable: false, className: 'dt-body-left'
                },], "order": [[1, 'asc']],
            });
        });
    }

    $('.modal').on('hidden.bs.modal', function () {
        $(this).find('form').trigger('reset');
        $(this).find('form').find("select, input").val("");
    });


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

    $('#commitAssets').on('click', function () {
        var originalRevenues = JSON.parse(JSON.stringify(userAssets.revenues));
        var originalInventories = JSON.parse(JSON.stringify(userAssets.inventories));
        var originalExpenses = JSON.parse(JSON.stringify(userAssets.expenses));
        var revenueChanges = compareArrays(originalRevenues, revenues);
        var inventoryChanges = compareArrays(originalInventories, inventories);
        var expenseChanges = compareArrays(originalExpenses, expenses);

        var changes = {
            'revenueChanges': revenueChanges, 'expenseChanges': expenseChanges, 'inventoryChanges': inventoryChanges
        };
        sendChangesToServer(changes, "/manage_assets");
    });

    function compareArrays(originalArray, modifiedArray) {
        const additions = [];
        const modifications = [];
        // Check for additions and modifications
        for (const modifiedItem of modifiedArray) {
            const originalItem = originalArray.find(item => String(item.id) === String(modifiedItem.id));
            if (!originalItem) {
                additions.push(modifiedItem);
            } else {
                let modified = Object.keys(originalItem).some(function (key) {
                    console.log(originalItem[key])
                    console.log(modifiedItem[key])
                    return originalItem[key] !== modifiedItem[key];
                })
                if (modified) {
                    modifications.push(modifiedItem);
                }
            }
        }

        // Check for deletions
        const deletions = originalArray.filter(originalItem => !modifiedArray.some(modifiedItem => String(modifiedItem.id) === String(originalItem.id)));

        return {additions, modifications, deletions};
    }

    function sendChangesToServer(changes, url) {
        // Combine changes for all asset types into a single array
        $.ajax({
            type: 'POST',
            url: url,
            contentType: 'application/json',
            data: JSON.stringify(changes),
            success: function (response) {
                window.location.href = response
            },
            error: function (error) {
                window.location.href = error
            }
        });
    }

    $('#printAssets').on('click', function () {
        $.ajax({
            type: 'POST',
            url: '/get_print_assets',
            contentType: 'application/json',
            dataType: "html",
            data: JSON.stringify({'inventory': inventories, 'revenue': revenues, 'expense': expenses}),
            success: function (response) {
                var w = window.open();
                w.document.write(response);

            },
            error: function (error) {
                console.error(error);
            }
        });
    });
})
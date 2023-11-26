$(document).ready(function () {
    const responsiveConfig = {
        details: {
            display: DataTable.Responsive.display.modal({
                header: function (row) {
                    var data = row.data();
                    return 'Details for item';
                }
            }),
            renderer: function (api, rowIdx, columns) {
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

    const datatablesSimple = document.getElementsByClassName('jDataTable');

    if (datatablesSimple.length > 0) {
        for (let i = 0; i < datatablesSimple.length; i++) {
            const tableElement = datatablesSimple[i];
            var table = $(tableElement).DataTable({
                responsive: responsiveConfig,
                dom: '<"row"<"col-md-12"B>>' +  // New DOM structure
                    '<"row"<"col-md-6"l><"col-md-6"f>>' +// New DOM structure
                    '<"row"<"col-md-12"tr>>' + // New DOM structure
                    '<"row"<"col-md-5"i><"col-md-7"p>>', // New DOM structure
                buttons: [
                    {
                        extend: 'copy',
                        exportOptions: {
                            columns: ':not(:eq(0))' // Exclude column 1
                        }
                    },
                    {
                        extend: 'csv',
                        exportOptions: {
                            columns: ':not(:eq(0))' // Exclude column 1
                        }
                    },
                    {
                        extend: 'excel',
                        exportOptions: {
                            columns: ':not(:eq(0))' // Exclude column 1
                        }
                    },
                    {
                        extend: 'pdf',
                        exportOptions: {
                            columns: ':not(:eq(0))' // Exclude column 1
                        }
                    },
                    {
                        extend: 'print',
                        exportOptions: {
                            columns: ':not(:eq(0))' // Exclude column 1
                        }
                    }
                ],
                columnDefs: [
                    {
                        targets: 0,
                        searchable: false,
                        orderable: false,
                        className: 'dt-body-left'
                    },
                ],
                "order": [[1, 'asc']],
            });
        }
    }

    let isButtonClicked = false;
    let isModalBlocked = true;

    $('.jDataTable').on('click', 'td', function (e) {

        if ($(e.target).is('.btn-delete, .btn-modify')) {
            isButtonClicked = true;
        } else {
            isButtonClicked = false;
        }
        isModalBlocked = false;
    });

    let manualShow = false;

    $(document).on('show.bs.modal', '.dtr-bs-modal', function (e) {
        isModalBlocked = true;
        if (!manualShow) {
            e.preventDefault();
        }

        function checkModalBlocked() {
            if (isModalBlocked) {
                setTimeout(checkModalBlocked, 10); // Retry after a short delay
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
        // Reset the flag after the modal is hidden
        isButtonClicked = false;
    });

    var userAssets = JSON.parse($('#userAssets').attr('data-assets'));
    var revenues = JSON.parse(JSON.stringify(userAssets.revenues));
    var inventories = JSON.parse(JSON.stringify(userAssets.inventories));
    var expenses = JSON.parse(JSON.stringify(userAssets.expenses));

    var revTempCount = 0;
    var invTempCount = 0;
    var expTempCount = 0;
    var deleteButton = '<button type="button" class="btn btn-danger btn-delete btn-temp m-1" style="margin-right:13px!important;"> Delete </button>';
    var revenueModifyButton = '<button type="button"  class="btn btn-secondary btn-modify m-1 btn-temp" data-bs-target="#revenueModal" data-bs-toggle="modal"> Modify </button>';
    var expenseModifyButton = '<button type="button" class="btn btn-secondary btn-modify m-1 btn-temp" data-bs-target="#expenseModal" data-bs-toggle="modal"> Modify </button>';
    var invModifyButton = '<button type="button" class="btn btn-secondary btn-modify m-1 btn-temp" data-bs-target="#inventoryModal" data-bs-toggle="modal"> Modify </button>';


    $('#revenue_form').on('submit', function (e) {
        e.preventDefault();
        const newTempRev = {};
        $(this).serializeArray().forEach((list) => {
            newTempRev[list['name']] = list['value'];
        });
        if (newTempRev['id'] === '') {
            newTempRev['id'] = 'temp_' + revTempCount;
            revTempCount++;
            var table = $('#revenues_tb').DataTable();
            table.row.add([
                deleteButton + revenueModifyButton,
                newTempRev.id,
                newTempRev.description,
                newTempRev.type,
                newTempRev.total
            ]).draw();
            revenues.push(newTempRev)
        } else {
            var rev = findDictById(revenues, newTempRev['id'])
            rev['description'] = newTempRev['description'];
            rev['type'] = newTempRev['type'];
            rev['total'] = newTempRev['total'];
            var table = $('#revenues_tb').DataTable();
            var rowIndex = table.column(1).data().toArray().map(function (r) {
                var elm = new DOMParser().parseFromString(r, "text/xml");
                if (isParseError(elm)) {
                    return String(r);  // Return original value on parsing error
                } else {
                    // Successful parsing
                    return elm.documentElement.textContent;
                }
            }).indexOf(String(newTempRev['id']))
            table.row(rowIndex).data([
                deleteButton + revenueModifyButton,
                rev['id'],
                rev['description'],
                rev['type'],
                rev['total'],
            ]).draw();
        }
        $('#revenueModal').modal('hide');
    });

    $('#revenues_tb').on('click', '.btn-delete', function () {
        var table = $('#revenues_tb').DataTable();
        var rowData = table.row($(this).parents('tr')).data();
        var id;
        if ($(this).hasClass('btn-temp')) {
            id = rowData[1];
        } else {
            id = $(rowData[1]).text();
        }
        table.row($(this).parents('tr'))
            .remove()
            .draw();
        revenues = revenues.filter(function (dict) {
            return dict !== findDictById(revenues, id);
        });
    });


    $('#revenues_tb').on('click', '.btn-modify', function (e) {
        var table = $('#revenues_tb').DataTable();
        var rowData = table.row($(this).parents('tr')).data();
        var id;
        if ($(this).hasClass('btn-temp')) {
            id = rowData[1];
        } else {
            id = $(rowData[1]).text();
        }
        rev = findDictById(revenues, id)
        $('#revenueModal').find('input[name="description"]').val(rev['description']);
        $('#revenueModal').find('input[name="total"]').val(rev['total']);
        $('#revenueModal').find('input[name="id"]').val(rev['id']);
        const element = "option[value='" + rev['type'] + "']"
        $('#revenueModal').find(element).prop('selected', true);
    });

    $('#expense_form').on('submit', function (e) {
        e.preventDefault();
        const newTempExp = {};
        $(this).serializeArray().forEach((list) => {
            newTempExp[list['name']] = list['value'];
            console.log(list['name'])
        });

        if (newTempExp['id'] === '') {
            newTempExp['id'] = 'temp_' + expTempCount;
            expTempCount++;
            var table = $('#expenses_tb').DataTable();
            table.row.add([
                deleteButton + expenseModifyButton,
                newTempExp.id,
                newTempExp.description,
                newTempExp.type,
                newTempExp.monthlyDeduction,
                newTempExp.total
            ]).draw();

            expenses.push(newTempExp);
        } else {
            var exp = findDictById(expenses, newTempExp['id']);
            exp['description'] = newTempExp['description'];
            exp['type'] = newTempExp['type'];
            exp['monthlyDeduction'] = newTempExp['monthlyDeduction'];
            exp['total'] = newTempExp['total'];

            var table = $('#expenses_tb').DataTable();
            var rowIndex = table.column(1).data().toArray().map(function (r) {
                var elm = new DOMParser().parseFromString(r, "text/xml");
                if (isParseError(elm)) {
                    return String(r);  // Return original value on parsing error
                } else {
                    // Successful parsing
                    return elm.documentElement.textContent;
                }
            }).indexOf(String(newTempExp['id']))
            table.row(rowIndex).data([
                deleteButton + expenseModifyButton,
                exp['id'],
                exp['description'],
                exp['type'],
                exp['monthlyDeduction'],
                exp['total']
            ]).draw();
        }

        $('#expenseModal').modal('hide');
    });

    $('#expenses_tb').on('click', '.btn-delete', function () {
        var table = $('#expenses_tb').DataTable();
        var rowData = table.row($(this).parents('tr')).data();
        var id;
        if ($(this).hasClass('btn-temp')) {
            id = rowData[1];
        } else {
            id = $(rowData[1]).text();
        }

        table.row($(this).parents('tr')).remove().draw();
        expenses = expenses.filter(function (dict) {
            return dict !== findDictById(expenses, id);
        });
    });

    $('#expenses_tb').on('click', '.btn-modify', function () {
        var table = $('#expenses_tb').DataTable();
        var rowData = table.row($(this).parents('tr')).data();
        var id;
        if ($(this).hasClass('btn-temp')) {
            id = rowData[1];
        } else {
            id = $(rowData[1]).text();
        }

        exp = findDictById(expenses, id);

        $('#expenseModal').find('input[name="description"]').val(exp['description']);
        $('#expenseModal').find('input[name="monthlyDeduction"]').val(exp['monthlyDeduction']);
        $('#expenseModal').find('input[name="total"]').val(exp['total']);
        $('#expenseModal').find('input[name="id"]').val(exp['id']);

        const element = "option[value='" + exp['type'] + "']";
        $('#expenseModal').find(element).prop('selected', true);
    });

    $('#inventory_form').on('submit', function (e) {
        e.preventDefault();
        const newTempInv = {};
        $(this).serializeArray().forEach((list) => {
            newTempInv[list['name']] = list['value'];
        });
        if (newTempInv['id'] === '') {
            newTempInv['id'] = 'temp_' + invTempCount;
            invTempCount++;
            var table = $('#inventories_tb').DataTable();
            table.row.add([
                deleteButton + invModifyButton,
                newTempInv.id,
                newTempInv.type,
                newTempInv.owner,
                newTempInv.invDescription,
                newTempInv.regCertificateNo,
                newTempInv.dateOfOwnership,
                newTempInv.quantityAmount,
                newTempInv.ownershipSize,
                newTempInv.quantitySize,
                newTempInv.acquisitionCost,
                newTempInv.estimatedCurrentValue,
                newTempInv.methodOfAcquisition
            ]).draw();
            inventories.push(newTempInv);
        } else {
            var inv = findDictById(inventories, newTempInv['id']);
            inv['id'] = newTempInv['id'];
            inv['type'] = newTempInv['type'];
            inv['owner'] = newTempInv['owner'];
            inv['invDescription'] = newTempInv['invDescription'];
            inv['regCertificateNo'] = newTempInv['regCertificateNo'];
            inv['dateOfOwnership'] = newTempInv['dateOfOwnership'];
            inv['quantityAmount'] = newTempInv['quantityAmount'];
            inv['ownershipSize'] = newTempInv['ownershipSize'];
            inv['quantitySize'] = newTempInv['quantitySize'];
            inv['acquisitionCost'] = newTempInv['acquisitionCost'];
            inv['estimatedCurrentValue'] = newTempInv['estimatedCurrentValue'];
            inv['methodOfAcquisition'] = newTempInv['methodOfAcquisition'];
            var table = $('#inventories_tb').DataTable();
            var rowIndex = table.column(1).data().toArray().map(function (r) {
                var elm = new DOMParser().parseFromString(r, "text/xml");
                if (isParseError(elm)) {
                    return String(r);
                } else {
                    return elm.documentElement.textContent;
                }
            }).indexOf(String(newTempInv['id']));

            table.row(rowIndex).data([
                deleteButton + invModifyButton,
                inv['id'],
                inv['type'],
                inv['owner'],
                inv['invDescription'],
                inv['regCertificateNo'],
                inv['dateOfOwnership'],
                inv['quantityAmount'],
                inv['ownershipSize'],
                inv['quantitySize'],
                inv['acquisitionCost'],
                inv['estimatedCurrentValue'],
                inv['methodOfAcquisition']
            ]).draw();
        }

        $('#inventoryModal').modal('hide');
    });

    $('#inventories_tb').on('click', '.btn-delete', function () {
        var table = $('#inventories_tb').DataTable();
        var rowData = table.row($(this).parents('tr')).data();
        var id;
        if ($(this).hasClass('btn-temp')) {
            id = rowData[1];
        } else {
            id = $(rowData[1]).text();
        }
        table.row($(this).parents('tr'))
            .remove()
            .draw();
        inventories = inventories.filter(function (dict) {
            return dict !== findDictById(inventories, id);
        });
    });

    $('#inventories_tb').on('click', '.btn-modify', function () {
        var table = $('#inventories_tb').DataTable();
        var rowData = table.row($(this).parents('tr')).data();
        var id;
        if ($(this).hasClass('btn-temp')) {
            id = rowData[1];
        } else {
            id = $(rowData[1]).text();
        }
        var inv = findDictById(inventories, id);
        $('#inventory_form input[name="id"]').val(inv['id']);
        const element = "option[value='" + inv['type'] + "']"
        $('#inventory_form').find(element).prop('selected', true);
        $('#inventory_form input[name="owner"]').val(inv['owner']);
        $('#inventory_form input[name="invDescription"]').val(inv['invDescription']);
        $('#inventory_form input[name="regCertificateNo"]').val(inv['regCertificateNo']);
        $('#inventory_form input[name="dateOfOwnership"]').val(inv['dateOfOwnership']);
        $('#inventory_form input[name="quantityAmount"]').val(inv['quantityAmount']);
        $('#inventory_form input[name="ownershipSize"]').val(inv['ownershipSize']);
        $('#inventory_form input[name="quantitySize"]').val(inv['quantitySize']);
        $('#inventory_form input[name="acquisitionCost"]').val(inv['acquisitionCost']);
        $('#inventory_form input[name="estimatedCurrentValue"]').val(inv['estimatedCurrentValue']);
        $('#inventory_form input[name="methodOfAcquisition"]').val(inv['methodOfAcquisition']);
        $('#inventoryModal').modal('show');
    });


    function findDictById(arrayOfDicts, idToFind) {
        return arrayOfDicts.find(function (dict) {
            return String(dict['id']) === String(idToFind);
        });
    };

    $('.modal').on('hidden.bs.modal', function () {
        $(this).find('form').trigger('reset');
        $(this).find('form').find("select, input, checkbox").val("");
    });


    function isParseError(parsedDocument) {
        // parser and parsererrorNS could be cached on startup for efficiency
        var parser = new DOMParser(),
            errorneousParse = parser.parseFromString('<', 'application/xml'),
            parsererrorNS = errorneousParse.getElementsByTagName("parsererror")[0].namespaceURI;

        if (parsererrorNS === 'http://www.w3.org/1999/xhtml') {
            // In PhantomJS the parseerror element doesn't seem to have a special namespace, so we are just guessing here :(
            return parsedDocument.getElementsByTagName("parsererror").length > 0;
        }

        return parsedDocument.getElementsByTagNameNS(parsererrorNS, 'parsererror').length > 0;
    };

    function compareArrays(originalArray, modifiedArray) {
        const additions = [];
        const modifications = [];
        // Check for additions and modifications
        for (const modifiedItem of modifiedArray) {
            const originalItem = originalArray.find(item => String(item.id) === String(modifiedItem.id));
            if (!originalItem) {
                // Item is not in the original array, consider it an addition
                additions.push(modifiedItem);
            } else {
                // Item is in both arrays, check for modifications
                for (var key in modifiedItem) {
                    if (modifiedItem.hasOwnProperty(key) && String(modifiedItem[key]) !== String(originalItem[key])) {
                        modifications.push({
                            id: modifiedItem.id,
                            [key]: modifiedItem[key]
                        });
                    }
                }
            }
        }

        // Check for deletions
        const deletions = originalArray.filter(originalItem =>
            !modifiedArray.some(modifiedItem => String(modifiedItem.id) === String(originalItem.id))
        );

        return {additions, modifications, deletions};
    }

    function sendChangesToServer(changes, url) {
        // Combine changes for all asset types into a single array
        console.log(changes)
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

    $('#commitAssets').on('click', function () {
        var originalRevenues = JSON.parse(JSON.stringify(userAssets.revenues));
        var originalInventories = JSON.parse(JSON.stringify(userAssets.inventories));
        var originalExpenses = JSON.parse(JSON.stringify(userAssets.expenses));
        var revenueChanges = compareArrays(originalRevenues, revenues);
        var inventoryChanges = compareArrays(originalInventories, inventories);
        var expenseChanges = compareArrays(originalExpenses, expenses);

        var changes = {
            'revenuesChanges': revenueChanges,
            'expensesChanges': expenseChanges,
            'inventoriesChange': inventoryChanges
        };
        sendChangesToServer(changes, "/manage_assets");
    });

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
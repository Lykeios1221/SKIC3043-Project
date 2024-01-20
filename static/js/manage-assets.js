document.addEventListener('DOMContentLoaded', () => {

  // Initialize storage
  // const userAssets = JSON.parse(
  //     $('#userAssets').attr('data-assets').replace(/'/g, '"'));
  // const revenues = JSON.parse(JSON.stringify(userAssets.revenues));
  // const inventories = JSON.parse(JSON.stringify(userAssets.inventories));
  // const expenses = JSON.parse(JSON.stringify(userAssets.expenses));
  // let storageIndex = {'revenue': 0, 'expense': 0, 'inventory': 0};
  initializeTables();

  function initializeTables() {
    const responsiveConfig = {
      details: {
        display: DataTable.Responsive.display.modal({
          header: function(row) {
            const data = row.data();
            return 'Details for item';
          },
        }), renderer: function(api, rowIdx, columns) {
          const clonedColumns = columns.slice(2);

          // Render the details in the modal with the modified columns array
          const data = $.map(clonedColumns, function(col, i) {
            return `<tr data-dt-row="${col.rowIndex}" data-dt-column="${col.columnIndex}">
                <td>${col.title}</td>
                <td>${col.data}</td>
            </tr>`;
          }).join('');

          return $('<table class="table"/>').append(data);
        },
      },
    };
    $('.jDataTable').each(function() {
      $(this).DataTable({
        responsive: responsiveConfig,
        dom: '<"row"<"col-md-12"B>>' +  // New DOM structure
            '<"row"<"col-md-6"l><"col-md-6"f>>' +// New DOM structure
            '<"row"<"col-md-12"tr>>' + // New DOM structure
            '<"row"<"col-md-5"i><"col-md-7"p>>', // New DOM structure
        buttons: [
          {
            extend: 'copy', exportOptions: {
              columns: ':not(:eq(0))', // Exclude column 1
            },
          }, {
            extend: 'csv', exportOptions: {
              columns: ':not(:eq(0)):not(:eq(1))', // Exclude column 1
            },
          }, {
            extend: 'excel', exportOptions: {
              columns: ':not(:eq(0)):not(:eq(1))', // Exclude column 1
            },
          }, {
            extend: 'pdf', exportOptions: {
              columns: ':not(:eq(0)):not(:eq(1))', // Exclude column 1
            },
          }, {
            extend: 'print', exportOptions: {
              columns: '\':not(:eq(0)):not(:eq(1))\'', // Exclude column 1
            },
          }],
        columnDefs: [
          {
            targets: 0,
            searchable: false,
            orderable: false,
            className: 'dt-body-left',
          },
          {
            targets: 1,
            searchable: false,
            orderable: false,
          }],
        'order': [[2, 'asc']],
      });
    });
  }

  console.log(JSON.stringify(
      userAsset));

  document.getElementById('printAssets').addEventListener('click', (evt) => {
    $.ajax({
      type: 'POST',
      url: '/get_print_assets',
      contentType: 'application/json',
      dataType: 'html',
      data: JSON.stringify(
          userAsset),
      success: function(response) {
        var w = window.open();
        w.document.write(response);

      },
      error: function(error) {
        console.error(error);
      },
    });
  });

  const assetFormsData = {
    'revenue': [],
    'expense': [],
    'inventory': [],
  };

  const assetRemovedIds = {
    'revenue': [],
    'expense': [],
    'inventory': [],
  };

  const assetFiles = {};

  const revenueModal = new bootstrap.Modal(
      document.getElementById('revenue-modal'));
  const expenseModal = new bootstrap.Modal(
      document.getElementById('expense-modal'));
  const inventoryModal = new bootstrap.Modal(
      document.getElementById('inventory-modal'));

  document.getElementById('add-revenue').addEventListener('click', (evt) => {
    revenueModal._element.reset();
    const elm = revenueModal._element.querySelector('input[type="file"]');
    elm.classList.remove('is-valid');
    elm.classList.remove('is-invalid');
    revenueModal.show();
  });

  document.getElementById('add-expense').addEventListener('click', (evt) => {
    expenseModal._element.reset();
    const elm = expenseModal._element.querySelector('input[type="file"]');
    elm.classList.remove('is-valid');
    elm.classList.remove('is-invalid');
    expenseModal.show();
  });

  document.getElementById('add-inventory').addEventListener('click', (evt) => {
    inventoryModal._element.reset();
    const elm = inventoryModal._element.querySelector('input[type="file"]');
    elm.classList.remove('is-valid');
    elm.classList.remove('is-invalid');
    inventoryModal.show();
  });

  $(document).on('click', '.btn-modify', (evt) => {
    const id = evt.target.dataset.id;
    const type = evt.target.dataset.type;
    let data = assetFormsData[type].find((form) => {
      return form['id'] === id;
    });
    if (!data) {
      console.log(evt.target.dataset.row);
      data = JSON.parse(evt.target.dataset.row.replace(/'/g, '"'));
    }
    const modal = eval(`${type}Modal`);
    const fileInput = modal._element.querySelector('input[type="file"]');
    fileInput.classList.remove('is-valid');
    fileInput.classList.remove('is-invalid');
    fileInput.value = '';
    Object.entries(data).forEach((entry) => {
      const inputElement = modal._element.querySelector(
          `input[name="${entry[0]}"], select[name="${entry[0]}"]`,
      );
      if (inputElement.type !== 'file') {
        inputElement.value = entry[1];
      } else {
        inputElement.value = '';
      }
    });
    modal.show();
  });

  $(document).on('click', '.btn-view', (evt) => {
    const id = evt.target.dataset.id;
    const type = evt.target.dataset.type;
    let data = assetFiles[`${type}_file_${id}`];
    if (!data) {
      $.ajax({
        type: 'GET',
        url: '/send_pdf',
        data: {'filename': `${type}_${id}`},
        xhrFields: {
          responseType: 'blob',
        },
        success: function(response) {
          data = response;
          const url = URL.createObjectURL(data);
          window.open(url, '_blank');
        },
        error: function(xhr, status, error) {
          console.error('Error fetching PDF:', error);
        },
      });
    } else {
      const url = URL.createObjectURL(data);
      window.open(url, '_blank');
    }
  });

  $(document).on('click', '.btn-delete', (evt) => {
    const id = evt.target.dataset.id;
    const type = evt.target.dataset.type;
    const formsData = assetFormsData[type];
    const index = formsData.indexOf((form) => {
      return form['id'] === id;
    });
    if (index !== -1) {
      const removeData = formsData.splice(index, 1);
      delete assetFiles[`${type}_file_${id}`];
    } else {
      assetRemovedIds[type].push(id);
    }
    $(document.getElementById(`${type}-table`)).
        DataTable().
        row(function(idx, data, node) {
          return data[2] === id;
        }).
        remove().
        draw();
  });

  revenueModal._element.addEventListener('submit', (evt) => {
    evt.preventDefault();
    addOrModifyEventProcess('revenue', evt);
  });

  expenseModal._element.addEventListener('submit', (evt) => {
    evt.preventDefault();
    addOrModifyEventProcess('expense', evt);
  });

  inventoryModal._element.addEventListener('submit', (evt) => {
    evt.preventDefault();
    addOrModifyEventProcess('inventory', evt);
  });

  async function uploadPdfForValidate(file) {
    return new Promise(function(resolve, reject) {
      const formData = new FormData();
      formData.append(``, file);
      $.ajax({
        type: 'post',
        url: 'validate_pdf',
        contentType: false,
        processData: false,
        data: formData,
      }).done(function(response) {
        console.log(response);
        const valid = response['result'];
        resolve(valid);
      }).fail(function() {
        reject('Validation failed due to AJAX error.');
      });
    });
  }

  for (let elm of document.getElementsByClassName(
      'pdfupload')) {

    elm.addEventListener('input', async (evt) => {
      evt.target.classList.remove('is-valid');
      evt.target.classList.remove('is-invalid');
      const file = evt.target.files[0];
      const result = await uploadPdfForValidate(file);
      if (result !== true) {
        evt.target.nextElementSibling.textContent = String(result);
        evt.target.value = '';
        evt.target.classList.add('is-invalid');
      } else {
        evt.target.classList.add('is-valid');
      }
    });
  }

  function addOrModifyEventProcess(type, evt) {
    const form = evt.target;
    const formData = new FormData(form);
    const formDataList = assetFormsData[type];
    let id = String(formData.get('id'));
    if (id === '') {
      id = 'temp_' + String(formDataList.length);
      formData.set('id', id);
    }
    assetFiles[`${type}_file_${id}`] = formData.get(`${type}File`);
    formData.delete(`${type}File`);
    const formDataDict = formDataToDict(formData);
    let dataIndex = formDataList.findIndex((form) => {
      return form['id'] === id;
    });
    if (!isNaN(dataIndex) && dataIndex !== -1) {
      formDataList[dataIndex] = formDataDict;
    } else {
      formDataList.push(formDataDict);
    }
    const table = $(document.getElementById(`${type}-table`)).DataTable();
    const dataForDisplay = [...formData].filter(
        (entry) => entry[0] !== 'email').map((entry) => entry[1]);
    const deleteButton = createButton(type, 'Delete', id);
    const modifyButton = createButton(type, 'Modify', id);
    const viewButton = createButton(type, 'View', id);
    const index = table.row(function(idx, data, node) {
      return data[2] === id;
    }).index();
    dataForDisplay['approveStatus'] = 'False';
    if (isNaN(index)) {
      table.row.add([
        '',
        `${deleteButton.outerHTML}${modifyButton.outerHTML}${viewButton.outerHTML}`,
        ...dataForDisplay]).draw();
    } else {
      table.row(index).data([
        '',
        `${deleteButton.outerHTML}${modifyButton.outerHTML}${viewButton.outerHTML}`,
        ...dataForDisplay]).draw();
    }
    eval(`${type}Modal`).hide();
  }

  function createButton(type, text, id) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = text;
    const actionType = text.toLowerCase();
    if (actionType === 'delete') {
      button.classList.add('btn', 'btn-danger', 'btn-delete');
    } else if (actionType === 'modify') {
      button.classList.add('btn', 'btn-secondary', 'btn-modify');
    } else if (actionType === 'view') {
      button.classList.add('btn', 'btn-warning', 'btn-view');
    }
    button.dataset.id = id;
    button.dataset.type = type;
    return button;
  }

  function formDataToDict(formData) {
    const dict = {};
    formData.forEach((value, key) => {
      dict[key] = value;
    });
    return dict;
  }

  function logFormData(formData) {
    for (let entry of formData.entries()) {
      console.log('key: ', entry[0]);
      console.log('value: ', entry[1]);
    }
  }

  document.getElementById('commitAssets').addEventListener('click', (evt) => {
    evt.preventDefault();
    const formData = new FormData();
    formData.append('data',
        JSON.stringify({'Add': assetFormsData, 'Delete': assetRemovedIds}));
    Object.entries(assetFiles).forEach((entry) => {
      formData.append(entry[0], entry[1]);
    });
    $.ajax({
      type: 'POST',
      url: '/manage_assets',
      contentType: false,
      processData: false,
      data: formData,
      success: function(response) {
        window.location.href = response;
      },
      error: function(error) {
        window.location.href = error;
      },
    });
  });
})
;


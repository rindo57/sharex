function showDirectory(data) {
    data = data['contents'];
    document.getElementById('directory-data').innerHTML = '';
    const isTrash = getCurrentPath().startsWith('/trash');
    const isShare = getCurrentPath().startsWith('/share'); // Check if path starts with /share

    let html = '';

    let entries = Object.entries(data);
    let folders = entries.filter(([key, value]) => value.type === 'folder');
    let files = entries.filter(([key, value]) => value.type === 'file');

    folders.sort((a, b) => a[1].name.localeCompare(b[1].name));
    files.sort((a, b) => a[1].name.localeCompare(b[1].name));

    for (const [key, item] of folders) {
        if (item.type === 'folder') {
            html += `<tr data-path="${item.path}" data-id="${item.id}" class="body-tr folder-tr">
                        <td><div class="file-tr"><i class="fas fa-folder icon"></i> ${item.name}</div></td>
                        <td><div class="td-align"></div></td>
                        <td><div class="download-btn"></div></td>`;
            
            // Only add the "More" button and options if the path does NOT start with /share
            if (!isShare) {
                html += `<td><div class="td-align"><a data-id="${item.id}" class="more-btn"><img src="static/assets/more-icon.svg" class="rotate-90"></a></div></td>
                         </tr>`;
                
                if (isTrash) {
                    html += `<div data-path="${item.path}" id="more-option-${item.id}" data-name="${item.name}" class="more-options">
                                <input class="more-options-focus" readonly="readonly" style="height:0;width:0;border:none;position:absolute">
                                <div id="restore-${item.id}" data-path="${item.path}"><img src="static/assets/load-icon.svg"> Restore</div><hr>
                                <div id="delete-${item.id}" data-path="${item.path}"><img src="static/assets/trash-icon.svg"> Delete</div>
                             </div>`;
                } else {
                    html += `<div data-path="${item.path}" id="more-option-${item.id}" data-name="${item.name}" class="more-options">
                                <input class="more-options-focus" readonly="readonly" style="height:0;width:0;border:none;position:absolute">
                                <div id="rename-${item.id}"><img src="static/assets/pencil-icon.svg"> Rename</div><hr>
                                <div id="trash-${item.id}"><img src="static/assets/trash-icon.svg"> Trash</div><hr>
                                <div id="folder-share-${item.id}"><img src="static/assets/share-icon.svg"> Share</div>
                             </div>`;
                }
            } else {
                html += `</tr>`;  // Close the row without the "More" button if in /share path
            }
        }
    }

    for (const [key, item] of files) {
        if (item.type === 'file') {
            const size = convertBytes(item.size);
            html += `<tr data-path="${item.path}" data-id="${item.id}" data-name="${item.name}" class="body-tr file-tr">
                        <td><div class="file-tr"><i class="far fa-file icon"></i> ${item.name}</div></td>
                        <td><div class="td-align">${size}</div></td>
                        <td><div class="td-align"><a href="#" onclick="openFilex(this)" data-path="${item.path}" data-id="${item.id}" data-name="${item.name}" class="download-btn"><i class="fas fa-download icon"></i></a></div></td>`;
            
            // Only add the "More" button and options if the path does NOT start with /share
            if (!isShare) {
                html += `<td><div class="td-align"><a data-id="${item.id}" class="more-btn"><img src="static/assets/more-icon.svg" class="rotate-90"></a></div></td>
                         </tr>`;

                if (isTrash) {
                    html += `<div data-path="${item.path}" id="more-option-${item.id}" data-name="${item.name}" class="more-options">
                                <input class="more-options-focus" readonly="readonly" style="height:0;width:0;border:none;position:absolute">
                                <div id="restore-${item.id}" data-path="${item.path}"><img src="static/assets/load-icon.svg"> Restore</div><hr>
                                <div id="delete-${item.id}" data-path="${item.path}"><img src="static/assets/trash-icon.svg"> Delete</div>
                             </div>`;
                } else {
                    html += `<div data-path="${item.path}" id="more-option-${item.id}" data-name="${item.name}" class="more-options">
                                <input class="more-options-focus" readonly="readonly" style="height:0;width:0;border:none;position:absolute">
                                <div id="rename-${item.id}"><img src="static/assets/pencil-icon.svg"> Rename</div><hr>
                                <div id="trash-${item.id}"><img src="static/assets/trash-icon.svg"> Trash</div><hr>
                                <div id="share-${item.id}"><img src="static/assets/share-icon.svg"> Share</div>
                             </div>`;
                }
            } else {
                html += `</tr>`;  // Close the row without the "More" button if in /share path
            }
        }
    }

    document.getElementById('directory-data').innerHTML = html;

    if (!isTrash) {
        document.querySelectorAll('.folder-tr').forEach(div => {
            div.ondblclick = openFolder;
        });
        document.querySelectorAll('.file-tr').forEach(div => {
            div.ondblclick = openFile;
        });
    }

    if (!isShare) {
        document.querySelectorAll('.more-btn').forEach(div => {
            div.addEventListener('click', function (event) {
                event.preventDefault();
                openMoreButton(div);
            });
        });
    }
}

window.addEventListener('DOMContentLoaded', function () {
    const searchInput = document.getElementById('file-search');

    // Check if 'query' parameter is in the URL
    const urlParams = new URLSearchParams(window.location.search);
    const query = urlParams.get('query');

    // If there's a query, set it in the search input field
    if (query) {
        searchInput.value = decodeURIComponent(query);
    }
});


document.getElementById('search-form').addEventListener('submit', function (event) {
    event.preventDefault();  // Prevent default form submission

    const searchInput = document.getElementById('file-search');
    const query = searchInput.value.trim();

    if (query === '') {
        alert('Search field is empty');
        return;
    }

    let currentPath = getCurrentPath();  // Function to get the current path
    let path;

    // Check if the current path starts with "/share_"
    if (currentPath.startsWith('/share_')) {
        currentPath = currentPath.replace(/\/query_.+$/, '');  // Remove any query after "/share_"
        path = '/?path=' + currentPath + '&auth=' + getFolderAuthFromPath() + '&query=' + encodeURIComponent(query);
    } else {
        // Remove "share_" only if it starts the path and anything after "search_" from the path
        currentPath = currentPath.replace(/^share_/, '');
        currentPath = currentPath.replace(/\/search_.+$/, '');  // Remove any previous search segment
        path = '/?path=' + currentPath + '/search_' + encodeURIComponent(query);
    }

    // Redirect to the constructed path with the query
    window.location.href = path;
});

// Loading Main Page

document.addEventListener('DOMContentLoaded', function () {
    const inputs = ['new-folder-name', 'rename-name', 'file-search']
    for (let i = 0; i < inputs.length; i++) {
        document.getElementById(inputs[i]).addEventListener('input', validateInput);
    }

    if (getCurrentPath().includes('/share_')) {
        getCurrentDirectory()
  } 
    //else if (getCurrentPath().includes('/search')) {
       // getCurrentDirectory()
     // Add your specific logic for the '/search' path here
       // handleSearchPath()
   // } 
    else {
        checkAdmin().then(isAdmin => {
            if (!isAdmin) {
                document.getElementById('bg-blur').style.zIndex = '2';
                document.getElementById('bg-blur').style.opacity = '0.1';

                document.getElementById('get-password').style.zIndex = '3';
                document.getElementById('get-password').style.opacity = '1';
            } else {
                getCurrentDirectory();
            }
        });
    }
});

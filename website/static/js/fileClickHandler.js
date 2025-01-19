function openFolder() {
    let path = (getCurrentPath() + '/' + this.getAttribute('data-id') + '/').replaceAll('//', '/')

    const auth = getFolderAuthFromPath()
    if (auth) {
        path = path + '&auth=' + auth
    }
    window.location.href = `/?path=${path}`
}

function getSharePath() {
    const url = new URL(window.location.href);
    return url
}

async function getVisitorIp() {
    try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        return data.ip;
    } catch (error) {
        console.error("Error fetching IP:", error);
    }
}


document.getElementById('search-form').addEventListener('submit', function (event) {
    event.preventDefault();  // Prevent default form submission

    const searchInput = document.getElementById('file-search');
    const query = searchInput.value.trim();

    if (query === '') {
        alert('Search field is empty');
        return;
    }

    let currentPath = window.location.href; // Function to get the current path
    let path;

    // Check if the current path starts with "/share_"

  //  currentPath = currentPath.replace(/\/query_.+$/, '');  // Remove any query after "/share_"
    path = currentPath + '&query=' + encodeURIComponent(query);
    

    // Redirect to the constructed path with the query
    window.location.href = path;
});





function encodeBase64(str) {
    return btoa(str);  // Converts the string to Base64
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const isVisible = sidebar.style.display === 'block';

    if (isVisible) {
        sidebar.style.display = 'none'; // Hide the sidebar
    } else {
        sidebar.style.display = 'block'; // Show the sidebar
    }
}
function openFile() {
    // Ensure that the action is from a user click, not programmatically triggered
 //   if (!this.hasAttribute('data-clicked')) {
        const fileName = this.getAttribute('data-name').toLowerCase();
        let pathSuffix = this.getAttribute('data-path') + '/' + this.getAttribute('data-id');
        
        // Encode pathSuffix to Base64
        const encodedPathSuffix = btoa(pathSuffix).split('').reverse().join('');

        let path = '/f?' + encodedPathSuffix;

        if (fileName.endsWith('.mp4') || fileName.endsWith('.mkv') || fileName.endsWith('.webm') || fileName.endsWith('.mov') || fileName.endsWith('.avi') || fileName.endsWith('.ts') || fileName.endsWith('.ogv')) {
            path = path;
        }

        // Mark this element as clicked, to prevent automated behavior
        //this.setAttribute('data-clicked', 'true');

        window.open(path, '_blank');
  //  }
}

// Add event listener to the element
document.querySelectorAll('.download-btn').forEach((button) => {
    button.addEventListener('click', openFile);
});

function openFilex(element) {
    // Ensure that the action is from a user click, not programmatically triggered
    if (!element.hasAttribute('data-clicked')) {
        const fileName = element.getAttribute('data-name').toLowerCase();
        let pathSuffix = element.getAttribute('data-path') + '/' + element.getAttribute('data-id');
        
        // Encode pathSuffix to Base64
        const encodedPathSuffix = btoa(pathSuffix).split('').reverse().join('');

        let path = '/f?' + encodedPathSuffix;

        if (fileName.endsWith('.mp4') || fileName.endsWith('.mkv') || fileName.endsWith('.webm') || fileName.endsWith('.mov') || fileName.endsWith('.avi') || fileName.endsWith('.ts') || fileName.endsWith('.ogv')) {
            path = path;
        }

        // Mark this element as clicked, to prevent automated behavior
        element.setAttribute('data-clicked', 'true');

        window.open(path, '_blank');
    }
}


// File More Button Handler Start

function openMoreButton(div) {
    const id = div.getAttribute('data-id')
    const moreDiv = document.getElementById(`more-option-${id}`)

    const rect = div.getBoundingClientRect();
    const x = rect.left + window.scrollX - 40;
    const y = rect.top + window.scrollY;

    moreDiv.style.zIndex = 2
    moreDiv.style.opacity = 1
    moreDiv.style.left = `${x}px`
    moreDiv.style.top = `${y}px`

    const isTrash = getCurrentPath().includes('/trash')

    moreDiv.querySelector('.more-options-focus').focus()
    moreDiv.querySelector('.more-options-focus').addEventListener('blur', closeMoreBtnFocus);
    moreDiv.querySelector('.more-options-focus').addEventListener('focusout', closeMoreBtnFocus);
    if (!isTrash) {
        moreDiv.querySelector(`#rename-${id}`).addEventListener('click', renameFileFolder)
        moreDiv.querySelector(`#trash-${id}`).addEventListener('click', trashFileFolder)
        try {
            moreDiv.querySelector(`#share-${id}`).addEventListener('click', shareFile)
        }
        catch { }
        try {
            moreDiv.querySelector(`#folder-share-${id}`).addEventListener('click', shareFolder)
        }
        catch { }
    }
    else {
        moreDiv.querySelector(`#restore-${id}`).addEventListener('click', restoreFileFolder)
        moreDiv.querySelector(`#delete-${id}`).addEventListener('click', deleteFileFolder)
    }
}

function closeMoreBtnFocus() {
    const moreDiv = this.parentElement
    moreDiv.style.opacity = '0'
    setTimeout(() => {
        moreDiv.style.zIndex = '-1'
    }, 300)
}

// Rename File Folder Start
function renameFileFolder() {
    const id = this.getAttribute('id').split('-')[1]
    console.log(id)

    document.getElementById('rename-name').value = this.parentElement.getAttribute('data-name');
    document.getElementById('bg-blur').style.zIndex = '2';
    document.getElementById('bg-blur').style.opacity = '0.1';

    document.getElementById('rename-file-folder').style.zIndex = '3';
    document.getElementById('rename-file-folder').style.opacity = '1';
    document.getElementById('rename-file-folder').setAttribute('data-id', id);
    setTimeout(() => {
        document.getElementById('rename-name').focus();
    }, 300)
}

document.getElementById('rename-cancel').addEventListener('click', () => {
    document.getElementById('rename-name').value = '';
    document.getElementById('bg-blur').style.opacity = '0';
    setTimeout(() => {
        document.getElementById('bg-blur').style.zIndex = '-1';
    }, 300)
    document.getElementById('rename-file-folder').style.opacity = '0';
    setTimeout(() => {
        document.getElementById('rename-file-folder').style.zIndex = '-1';
    }, 300)
});

document.getElementById('rename-create').addEventListener('click', async () => {
    const name = document.getElementById('rename-name').value;
    if (name === '') {
        alert('Name cannot be empty')
        return
    }

    const id = document.getElementById('rename-file-folder').getAttribute('data-id')

    const path = document.getElementById(`more-option-${id}`).getAttribute('data-path') + '/' + id

    const data = {
        'name': name,
        'path': path
    }

    const response = await postJson('/api/renameFileFolder', data)
    if (response.status === 'ok') {
        alert('File/Folder Renamed Successfully')
        window.location.reload();
    } else {
        alert('Failed to rename file/folder')
        window.location.reload();
    }
});


// Rename File Folder End

async function trashFileFolder() {
    const id = this.getAttribute('id').split('-')[1]
    console.log(id)
    const path = document.getElementById(`more-option-${id}`).getAttribute('data-path') + '/' + id
    const data = {
        'path': path,
        'trash': true
    }
    const response = await postJson('/api/trashFileFolder', data)

    if (response.status === 'ok') {
        alert('File/Folder Sent to Trash Successfully')
        window.location.reload();
    } else {
        alert('Failed to Send File/Folder to Trash')
        window.location.reload();
    }
}

async function restoreFileFolder() {
    const id = this.getAttribute('id').split('-')[1]
    const path = this.getAttribute('data-path') + '/' + id
    const data = {
        'path': path,
        'trash': false
    }
    const response = await postJson('/api/trashFileFolder', data)

    if (response.status === 'ok') {
        alert('File/Folder Restored Successfully')
        window.location.reload();
    } else {
        alert('Failed to Restored File/Folder')
        window.location.reload();
    }
}

async function deleteFileFolder() {
    const id = this.getAttribute('id').split('-')[1]
    const path = this.getAttribute('data-path') + '/' + id
    const data = {
        'path': path
    }
    const response = await postJson('/api/deleteFileFolder', data)

    if (response.status === 'ok') {
        alert('File/Folder Deleted Successfully')
        window.location.reload();
    } else {
        alert('Failed to Delete File/Folder')
        window.location.reload();
    }
}

async function shareFile() {
    const fileName = this.parentElement.getAttribute('data-name').toLowerCase()
    const id = this.getAttribute('id').split('-')[1]
    const path = document.getElementById(`more-option-${id}`).getAttribute('data-path') + '/' + id
    const root_url = getRootUrl()

    let link
    if (fileName.endsWith('.mp4') || fileName.endsWith('.mkv') || fileName.endsWith('.webm') || fileName.endsWith('.mov') || fileName.endsWith('.avi') || fileName.endsWith('.ts') || fileName.endsWith('.ogv')) {
        link = `${root_url}/file?download=${path}`
    } else {
        link = `${root_url}/file?download=${path}`

    }

    copyTextToClipboard(link)
}


async function shareFolder() {
    const id = this.getAttribute('id').split('-')[2]
    console.log(id)
    let path = document.getElementById(`more-option-${id}`).getAttribute('data-path') + '/' + id
    const root_url = getRootUrl()

    const auth = await getFolderShareAuth(path)
    path = path.slice(1)

    let link = `${root_url}/?path=/share_${path}&auth=${auth}`
    console.log(link)

    copyTextToClipboard(link)
}

// File More Button Handler  End

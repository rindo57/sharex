
// const { JSDOM } = require("jsdom");


// Api Functions
async function postJson(url, data) {
    data['password'] = getPassword();
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
    return await response.json();
}

//let attempts = 0; // Declare attempts outside the event listener
const maxAttempts = 5;
const lockoutDuration = 60 * 60 * 1000; // 12 hours in milliseconds
const attemptsKey = "loginAttempts";
const lockoutTimeKey = "lockoutTime";
// Interaction tracking for invisible CAPTCHA


const interactionData = {
    mouseMovements: [],
    clicks: 0,
    keypresses: 0,
    touchMovements: [], // New property for touch interactions
};

function initializeAttempts() {
    const storedAttempts = localStorage.getItem(attemptsKey);
    const lockoutTime = localStorage.getItem(lockoutTimeKey);

    if (lockoutTime && Date.now() >= Number(lockoutTime)) {
        // Reset attempts if the lockout period has expired
        localStorage.removeItem(attemptsKey);
        localStorage.removeItem(lockoutTimeKey);
        return 0;
    }

    return storedAttempts ? Number(storedAttempts) : 0;
}

let attempts = initializeAttempts();

// Update attempts in localStorage
function saveAttempts(attempts) {
    localStorage.setItem(attemptsKey, attempts);

    if (attempts >= maxAttempts) {
        // Set lockout expiration time
        localStorage.setItem(lockoutTimeKey, Date.now() + lockoutDuration);
    }
}
// Track mouse movements
document.addEventListener("mousemove", (e) => {
    interactionData.mouseMovements.push({ x: e.clientX, y: e.clientY, time: Date.now() });
});

// Track button clicks
document.getElementById("pass-login").addEventListener("click", () => {
    interactionData.clicks++;
});

document.addEventListener("touchmove", (e) => {
    const touch = e.touches[0];
    interactionData.touchMovements.push({ x: touch.clientX, y: touch.clientY, time: Date.now() });
});

document.getElementById("auth-pass").addEventListener("input", () => {
    interactionData.keypresses++;
});

// Track keypresses
document.getElementById("auth-pass").addEventListener("keypress", () => {
    interactionData.keypresses++;
});

document.getElementById('pass-login').addEventListener('click', async () => {
    const loginButton = document.getElementById("pass-login");
    const password = document.getElementById('auth-pass').value;
    const errorMessage = document.getElementById('error-message');
 // Check if user is locked out
    const lockoutTime = localStorage.getItem(lockoutTimeKey);
    if (lockoutTime && Date.now() < Number(lockoutTime)) {
        errorMessage.textContent = "You are locked out. Please try again later.";
        errorMessage.style.display = "block";
        return;
    }
    
    if (!password) {
        alert('Please enter your password.');
        return;
    }

    const data = { 
        pass: password,
        interactionData: interactionData, // Send interaction data to backend
    };

    const json = await postJson('/api/checkPassword', data);

    //const json = await response.json();

    if (json.status === 'ok') {
        alert('Check your inbox!');
        window.location.reload();
    } else {
        attempts++;
        saveAttempts(attempts);
        if (attempts >= maxAttempts) {
            loginButton.disabled = true;
            errorMessage.style.display = "block";
        } else {
            alert(`Incorrect password. You have ${maxAttempts - attempts} attempts left.`);
        }
    }

    // Clear the password field
    document.getElementById('auth-pass').value = "";
});


function hideMoreColumnIfSharedPath() {
    // Check if the current path starts with '/share'
    if (getCurrentPath().startsWith('/share')) {
        // Select the "More" column header
        const moreColumnHeader = document.querySelector('.directory th:last-child');
        
        // Hide the "More" header cell
        if (moreColumnHeader) {
            moreColumnHeader.style.display = 'none';
        }

        // Select all cells in the "More" column
        const rows = document.querySelectorAll('.directory tbody tr');
        rows.forEach(row => {
            const moreColumnCell = row.querySelector('td:last-child');
            if (moreColumnCell) {
                moreColumnCell.style.display = 'none';
            }
        });
    }
}
async function getCurrentDirectory() {
    let path = getCurrentPath();
    if (path === 'redirect') {
        return;
    }
    try {
        const auth = getFolderAuthFromPath();
        const query = getFolderQueryFromPath();
        const data = { 'path': path, 'auth': auth, 'query': query };
        const json = await postJson('/api/getDirectory', data);

        if (json.status === 'ok') {
            if (getCurrentPath().startsWith('/share')) {
                const sections = document.querySelector('.sidebar-menu').getElementsByTagName('a');

                if (removeSlash(json['auth_home_path']) === removeSlash(path.split('_')[1])) {
                    sections[0].setAttribute('class', 'selected-item');
                } else {
                    sections[0].setAttribute('class', 'unselected-item');
                }
                sections[0].href = `/?path=/share_${removeSlash(json['auth_home_path'])}&auth=${auth}`;
                hideMoreColumnIfSharedPath(); 
                console.log(`/?path=/share_${removeSlash(json['auth_home_path'])}&auth=${auth}`)
            }// else if (getCurrentPath().includes('/search_')) {
                //const sidebarmenu = document.querySelector('.sidebar-menu');
              //  if (sidebarmenu) {
                   // sidebarmenu.style.display = 'none';
                //}
          //  }
            console.log(json)
            showDirectory(json['data']);
        } else {
            alert('404 Current Directory Not Found');
        }
    }
    catch (err) {
        alert('404 Current Directory Not Found');
    }
}

async function createNewFolder() {
    const folderName = document.getElementById('new-folder-name').value;
    const path = getCurrentPath();
    if (path === 'redirect') {
        return;
    }
    if (folderName.length > 0) {
        const data = {
            'name': folderName,
            'path': path
        };
        try {
            const json = await postJson('/api/createNewFolder', data);

            if (json.status === 'ok') {
                window.location.reload();
            } else {
                alert(json.status);
            }
        }
        catch (err) {
            alert('Error Creating Folder');
        }
    } else {
        alert('Folder Name Cannot Be Empty');
    }
}

async function getFolderShareAuth(path) {
    const data = { 'path': path };
    const json = await postJson('/api/getFolderShareAuth', data);
    if (json.status === 'ok') {
        return json.auth;
    } else {
        alert('Error Getting Folder Share Auth');
    }
}

// File Uploader Start
// File Uploader Start
const MAX_FILE_SIZE = 2126008811.52; // Will be replaced by the python

const fileInput = document.getElementById('fileInput');
const progressBar = document.getElementById('progress-bar');
const cancelButton = document.getElementById('cancel-file-upload');
const uploadPercent = document.getElementById('upload-percent');
let uploadQueue = []; // Queue for files to upload
let activeUploads = 0; // Counter for active uploads
const maxConcurrentUploads = 1; // Limit concurrent uploads to 1

let currentUploadingFile = null; // Track the file that is being uploaded

fileInput.addEventListener('change', async (e) => {
    const files = fileInput.files;

    // Validate file sizes and add them to the queue
    for (const file of files) {
        if (file.size > MAX_FILE_SIZE) {
            alert(`File size exceeds ${(MAX_FILE_SIZE / (1024 * 1024 * 1024)).toFixed(2)} GB limit`);
            return;
        }
        uploadQueue.push(file); // Add valid files to the queue
    }

    // Start processing uploads
    processUploadQueue();
    renderPendingUploadList(); // Render pending uploads excluding the currently uploading file
});

function processUploadQueue() {
    if (activeUploads < maxConcurrentUploads && uploadQueue.length > 0) {
        const file = uploadQueue.shift(); // Get the next file from the queue
        currentUploadingFile = file; // Mark the current file as uploading
        uploadFile(file);
    } else if (activeUploads === 0 && uploadQueue.length === 0) {
        alert('All uploads completed boss! 😎'); // Show alert when queue is fully processed
        window.location.reload();
    }

    renderPendingUploadList(); // Update pending list whenever queue changes
}

function renderPendingUploadList() {
    const pendingFilesList = document.getElementById('pending-files');
    const pendingHeading = document.getElementById('pending-heading');
    const pendingUploadListContainer = document.getElementById('Pending-upload-list');

    // Clear previous list
    pendingFilesList.innerHTML = '';

    // Filter the queue to exclude the current uploading file
    const pendingFiles = uploadQueue.filter(file => file !== currentUploadingFile);

    // Show or hide the "Pending Uploads" heading and list based on whether there are pending files
    if (pendingFiles.length > 0) {
        pendingHeading.style.display = 'block'; // Show the heading if there are pending files
        pendingFilesList.style.display = 'block'; // Show the pending uploads list
        pendingUploadListContainer.style.border = '1px solid #ccc'; // Show the border
    } else {
        pendingHeading.style.display = 'none'; // Hide the heading if no pending files
        pendingFilesList.style.display = 'none'; // Hide the pending uploads list
        pendingUploadListContainer.style.border = 'none'; // Hide the border
    }

    pendingFiles.forEach(file => {
        const listItem = document.createElement('li');
        listItem.style.display = 'flex'; // Use flexbox for inline items
        listItem.style.justifyContent = 'space-between'; // Spread items across the row
        listItem.style.alignItems = 'center'; // Vertically align items in the center
        listItem.style.marginBottom = '5px'; // Add margin between items
        listItem.style.flexWrap = 'nowrap'; // Prevent line breaks for the elements

        const fileNameSpan = document.createElement('span');
        fileNameSpan.textContent = `📁 ${file.name}`; // Prepend the emoji to the filename
        fileNameSpan.style.overflow = 'hidden'; // Ensure long names don't overflow
        fileNameSpan.style.textOverflow = 'ellipsis'; // Add ellipsis for long names
        fileNameSpan.style.whiteSpace = 'nowrap'; // Prevent filename from wrapping
        fileNameSpan.style.flexGrow = '1'; // Ensure the filename takes the remaining space
        fileNameSpan.style.marginRight = '10px'; // Add some spacing between filename and remove button
        fileNameSpan.style.maxWidth = '300px'; // Set a fixed width where ellipsis will kick in

        // Create a remove button
        const removeButton = document.createElement('button');
        removeButton.textContent = '❌';
        removeButton.onclick = () => removeFilex(file); // Bind the remove function to the button

        listItem.appendChild(fileNameSpan); // Add the filename span to the list item
        listItem.appendChild(removeButton); // Add the remove button inline with the filename
        pendingFilesList.appendChild(listItem); // Add the list item to the pending files list
    });
}

function removeFilex(fileToRemove) {
    // Remove the file from the upload queue
    uploadQueue = uploadQueue.filter(file => file.name !== fileToRemove.name);

    // Re-render the pending upload list
    renderPendingUploadList();

}



async function uploadFile(file) {
    const CHUNK_SIZE = 50 * 1024 * 1024; // 50 MB
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

    activeUploads++;

    // Show uploader UI
    document.getElementById("bg-blur").style.zIndex = "2";
    document.getElementById("bg-blur").style.opacity = "0.1";
    document.getElementById("file-uploader").style.zIndex = "3";
    document.getElementById("file-uploader").style.opacity = "1";

    document.getElementById("upload-filename").innerText =
        "Filename: " + file.name;
    document.getElementById("upload-filesize").innerText =
        "Filesize: " + (file.size / (1024 * 1024)).toFixed(2) + " MB";
    document.getElementById("upload-status").innerText =
        "Status: Uploading To Backend Server";

    const id = getRandomId();
    const path = getCurrentPath();
    const password = getPassword();
    const filenamex = file.name
    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
        const start = chunkIndex * CHUNK_SIZE;
        const end = Math.min(file.size, start + CHUNK_SIZE);
        const chunk = file.slice(start, end);

        const formData = new FormData();
        formData.append("file", chunk);
        formData.append("path", path);
        formData.append("password", password);
        formData.append("id", id);
        formData.append("chunkIndex", chunkIndex);
        formData.append("totalChunks", totalChunks);
        formData.append("filename", file.name);
         formData.append("filenamex", filenamex);
        formData.append("total_size", file.size);

        const uploadRequest = new XMLHttpRequest();
        uploadRequest.open("POST", "/api/upload", true);
        uploadRequest.setRequestHeader(
            "Cache-Control",
            "no-cache, no-store, must-revalidate"
        );
        uploadRequest.setRequestHeader("Pragma", "no-cache");
        uploadRequest.setRequestHeader("Expires", "0");

        uploadRequest.upload.addEventListener("progress", (e) => {
            if (e.lengthComputable) {
                const percentComplete =
                    ((chunkIndex + e.loaded / e.total) / totalChunks) * 100;
                progressBar.style.width = percentComplete + "%";
                uploadPercent.innerText =
                    "Progress: " + percentComplete.toFixed(2) + "%";
            }
        });

        await new Promise((resolve, reject) => {
            uploadRequest.onload = () => {
                if (uploadRequest.status === 200) {
                    resolve();
                } else {
                    reject(`Chunk ${chunkIndex + 1} failed to upload`);
                }
            };

            uploadRequest.onerror = () =>
                reject(`Network error while uploading chunk ${chunkIndex + 1}`);
            uploadRequest.send(formData);
        });
    }

    activeUploads--;
    currentUploadingFile = null; // clear current uploading file

    processUploadQueue();

    //alert("Upload completed successfully!");
}

cancelButton.addEventListener('click', () => {
    alert('Upload canceled');
    window.location.reload();
});

async function updateSaveProgress(id) {
    console.log('save progress')
    progressBar.style.width = '0%';
    uploadPercent.innerText = 'Progress : 0%'
    document.getElementById('upload-status').innerText = 'Status: Processing File On Backend Server';

    const interval = setInterval(async () => {
        const response = await postJson('/api/getSaveProgress', { 'id': id })
        const data = response['data']

        if (data[0] === 'running') {
            const current = data[1];
            const total = data[2];
            document.getElementById('upload-filesize').innerText = 'Filesize: ' + (total / (1024 * 1024)).toFixed(2) + ' MB';

            const percentComplete = (current / total) * 100;
            progressBar.style.width = percentComplete + '%';
            uploadPercent.innerText = 'Progress : ' + percentComplete.toFixed(2) + '%';
        }
        else if (data[0] === 'completed') {
            clearInterval(interval);
            uploadPercent.innerText = 'Progress : 100%'
            progressBar.style.width = '100%';

            await handleUpload2(id)
        }
    }, 3000)

}

async function handleUpload2(id) {
    document.getElementById('upload-status').innerText = 'Status: Uploading To Telegram Server';
    progressBar.style.width = '0%';
    uploadPercent.innerText = 'Progress : 0%';

    const interval = setInterval(async () => {
        const response = await postJson('/api/getUploadProgress', { 'id': id });
        const data = response['data'];
        if (data[0] === 'running') {
            const current = data[1];
            const total = data[2];
            document.getElementById('upload-filesize').innerText = 'Filesize: ' + (total / (1024 * 1024)).toFixed(2) + ' MB';

            let percentComplete;
            if (total === 0) {
                percentComplete = 0;
            } else {
                percentComplete = (current / total) * 100;
            }
            progressBar.style.width = percentComplete + '%';
            uploadPercent.innerText = 'Progress : ' + percentComplete.toFixed(2) + '%';
        }
        else if (data[0] === 'completed') {
            clearInterval(interval);
            activeUploads--; // Decrement active uploads counter after uploading
            processUploadQueue(); // Check for the next file in the queue
        }
    }, 3000);
}
// File Uploader End
// URL Uploader Start

// URL Uploader Start

let remoteUploadQueue = []; // Queue for remote URL uploads
let activeRemoteUploads = 0; // Counter for active remote uploads
const maxRemoteConcurrentUploads = 1; // Limit concurrent remote uploads to 1
let currentUploadingRemoteFile = null; // Track the file being uploaded from URL

async function handleUpload3(id) {
    console.log(id)
    document.getElementById('upload-status').innerText = 'Status: Uploading To Telegram Server';
    progressBar.style.width = '0%';
    uploadPercent.innerText = 'Progress : 0%';

    const interval = setInterval(async () => {
        const response = await postJson('/api/getUploadProgress', { 'id': id })
        const data = response['data']

        if (data[0] === 'running') {
            const current = data[1];
            const total = data[2];
            document.getElementById('upload-filesize').innerText = 'Filesize: ' + (total / (1024 * 1024)).toFixed(2) + ' MB';

            let percentComplete
            if (total === 0) {
                percentComplete = 0
            }
            else {
                percentComplete = (current / total) * 100;
            }
            progressBar.style.width = percentComplete + '%';
            uploadPercent.innerText = 'Progress : ' + percentComplete.toFixed(2) + '%';
        }
       else if (data[0] === 'completed') {
            clearInterval(interval);
            activeRemoteUploads--;
            //currentUploadingRemoteFile = null; // Reset the current uploading file
            
            processRemoteUploadQueue(); // Check for the next file in the queue
         //   clearInterval(interval);
           // alert('Upload Completed')
            //window.location.reload();
      }
    }, 3000)
}

async function get_file_info_from_url(url) {
    const data = { 'url': url }
    const json = await postJson('/api/getFileInfoFromUrl', data)
    if (json.status === 'ok') {
        return json.data
        console.log("jsondata: ", json.data);
    } else {
        throw new Error(`Error Getting File Info : ${json.status}`)
    }

}

async function start_file_download_from_url(url, filename, singleThreaded=true) {
    const data = { 'url': url, 'path': getCurrentPath(), 'filename': filename, 'singleThreaded': singleThreaded }
    const json = await postJson('/api/startFileDownloadFromUrl', data)
    if (json.status === 'ok') {
        return json.id
    } else {
        throw new Error(`Error Starting File Download : ${json.status}`)
    }
}

async function Start_URL_Upload() {
    try {
        document.getElementById('new-url-upload').style.opacity = '0';
        setTimeout(() => {
            document.getElementById('new-url-upload').style.zIndex = '-1';
        }, 300)
        const file_url = document.getElementById('remote-url').value
        const singleThreaded = true 

        const file_info = await get_file_info_from_url(file_url);

        for (let i = 0; i < file_info.length; i++) {
            const file_urlx = file_info[i]['file_url'];
            const file_name = file_info[i]['file_name'];
            const file_size = file_info[i]['file_size'];

            if (file_size > MAX_FILE_SIZE) {
                throw new Error(`File size exceeds ${(MAX_FILE_SIZE / (1024 * 1024 * 1024)).toFixed(2)} GB limit`);
            }

            // Add each file to the queue
            remoteUploadQueue.push({ file_urlx, file_name, file_size, singleThreaded });
        }

        // Start processing uploads
        processRemoteUploadQueue();
        renderPendingRemoteUploadList();
    }
    catch (err) {
        alert("Error: " + err.message);
        window.location.reload();
    }
}

function processRemoteUploadQueue() {
    if (activeRemoteUploads < maxRemoteConcurrentUploads && remoteUploadQueue.length > 0) {
        const file = remoteUploadQueue.shift(); // Get the next file from the queue
        currentUploadingRemoteFile = file; // Mark the current file as uploading
        download_progress_updater(file);
        //activeRemoteUploads++; // Increase active uploads count
    } else if (activeRemoteUploads === 0 && remoteUploadQueue.length === 0) {
        alert('All remote uploads completed!');
        window.location.reload();
    }

    renderPendingRemoteUploadList(); // Update pending list whenever queue changes
}

function renderPendingRemoteUploadList() {
    const pendingFilesList = document.getElementById('pending-files');
    const pendingHeading = document.getElementById('pending-heading');
    const pendingUploadListContainer = document.getElementById('Pending-upload-list');

    // Clear previous list
    pendingFilesList.innerHTML = '';

    // Filter the queue to exclude the current uploading file
    const pendingFiles = remoteUploadQueue.filter(file => file !== currentUploadingRemoteFile);

    if (pendingFiles.length > 0) {
        pendingHeading.style.display = 'block';
        pendingFilesList.style.display = 'block';
        pendingUploadListContainer.style.border = '1px solid #ccc';
    } else {
        pendingHeading.style.display = 'none';
        pendingFilesList.style.display = 'none';
        pendingUploadListContainer.style.border = 'none';
    }

    pendingFiles.forEach(file => {
        const listItem = document.createElement('li');
        listItem.style.display = 'flex'; // Use flexbox for inline items
        listItem.style.justifyContent = 'space-between'; // Spread items across the row
        listItem.style.alignItems = 'center'; // Vertically align items in the center
        listItem.style.marginBottom = '5px'; // Add margin between items
        listItem.style.flexWrap = 'nowrap'; // Prevent line breaks for the elements

        const fileNameSpan = document.createElement('span');
        fileNameSpan.textContent = `📁 ${file.file_name}`; // Prepend the emoji to the filename
        fileNameSpan.style.overflow = 'hidden'; // Ensure long names don't overflow
        fileNameSpan.style.textOverflow = 'ellipsis'; // Add ellipsis for long names
        fileNameSpan.style.whiteSpace = 'nowrap'; // Prevent filename from wrapping
        fileNameSpan.style.flexGrow = '1'; // Ensure the filename takes the remaining space
        fileNameSpan.style.marginRight = '10px'; // Add some spacing between filename and remove button
        fileNameSpan.style.maxWidth = '300px'; // Set a fixed width where ellipsis will kick in

        // Create a remove button
        const removeButton = document.createElement('button');
        removeButton.textContent = '❌';
        removeButton.onclick = () => removeFile(file); // Bind the remove function to the button

        listItem.appendChild(fileNameSpan); // Add the filename span to the list item
        listItem.appendChild(removeButton); // Add the remove button inline with the filename
        pendingFilesList.appendChild(listItem); // Add the list item to the pending files list
    });
}

function removeFile(fileToRemove) {
    // Remove the file from the upload queue
    remoteUploadQueue = remoteUploadQueue.filter(file => file.file_name !== fileToRemove.file_name);

    // Re-render the pending upload list
    renderPendingRemoteUploadList();

}

async function download_progress_updater({ file_urlx, file_name, file_size, singleThreaded=true}) {
    
    document.getElementById('upload-filename').innerText = 'Filename: ' + file_name;
    document.getElementById('upload-filesize').innerText = 'Filesize: ' + (file_size / (1024 * 1024)).toFixed(2) + ' MB';
    document.getElementById('upload-status').innerText = 'Status: Downloading File From Url To Backend Server';
    uploadPercent.innerText = 'Progress : 0%'
    progressBar.style.width = '0%';
    const id = await start_file_download_from_url(file_urlx, file_name, singleThreaded);
    document.getElementById('bg-blur').style.zIndex = '2';
    document.getElementById('bg-blur').style.opacity = '0.1';
    document.getElementById('file-uploader').style.zIndex = '3';
    document.getElementById('file-uploader').style.opacity = '1';

    

    const interval = setInterval(async () => {
        const response = await postJson('/api/getFileDownloadProgress', { 'id': id });
        const data = response['data'];

        if (data[0] === 'error') {
            clearInterval(interval);
            alert('Failed to download file from URL to backend server');
            window.location.reload();
        } else if (data[0] === 'completed') {
            clearInterval(interval);
            uploadPercent.innerText = 'Progress : 100%'
            progressBar.style.width = '100%';
            await handleUpload3(id)
            activeRemoteUploads++;
        } else {
            const current = data[1];
            const total = data[2];
            const percentComplete = (current / total) * 100;
            progressBar.style.width = percentComplete + '%';
            uploadPercent.innerText = 'Progress : ' + percentComplete.toFixed(2) + '%';
            if (data[0] === 'Downloading') {
                
                document.getElementById('upload-status').innerText = 'Status: Downloading File From Url To Backend Server';
            }
            else {
                document.getElementById('upload-status').innerText = `Status: ${data[0]}`;
            }
        }
    }, 3000)
}

// URL Uploader End


// URL Uploader End

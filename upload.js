function ID(id) { return document.getElementById(id); }
function N1(t,e) { return e.getElementsByTagName(t)[0]; }
// is this the live site or dev environment
const live = window.location.hostname === 'filesafe.org';

var Up = {
    // URL of the file upload handler
	url: live ? 'wss://filesafe.org/store' : 'ws://127.0.0.1:8000/store',
	// URL serving list of user's files
	user_files_url: live ? 'https://filesafe.org/files/' : 'http://127.0.0.1:8000/files/',
	// HTML template to render each uploaded file
	form_tpl: `<div class="upload__file">
        <div class="upload__file__wrap">
            <span class="upload__progress_bar"><i></i></span>
            <img class="upload__file__thumb" src="#thumb#">
        </div>
        <div>
            <label class="upload__delete" title="Delete forever">
                &times; <input type="checkbox" name="delete" id="deleteSUFFIX">
            </label>
        </div>
        <a class="upload__file_name" id="fnSUFFIX"></a>
        <div class="upload__file__caption"><input type="text" id="altSUFFIX" name="altSUFFIX" placeholder="Enter caption"></div>
        <input type="hidden" id="posSUFFIX" name="posSUFFIX">
        <input type="hidden" id="hashSUFFIX" name="hashSUFFIX">
    </div>
    `,
	// device and browser capability tests
	tests: {
		filereader: typeof FileReader != 'undefined', // is filereader supported
		dnd: 'draggable' in document.createElement('span'), // is drag and drop supported
		progress: "upload" in new XMLHttpRequest // will progress bars work
	},
	// handle adding file forms to a formset
	add_form: function(file_hash){
		var list = ID('upload_list');
		var total = document.querySelectorAll('input[name="delete"]').length;
		var form = Up.form_tpl.replace(/SUFFIX/g, total),
			id = 'id' + total,
			tmp = document.createElement('div');
		tmp.innerHTML = form;
		form = tmp.firstChild;
		form.id = id;
		list.appendChild(form);
		sortable_uploads();
		setup_delete(ID("delete"+total), file_hash);
		setup_update(ID("alt"+total), file_hash);
		return id;
	},
	fill_form: function(id, data){
		var box = ID(id);
		var img = N1('img', box);
		var i = id.replace('id', '')
		// img.src = data.url;
		ID(id).value = data.file_hash;
        setup_delete(ID('delete'+i), data.file_hash);
		setup_update(ID('alt'+i), data.file_hash);
	},
	post: function(i, data, id, fn){
	    const caption = ID(id.replace('id', 'alt')).value;
	    const user_hash = localStorage.getItem('user_sha') || 'anonymous';
	    const metadata = JSON.stringify({file_name: fn, caption: caption, user_hash: user_hash});
		return function(){
		    const socket = new WebSocket(Up.url);
            socket.onopen = function() {
                socket.send(metadata);
                socket.send(data.get('file'));
            };
            socket.onmessage = function(event) {
                var resp = JSON.parse(event.data);
                if (resp.status === 'error') {
                    // Handle errors
                    var box = ID(id);
                    box.parentNode.removeChild(box);
                } else {
                    // Handle success
                    Up.fill_form(id, resp); // Update the UI
                }
            };
            socket.onerror = function(error) {
                console.error("WebSocket error: ", error);
            };
		}
	},
	read: function(files){
		var qs = [];
		for(var i=0; i < files.length; i++){
		    var file = files[i];
            var data = new FormData();
            data.append('file', file);
            var id = Up.add_form();
            if (file.type.startsWith('image/')) {  // display thumbnail
                var reader = new FileReader();
                reader.onload = (function(id) {
                    return function(e) {
                        var img = N1('img', ID(id)); // Get the thumbnail image element
                        img.src = e.target.result;   // Set the src to the file's data URL
                    };
                })(id);
                reader.readAsDataURL(file);
            } else {  // or display extension
                Up.addExt(id, file.name);
            }
            ID(id.replace('id', 'fn')).textContent = file.name;
            qs[i] = Up.post(i, data, id, file.name);
		}
		for(var j=0; j < qs.length; j++){
			qs[j](); // run requests
		}
	},
	addExt: function(id, fn){
        // For non-image files, display the file extension instead of the thumbnail
        var img = N1('img', ID(id));
        img.style.display = 'none';
        var ext = fn.split('.').pop().toUpperCase(); // Get the file extension
        var wrap = ID(id).querySelector('.upload__file__wrap');
        var extEl = document.createElement('div');
        extEl.className = 'upload__file__ext';
        if(fn.includes('.')) extEl.textContent = '.' + ext; // Show extension
        wrap.appendChild(extEl);
	},
	load: function(){
		var d = ID('droparea'),
			file = ID('file');
		if(Up.tests.dnd && Up.tests.filereader){
			d.style.display = 'block';
			d.ondragover = function( ){
				this.className='upload__droparea hover';
				return false;
			}
			d.ondragend  = function( ){
				this.className='upload__droparea';
				return false;
			}
			d.ondrop = function(e){
				this.className='upload__droparea';
				e.preventDefault();
				Up.read(e.dataTransfer.files);
			}
		}
		if(Up.tests.filereader){
			var rm = document.getElementsByClassName('upload__fallback');
			for(var i=rm.length;i--;){rm[i].parentNode.removeChild(rm[i]);}
		}
		if(Up.tests.filereader){
			file.onchange = function(e){
				Up.read(e.target.files);
			}
		}
	}
}


function sortable_uploads(){
    var list = ID("upload_list");
    Sortable.create(list, {
        draggable: '.upload__file',
        onUpdate: function(evt){
            var inputs = document.querySelectorAll('input[name$="pos"]');
			for(var i=inputs.length; i--;){
				inputs[i].value = i;
			}
        }
    });
}

function setup_delete(btn, file_hash) {
    const user_hash = localStorage.getItem('user_sha') ;
    const delete_url = `${Up.user_files_url}${user_hash}/${file_hash}`;
    if(file_hash === undefined) return;
    btn.addEventListener('change', async function() {
        if (this.checked) {
            var fileDiv = this.closest('.upload__file');
            try {
                const response = await fetch(delete_url, { method: 'DELETE' });
                if (!response.ok) {
                    throw new Error('Error deleting file from server');
                }
                fileDiv.parentNode.removeChild(fileDiv);
            } catch (error) {
                console.error("Failed to delete file:", error);
            }
        }
    });
}

function setup_update(input, file_hash) {
    const user_hash = localStorage.getItem('user_sha');
    const update_url = `${Up.user_files_url}${user_hash}/${file_hash}`;
    let timer;
    input.addEventListener('input', function() {
        clearTimeout(timer);
        timer = setTimeout(async () => {
            const caption = input.value;
            try {
                const response = await fetch(update_url, {
                    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ caption: caption })
                });
                if (!response.ok) {
                    throw new Error('Error updating');
                }
                console.log("Update saved");
            } catch (error) {
                console.error("Failed to update:", error);
            }
        }, 800); // 800ms after user stops typing
    });

    // Reset timer if user continues typing
    input.addEventListener('keydown', function() {
        clearTimeout(timer);
    });
}


// Fire when DOM is ready
document.addEventListener('readystatechange', function(){
    if(document.readyState === 'complete'){
        const user_hash = localStorage.getItem('user_sha');
		Up.load();
		sortable_uploads();
		fetchUserFiles(user_hash);  // Fetch and display already uploaded files
	}
}, false);

async function fetchUserFiles(user_hash) {
    try {
        const response = await fetch(Up.user_files_url+user_hash);
        if (!response.ok) { throw new Error("Failed to fetch files."); }
        const files = await response.json();
        files.forEach(file => {
            displayFile(file);
        });
    } catch (error) {
        console.error("Error fetching files:", error);
    }
}

function displayFile(file) {
    var id = Up.add_form(file.file_hash);
    Up.addExt(id, file.file_name);
    // TODO show thumbnail
    // var img = N1('img', ID(id));
    // img.src = file.url || "spinner.gif";
    ID(id.replace('id', 'hash')).value = file.file_hash;
    ID(id.replace('id', 'alt')).value = file.caption;
    ID(id.replace('id', 'fn')).textContent = file.file_name;
    ID(id.replace('id', 'fn')).href = `${Up.user_files_url}${file.user_hash}${file.file_hash}`;
}

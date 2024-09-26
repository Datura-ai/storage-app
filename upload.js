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
            <label class="upload__delete" title="Mark for deletion">
                &times; <input type="checkbox" name="delete" id="deleteSUFFIX">
            </label>
        </div>
        <div class="upload__file__caption"><input type="text" id="altSUFFIX" name="altSUFFIX"></div>
        <input type="hidden" id="posSUFFIX" name="posSUFFIX">
        <input type="hidden" id="idSUFFIX" name="idSUFFIX">
    </div>
    `,
	// device and browser capability tests
	tests: {
		filereader: typeof FileReader != 'undefined', // is filereader supported
		dnd: 'draggable' in document.createElement('span'), // is drag and drop supported
		progress: "upload" in new XMLHttpRequest // will progress bars work
	},
	// handle adding file forms to a formset
	add_form: function(i){
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
		Up.setup_delete(ID("delete"+total));
		return id;
	},
	setup_delete: function(btn) {
        btn.addEventListener('change', function() {
            if (this.checked) {
                var fileDiv = this.closest('.upload__file');
                fileDiv.parentNode.removeChild(fileDiv);
                // handle server-side deletion
            }
        });
    },
	fill_form: function(id, xhr_response){
		var data = JSON.parse(xhr_response); // safe source
		var box = ID(id);
		var img = N1('img', box);
		img.src = data.url;
		ID('id'+id).value = data.id;
	},
	post: function(i, data, id, filename){
	    const caption = ID(id.replace('id', 'alt')).value;
	    const user_hash = localStorage.getItem('user_sha') || 'anonymous';
	    const metadata = JSON.stringify({filename: filename, caption: caption, user_hash: user_hash});
		return function(){
		    const socket = new WebSocket(Up.url);
            socket.onopen = function() {
                socket.send(metadata);
                socket.send(data.get('file'));
            };
            socket.onmessage = function(event) {
                var resp = event.data;  // Handle the response from the server
                if (resp === 'error') {
                    var box = ID(id);
                    box.parentNode.removeChild(box);
                } else {
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
            // prefill caption field with the filename
            ID(id.replace('id', 'alt')).value = file.name;
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


// Fire when DOM is ready
document.addEventListener('readystatechange', function(){
    if(document.readyState === 'complete'){
        const user_hash = 'anonymous'; // localStorage.getItem('user_sha');
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
    var id = Up.add_form();
    Up.addExt(id, '.encrypted'); // TODO show decrypted extension or thumbnail and caption
    // var img = N1('img', ID(id));
    // img.src = file.url || "spinner.gif";
    ID(id).value = file.id;
    ID(id.replace('id', 'alt')).value = file.file_hash;
}

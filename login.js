function ID(id) { return document.getElementById(id); }
const dialog   = ID('login_dialog');
const btn_open = ID('login_open');
const btn_shut = ID('login_shut');
const btn_save = ID('login_save');
const user_sha = ID('user_sha');
const logout = ID('logout');

btn_open.addEventListener('click', function() { dialog.showModal(); });
btn_shut.addEventListener('click', function() { dialog.close(); });
logout.addEventListener('click', function() {
    localStorage.removeItem('user_sha');
    window.location.reload();
});

// Check if user hash/username is already stored in localStorage
window.onload = function() {
    const storedHash = localStorage.getItem('user_sha');
    if (storedHash) {
        console.log('Key found:', storedHash);
        user_sha.value = storedHash;
        ID('login_prompt').innerText = storedHash;
        ID('logout').style.display = 'inline';
    } else {
        dialog.showModal();
    }
};

// Save the user hash/username to localStorage
btn_save.addEventListener('click', function() {
    const uname = user_sha.value;
    if (uname) {
        localStorage.setItem('user_sha', uname);
        ID('login_prompt').innerText = uname;
        ID('logout').style.display = 'inline';
        dialog.close();
        fetchUserFiles(uname);
    } else {
        ID('login_error').innerText ='Please enter your key or username.';
    }
});
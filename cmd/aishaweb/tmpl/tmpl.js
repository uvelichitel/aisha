// {{define "headerjs"}}
function checkauth() {
	if (decodeURIComponent(document.cookie).indexOf("aishatoken") == -1) {
		alert("Требуется авторизация");
		//		document.getElementById("loginModal").showModal();
		return false;
	}
	return true;
}

function register() {
	let tgID = document.getElementById("regtelegramID").value;
	let pswrd = document.getElementById("regpsw").value;
	if (!tgID || !pswrd) {
		alert("Заполните поля")
		return
	}
	const xhttp = new XMLHttpRequest();
	xhttp.onload = function() {
		if (this.status == 200) {
			document.getElementById("registerModal").close();
		}
		alert(this.responseText);
	}
	xhttp.open("POST", "register", true);
	xhttp.setRequestHeader("Authorization", "Basic " + btoa(tgID + ":" + pswrd));
	xhttp.send();
}

function login() {
	let tgID = document.getElementById("telegramID").value;
	let pswrd = document.getElementById("psw").value;
	const xhttp = new XMLHttpRequest();
	xhttp.onload = function() {
		if (this.status == 200) {
			if (document.getElementById("saveCred").checked) {
				localStorage.setItem("aishatoken", this.responseText);
				localStorage.setItem("telegramID", tgID);
				localStorage.setItem("psw", pswrd);
			} else {
				sessionStorage.setItem("aishatoken", this.responseText);
				sessionStorage.setItem("telegramID", tgID);
				sessionStorage.setItem("psw", pswrd);
			}
			const d = new Date();
			d.setTime(d.getTime() + (30 * 24 * 60 * 60 * 1000));
			let expires = "expires=" + d.toUTCString();
			document.cookie = "aishatoken=" + this.responseText + ";" + expires + ";path=/";
			alert("Вы успешно авторизовались");
			document.getElementById("loginModal").close();
			return;
		} else {
			alert(this.responseText);
		}
	}
	xhttp.open("POST", "login", true);
	xhttp.setRequestHeader("Authorization", "Basic " + btoa(tgID + ":" + pswrd));
	xhttp.send();
}
// {{end}}

// {{define "cabinetjs"}}
document.getElementById('tPlan').value = "{{.Tarif }}";
document.getElementById('model').value = "{{.Model }}";
document.getElementById('imgres').value = "{{.ImgRes }}";
document.getElementById('imgqlt').value = "{{.ImgQlt }}";
document.getElementById('imgstyle').value = "{{.ImgStyle }}";

document.getElementById("count").style.marginTop = document.getElementById("shapka").scrollHeight + "px"

document.getElementById('pay-button').addEventListener('click', (event) => {
	event.preventDefault();
	sendPayment(document.getElementById("payment").value);
});
document.getElementById('payment').addEventListener('keydown', (event) => {
	if (event.key === 'Enter') {
		event.preventDefault();
		sendPayment(document.getElementById("payment").value);
	}
});
function sendPayment() {
	if (!checkauth()) {
		return;
	}
	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
	amount = document.getElementById("payment").value;
	const xhttp = new XMLHttpRequest();
	xhttp.onload = function() {
		if (this.status == 200) {
			window.open(this.responseText, "_self");
			console.log("Get response open url")
			return
		} else {
			alert(this.responseText);
		}
	}
	xhttp.open("POST", "payment", true);
	console.log("open request")
	xhttp.setRequestHeader("Authorization", "Bearer " + token);
	xhttp.send(amount);
	console.log("send request")
}

function prefs() {
	if (!checkauth()) {
		return;
	}
	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
	const prfs = { tarif: document.getElementById("tPlan").value, model: document.getElementById("model").value, imgres: document.getElementById("imgres").value, imgqlt: document.getElementById("imgqlt").value, imgstyle: document.getElementById("imgstyle").value };
	const xhttp = new XMLHttpRequest();
	xhttp.onload = function() {
		alert(this.responseText);
	}
	xhttp.open("POST", "prefs", true);
	xhttp.setRequestHeader("Authorization", "Bearer " + token);
	xhttp.send(JSON.stringify(prfs));
}
// {{end}}

// {{define "chatjs"}}
var conversation = [{ "role": "system", "content": "You are a helpfull assistent. Your name is Aisha. Тебя зовут Аиша." }];
var imgregex = new RegExp("нарис.*|показ.*|покаж.*|изобр.*|картин.*", "i");
//var files = [];
var imgFiles = [];
var audioFiles = [];
var otherFiles = [];
var fr = new FileReader();

function listFilesToUpload(files) {
	let list = "";
	for (const file of files) {
		list = list + "," + file.name;
	}
	return list.slice(1);
}
const dropZone = document.body;
if (dropZone) {
	let hoverClassName = 'hover';

	dropZone.addEventListener("dragenter", function(e) {
		e.preventDefault();
		dropZone.classList.add(hoverClassName);
	});

	dropZone.addEventListener("dragover", function(e) {
		e.preventDefault();
		dropZone.classList.add(hoverClassName);
	});

	dropZone.addEventListener("dragleave", function(e) {
		e.preventDefault();
		dropZone.classList.remove(hoverClassName);
	});

	// Это самое важное событие, событие, которое дает доступ к файлам
	dropZone.addEventListener("drop", function(e) {
		if (document.getElementById('demo-area')) {
			e.preventDefault();
			dropZone.classList.remove(hoverClassName);
			let file = e.dataTransfer.files[0];
			if (file.type.includes("image")) {
				imgFiles.push(file);
				var fr = new FileReader();
				fr.onload = function(e) {
					renderImage(e.target.result);
				}
				fr.readAsDataURL(file);
			} else if (file.type.includes("audio")) {
				//TODO FileReader
				audioFiles.push(file);
				var fr = new FileReader();
				fr.onload = function(e) {
					renderAudio(e.target.result);
				}
				fr.readAsDataURL(file);
			} else {
				otherFiles.push(file);
			}
			document.getElementById("files-to-upload").innerText = listFilesToUpload([...imgFiles, ...audioFiles, ...otherFiles]);
		}
	});
}
function renderMessage(content, role) {
	const messageInput = document.getElementById('message-input');
	const chatMessages = document.getElementById('chat-messages');
	const messageElement = document.createElement('div');
	messageElement.classList.add(role + 'message');
	messageElement.textContent = content;
	chatMessages.appendChild(messageElement);
	messageInput.value = '';
	document.getElementById("chat-messages").style.marginBottom = document.getElementById("prompt").scrollHeight + "px"
	document.getElementById("chat-messages").style.marginTop = document.getElementById("shapka").scrollHeight + "px"
	//chatMessages.scrollTop = chatMessages.scrollHeight;
	chatMessages.lastElementChild.scrollIntoView()
}
function renderImage(url) {
	const messageInput = document.getElementById('message-input');
	const chatMessages = document.getElementById('chat-messages');
	const messageElement = document.createElement('div');
	messageElement.classList.add('image');
	const image = document.createElement('img');
	image.src = url;
	messageElement.appendChild(image);
	chatMessages.appendChild(messageElement);
	messageInput.value = '';
	document.getElementById("chat-messages").style.marginBottom = document.getElementById("prompt").scrollHeight + "px"
	document.getElementById("chat-messages").style.marginTop = document.getElementById("shapka").scrollHeight + "px"
	//chatMessages.scrollTop = chatMessages.scrollHeight;
	chatMessages.lastElementChild.scrollIntoView()
}

function renderAudio(url) {
	const messageInput = document.getElementById('message-input');
	const chatMessages = document.getElementById('chat-messages');
	const messageElement = document.createElement('div');
	const audio = document.createElement('audio');
	audio.setAttribute("controls", "true");
	audio.src = url;
	messageElement.appendChild(audio);
	chatMessages.appendChild(messageElement);
	messageInput.value = '';
	document.getElementById("chat-messages").style.marginBottom = document.getElementById("prompt").scrollHeight + "px";
	document.getElementById("chat-messages").style.marginTop = document.getElementById("shapka").scrollHeight + "px";
	//chatMessages.scrollTop = chatMessages.scrollHeight;
	chatMessages.lastElementChild.scrollIntoView();
	audio.play();
}

function renderReplyMessage(reply) {
	renderMessage(reply.Text, "assistant")
	document.getElementById("counter").innerText = reply.Usage
}
// Function to handle sending a message
function sendMessage() {
	if (audioFiles[0]) {
		sendAudio();
		return;
	}
	if (imgFiles[0]) {
		sendImages();
		return;
	}
	const messageInput = document.getElementById('message-input');
	const message = messageInput.value.replace(/\r?\n|\r/g, " ").trim();
	if (message === '') {
		alert("Введите текст")
		return;
	}
	renderMessage(message, "user")
	if (imgregex.test(message)) {
		requestImage(message);
		return;
	}
	conversation.push({ "role": "user", "content": message });
	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
	const xhttp = new XMLHttpRequest();
	xhttp.onload = function() {
		if (this.status == 200) {
			var reply = JSON.parse(this.responseText);
			conversation.push({ "role": "assistant", "content": reply.Text });
			renderReplyMessage(reply);
			if (document.getElementById("aloud").checked) {
				requestAudio(reply.Text);
				reply.Usage = reply.Usage + (reply.Text.length * 30);
				document.getElementById("counter").innerText = reply.Usage
			}
		} else {
			alert(this.responseText)
		}
	}
	xhttp.open("POST", "completion", true);
	// Some simple headers are required for this to work properly with their API.
	xhttp.setRequestHeader("Content-Type", "application/json");
	xhttp.setRequestHeader("Authorization", "Bearer " + token);
	xhttp.send(JSON.stringify(conversation));
}

function sendAudio() {
	const messageInput = document.getElementById('message-input');
	const message = messageInput.value.replace(/\r?\n|\r/g, " ").trim();
	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
	if (message === '') {
		alert("Введите текст")
		return;
	}
	renderMessage(message, "user")
	let formAudio = new FormData();
	// TODO uniqual name
	let file = audioFiles[0]
	formAudio.append("audio", file, token.split(".")[1] + file.name);
	formAudio.append("prompt", "message")
	const xhttp = new XMLHttpRequest();
	xhttp.onload = function() {
		if (this.status == 200) {
			var reply = JSON.parse(this.responseText);
			renderReplyMessage(reply);
			audioFiles.shift();
			document.getElementById("files-to-upload").innerText = listFilesToUpload([...imgFiles, ...audioFiles, ...otherFiles]);
		} else {
			alert(this.responseText)
		}
	}
	xhttp.open("POST", "transcription", true);
	xhttp.setRequestHeader("Authorization", "Bearer " + token);
	xhttp.send(formAudio);
}

function sendImages() {
	const messageInput = document.getElementById('message-input');
	const message = messageInput.value.replace(/\r?\n|\r/g, " ").trim();
	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
	if (message === '') {
		alert("Введите текст");
		return;
	}
	renderMessage(message, "user");
	// TODO with fetch
	console.log("START FETCH");
	fileString = "";
	(async () => {
		const promises = imgFiles.map((file) => {
			const formData = new FormData();
			const fileName = token.split(".")[1] + file.name;
			fileString = fileString + "," + fileName;
			formData.append("image", file, fileName);
			fetch("upload", {
				method: "POST",
				body: formData,
				headers: { "Authorization": "Bearer " + token },
			});
			//		.then((response) => {
			//		if (response.ok) {
			//			alert(response.text());
			//			return token.split(".")[1] + file.name;
			//		} else {
			//			alert(response.text());
			//			return "";
			//		}
			//	});
		}
		);
		//const uploadedImageFiles = await Promise.all(promises);
		await Promise.all(promises);
		//	console.log("UPLOADED IMAGE Files");
		//	console.log(uploadedImageFiles);
		imgFiles = [];
		document.getElementById("files-to-upload").innerText = listFilesToUpload([...imgFiles, ...audioFiles, ...otherFiles]);
		let formPrompt = new FormData();
		formPrompt.append("prompt", message);
		//const fileString = uploadedImageFiles.toString();
		console.log("FILESTRING" + fileString);
		formPrompt.append("files", fileString.substring(1));
		const xhttp = new XMLHttpRequest();
		xhttp.onload = function() {
			if (this.status == 200) {
				var reply = JSON.parse(this.responseText);
				console.log("REPLY = " + reply);
				//conversation.push({ "role": "assistant", "content": reply.Text });
				renderReplyMessage(reply);
			} else { alert(this.responseText) }
		}
		xhttp.open("POST", "vision", true);
		xhttp.setRequestHeader("Authorization", "Bearer " + token);
		xhttp.send(formPrompt);
	})();
}

let uploadedAssistFiles;

function sendOther() {
	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
	// TODO with fetch
	(async () => {
		const promises = otherFiles.map((file) => {
			//		data = new FormData();
			//      data.append("purpose", "assistants");
			//		data.append("file", file, token.split(".")[1] + file.name);
			const myHeaders = new Headers();
			myHeaders.append("Authorization", "Bearer " + token);
			myHeaders.append("Filename", token.split(".")[1] + file.name);
			fetch("uploadassist", {
				method: "POST",
				body: file,
				headers: myHeaders,
			});
		});
		await Promise.all(promises);
		//TODO
		uploadedAssistFiles.push(...otherFiles);
		console.log(uploadedAssistFiles);
		otherFiles = [];
		document.getElementById("files-to-upload").innerText = listFilesToUpload([...imgFiles, ...audioFiles, ...otherFiles]);
	})();
}
// TODO
//	do {
//		file = imgFiles.shift();
//		uploadedImageFiles = uploadedImageFiles + "," + token.split(".")[1] + file.name;
//		formImg = new FormData();
//		// TODO uniqual name
//		formImg.append("image", file, token.split(".")[1] + file.name);
//		const xhttp = new XMLHttpRequest();
//		xhttp.onload = function() {
//			if (this.status == 200) {
//				var reply = this.responseText.replace(token.split(".")[1], "");
//				renderMessage(reply);
//				document.getElementById("files-to-upload").innerText = listFilesToUpload([...imgFiles, ...audioFiles, ...otherFiles]);
//			} else { alert(this.responseText) }
//		}
//		xhttp.open("POST", "upload", true);
//		xhttp.setRequestHeader("Authorization", "Bearer " + token);
//		xhttp.send(formImg);
//		console.log(formImg)
//	} while (imgFiles[0]);
//	let formPrompt = new FormData();
//	formPrompt.append("prompt", message);
//	formPrompt.append("files", uploadedImageFiles.slice(1));
//	const xhttp = new XMLHttpRequest();
//	xhttp.onload = function() {
//		if (this.status == 200) {
//			var reply = this.responseText;
//			renderMessage(reply)
//		} else { alert(this.responseText) }
//	}
//	xhttp.open("POST", "vision", true);
//	xhttp.setRequestHeader("Authorization", "Bearer " + token);
//	xhttp.send(formPrompt);
//}

function requestImage(prmpt) {
	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
	const xhttp = new XMLHttpRequest();
	xhttp.onload = function() {
		if (this.status == 200) {
			var reply = JSON.parse(this.responseText);
			renderImage(reply.URL)
			document.getElementById("counter").innerText = reply.Usage
		} else { alert(this.responseText) }
	}
	xhttp.open("POST", "painting", true);
	// Some simple headers are required for this to work properly with their API.
	xhttp.setRequestHeader("Content-Type", "text/plain");
	xhttp.setRequestHeader("Authorization", "Bearer " + token);
	xhttp.send(prmpt);
}

//function requestAudio(prmpt) {
//	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
//	const xhttp = new XMLHttpRequest();
//	xhttp.onload = function() {
//		if (this.status == 200) {
//			let fileData = new Blob([xhttp.response.value], {type: 'audio/mp3'});
//			let audioURL = window.URL.createObjectURL(fileData);
//			//var reply = JSON.parse(this.responseText);
//			renderAudio(audioURL)
//			//document.getElementById("counter").innerText = reply.Usage
//		} else { alert(this.responseText) }
//	}
//	xhttp.open("POST", "speech", true);
//	// Some simple headers are required for this to work properly with their API.
//	xhttp.setRequestHeader("Content-Type", "text/plain");
//	xhttp.setRequestHeader("Authorization", "Bearer " + token);
//	xhttp.send(prmpt);
//}

//function addFileToUpload(input) {
//	let file = input.files[0];
//	files.push(file);
//}
async function requestAudio(prmpt) {
	let token = sessionStorage.getItem("aishatoken") ? sessionStorage.getItem("aishatoken") : localStorage.getItem("aishatoken");
	try {
		const response = await fetch("speech",
			{
				method: 'POST',
				headers: {
					'Authorization': "Bearer " + token
				},
				body: prmpt
			}
		);
		if (!response.ok) {
			throw new Error(`Response status: ${response.status}`);
		}
		const blob = await response.blob();
		const objectURL = URL.createObjectURL(blob);
		renderAudio(objectURL);
	} catch (e) {
		console.error(e);
	}
}

function clearFiles() {
	otherFiles.length = 0;
	audioFiles.length = 0;
	imgFiles.length = 0;
	document.getElementById("files-to-upload").innerText = listFilesToUpload([...imgFiles, ...audioFiles, ...otherFiles]);
}

function clearContext() {
	conversation = [{ "role": "system", "content": "You are a helpfull assistent. Your name is Aisha. Тебя зовут Аиша." }];
}

// Event listener
document.getElementById("sfile").addEventListener("change", (event) => {
	let file = event.target.files[0];
	document.getElementById("files-to-upload").innerText = listFilesToUpload([...imgFiles, ...audioFiles, ...otherFiles]);
	if (file.type.includes("image")) {
		imgFiles.push(file);
		var fr = new FileReader();
		fr.onload = function(e) {
			renderImage(e.target.result);
		}
		fr.readAsDataURL(file);
	} else if (file.type.includes("audio")) {
		//TODO FileReader
		audioFiles.push(file);
		var fr = new FileReader();
		fr.onload = function(e) {
			renderAudio(e.target.result);
		}
		fr.readAsDataURL(file);
	} else {
		otherFiles.push(file);
	}
});

//TODO switch https://www.w3schools.com/js/js_switch.asp
document.getElementById('send-button').addEventListener('click', (event) => {
	event.preventDefault();
	sendMessage();
});
document.getElementById('message-input').addEventListener('keydown', (event) => {
	if (event.key === 'Enter') {
		event.preventDefault();
		sendMessage();
	}
});

// {{end}}

//function getCookie(cname) {
//	let name = cname + "=";
//	let decodedCookie = decodeURIComponent(document.cookie);
//	let ca = decodedCookie.split(';');
//	for (let i = 0; i < ca.length; i++) {
//		let c = ca[i];
//		while (c.charAt(0) == ' ') {
//			c = c.substring(1);
//		}
//		if (c.indexOf(name) == 0) {
//			return c.substring(name.length, c.length);
//		}
//	}
//	return "";
//}
//function setCookie(cname, cvalue, exdays) {
//	const d = new Date();
//	d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
//	let expires = "expires=" + d.toUTCString();
//	document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
//}
//function checkCookie() {
//	let username = getCookie("username");
//	if (username != "") {
//		alert("Welcome again " + username);
//} else {
//		username = prompt("Please enter your name:", "");
//		if (username != "" && username != null) {
//			setCookie("username", username, 365);
//		}
//	}
//}

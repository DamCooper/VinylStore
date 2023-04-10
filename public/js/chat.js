const form = document.querySelector('#message-form');
const messages = document.querySelector('#messages');

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const input = document.querySelector('input[name="message_text"]');
  const message = input.value;
  input.value = '';
  fetch('/addChatMessage', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      'message_text': message
    }),
  })
    .catch(err => console.error(err));
});

fetch('/getChatMessages')
.then(res => res.json())
.then(data => {
  messages.innerHTML = '';
  data.forEach(msg => {
    const div = document.createElement('div');
    div.classList.add('message');
    const userSpan = document.createElement('span');
    userSpan.classList.add('user');
    userSpan.textContent = msg.user_name + ':';
    const textSpan = document.createElement('span');
    textSpan.classList.add('text');
    textSpan.textContent = msg.text;
    div.appendChild(userSpan);
    div.appendChild(textSpan);
    messages.appendChild(div);
  });
})
.catch(err => console.error(err));

setInterval(() => {
  fetch('/getChatMessages')
  .then(res => res.json())
  .then(data => {
    messages.innerHTML = '';
    data.forEach(msg => {
      const div = document.createElement('div');
      div.classList.add('message');
      const userSpan = document.createElement('span');
      userSpan.classList.add('user');
      userSpan.textContent = msg.user_name + ':';
      const textSpan = document.createElement('span');
      textSpan.classList.add('text');
      textSpan.textContent = msg.text;
      div.appendChild(userSpan);
      div.appendChild(textSpan);
      messages.appendChild(div);
    });
  })
  .catch(err => console.error(err));
}, 5000);
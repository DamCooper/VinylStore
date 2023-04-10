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

setInterval(() => {
  fetch('/getChatMessages')
  .then(res => res.json())
  .then(data => console.log(data))
  .catch(err => console.error(err));
}, 5000);

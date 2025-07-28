const themeToggle = document.getElementById('themeToggle');
const searchInput = document.getElementById('search');
const tagsContainer = document.getElementById('tags');
const articlesContainer = document.getElementById('articles');

let articles = [];

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
}

function applyThemeFromStorage() {
  const saved = localStorage.getItem('theme');
  if (saved) {
    document.documentElement.setAttribute('data-theme', saved);
  }
}

themeToggle.addEventListener('click', toggleTheme);
applyThemeFromStorage();

function fetchArticles() {
  fetch('posts/index.json')
    .then(res => res.json())
    .then(data => {
      articles = data;
      renderTags();
      renderArticles();
    });
}

function renderTags() {
  const allTags = new Set();
  articles.forEach(a => a.tags.forEach(t => allTags.add(t)));
  tagsContainer.innerHTML = '';
  allTags.forEach(tag => {
    const btn = document.createElement('button');
    btn.textContent = tag;
    btn.onclick = () => filterByTag(tag);
    tagsContainer.appendChild(btn);
  });
}

function renderArticles(filter = '') {
  const query = searchInput.value.toLowerCase();
  articlesContainer.innerHTML = '';
  articles
    .filter(a => 
      (!filter || a.tags.includes(filter)) &&
      (a.title.toLowerCase().includes(query) || a.description.toLowerCase().includes(query))
    )
    .forEach(article => {
      const el = document.createElement('article');
      el.innerHTML = `<h2>${article.title}</h2><p>${article.description}</p>`;
      el.onclick = () => loadMarkdown(article.file);
      articlesContainer.appendChild(el);
    });
}

function filterByTag(tag) {
  renderArticles(tag);
}

searchInput.addEventListener('input', () => renderArticles());

function loadMarkdown(file) {
  fetch(`posts/${file}`)
    .then(res => res.text())
    .then(md => {
      const el = document.createElement('article');
      el.innerHTML = marked.parse(md);
      articlesContainer.innerHTML = '';
      articlesContainer.appendChild(el);
    });
}

fetchArticles();

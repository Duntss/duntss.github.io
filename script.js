const themeToggle = document.getElementById('themeToggle');
const searchInput = document.getElementById('search');
const tagsContainer = document.getElementById('tags');
const articlesContainer = document.getElementById('articles');

let articles = [];

// 🌙 Thème clair/sombre
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

// 📦 Récupère les métadonnées des articles
function fetchArticles() {
  fetch('posts/index.json')
    .then(res => res.json())
    .then(data => {
      articles = data;
      renderTags();
      renderArticles();
      handleInitialHash(); // charge article direct si hash présent
    });
}

// 🏷️ Génère les tags
function renderTags() {
  const allTags = new Set();
  articles.forEach(a => a.tags.forEach(t => allTags.add(t)));
  tagsContainer.innerHTML = '';
  allTags.forEach(tag => {
    const btn = document.createElement('button');
    btn.textContent = tag;
    btn.onclick = () => renderArticles(tag);
    tagsContainer.appendChild(btn);
  });
}

// 📝 Affiche les articles (filtres recherche + tags)
function renderArticles(filterTag = '') {
  const query = searchInput.value.toLowerCase();
  articlesContainer.innerHTML = '';
  articles
    .filter(a =>
      (!filterTag || a.tags.includes(filterTag)) &&
      (a.title.toLowerCase().includes(query) || a.description.toLowerCase().includes(query))
    )
    .forEach(article => {
      const el = document.createElement('article');
      el.innerHTML = `
        <h2><a href="#${article.file}">${article.title}</a></h2>
        <p>${article.description}</p>
      `;
      articlesContainer.appendChild(el);
    });
}

searchInput.addEventListener('input', () => renderArticles());

// 📄 Charge le contenu Markdown dynamiquement
function loadMarkdown(file) {
  fetch(`posts/${file}`)
    .then(res => res.text())
    .then(md => {
      // Supprime le frontmatter YAML s'il existe
      const content = md.replace(/---(.|\n)*?---/, '');
      const el = document.createElement('article');
      el.innerHTML = marked.parse(content);
      articlesContainer.innerHTML = '';
      articlesContainer.appendChild(el);
    })
    .catch(() => {
      articlesContainer.innerHTML = `<p>⚠️ Failed to load ${file}</p>`;
    });
}

// 🔗 Gère les liens dans l'URL (hash)
function handleInitialHash() {
  const hash = location.hash.slice(1);
  if (hash.endsWith('.md')) {
    loadMarkdown(hash);
  }
}

window.addEventListener('hashchange', handleInitialHash);

// 🚀 Démarrage
fetchArticles();

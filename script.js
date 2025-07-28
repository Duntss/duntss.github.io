document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('themeToggle');
    const listContainer = document.getElementById('list-container');
    const postContainer = document.getElementById('post-container');
    const articlesList = document.getElementById('articles-list');
    const postContent = document.getElementById('post-content');
    const backButton = document.getElementById('back-button');

    // --- Theme ---
    function applyTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
    }

    themeToggle.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    });

    // --- Routing ---
    function showPost(fileName) {
        listContainer.classList.add('hidden');
        postContainer.classList.remove('hidden');
        loadPost(fileName);
    }

    function showList() {
        listContainer.classList.remove('hidden');
        postContainer.classList.add('hidden');
        location.hash = '';
    }

    // --- Data Loading ---
    async function loadPost(fileName) {
        try {
            const response = await fetch(`./posts/${fileName}`);
            if (!response.ok) {
                throw new Error(`Failed to fetch ${fileName}`);
            }
            const md = await response.text();
            // Strip YAML frontmatter
            const content = md.replace(/---(.|\n)*?---/, '');
            postContent.innerHTML = marked.parse(content);
        } catch (error) {
            console.error(error);
            postContent.innerHTML = `<p>Error loading article. Please try again.</p>`;
        }
    }

    async function loadArticleIndex() {
        try {
            const response = await fetch('./posts/index.json');
            const articles = await response.json();
            articlesList.innerHTML = '';
            for (const article of articles) {
                const link = document.createElement('a');
                link.href = `#${article.file}`;
                link.innerHTML = `
                    <h3>${article.title}</h3>
                    <p>${article.description}</p>
                `;
                articlesList.appendChild(link);
            }
        } catch (error) {
            console.error(error);
            articlesList.innerHTML = 'Could not load articles.';
        }
    }

    // --- Event Listeners ---
    backButton.addEventListener('click', showList);
    window.addEventListener('hashchange', handleHashChange);

    // --- Initialization ---
    function handleHashChange() {
        const hash = location.hash.slice(1);
        if (hash.endsWith('.md')) {
            showPost(hash);
        } else {
            showList();
        }
    }

    applyTheme();
    loadArticleIndex();
    handleHashChange(); // Check hash on initial load
});

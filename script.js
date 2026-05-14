/**
 * Duntss Security Research Blog
 * Main application logic
 */

// ===========================================
// State Management
// ===========================================
const AppState = {
    currentPostFile: '',
    currentArticleData: null,
    articles: []
};

// ===========================================
// DOM Elements Cache
// ===========================================
const DOM = {
    themeToggle: null,
    listContainer: null,
    postContainer: null,
    articlesList: null,
    postContent: null,
    postMeta: null,
    backButton: null,
    likeButton: null,
    likeCount: null
};

// ===========================================
// Theme Management
// ===========================================
const ThemeManager = {
    init() {
        DOM.themeToggle = document.getElementById('themeToggle');
        this.applyTheme();
        DOM.themeToggle.addEventListener('click', () => this.toggleTheme());
    },

    applyTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
    },

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    }
};

// ===========================================
// Router / Navigation
// ===========================================
const Router = {
    init() {
        DOM.backButton = document.getElementById('back-button');
        DOM.backButton.addEventListener('click', () => this.showList());
        window.addEventListener('hashchange', () => this.handleHashChange());
        this.handleHashChange();
    },

    showPost(fileName) {
        AppState.currentPostFile = fileName;
        DOM.listContainer.classList.add('hidden');
        DOM.postContainer.classList.remove('hidden');
        ContentLoader.loadPost(fileName);
        LikeManager.updateLikeCount();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    },

    showList() {
        DOM.listContainer.classList.remove('hidden');
        DOM.postContainer.classList.add('hidden');
        location.hash = '';
        window.scrollTo({ top: 0, behavior: 'smooth' });
    },

    handleHashChange() {
        const hash = location.hash.slice(1);
        if (hash.endsWith('.md')) {
            this.showPost(hash);
        } else {
            this.showList();
        }
    }
};

// ===========================================
// GitHub Projects Loader
// ===========================================
const GitHubLoader = {
    GITHUB_USER: 'Duntss',
    MAX_REPOS: 6,

    async fetchRepos() {
        try {
            const res = await fetch(
                `https://api.github.com/users/${this.GITHUB_USER}/repos?sort=pushed&direction=desc&per_page=${this.MAX_REPOS}&type=public`
            );
            if (!res.ok) return [];
            const repos = await res.json();
            return repos.filter(r => !r.fork && r.stargazers_count >= 3);
        } catch {
            return [];
        }
    },

    formatDate(iso) {
        const d = new Date(iso);
        return d.toLocaleDateString('fr-FR', { day: 'numeric', month: 'short', year: 'numeric' });
    },

    toFeedItem(repo) {
        return {
            type: 'github',
            title: repo.name,
            description: repo.description || 'No description',
            date: repo.pushed_at,
            url: repo.html_url,
            language: repo.language,
            stars: repo.stargazers_count,
            forks: repo.forks_count
        };
    }
};

// ===========================================
// Content Loader
// ===========================================
const ContentLoader = {
    async loadPost(fileName) {
        try {
            const response = await fetch(`./posts/${fileName}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const md = await response.text();

            // Find article metadata
            const articleData = AppState.articles.find(a => a.file === fileName);
            AppState.currentArticleData = articleData;

            // Render metadata
            if (articleData) {
                this.renderPostMeta(articleData);
            }

            // Strip YAML frontmatter and parse markdown
            const content = md.replace(/^---[\s\S]*?---\n/, '');
            DOM.postContent.innerHTML = marked.parse(content);

            // Syntax highlighting
            DOM.postContent.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);
            });

        } catch (error) {
            console.error('Error loading post:', error);
            DOM.postContent.innerHTML = `
                <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                    <h3>Error Loading Article</h3>
                    <p>Unable to load the requested article. Please try again later.</p>
                </div>
            `;
        }
    },

    renderPostMeta(article) {
        if (!DOM.postMeta) return;

        const metaHTML = `
            <div class="meta-item">
                <span class="meta-label">Title:</span>
                <span>${article.title}</span>
            </div>
            ${article.tags && article.tags.length > 0 ? `
                <div class="meta-item">
                    <span class="meta-label">Tags:</span>
                    <div class="article-tags">
                        ${article.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                    </div>
                </div>
            ` : ''}
        `;

        DOM.postMeta.innerHTML = metaHTML;
    },

    async loadArticleIndex() {
        try {
            const [indexRes, githubRepos] = await Promise.all([
                fetch('./posts/index.json'),
                GitHubLoader.fetchRepos()
            ]);

            if (!indexRes.ok) throw new Error(`HTTP error! status: ${indexRes.status}`);
            const articles = await indexRes.json();
            AppState.articles = articles;

            const articleItems = articles.map(a => {
                const dateMatch = a.file.match(/^(\d{4}-\d{2}-\d{2})/);
                return {
                    type: 'article',
                    title: a.title,
                    description: a.description,
                    date: a.date || (dateMatch ? dateMatch[1] : null),
                    file: a.file,
                    tags: a.tags || []
                };
            });

            const githubItems = githubRepos.map(r => GitHubLoader.toFeedItem(r));

            const feed = [...articleItems, ...githubItems].sort((a, b) => {
                if (!a.date) return 1;
                if (!b.date) return -1;
                return new Date(b.date) - new Date(a.date);
            });

            this.renderFeed(feed);
        } catch (error) {
            console.error('Error loading feed:', error);
            DOM.articlesList.innerHTML = `
                <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                    <p>Unable to load content. Please try again later.</p>
                </div>
            `;
        }
    },

    renderFeed(items) {
        DOM.articlesList.innerHTML = '';

        items.forEach(item => {
            if (item.type === 'article') {
                const card = document.createElement('a');
                card.href = `#${item.file}`;
                card.className = 'article-card';

                const tagsHTML = item.tags.length > 0
                    ? `<div class="article-tags">${item.tags.map(t => `<span class="tag">${t}</span>`).join('')}</div>`
                    : '';

                const dateHTML = item.date
                    ? `<span class="card-date">${GitHubLoader.formatDate(item.date)}</span>`
                    : '';

                card.innerHTML = `
                    <div class="card-type-badge badge-article">Article</div>
                    <h3>${item.title}</h3>
                    <p>${item.description}</p>
                    ${tagsHTML}
                    ${dateHTML}
                `;
                DOM.articlesList.appendChild(card);
            } else {
                const card = document.createElement('a');
                card.href = item.url;
                card.target = '_blank';
                card.rel = 'noopener noreferrer';
                card.className = 'article-card github-card';

                const langHTML = item.language
                    ? `<span class="tag lang-tag">${item.language}</span>`
                    : '';

                card.innerHTML = `
                    <div class="card-type-badge badge-github">
                        <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
                        GitHub
                    </div>
                    <h3>${item.title}</h3>
                    <p>${item.description}</p>
                    <div class="github-card-footer">
                        <div class="article-tags">${langHTML}</div>
                        <div class="github-stats">
                            <span title="Stars">★ ${item.stars}</span>
                            <span title="Forks">⑂ ${item.forks}</span>
                            <span class="card-date">${GitHubLoader.formatDate(item.date)}</span>
                        </div>
                    </div>
                `;
                DOM.articlesList.appendChild(card);
            }
        });
    }
};

// ===========================================
// Like System
// ===========================================
const LikeManager = {
    init() {
        DOM.likeButton = document.getElementById('like-button');
        DOM.likeCount = document.getElementById('like-count');
        DOM.likeButton.addEventListener('click', () => this.handleLike());
    },

    getLikes(fileName) {
        return parseInt(localStorage.getItem(`likes_${fileName}`) || '0', 10);
    },

    setLikes(fileName, count) {
        localStorage.setItem(`likes_${fileName}`, count.toString());
    },

    hasLiked(fileName) {
        return localStorage.getItem(`liked_${fileName}`) === 'true';
    },

    setLiked(fileName) {
        localStorage.setItem(`liked_${fileName}`, 'true');
    },

    updateLikeCount() {
        const likes = this.getLikes(AppState.currentPostFile);
        DOM.likeCount.textContent = likes.toString();

        if (this.hasLiked(AppState.currentPostFile)) {
            DOM.likeButton.disabled = true;
            DOM.likeButton.style.opacity = '0.5';
        } else {
            DOM.likeButton.disabled = false;
            DOM.likeButton.style.opacity = '1';
        }
    },

    handleLike() {
        if (!this.hasLiked(AppState.currentPostFile)) {
            let likes = this.getLikes(AppState.currentPostFile);
            likes++;
            this.setLikes(AppState.currentPostFile, likes);
            this.setLiked(AppState.currentPostFile);
            this.updateLikeCount();

            // Visual feedback
            DOM.likeButton.style.transform = 'scale(1.2)';
            setTimeout(() => {
                DOM.likeButton.style.transform = '';
            }, 200);
        }
    }
};

// ===========================================
// Application Initialization
// ===========================================
function initApp() {
    // Cache DOM elements
    DOM.listContainer = document.getElementById('list-container');
    DOM.postContainer = document.getElementById('post-container');
    DOM.articlesList = document.getElementById('articles-list');
    DOM.postContent = document.getElementById('post-content');
    DOM.postMeta = document.getElementById('post-meta');

    // Initialize modules
    ThemeManager.init();
    LikeManager.init();
    Router.init();

    // Load articles
    ContentLoader.loadArticleIndex();

    // Configure marked.js options
    if (typeof marked !== 'undefined') {
        marked.setOptions({
            breaks: true,
            gfm: true,
            headerIds: true,
            mangle: false
        });
    }
}

// Start the application when DOM is ready
document.addEventListener('DOMContentLoaded', initApp);

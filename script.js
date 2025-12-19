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
            const response = await fetch('./posts/index.json');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const articles = await response.json();
            // Reverse the array to show newest articles first
            const articlesReversed = articles.reverse();
            AppState.articles = articlesReversed;
            this.renderArticlesList(articlesReversed);
        } catch (error) {
            console.error('Error loading articles index:', error);
            DOM.articlesList.innerHTML = `
                <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                    <p>Unable to load articles. Please try again later.</p>
                </div>
            `;
        }
    },

    renderArticlesList(articles) {
        DOM.articlesList.innerHTML = '';

        articles.forEach(article => {
            const card = document.createElement('a');
            card.href = `#${article.file}`;
            card.className = 'article-card';

            const tagsHTML = article.tags && article.tags.length > 0
                ? `<div class="article-tags">
                     ${article.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                   </div>`
                : '';

            card.innerHTML = `
                <h3>${article.title}</h3>
                <p>${article.description}</p>
                ${tagsHTML}
            `;

            DOM.articlesList.appendChild(card);
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

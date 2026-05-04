// ─── NAV SCROLL ───────────────────────────────────────────────────
const navbar = document.getElementById('navbar');
window.addEventListener('scroll', () => {
  navbar.classList.toggle('scrolled', window.scrollY > 40);
});

// ─── MOBILE NAV ───────────────────────────────────────────────────
const toggle = document.getElementById('navToggle');
const navLinks = document.getElementById('navLinks');
toggle.addEventListener('click', () => navLinks.classList.toggle('open'));
navLinks.querySelectorAll('a').forEach(a => {
  a.addEventListener('click', () => navLinks.classList.remove('open'));
});

// ─── ACTIVE NAV ON SCROLL ─────────────────────────────────────────
const sections = document.querySelectorAll('section[id]');
const navAnchors = document.querySelectorAll('#navLinks a');

const observer = new IntersectionObserver(
  entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        navAnchors.forEach(a => {
          a.classList.toggle('active', a.getAttribute('href') === '#' + entry.target.id);
        });
      }
    });
  },
  { rootMargin: '-40% 0px -55% 0px' }
);
sections.forEach(s => observer.observe(s));

// ─── TABS ─────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const group = btn.closest('.tab-group');
    group.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    group.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

// ─── SCORE BAR ANIMATION ──────────────────────────────────────────
const barObserver = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.querySelectorAll('.score-bar-fill').forEach(bar => {
        bar.style.width = bar.dataset.w || '0%';
      });
    }
  });
}, { threshold: 0.2 });

document.querySelectorAll('.scoring-bars').forEach(el => {
  el.querySelectorAll('.score-bar-fill').forEach(bar => {
    bar.dataset.w = bar.style.width;
    bar.style.width = '0%';
    bar.style.transition = 'width 1s ease';
  });
  barObserver.observe(el);
});

// ─── CONTACT FORM ─────────────────────────────────────────────────
const contactForm = document.getElementById('contactForm');
if (contactForm) {
  contactForm.addEventListener('submit', e => {
    e.preventDefault();

    const name    = document.getElementById('cf-name').value.trim();
    const email   = document.getElementById('cf-email').value.trim();
    const subject = document.getElementById('cf-subject').value;
    const message = document.getElementById('cf-message').value.trim();

    if (!name || !email || !message) return;

    const body = `Name: ${name}\nEmail: ${email}\n\n${message}`;
    const mailto = `mailto:capslockkube@gmail.com`
      + `?subject=${encodeURIComponent('[CAPSLock] ' + subject)}`
      + `&body=${encodeURIComponent(body)}`;

    window.location.href = mailto;

    const btn = contactForm.querySelector('button[type=submit]');
    btn.textContent = 'Opening email client...';
    btn.style.background = 'var(--accent-green)';
    btn.style.color = '#060b18';
    setTimeout(() => {
      btn.textContent = 'Send Message';
      btn.style.background = '';
      btn.style.color = '';
    }, 3000);
  });
}

// ─── COUNTER ANIMATION ────────────────────────────────────────────
function animateCount(el, target, duration = 1200) {
  const start = performance.now();
  const isFloat = target % 1 !== 0;
  const step = ts => {
    const progress = Math.min((ts - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = eased * target;
    el.textContent = isFloat ? current.toFixed(1) : Math.floor(current).toLocaleString();
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

const countObserver = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const el = entry.target;
      const target = parseFloat(el.dataset.count);
      animateCount(el, target);
      countObserver.unobserve(el);
    }
  });
}, { threshold: 0.5 });

document.querySelectorAll('[data-count]').forEach(el => countObserver.observe(el));

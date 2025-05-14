document.addEventListener("DOMContentLoaded", function() {
    // Initialize Bootstrap scrollspy
    var scrollSpy = new bootstrap.ScrollSpy(document.body, {
        target: '#navbar',
        offset: 100
    });
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('.scroll-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                const navbarHeight = document.querySelector('#navbar').offsetHeight;
                const targetPosition = targetElement.offsetTop - navbarHeight;
                
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
                
                // Close mobile menu when clicking a link
                const navbarToggler = document.querySelector('.navbar-toggler');
                const navbarCollapse = document.querySelector('.navbar-collapse');
                if (navbarCollapse.classList.contains('show')) {
                    navbarToggler.click();
                }
            }
        });
    });
    
    // Add active class to nav items on scroll
    window.addEventListener('scroll', function() {
        const sections = document.querySelectorAll('section');
        const navLinks = document.querySelectorAll('.nav-link');
        
        let current = '';
        
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100;
            const sectionHeight = section.clientHeight;
            
            if (pageYOffset >= sectionTop) {
                current = section.getAttribute('id');
            }
        });
        
        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + current) {
                link.classList.add('active');
            }
        });
    });
    
    // Form submission handling
// Update your existing form submission code
document.addEventListener("DOMContentLoaded", function() {
    // Keep all your existing code
    
    // Replace the contactForm event listener with this:
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            // We don't prevent default here as we want the form to submit to Formspree
            
            // Add form submission status indicator
            const submitBtn = contactForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.innerHTML;
            
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sending...';
            
            // We'll handle the success/error display via Formspree's built-in redirect
            // No need for additional AJAX handling
            
            // If you want to handle the response on the same page, you can use fetch API instead
            // and remove the form's action attribute. Example in documentation.
        });
    }
});
    
    // Navbar background color change on scroll
    window.addEventListener('scroll', function() {
        const navbar = document.querySelector('.navbar');
        
        if (window.scrollY > 50) {
            navbar.classList.add('bg-dark');
            navbar.classList.remove('bg-transparent');
        } else if (window.location.hash === '' || window.location.hash === '#home') {
            navbar.classList.add('bg-transparent');
            navbar.classList.remove('bg-dark');
        }
    });
});


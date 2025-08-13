/**
 * DC Water Service Status Dashboard - Frontend Logic
 * 
 * Core Functionality:
 * - Real-time status updates
 * - Search and filtering
 * - Auto-refresh management
 * - Status summary calculations
 * - Tutorial system
 * 
 * Performance Considerations:
 * - Debounced search
 * - Optimized DOM operations
 * - Event delegation for dynamic elements
 * - Memory leak prevention
 * 
 * Browser Compatibility:
 * - ES6+ with basic polyfills
 * - Touch events supported
 * - Graceful degradation for older browsers
 * 
 * Security:
 * - XSS prevention in dynamic content
 * - Content Security Policy compliant
 * - No sensitive data in client-side code
 */

document.addEventListener('DOMContentLoaded', function() {
    // Show loader initially
    toggleLoader(true);
    
    // Hide loader after initial load
    setTimeout(() => {
        toggleLoader(false);
    }, 1000);

    // Hide loading screen when page is loaded
    const loader = document.getElementById('initial-loader');
    if (loader) {
        setTimeout(() => {
            loader.style.opacity = '0';
            setTimeout(() => {
                loader.style.display = 'none';
            }, 500);
        }, 1000);
    }

    const searchInput = document.querySelector('#searchInput');
    const issuesOnlyToggle = document.querySelector('#showIssuesOnly');
    const noIssuesMessage = document.querySelector('#no-issues-message');

    const cardElements = {
        cards: document.querySelectorAll('.host-card'),
        statusIndicators: document.querySelectorAll('.status-indicator'),
        headers: document.querySelectorAll('.card-header')
    };

    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                filterCards();
            }, 300);
        });
    }

    if (issuesOnlyToggle) {
        issuesOnlyToggle.addEventListener('change', function() {
            filterCards();
        });
    }

    // Check initial state when page loads
    checkForIssues();

    function checkForIssues() {
        const cards = document.querySelectorAll('.host-card');
        let hasIssues = false;
        const showIssuesOnly = issuesOnlyToggle ? issuesOnlyToggle.checked : false;

        cards.forEach(card => {
            const statusIndicator = card.querySelector('.status-indicator i');
            if (statusIndicator && !statusIndicator.classList.contains('green-drop')) {
                hasIssues = true;
            }
        });

        if (noIssuesMessage) {
            if (showIssuesOnly && !hasIssues) {
                noIssuesMessage.style.display = 'block';
            } else {
                noIssuesMessage.style.display = 'none';
            }
        }
    }

    function filterCards() {
        const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        const showIssuesOnly = document.getElementById('showIssuesOnly')?.checked || false;
        const showCriticalOnly = document.getElementById('showCriticalOnly')?.checked || false;
        const showWarningOnly = document.getElementById('showWarningOnly')?.checked || false;
        const showUnknownOnly = document.getElementById('showUnknownOnly')?.checked || false;
        
        const cards = document.querySelectorAll('.host-card');
        let visibleCards = 0;
        let hasIssues = false;
        let hasCritical = false;
        let hasWarning = false;
        let hasUnknown = false;

        cards.forEach(card => {
            const hostNameElement = card.querySelector('.font-weight-bold');
            const hostName = hostNameElement ? hostNameElement.textContent.toLowerCase().trim() : '';
            const services = Array.from(card.querySelectorAll('td')).map(el => el?.textContent?.toLowerCase()?.trim() || '');
            const statusIndicator = card.querySelector('.status-indicator i');
            const cardStatus = getCardStatus(statusIndicator);
            
            const matchesSearch = hostName.includes(searchTerm) || 
                                  services.some(service => service.includes(searchTerm));
            
            let matchesFilter = true;
            if (showIssuesOnly) {
                matchesFilter = cardStatus !== 'online';
                if (matchesFilter) hasIssues = true;
            } else if (showCriticalOnly) {
                matchesFilter = cardStatus === 'critical';
                if (matchesFilter) hasCritical = true;
            } else if (showWarningOnly) {
                matchesFilter = cardStatus === 'warning';
                if (matchesFilter) hasWarning = true;
            } else if (showUnknownOnly) {
                matchesFilter = cardStatus === 'unknown';
                if (matchesFilter) hasUnknown = true;
            }
            
            const shouldShow = matchesSearch && matchesFilter;
            card.style.display = shouldShow ? '' : 'none';
            
            if (shouldShow) visibleCards++;
        });

        // Hide all messages first
        const messages = [
            'no-issues-message',
            'no-critical-message',
            'no-warning-message',
            'no-unknown-message',
            'no-results-message'
        ];
        messages.forEach(id => {
            const element = document.getElementById(id);
            if (element) element.style.display = 'none';
        });

        // Show appropriate message based on filter and results
        if (visibleCards === 0) {
            document.getElementById('no-results-message').style.display = 'block';
        } else if (showIssuesOnly && !hasIssues) {
            document.getElementById('no-issues-message').style.display = 'block';
        } else if (showCriticalOnly && !hasCritical) {
            document.getElementById('no-critical-message').style.display = 'block';
        } else if (showWarningOnly && !hasWarning) {
            document.getElementById('no-warning-message').style.display = 'block';
        } else if (showUnknownOnly && !hasUnknown) {
            document.getElementById('no-unknown-message').style.display = 'block';
        }

        updateStatusSummaries();
    }

    function getCardStatus(statusIndicator) {
        if (!statusIndicator) return 'unknown';
        if (statusIndicator.classList.contains('green-drop')) return 'online';
        if (statusIndicator.classList.contains('yellow-drop')) return 'warning';
        if (statusIndicator.classList.contains('red-drop')) return 'critical';
        return 'unknown';
    }

    // Add event listeners for filters
    const filterIds = ['showIssuesOnly', 'showCriticalOnly', 'showWarningOnly', 'showUnknownOnly'];
    filterIds.forEach(filterId => {
        document.getElementById(filterId)?.addEventListener('change', function() {
            if (this.checked) {
                filterIds.forEach(otherId => {
                    if (otherId !== filterId) {
                        const otherElement = document.getElementById(otherId);
                        if (otherElement) otherElement.checked = false;
                    }
                });
            }
            filterCards();
        });
    });

    // Keep existing collapse icon functionality
    document.querySelectorAll('.card-header').forEach(header => {
        header.addEventListener('click', function() {
            const icon = this.querySelector('.collapse-icon');
            const isExpanded = this.getAttribute('aria-expanded') === 'true';
            
            if (isExpanded) {
                icon.classList.remove('fa-minus');
                icon.classList.add('fa-plus');
            } else {
                icon.classList.remove('fa-plus');
                icon.classList.add('fa-minus');
            }
        });
    });

    // Status summary updates
    function updateStatusSummaries() {
        const cards = document.querySelectorAll('.host-card');
        let hostStats = {
            total: 0,
            online: 0,
            warning: 0,
            critical: 0,
            unknown: 0
        };
        
        let serviceStats = {
            total: 0,
            online: 0,
            warning: 0,
            critical: 0,
            unknown: 0
        };

        cards.forEach(card => {
            hostStats.total++;
            const statusIndicator = card.querySelector('.status-indicator i');
            if (statusIndicator) {
                if (statusIndicator.classList.contains('green-drop')) hostStats.online++;
                else if (statusIndicator.classList.contains('yellow-drop')) hostStats.warning++;
                else if (statusIndicator.classList.contains('red-drop')) hostStats.critical++;
                else hostStats.unknown++;
            }

            const serviceRows = card.querySelectorAll('tbody tr');
            serviceRows.forEach(row => {
                serviceStats.total++;
                const statusBadge = row.querySelector('td:nth-child(2) .badge');
                if (statusBadge) {
                    const status = statusBadge.textContent.trim().toLowerCase();
                    switch (status) {
                        case 'online': serviceStats.online++; break;
                        case 'warning': serviceStats.warning++; break;
                        case 'critical': serviceStats.critical++; break;
                        default: serviceStats.unknown++;
                    }
                }
            });
        });

        // Update the display
        Object.entries({
            'hostTotal': hostStats.total,
            'hostOnline': hostStats.online,
            'hostWarning': hostStats.warning,
            'hostCritical': hostStats.critical,
            'hostUnknown': hostStats.unknown,
            'serviceTotal': serviceStats.total,
            'serviceOnline': serviceStats.online,
            'serviceWarning': serviceStats.warning,
            'serviceCritical': serviceStats.critical,
            'serviceUnknown': serviceStats.unknown
        }).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });
    }

    // Initialize
    updateStatusSummaries();

    // Add refresh functionality
    const autoRefreshToggle = document.querySelector('#autoRefreshToggle');
    const manualRefresh = document.querySelector('#manualRefresh');
    const lastUpdated = document.querySelector('#lastUpdated');
    let refreshInterval;
    const REFRESH_INTERVAL = 120000; // 2 minutes in milliseconds

    // Function to update the last updated time
    function updateLastUpdatedTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        if (lastUpdated) lastUpdated.textContent = `Last updated: ${timeString}`;
    }

    // Function to refresh page
    function refreshPage() {
        showRefreshAnimation();
        toggleLoader(true);  // Show loader
        fetch(window.location.href)
            .then(response => {
                if (!response.ok) throw new Error('Network response was not ok');
                return response.text();
            })
            .then(html => {
                const parser = new DOMParser();
                const newDoc = parser.parseFromString(html, 'text/html');
                
                // Update the cards section using DocumentFragment
                const cardsSection = document.querySelector('.cards-section');
                const newCards = newDoc.querySelector('.cards-section');
                if (cardsSection && newCards) {
                    const fragment = document.createDocumentFragment();
                    Array.from(newCards.children).forEach(child => {
                        fragment.appendChild(child.cloneNode(true));
                    });
                    cardsSection.innerHTML = '';
                    cardsSection.appendChild(fragment);
                }
                
                // Reattach event listeners and update UI
                attachCardEventListeners();
                updateStatusSummaries();
                updateLastUpdatedTime();
                toggleLoader(false);  // Hide loader
            })
            .catch(error => {
                console.error('Error refreshing page:', error);
                // Show error message to user
                const errorMessage = document.createElement('div');
                errorMessage.className = 'alert alert-danger';
                errorMessage.textContent = 'Failed to refresh data. Please try again.';
                document.querySelector('.main-content').prepend(errorMessage);
                setTimeout(() => errorMessage.remove(), 5000);
                toggleLoader(false);  // Hide loader even if there's an error
            });
    }

    // Function to start auto refresh
    function startAutoRefresh() {
        if (refreshInterval) clearInterval(refreshInterval);
        refreshInterval = setInterval(refreshPage, REFRESH_INTERVAL);
    }

    // Function to stop auto refresh
    function stopAutoRefresh() {
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
        }
    }

    // Initialize auto refresh based on toggle state
    if (autoRefreshToggle && autoRefreshToggle.checked) {
        startAutoRefresh();
    }

    // Auto refresh toggle handler
    if (autoRefreshToggle) {
        autoRefreshToggle.addEventListener('change', function() {
            if (this.checked) {
                startAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        });
    }

    // Manual refresh button handler
    if (manualRefresh) {
        manualRefresh.addEventListener('click', function() {
            refreshPage();
            updateLastUpdatedTime();
        });
    }

    // Set initial last updated time
    updateLastUpdatedTime();

    // Add cleanup on page unload
    window.addEventListener('unload', () => {
        if (refreshInterval) {
            clearInterval(refreshInterval);
        }
    });

    // Tutorial functionality
    const tutorialSteps = [
        {
            element: 'body',
            title: 'Welcome to Service Status Dashboard',
            content: 'Let us show you around the dashboard and explain its key features. This quick tour will help you make the most of the monitoring system.',
            isWelcome: true
        },
        {
            element: '.header-search',
            title: 'Search',
            content: 'Search for specific hosts or services using keywords'
        },
        {
            element: '.status-summary-section',
            title: 'Status Summary',
            content: 'View the overall status of hosts and services at a glance'
        },
        {
            element: '.host-card',
            title: 'Service Cards',
            content: 'Click on a card to view detailed service information'
        },
        {
            element: '.refresh-box',
            title: 'Auto Refresh',
            content: 'Toggle automatic refresh (2 mins) or manually refresh the data'
        },
        {
            element: '.status-legend',
            title: 'Status Legend',
            content: 'Understand what each status indicator means'
        },
        {
            element: '.filter-box',
            title: 'Filter Options',
            content: 'Filter services based on their status'
        }
    ];

    let currentStep = 0;
    let tutorialActive = false;
    let overlay, tooltip;

    // Initialize tutorial elements
    function initializeTutorial() {
        overlay = document.createElement('div');
        overlay.className = 'tutorial-overlay';
        
        tooltip = document.createElement('div');
        tooltip.className = 'tutorial-tooltip';

        document.body.appendChild(overlay);
        document.body.appendChild(tooltip);

        const tutorialButton = document.getElementById('startTutorial');
        if (tutorialButton) {
            tutorialButton.addEventListener('click', startTutorial);
        }

        window.nextTutorialStep = nextTutorialStep;
        window.skipTutorial = endTutorial;
    }

    function startTutorial() {
        tutorialActive = true;
        currentStep = 0;
        showTutorialStep();
    }

    function showTutorialStep() {
        if (currentStep >= tutorialSteps.length) {
            endTutorial();
            return;
        }

        const step = tutorialSteps[currentStep];
        const element = document.querySelector(step.element);
        
        if (!element) {
            currentStep++;
            showTutorialStep();
            return;
        }

        document.querySelectorAll('.tutorial-highlight').forEach(el => {
            el.classList.remove('tutorial-highlight');
        });

        overlay.style.display = 'block';

        if (!step.isWelcome) {
            element.classList.add('tutorial-highlight');
        }

        tooltip.innerHTML = `
            <div class="tutorial-tooltip-content">
                <h6 style="color: rgb(9, 93, 108); margin-bottom: 8px;">${step.title}</h6>
                <p style="margin-bottom: 15px;">${step.content}</p>
            </div>
            <div class="tutorial-tooltip-buttons">
                <button class="tutorial-skip" onclick="skipTutorial()">Skip</button>
                <button class="tutorial-next" onclick="nextTutorialStep()">
                    ${currentStep === tutorialSteps.length - 1 ? 'Finish' : 'Next'}
                </button>
            </div>
        `;

        tooltip.style.display = 'block';

        if (step.isWelcome) {
            // Center the tooltip
            tooltip.style.left = '50%';
            tooltip.style.top = '50%';
            tooltip.style.transform = 'translate(-50%, -50%)';
        } else {
            // Position near target element
            const rect = element.getBoundingClientRect();
            tooltip.style.left = `${rect.left + (rect.width / 2) - 150}px`;
            tooltip.style.top = `${rect.bottom + 10}px`;
            tooltip.style.transform = 'none';
        }
    }

    function nextTutorialStep() {
        currentStep++;
        showTutorialStep();
    }

    function endTutorial() {
        tutorialActive = false;
        overlay.style.display = 'none';
        tooltip.style.display = 'none';
        document.querySelectorAll('.tutorial-highlight').forEach(el => {
            el.classList.remove('tutorial-highlight');
        });
    }

    // Initialize tutorial
    initializeTutorial();

    // Handle expand all functionality
    document.getElementById('expandAllCards')?.addEventListener('change', function() {
        const cards = document.querySelectorAll('.collapse');
        if (this.checked) {
            cards.forEach(card => {
                card.classList.add('show');
                const header = document.querySelector(`[data-target="#${card.id}"]`);
                const icon = header?.querySelector('.collapse-icon');
                if (icon) {
                    icon.classList.remove('fa-plus');
                    icon.classList.add('fa-minus');
                }
            });
        } else {
            cards.forEach(card => {
                card.classList.remove('show');
                const header = document.querySelector(`[data-target="#${card.id}"]`);
                const icon = header?.querySelector('.collapse-icon');
                if (icon) {
                    icon.classList.remove('fa-minus');
                    icon.classList.add('fa-plus');
                }
            });
        }
    });

    function attachCardEventListeners() {
        // Reattach collapse icon functionality
        document.querySelectorAll('.card-header').forEach(header => {
            header.addEventListener('click', function() {
                const icon = this.querySelector('.collapse-icon');
                const isExpanded = this.getAttribute('aria-expanded') === 'true';
                
                if (isExpanded) {
                    icon.classList.remove('fa-minus');
                    icon.classList.add('fa-plus');
                } else {
                    icon.classList.remove('fa-plus');
                    icon.classList.add('fa-minus');
                }
            });
        });

        // Reattach collapse event listeners
        document.querySelectorAll('.collapse').forEach(collapse => {
            collapse.addEventListener('show.bs.collapse', function() {
                const header = document.querySelector(`[data-target="#${this.id}"]`);
                const icon = header.querySelector('.collapse-icon');
                icon.classList.remove('fa-plus');
                icon.classList.add('fa-minus');
                header.setAttribute('aria-expanded', 'true');
            });

            collapse.addEventListener('hide.bs.collapse', function() {
                const header = document.querySelector(`[data-target="#${this.id}"]`);
                const icon = header.querySelector('.collapse-icon');
                icon.classList.remove('fa-minus');
                icon.classList.add('fa-plus');
                header.setAttribute('aria-expanded', 'false');
            });
        });
    }

    attachCardEventListeners();

    function showRefreshAnimation() {
        const refreshIcon = manualRefresh.querySelector('i');
        if (refreshIcon) {
            refreshIcon.classList.add('fa-spin');
            setTimeout(() => {
                refreshIcon.classList.remove('fa-spin');
            }, 1000);
        }
    }

    function toggleLoader(show) {
        const loader = document.getElementById('initial-loader');
        if (loader) {
            if (show) {
                loader.style.display = 'flex';
                loader.style.opacity = '1';
            } else {
                loader.style.opacity = '0';
                setTimeout(() => {
                    loader.style.display = 'none';
                }, 500);
            }
        }
    }

    // ========================
    // New Day/Night Mode Logic
    // ========================
    const themeToggleCheckbox = document.getElementById('themeToggle');
    if (themeToggleCheckbox) {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const savedTheme = localStorage.getItem('theme');
      
      // On load, apply user’s saved theme or system preference
      if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
          document.body.classList.add('dark-mode');
          themeToggleCheckbox.checked = true;
      } else {
          document.body.classList.remove('dark-mode');
          themeToggleCheckbox.checked = false;
      }
      
      // Listen for manual changes
      themeToggleCheckbox.addEventListener('change', () => {
          if (themeToggleCheckbox.checked) {
              document.body.classList.add('dark-mode');
              localStorage.setItem('theme', 'dark');
          } else {
              document.body.classList.remove('dark-mode');
              localStorage.setItem('theme', 'light');
          }
      });
      
      // Listen for system theme changes (only if user hasn't manually chosen)
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
          if (!localStorage.getItem('theme')) {
              if (e.matches) {
                  document.body.classList.add('dark-mode');
                  themeToggleCheckbox.checked = true;
              } else {
                  document.body.classList.remove('dark-mode');
                  themeToggleCheckbox.checked = false;
              }
          }
      });
    }
});

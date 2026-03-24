// ==================== GLOBAL VARIABLES ====================
let notifications = [];
let notificationCheckInterval;
let currentChatMatchId = null;
let chatPollingInterval = null;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', function() {
    initializeTooltips();
    initializeForms();
    initializeNotifications();
    initializeFilters();
    initializeModals();
    initializeTabs();
    initializeFileUploads();
    initializePasswordStrength();
    initializeRangeInputs();
    initializeChat();
    initializeChecklist();
    
    if (document.querySelector('.notification-dropdown')) {
        checkNotifications();
        notificationCheckInterval = setInterval(checkNotifications, 30000);
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (notificationCheckInterval) {
        clearInterval(notificationCheckInterval);
    }
    if (chatPollingInterval) {
        clearInterval(chatPollingInterval);
    }
});

// ==================== TOOLTIPS ====================
function initializeTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    tooltips.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}

function showTooltip(e) {
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = e.target.dataset.tooltip;
    tooltip.style.position = 'absolute';
    tooltip.style.background = 'var(--dark)';
    tooltip.style.color = 'white';
    tooltip.style.padding = '0.5rem';
    tooltip.style.borderRadius = '4px';
    tooltip.style.fontSize = '0.875rem';
    tooltip.style.zIndex = '1000';
    tooltip.style.pointerEvents = 'none';
    
    const rect = e.target.getBoundingClientRect();
    tooltip.style.top = rect.top - 30 + window.scrollY + 'px';
    tooltip.style.left = rect.left + (rect.width / 2) + 'px';
    tooltip.style.transform = 'translateX(-50%)';
    
    document.body.appendChild(tooltip);
    
    setTimeout(() => {
        tooltip.style.opacity = '1';
    }, 10);
    
    e.target._tooltip = tooltip;
}

function hideTooltip(e) {
    if (e.target._tooltip) {
        e.target._tooltip.remove();
        delete e.target._tooltip;
    }
}

// ==================== FORM HANDLING ====================
function initializeForms() {
    const forms = document.querySelectorAll('form[data-ajax]');
    forms.forEach(form => {
        form.addEventListener('submit', handleAjaxSubmit);
    });
    
    const validationForms = document.querySelectorAll('form[data-validate]');
    validationForms.forEach(form => {
        form.addEventListener('submit', validateForm);
    });
}

async function handleAjaxSubmit(e) {
    e.preventDefault();
    
    const form = e.target;
    const formData = new FormData(form);
    const url = form.action;
    const method = form.method || 'POST';
    
    const submitBtn = form.querySelector('[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-small"></span> Processing...';
    
    try {
        const response = await fetch(url, {
            method: method,
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('Success!', 'success');
            if (data.redirect) {
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
            }
        } else {
            showAlert(data.error || 'An error occurred', 'danger');
        }
    } catch (error) {
        showAlert('Network error. Please try again.', 'danger');
        console.error('AJAX Error:', error);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

function validateForm(e) {
    const form = e.target;
    const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            showInputError(input, 'This field is required');
            isValid = false;
        } else {
            clearInputError(input);
        }
        
        if (input.type === 'email' && input.value) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(input.value)) {
                showInputError(input, 'Please enter a valid email address');
                isValid = false;
            }
        }
        
        if (input.type === 'number' && input.value) {
            const num = parseFloat(input.value);
            if (isNaN(num)) {
                showInputError(input, 'Please enter a valid number');
                isValid = false;
            } else if (input.min && num < parseFloat(input.min)) {
                showInputError(input, `Minimum value is ${input.min}`);
                isValid = false;
            } else if (input.max && num > parseFloat(input.max)) {
                showInputError(input, `Maximum value is ${input.max}`);
                isValid = false;
            }
        }
    });
    
    if (!isValid) {
        e.preventDefault();
    }
}

function showInputError(input, message) {
    const container = input.closest('.form-group');
    let error = container.querySelector('.error-message');
    
    input.classList.add('error');
    
    if (!error) {
        error = document.createElement('div');
        error.className = 'error-message text-danger mt-1';
        error.style.fontSize = '0.875rem';
        container.appendChild(error);
    }
    
    error.textContent = message;
}

function clearInputError(input) {
    input.classList.remove('error');
    const container = input.closest('.form-group');
    const error = container.querySelector('.error-message');
    if (error) {
        error.remove();
    }
}

// ==================== PASSWORD STRENGTH ====================
function initializePasswordStrength() {
    const passwordInput = document.querySelector('input[type="password"][data-strength]');
    if (passwordInput) {
        passwordInput.addEventListener('input', checkPasswordStrength);
    }
}

function checkPasswordStrength(e) {
    const password = e.target.value;
    const meter = document.querySelector('.password-strength-meter');
    const strengthText = document.querySelector('.password-strength-text');
    
    if (!meter) return;
    
    let strength = 0;
    let feedback = '';
    
    if (password.length >= 8) strength += 25;
    if (password.match(/[a-z]+/)) strength += 25;
    if (password.match(/[A-Z]+/)) strength += 25;
    if (password.match(/[0-9]+/)) strength += 25;
    if (password.match(/[$@#&!]+/)) strength += 25;
    
    strength = Math.min(100, strength);
    meter.style.width = strength + '%';
    
    if (strength < 50) {
        meter.style.background = '#e74c3c';
        feedback = 'Weak password';
    } else if (strength < 75) {
        meter.style.background = '#f39c12';
        feedback = 'Medium password';
    } else {
        meter.style.background = '#27ae60';
        feedback = 'Strong password';
    }
    
    if (strengthText) {
        strengthText.textContent = feedback;
    }
}

// ==================== RANGE INPUTS ====================
function initializeRangeInputs() {
    const rangeInputs = document.querySelectorAll('input[type="range"]');
    rangeInputs.forEach(input => {
        const output = input.nextElementSibling;
        if (output && output.tagName === 'OUTPUT') {
            output.textContent = input.value;
            input.addEventListener('input', function() {
                output.textContent = this.value;
            });
        }
    });
}

// ==================== NOTIFICATIONS ====================
function initializeNotifications() {
    const notificationBtn = document.querySelector('.notification-btn');
    if (notificationBtn) {
        notificationBtn.addEventListener('click', toggleNotifications);
    }
    
    document.addEventListener('click', function(e) {
        if (e.target.closest('.notification-item')) {
            const item = e.target.closest('.notification-item');
            const notificationId = item.dataset.id;
            const link = item.dataset.link;
            if (notificationId) {
                markNotificationRead(notificationId);
            }
            if (link) {
                window.location.href = link;
            }
        }
    });
}

function toggleNotifications(e) {
    e.stopPropagation();
    const list = document.querySelector('.notification-list');
    if (list) {
        list.style.display = list.style.display === 'block' ? 'none' : 'block';
    }
}

async function checkNotifications() {
    try {
        const response = await fetch('/notifications');
        const data = await response.json();
        
        updateNotificationBadge(data.length);
        updateNotificationList(data);
    } catch (error) {
        console.error('Error checking notifications:', error);
    }
}

function updateNotificationBadge(count) {
    const badge = document.querySelector('.notification-badge');
    if (badge) {
        badge.textContent = count;
        badge.style.display = count > 0 ? 'inline' : 'none';
    }
}

function updateNotificationList(notifications) {
    const list = document.querySelector('.notification-list');
    if (!list) return;
    
    if (notifications.length === 0) {
        list.innerHTML = '<div class="notification-item">No new notifications</div>';
        return;
    }
    
    list.innerHTML = '';
    
    notifications.forEach(notification => {
        const item = document.createElement('div');
        item.className = `notification-item ${notification.is_read ? '' : 'unread'}`;
        item.dataset.id = notification.id;
        item.dataset.link = notification.link;
        item.innerHTML = `
            <div class="notification-title">${notification.title}</div>
            <div class="notification-message">${notification.message}</div>
            <div class="notification-time">${notification.created_at}</div>
        `;
        list.appendChild(item);
    });
}

async function markNotificationRead(notificationId) {
    try {
        await fetch(`/notifications/mark_read/${notificationId}`, {
            method: 'POST'
        });
        
        const item = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
        if (item) {
            item.classList.remove('unread');
        }
    } catch (error) {
        console.error('Error marking notification as read:', error);
    }
}

// ==================== FILTERS ====================
function initializeFilters() {
    const filterForms = document.querySelectorAll('.filter-form');
    filterForms.forEach(form => {
        const inputs = form.querySelectorAll('input, select');
        inputs.forEach(input => {
            input.addEventListener('change', debounce(() => applyFilters(form), 500));
        });
        
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            applyFilters(form);
        });
    });
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

async function applyFilters(form) {
    const formData = new FormData(form);
    const params = new URLSearchParams(formData).toString();
    const url = form.action + '?' + params;
    
    try {
        const response = await fetch(url);
        const html = await response.text();
        
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        const results = doc.querySelector('.filter-results');
        
        if (results) {
            const currentResults = document.querySelector('.filter-results');
            if (currentResults) {
                currentResults.innerHTML = results.innerHTML;
            }
        }
    } catch (error) {
        console.error('Error applying filters:', error);
    }
}

// ==================== MODALS ====================
function initializeModals() {
    const modalTriggers = document.querySelectorAll('[data-modal]');
    modalTriggers.forEach(trigger => {
        trigger.addEventListener('click', function() {
            const modalId = this.dataset.modal;
            openModal(modalId);
        });
    });
    
    const closeButtons = document.querySelectorAll('.modal-close, [data-modal-close]');
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const modal = this.closest('.modal');
            if (modal) {
                closeModal(modal);
            }
        });
    });
    
    window.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            closeModal(e.target);
        }
    });
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modal) {
    modal.style.display = 'none';
    document.body.style.overflow = 'auto';
}

// ==================== TABS ====================
function initializeTabs() {
    const tabContainers = document.querySelectorAll('.tabs');
    tabContainers.forEach(container => {
        const tabs = container.querySelectorAll('.tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', function() {
                const tabId = this.dataset.tab;
                switchTab(this.closest('.tabs'), tabId);
            });
        });
    });
}

function switchTab(container, tabId) {
    const tabs = container.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.tab === tabId) {
            tab.classList.add('active');
        }
    });
    
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.remove('active');
        if (content.id === tabId) {
            content.classList.add('active');
        }
    });
}

// ==================== FILE UPLOADS ====================
function initializeFileUploads() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', handleFileSelect);
    });
}

function handleFileSelect(e) {
    const input = e.target;
    const files = Array.from(input.files);
    const previewContainer = document.querySelector(input.dataset.preview);
    
    if (previewContainer && files.length > 0) {
        previewContainer.innerHTML = '';
        
        files.forEach(file => {
            if (file.type.startsWith('image/')) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const img = document.createElement('img');
                    img.src = e.target.result;
                    img.className = 'preview-image';
                    img.style.width = '100px';
                    img.style.height = '100px';
                    img.style.objectFit = 'cover';
                    img.style.borderRadius = '4px';
                    img.style.margin = '0.5rem';
                    previewContainer.appendChild(img);
                };
                reader.readAsDataURL(file);
            }
        });
    }
}

// ==================== MATCH REQUESTS ====================
function sendMatchRequest(receiverId) {
    const modal = document.getElementById('matchModal');
    if (modal) {
        modal.dataset.receiverId = receiverId;
        openModal('matchModal');
    }
}

function confirmMatchRequest() {
    const modal = document.getElementById('matchModal');
    const receiverId = modal.dataset.receiverId;
    const message = document.getElementById('match-message')?.value || '';
    
    fetch(`/send_match_request/${receiverId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: message })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('Match request sent successfully!', 'success');
            closeModal(modal);
            setTimeout(() => location.reload(), 1500);
        } else {
            showAlert(data.error || 'Failed to send request', 'danger');
        }
    })
    .catch(error => {
        showAlert('Network error. Please try again.', 'danger');
        console.error('Error:', error);
    });
}

function respondToMatchRequest(requestId, action) {
    if (confirm(`Are you sure you want to ${action} this match request?`)) {
        fetch(`/respond_match_request/${requestId}/${action}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert(`Request ${action}ed!`, 'success');
                setTimeout(() => location.reload(), 1500);
            } else {
                showAlert('Failed to respond to request', 'danger');
            }
        })
        .catch(error => {
            showAlert('Network error. Please try again.', 'danger');
            console.error('Error:', error);
        });
    }
}

// ==================== CHAT SYSTEM ====================
function initializeChat() {
    const chatContainer = document.querySelector('.chat-container');
    if (chatContainer) {
        const matchId = chatContainer.dataset.matchId;
        if (matchId) {
            currentChatMatchId = matchId;
            startChatPolling(matchId);
            scrollChatToBottom();
            
            const chatInput = document.getElementById('chat-input');
            const sendButton = document.getElementById('send-message');
            
            if (chatInput) {
                chatInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        sendMessage();
                    }
                });
            }
            
            if (sendButton) {
                sendButton.addEventListener('click', sendMessage);
            }
        }
    }
}

function startChatPolling(matchId) {
    if (chatPollingInterval) {
        clearInterval(chatPollingInterval);
    }
    
    chatPollingInterval = setInterval(() => {
        fetchMessages(matchId);
    }, 3000);
}

async function fetchMessages(matchId) {
    try {
        const response = await fetch(`/chat/${matchId}/messages`);
        const data = await response.json();
        updateChatMessages(data.messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
    }
}

function updateChatMessages(messages) {
    const container = document.getElementById('chat-messages');
    if (!container) return;
    
    const wasAtBottom = isScrolledToBottom(container);
    
    container.innerHTML = '';
    messages.forEach(msg => {
        const messageDiv = createMessageElement(msg);
        container.appendChild(messageDiv);
    });
    
    if (wasAtBottom) {
        scrollChatToBottom();
    }
}

function createMessageElement(message) {
    const div = document.createElement('div');
    div.className = `message ${message.sender_id == currentUserId ? 'sent' : 'received'}`;
    div.innerHTML = `
        <div class="message-content">${escapeHtml(message.content)}</div>
        <div class="message-time">${message.created_at}</div>
    `;
    return div;
}

function sendMessage() {
    const input = document.getElementById('chat-input');
    const content = input.value.trim();
    
    if (!content || !currentChatMatchId) return;
    
    fetch(`/send_message/${currentChatMatchId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ content: content })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            input.value = '';
            fetchMessages(currentChatMatchId);
        } else {
            showAlert('Failed to send message', 'danger');
        }
    })
    .catch(error => {
        showAlert('Network error. Please try again.', 'danger');
        console.error('Error:', error);
    });
}

function scrollChatToBottom() {
    const container = document.getElementById('chat-messages');
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

function isScrolledToBottom(element) {
    return Math.abs(element.scrollHeight - element.scrollTop - element.clientHeight) < 1;
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ==================== CHECKLIST ====================
function initializeChecklist() {
    const checklistContainer = document.querySelector('.checklist-container');
    if (checklistContainer) {
        const addButton = document.getElementById('add-checklist-item');
        if (addButton) {
            addButton.addEventListener('click', addChecklistItem);
        }
    }
}

function addChecklistItem() {
    const input = document.getElementById('new-item-name');
    const itemName = input.value.trim();
    const matchId = document.querySelector('.checklist-container').dataset.matchId;
    
    if (!itemName) {
        showAlert('Please enter an item name', 'warning');
        return;
    }
    
    fetch(`/checklist/add_item/${matchId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ item_name: itemName })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            input.value = '';
            location.reload();
        } else {
            showAlert('Failed to add item', 'danger');
        }
    })
    .catch(error => {
        showAlert('Network error. Please try again.', 'danger');
        console.error('Error:', error);
    });
}

function updateChecklistItem(itemId) {
    const status = document.getElementById(`status-${itemId}`).value;
    const price = document.getElementById(`price-${itemId}`)?.value;
    const matchId = document.querySelector('.checklist-container').dataset.matchId;
    
    fetch(`/checklist/update_item/${itemId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
            status: status,
            price: price ? parseFloat(price) : null
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        }
    })
    .catch(error => {
        console.error('Error updating item:', error);
    });
}

function deleteChecklistItem(itemId) {
    if (confirm('Are you sure you want to delete this item?')) {
        const matchId = document.querySelector('.checklist-container').dataset.matchId;
        
        fetch(`/checklist/delete_item/${itemId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            }
        })
        .catch(error => {
            console.error('Error deleting item:', error);
        });
    }
}

// ==================== HOUSING APPLICATIONS ====================
function applyForHousing(housingId) {
    const form = document.getElementById('application-form');
    const formData = new FormData(form);
    const data = Object.fromEntries(formData);
    
    fetch(`/apply_housing/${housingId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('Application submitted successfully!', 'success');
            setTimeout(() => location.reload(), 1500);
        } else {
            showAlert(data.error || 'Failed to submit application', 'danger');
        }
    })
    .catch(error => {
        showAlert('Network error. Please try again.', 'danger');
        console.error('Error:', error);
    });
}

// ==================== AGREEMENTS ====================
function viewAgreement(agreementId) {
    const content = document.getElementById(`agreement-${agreementId}`).innerHTML;
    document.getElementById('agreementContent').innerHTML = content;
    openModal('agreementModal');
    window.currentAgreementId = agreementId;
}

function respondToAgreement(agreementId, action) {
    if (confirm(`Are you sure you want to ${action} this agreement?`)) {
        fetch(`/agreement/${agreementId}/respond/${action}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert(`Agreement ${action}ed!`, 'success');
                setTimeout(() => location.reload(), 1500);
            } else {
                showAlert('Failed to respond to agreement', 'danger');
            }
        })
        .catch(error => {
            showAlert('Network error. Please try again.', 'danger');
            console.error('Error:', error);
        });
    }
}

function confirmFromModal() {
    if (window.currentAgreementId) {
        respondToAgreement(window.currentAgreementId, 'confirm');
    }
}

function rejectFromModal() {
    if (window.currentAgreementId) {
        respondToAgreement(window.currentAgreementId, 'reject');
    }
}

// ==================== ALERTS ====================
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alert-container');
    if (!alertContainer) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    
    alertContainer.appendChild(alert);
    
    setTimeout(() => {
        alert.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => {
            alert.remove();
        }, 300);
    }, 5000);
}

// ==================== ADMIN FUNCTIONS ====================
function resetPassword(userId) {
    if (confirm('Reset password for this user?')) {
        fetch(`/admin/users/reset_password/${userId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`New temporary password: ${data.temp_password}\nPlease share this with the user.`);
            } else {
                alert('Failed to reset password');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to reset password');
        });
    }
}

function toggleUser(userId) {
    if (confirm('Toggle user active status?')) {
        fetch(`/admin/users/toggle_active/${userId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to toggle user status');
        });
    }
}

function deleteListing(listingId) {
    if (confirm('Are you sure you want to delete this listing? This action cannot be undone.')) {
        fetch(`/admin/housing/delete/${listingId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert('Listing deleted successfully', 'success');
                setTimeout(() => location.reload(), 1500);
            } else {
                showAlert('Failed to delete listing', 'danger');
            }
        })
        .catch(error => {
            showAlert('Network error. Please try again.', 'danger');
            console.error('Error:', error);
        });
    }
}

function handleApplication(applicationId, action, type) {
    if (confirm(`Are you sure you want to ${action} this ${type} application?`)) {
        fetch(`/admin/applications/${applicationId}/${action}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ type: type })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert(`Application ${action}ed!`, 'success');
                setTimeout(() => location.reload(), 1500);
            }
        })
        .catch(error => {
            showAlert('Network error. Please try again.', 'danger');
            console.error('Error:', error);
        });
    }
}

// ==================== SEARCH & FILTER ====================
function filterTable() {
    const searchInput = document.getElementById('search');
    const statusSelect = document.getElementById('status');
    const citySelect = document.getElementById('city');
    
    if (!searchInput) return;
    
    const search = searchInput.value.toLowerCase();
    const status = statusSelect?.value || 'all';
    const city = citySelect?.value || 'all';
    
    const rows = document.querySelectorAll('tbody tr');
    
    rows.forEach(row => {
        let show = true;
        
        if (search) {
            const text = row.textContent.toLowerCase();
            if (!text.includes(search)) show = false;
        }
        
        if (status !== 'all') {
            const statusCell = row.querySelector('.badge')?.textContent.toLowerCase() || '';
            if (status === 'available' && !statusCell.includes('available')) show = false;
            if (status === 'unavailable' && !statusCell.includes('unavailable')) show = false;
        }
        
        if (city !== 'all') {
            const cityCell = row.querySelector('td:nth-child(4)')?.textContent.split(',')[1]?.trim() || '';
            if (!cityCell.includes(city)) show = false;
        }
        
        row.style.display = show ? '' : 'none';
    });
}

// ==================== EXPORT FUNCTIONS ====================
window.sendMatchRequest = sendMatchRequest;
window.confirmMatchRequest = confirmMatchRequest;
window.respondToMatchRequest = respondToMatchRequest;
window.applyForHousing = applyForHousing;
window.viewAgreement = viewAgreement;
window.respondToAgreement = respondToAgreement;
window.confirmFromModal = confirmFromModal;
window.rejectFromModal = rejectFromModal;
window.showAlert = showAlert;
window.resetPassword = resetPassword;
window.toggleUser = toggleUser;
window.deleteListing = deleteListing;
window.handleApplication = handleApplication;
window.filterTable = filterTable;
window.updateChecklistItem = updateChecklistItem;
window.deleteChecklistItem = deleteChecklistItem;
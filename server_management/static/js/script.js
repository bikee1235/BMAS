// Add any custom JavaScript here

// Add smooth scrolling
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Remove existing table row animation code and replace with:
document.addEventListener('DOMContentLoaded', function() {
    const tableRows = document.querySelectorAll('tbody tr');
    
    // Add animation class with delay
    tableRows.forEach((row, index) => {
        setTimeout(() => {
            row.classList.add('animate');
        }, index * 100);
    });

    // Handle modal cleanup
    document.querySelectorAll('.modal').forEach(modalElement => {
        modalElement.addEventListener('hidden.bs.modal', function () {
            // Remove any leftover backdrop
            const backdrops = document.querySelectorAll('.modal-backdrop');
            backdrops.forEach(backdrop => backdrop.remove());
            
            // Remove modal-open class from body
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
        });
    });

    // Initialize Bootstrap modals
    const deleteModals = document.querySelectorAll('.modal');
    deleteModals.forEach(modal => {
        new bootstrap.Modal(modal);
    });
});

// Add hover effect to cards
document.querySelectorAll('.card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-5px)';
    });
    card.addEventListener('mouseleave', function() {
        this.style.transform = 'translateY(0)';
    });
});

// Update delete modal functionality
function showDeleteModal(machineId, machineName) {
    // Remove any existing backdrops first
    document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
    
    const modalEl = document.getElementById('deleteModal');
    const modal = new bootstrap.Modal(modalEl);
    
    document.getElementById('machineToDelete').textContent = machineName;
    document.getElementById('deleteForm').action = `/admin/machine/${machineId}/delete`;
    
    modalEl.addEventListener('shown.bs.modal', function () {
        document.body.classList.add('modal-open');
    });
    
    modalEl.addEventListener('hidden.bs.modal', function () {
        document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
        document.body.classList.remove('modal-open');
        document.body.style.overflow = '';
        document.body.style.paddingRight = '';
    }, { once: true });
    
    modal.show();
}

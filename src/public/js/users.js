const modalBuilder = (title, message, yesText, noText, yesCallback, noCallback) => {
    const modalHTML = `
        <div class="modal-container hidden">
            <div class="modal">
                <div class="modal-content">
                    <h2>${title}</h2>
                    <p>${message}</p>
                    <div class="modal-actions">
                        <button class="yes-btn">${yesText}</button>
                        <button class="no-btn">${noText}</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    $('body').append(modalHTML);
    $('.modal-container').removeClass('hidden');
    $('.yes-btn').click(function() {
        yesCallback();
        $('.modal-container').addClass('hidden');
    });
    $('.no-btn').click(function() {
        noCallback();
        $('.modal-container').addClass('hidden');
    });
};


const deleteUser = id => modalBuilder('Delete User', 'Are you sure you want to delete this user?', 'Yes', 'No', () => {
    $.ajax({
        url: `/api/delete/user/${id}`,
        method: 'DELETE',
        success: function(data) {
            if (data.status === 'success') {
                location.reload();
            }
        },
        error: function(error) {
            console.log(error);
        }
    });
}, () => { });


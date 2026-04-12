/**
 * FreshAuthModal - A reference UI component for handling "Sudo Mode" (requireFreshAuth).
 * 
 * This component listens for 403 FRESH_AUTH_REQUIRED errors and prompts the user
 * to re-authenticate without leaving the current page.
 */

export class FreshAuthModal {
  constructor(authClient) {
    this.auth = authClient;
    this.modal = null;
    this._initStyles();
  }

  /**
   * Shows the re-authentication modal.
   * @returns {Promise<boolean>} - Resolves to true if re-auth succeeded, false otherwise.
   */
  async prompt() {
    return new Promise((resolve) => {
      this._createModal(resolve);
    });
  }

  _initStyles() {
    if (document.getElementById('fresh-auth-styles')) return;
    const style = document.createElement('style');
    style.id = 'fresh-auth-styles';
    style.textContent = `
      .fa-modal-overlay {
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background: rgba(0,0,0,0.5); display: flex; align-items: center;
        justify-content: center; z-index: 9999; font-family: sans-serif;
      }
      .fa-modal {
        background: white; padding: 2rem; border-radius: 8px; width: 100%; max-width: 400px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.2);
      }
      .fa-modal h2 { margin-top: 0; color: #333; }
      .fa-modal p { color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }
      .fa-modal input {
        width: 100%; padding: 0.8rem; margin-bottom: 1rem; border: 1px solid #ddd;
        border-radius: 4px; box-sizing: border-box;
      }
      .fa-modal button {
        width: 100%; padding: 0.8rem; background: #007bff; color: white;
        border: none; border-radius: 4px; cursor: pointer; font-weight: bold;
      }
      .fa-modal button:hover { background: #0056b3; }
      .fa-modal .cancel {
        background: none; color: #888; margin-top: 0.5rem; font-weight: normal;
      }
      .fa-error { color: #dc3545; font-size: 0.8rem; margin-bottom: 1rem; display: none; }
    `;
    document.head.appendChild(style);
  }

  _createModal(resolve) {
    const overlay = document.createElement('div');
    overlay.className = 'fa-modal-overlay';
    overlay.innerHTML = `
      <div class="fa-modal">
        <h2>Confirm Identity</h2>
        <p>This action requires recent authentication. Please enter your password to continue.</p>
        <div class="fa-error" id="fa-error-msg"></div>
        <input type="password" id="fa-password" placeholder="Password" autofocus>
        <button id="fa-confirm">Confirm</button>
        <button id="fa-cancel" class="cancel">Cancel</button>
      </div>
    `;

    document.body.appendChild(overlay);

    const passwordInput = overlay.querySelector('#fa-password');
    const confirmBtn = overlay.querySelector('#fa-confirm');
    const cancelBtn = overlay.querySelector('#fa-cancel');
    const errorMsg = overlay.querySelector('#fa-error-msg');

    const handleConfirm = async () => {
      confirmBtn.disabled = true;
      confirmBtn.textContent = 'Verifying...';
      errorMsg.style.display = 'none';

      try {
        const password = passwordInput.value;
        if (!password) throw new Error('Password is required');
        
        await this.auth.request('/fresh-auth', {
          method: 'POST',
          body: { password }
        });

        document.body.removeChild(overlay);
        resolve(true);
      } catch (err) {
        errorMsg.textContent = err.message || 'Verification failed';
        errorMsg.style.display = 'block';
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Confirm';
      }
    };

    confirmBtn.onclick = handleConfirm;
    passwordInput.onkeypress = (e) => { if (e.key === 'Enter') handleConfirm(); };
    cancelBtn.onclick = () => {
      document.body.removeChild(overlay);
      resolve(false);
    };
  }
}

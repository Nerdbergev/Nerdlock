// Menu toggle functionality
const menuToggle = document.getElementById("menu-toggle");
const mainNav = document.getElementById("main-nav");

if (menuToggle && mainNav) {
  menuToggle.addEventListener("click", function () {
    mainNav.classList.toggle("nav-collapsed");
    this.textContent = mainNav.classList.contains("nav-collapsed")
      ? "☰"
      : "✕";
  });

  mainNav.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", function () {
      mainNav.classList.add("nav-collapsed");
      if (menuToggle) menuToggle.textContent = "☰";
    });
  });

  document.addEventListener("click", function (event) {
    if (
      !mainNav.contains(event.target) &&
      !menuToggle.contains(event.target)
    ) {
      mainNav.classList.add("nav-collapsed");
      if (menuToggle) menuToggle.textContent = "☰";
    }
  });
}

// Bergwerk Easter Egg
(function () {
  const sequence = ["g", "l", "u", "e", "c", "k", "a", "u", "f"];
  let position = 0;
  let tapCount = 0;
  let tapTimer = null;

  document.addEventListener("keydown", function (e) {
    if (e.key.toLowerCase() === sequence[position]) {
      position++;
      if (position === sequence.length) {
        einfahren();
        position = 0;
      }
    } else {
      position = 0;
    }
  });

  const footerStatus = document.getElementById("footer-status");
  if (footerStatus) {
    footerStatus.addEventListener("click", function () {
      tapCount++;
      clearTimeout(tapTimer);

      if (tapCount === 5) {
        einfahren();
        tapCount = 0;
      }

      tapTimer = setTimeout(() => {
        tapCount = 0;
      }, 2000);
    });
  }

  function einfahren() {
    const style = document.createElement("style");
    style.id = "bergwerk-mode";
    style.textContent = `
          :root {
              --terminal-green: #ff8800 !important;
              --terminal-green-dim: #cc6600 !important;
              --terminal-green-glow: rgba(255, 136, 0, 0.3) !important;
          }
          body::after {
              content: '⛏️ GLÜCK AUF! ⛏️';
              position: fixed;
              top: 50%;
              left: 50%;
              transform: translate(-50%, -50%);
              font-size: 48px;
              color: #ff8800;
              text-shadow: 0 0 20px rgba(255, 136, 0, 0.8);
              animation: einfahrt 3s ease-out forwards;
              pointer-events: none;
              z-index: 9999;
              font-weight: bold;
          }
          @keyframes einfahrt {
              0% { opacity: 0; transform: translate(-50%, -150%); }
              50% { opacity: 1; transform: translate(-50%, -50%); }
              100% { opacity: 0; transform: translate(-50%, 50%); }
          }
      `;
    document.head.appendChild(style);

    const steigerlied = document.createElement("div");
    steigerlied.style.cssText = `
          position: fixed;
          bottom: 20px;
          left: 50%;
          transform: translateX(-50%);
          background: rgba(15, 20, 25, 0.95);
          border: 2px solid #ff8800;
          border-radius: 8px;
          padding: 20px;
          max-width: 90%;
          width: 400px;
          color: #ff8800;
          font-family: 'Courier New', monospace;
          font-size: 14px;
          line-height: 1.6;
          box-shadow: 0 0 30px rgba(255, 136, 0, 0.5);
          z-index: 10000;
          animation: slideInFromBottom 0.5s ease-out;
      `;
    steigerlied.innerHTML = `
          <div style="text-align: center; font-weight: bold; font-size: 16px; margin-bottom: 15px; border-bottom: 1px solid #ff8800; padding-bottom: 10px;">
              ⛏️ STEIGERLIED ⛏️
          </div>
          <div style="white-space: pre-line;">
Glück auf, Glück auf!
Der Steiger kommt,
Und er hat sein helles Licht bei der Nacht,
Schon angezündt, schon angezündt.

Schon angezünd't! Das gibt ein'n Schein,
und damit so fahren wir bei der Nacht,
und damit so fahren wir bei der Nacht,
ins Bergwerk ein, ins Bergwerk ein.

          </div>
          <div style="margin-top: 15px; text-align: center; font-size: 12px; color: #cc6600;">
              [ Tippe hier zum Ausfahren ]
          </div>
      `;

    const styleSheet = document.createElement("style");
    styleSheet.textContent = `
          @keyframes slideInFromBottom {
              from { transform: translate(-50%, 500px); opacity: 0; }
              to { transform: translate(-50%, 0); opacity: 1; }
          }
      `;
    document.head.appendChild(styleSheet);
    document.body.appendChild(steigerlied);

    const closeHandler = function () {
      steigerlied.style.animation =
        "slideInFromBottom 0.5s ease-out reverse";
      setTimeout(() => {
        steigerlied.remove();
        style.remove();
        styleSheet.remove();
      }, 500);
      steigerlied.removeEventListener("click", closeHandler);
      document.removeEventListener("keydown", escHandler);
    };

    const escHandler = function (e) {
      if (e.key === "Escape") {
        closeHandler();
      }
    };

    steigerlied.addEventListener("click", closeHandler);
    document.addEventListener("keydown", escHandler);

    setTimeout(() => {
      if (document.body.contains(steigerlied)) {
        steigerlied.style.animation =
          "slideInFromBottom 0.5s ease-out reverse";
        setTimeout(() => {
          steigerlied.remove();
          style.remove();
          styleSheet.remove();
        }, 500);
      }
    }, 30000);
  }
})();

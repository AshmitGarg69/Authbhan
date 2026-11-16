/**
 * CRISPR AuthBahn - Captive Portal Auto-Login Content Script
 * Auto-fills and submits the FortiGate captive portal login form
 * (192.168.55.253) when saved credentials exist.
 */

(function () {
  chrome.storage.local.get(["username", "password"], function (data) {
    if (!data || !data.username || !data.password) return;

    // Only act when the actual login form is present on this page.
    const userField = document.getElementById("ft_un");
    const passField = document.getElementById("ft_pd");
    const form = userField && userField.closest("form");
    if (!userField || !passField || !form) return;

    // Fill the login form
    userField.value = data.username;
    passField.value = data.password;

    // Track the post-login keepalive URL for the popup's logout action
    const checkUrl = setInterval(function () {
      if (window.location.href.includes("192.168.55.253:1003/keepalive")) {
        clearInterval(checkUrl);
        const currentUrl = window.location.href;
        chrome.storage.local.set({ submittedUrl: currentUrl });
        console.log("The submitted URL is: " + currentUrl);
        setTimeout(function () {
          window.location.href = "https://crispr.iiitn.ac.in/";
        }, 1000);
      }
    }, 100);

    // Submit the login form programmatically
    try {
      form.submit();
    } catch (e) {
      console.warn("AuthBahn: could not submit portal form:", e);
    }
  });
})();

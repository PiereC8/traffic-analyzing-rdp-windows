const controls = document.querySelector(".case-controls");
const caseButtons = controls.querySelectorAll("button");

function showCase(selected) {
  for (const button of caseButtons) {
    const active = button === selected;
    button.setAttribute("aria-pressed", String(active));
    document.getElementById(button.getAttribute("aria-controls")).hidden = !active;
  }
}

for (const button of caseButtons) {
  button.addEventListener("click", () => showCase(button));
}

showCase(caseButtons[0]);
controls.hidden = false;

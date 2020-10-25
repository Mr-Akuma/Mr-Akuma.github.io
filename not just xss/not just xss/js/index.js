const input = document.querySelector("#input");
const button = document.querySelector("button");
const output = document.querySelector("#output");
const radioButtons = document.querySelector("#radioButtons");
const codeTitle = document.querySelector("#code-title");
const code = document.querySelector("#code");
const chal1 = document.querySelector("#chal-1");
const chal2 = document.querySelector("#chal-2");
const chal3 = document.querySelector("#chal-3");
const rules = document.querySelector("#rules");
const ruleLine = document.querySelector("#ruleLine");

function xssChallenge() {
  code.textContent = "";
  inputV = input.value.toLowerCase();
  if (chal1.checked) {
    codeOutput(`<h2>${inputV}</h2>`);
  } else if (chal2.checked) {
    inputV = inputV.replace(/>|(”)|(“)|(")|</g, "");
    codeOutput(`<a href=\"${inputV}\">Click Me</a>`);
  } else if (chal3.checked) {
    inputV = inputV.replace(/>|</g, "");
    inputV = inputV.replace(/(“)|(”)/g, '"');
    codeOutput(`<img src=\"${inputV}\">`);
  }
}

function codeOutput(outputCode) {
  
  output.innerHTML = outputCode;
  
}

function codeSelection() {
  code.textContent = "";
  output.textContent = "";
  if (chal1.checked) {

  } else if (chal2.checked) {
   
  } else if (chal3.checked) {

  } else {
   
  }
}

function codeSnippet(codeSnip) {

}

function rulesDisplay(rule) {

}

button.addEventListener("click", xssChallenge);
radioButtons.addEventListener("click", codeSelection);
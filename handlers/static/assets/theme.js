// The stylesheet's light tokens hang off [data-theme="light"], so mirror the system setting.
const lightScheme = matchMedia('(prefers-color-scheme: light)')

function applyTheme() {
  if (lightScheme.matches) {
    document.documentElement.dataset.theme = 'light'
    return
  }
  document.documentElement.dataset.theme = 'dark'
}

applyTheme()
lightScheme.addEventListener('change', applyTheme)

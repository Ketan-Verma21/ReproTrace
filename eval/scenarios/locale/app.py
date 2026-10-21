"""Applies the locale from the environment, as many CLI tools do at start-up."""

import locale

print(locale.setlocale(locale.LC_ALL, ""))

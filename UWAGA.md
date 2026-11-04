# UWAGA: ograniczenia zabezpieczeń ToolGate

**Status: wymaga dalszej weryfikacji.** Ta notatka dotyczy przeglądu commita [`6dd9795`](https://github.com/jarohull-ai/JFP-Box/commit/6dd979545d937e4f4f3564b8fcb8541722b147b2) oraz poprawki w branchu `fix/toolgate-validation-and-version` (commit [`050709d`](https://github.com/jarohull-ai/JFP-Box/commit/050709dd51aabecf967c9ab45c890f70c88824ff)).

## Ustalenia

- `ToolGate` wykonuje heurystyczną kontrolę tekstu. Dzielenie argumentu po białych znakach nie jest parserem składni powłoki i nie pozwala wiarygodnie ustalić, jakie działanie zostanie wykonane.
- Lista wykrywanych poleceń, ścieżek i wzorców nie jest kompletna. Nie należy traktować jej jako samodzielnej granicy bezpieczeństwa ani dowodu, że wywołanie jest bezpieczne.
- Poprawka `050709d` dodaje walidację manifestu przed decyzją `Allowed` oraz testy regresyjne dla niepoprawnego bindingu i niedozwolonego typu bramy.
- Testów tej poprawki **nie uruchomiono** w chwili sporządzenia notatki. Dla commita nie było dostępnych wyników CI. Nie wiadomo więc, czy zmiana przechodzi kompilację i testy.
- W przeglądanym commicie wersję pakietów zmieniono na `0.5.1`, ale `python-binding/src/lib.rs` nadal ustawia `__version__` na `0.5.0`.

## Co zrobić przed wydaniem

1. Uruchomić `cargo test --locked`, `cargo fmt -- --check` i `cargo clippy --all-targets -- -D warnings` na branchu `fix/toolgate-validation-and-version` lub w CI.
2. Zsynchronizować wersję `__version__` Python bindingu z wersją wydania.
3. Dodać testy dla błędnych i niekompletnych manifestów oraz przypadków, w których kontrola poleceń może błędnie dopuścić lub zablokować tekst.
4. Nie polegać na kontroli tekstowej jako sandboxie. Wykonanie narzędzi powinno być ograniczone niezależnie, np. przez jawne API narzędzi, minimalne uprawnienia i izolację środowiska.

**Ważne:** ta notatka jest przeglądem kodu, nie wynikiem audytu bezpieczeństwa ani potwierdzeniem odporności na obejście.

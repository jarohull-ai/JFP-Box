# UWAGA: ograniczenia zabezpieczeń ToolGate

**Status: wymaga dalszej weryfikacji.** Ta notatka dotyczy przeglądu commita [`6dd9795`](https://github.com/jarohull-ai/JFP-Box/commit/6dd979545d937e4f4f3564b8fcb8541722b147b2) oraz poprawki w branchu `fix/toolgate-validation-and-version` (commit [`050709d`](https://github.com/jarohull-ai/JFP-Box/commit/050709dd51aabecf967c9ab45c890f70c88824ff)).

## Ustalenia

- `ToolGate` wykonuje heurystyczną kontrolę tekstu. Dzielenie argumentu po białych znakach nie jest parserem składni powłoki i nie pozwala wiarygodnie ustalić, jakie działanie zostanie wykonane.
- Lista wykrywanych poleceń, ścieżek i wzorców nie jest kompletna. Nie należy traktować jej jako samodzielnej granicy bezpieczeństwa ani dowodu, że wywołanie jest bezpieczne.
- Poprawka `050709d` dodaje walidację manifestu przed decyzją `Allowed` oraz testy regresyjne dla niepoprawnego bindingu i niedozwolonego typu bramy.
- Testów tej poprawki **nie uruchomiono** w chwili sporządzenia notatki. Dla commita nie było dostępnych wyników CI. Nie wiadomo więc, czy zmiana przechodzi kompilację i testy.
- W przeglądanym commicie wersję pakietów zmieniono na `0.5.1`, ale `python-binding/src/lib.rs` nadal ustawia `__version__` na `0.5.0`.

## Szczegółowa analiza commita `6dd9795`

Zakres zmian: [`src/tool_gate.rs` w commicie `6dd9795`](https://github.com/jarohull-ai/JFP-Box/blob/6dd979545d937e4f4f3564b8fcb8541722b147b2/src/tool_gate.rs) oraz wpis w [CHANGELOG.md](https://github.com/jarohull-ai/JFP-Box/commit/6dd979545d937e4f4f3564b8fcb8541722b147b2).

- **Kontrole są heurystykami tekstowymi, nie analizą wykonania.** Normalizacja białych znaków i podział po whitespace nie uwzględniają składni, cytowania ani sposobu, w jaki konkretne narzędzie interpretuje argument. Wynik `Allowed` nie jest dowodem bezpieczeństwa polecenia.
- **Wykrywanie operacji destrukcyjnych i sieciowych jest niekompletne.** Kod rozpoznaje wybrane nazwy programów i fragmenty tekstu, więc nie daje gwarancji wykrycia wszystkich równoważnych działań. Z drugiej strony dopasowania podciągów mogą blokować tekst, który jedynie wspomina o danej ścieżce lub komendzie.
- **Sprawdzanie schematu URL jest ograniczone.** Weryfikacja obejmuje tylko wybrane narzędzia i argumenty zaczynające się od kilku wymienionych schematów; nie zastępuje walidacji URL w samym narzędziu `FETCH`/`SEARCH` ani ograniczeń po stronie sieci.
- **Deklarowany wynik audytu nie wynika z widocznych testów.** Changelog mówi o „10/10 PASS”, natomiast test w `src/tool_gate.rs` nazywa się `test_audit_suite_8_of_8` i obejmuje osiem scenariuszy. To rozbieżność wymagająca wyjaśnienia; te testy nie stanowią samodzielnego audytu bezpieczeństwa.
- **Podpis commita nie został zweryfikowany przez GitHub** (`verified: false`). To informacja o podpisie/pochodzeniu commita, nie sama w sobie dowód błędu w kodzie.

## Co zrobić przed wydaniem

1. Uruchomić `cargo test --locked`, `cargo fmt -- --check` i `cargo clippy --all-targets -- -D warnings` na branchu `fix/toolgate-validation-and-version` lub w CI.
2. Zsynchronizować wersję `__version__` Python bindingu z wersją wydania.
3. Dodać testy dla błędnych i niekompletnych manifestów oraz przypadków, w których kontrola poleceń może błędnie dopuścić lub zablokować tekst.
4. Nie polegać na kontroli tekstowej jako sandboxie. Wykonanie narzędzi powinno być ograniczone niezależnie, np. przez jawne API narzędzi, minimalne uprawnienia i izolację środowiska.
5. Wyjaśnić rozbieżność między deklaracją „10/10 PASS” w changelogu a zestawem testów opisanym jako „8 of 8”.

**Ważne:** ta notatka jest przeglądem kodu, nie wynikiem audytu bezpieczeństwa ani potwierdzeniem odporności na obejście.

from typing import Sequence


class Selector:
    def __init__(self, choices: Sequence[str]):
        self.choices = choices

    def select(self, prompt: str, default=None, error_text: str = "Invalid choice") -> str:
        for choice in self.choices:
            print(f"    {choice}")

        if default is not None:
            text_prompt = f"{prompt} [{default}]: "
        else:
            text_prompt = f"{prompt}: "

        while True:
            response = input(text_prompt).strip()
            if default is not None and not response:
                response = default

            selected = next(
                (choice for choice in self.choices if choice == response),
                None
            )
            if selected:
                return selected

            print(error_text)

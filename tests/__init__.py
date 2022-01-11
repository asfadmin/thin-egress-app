import pathlib
from typing import IO, Any

RESOURCES_PATH = pathlib.Path(__file__).parent.joinpath("resources/").absolute()


def open_resource(file: str, *args, **kwargs) -> IO[Any]:
    return (RESOURCES_PATH / file).open(*args, **kwargs)
